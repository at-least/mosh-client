//! The UDP mosh session (spec §3, §8) — composes the crypto and SSP
//! engines onto real sockets, driven by one dedicated thread. The
//! terminal engine is YOURS: the receiver's [`HostStreamState`] is a
//! pure event log, and the loop replays its newest prefix into one live
//! display — anything implementing [`MoshDisplay`] — through a
//! watermark (suffix feed when the newest state descends from the
//! display's position; full-log rebuild when a state branched). Raw
//! host bytes are also available via [`MoshSession::take_host_bytes`]
//! for embedders that feed their own engine off-session.
//!
//! Timing model: a monotonic `Instant` origin provides both the SSP
//! clock (ms) and the u16 wire timestamps (mod 2^16, 0xFFFF = "none").
//! The newest socket blocks with the sender's wait-time as its read
//! timeout (clamped); older sockets — kept for roaming — are drained
//! non-blocking, capped per wake like mosh.

use std::io::ErrorKind;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::crypto::{Base64Key, Direction, MoshOpener, MoshSealer, PacketHeader};
use super::fragment::{Fragment, FragmentAssembly, Fragmenter};
use super::ssp::{
    send_interval_ms, EventLog, HostEvent, HostStreamState, RecvOutcome, SspError, SspReceiver,
    SspSender, SspSentState, UserStream,
};
use super::wire::MOSH_PROTOCOL_VERSION;

/// mosh's port-hop interval (network.h PORT_HOP_INTERVAL).
pub const PORT_HOP_INTERVAL_MS: u64 = 10_000;
pub const MAX_PORTS_OPEN: usize = 10;
pub const MAX_OLD_SOCKET_AGE_MS: u64 = 60_000;
/// Never block longer than this waiting for a datagram (mosh's
/// POLL_TIMEOUT_MS).
const POLL_CAP_MS: u64 = 50;
/// Per-wake drain cap on old sockets (mosh caps at 64 datagrams/pump).
const OLD_SOCKET_DRAIN_CAP: usize = 64;
/// Timestamp freshness window for echoing (network.cc:105).
const TS_FRESH_MS: u64 = 1000;
/// RTT samples at or above this are ignored (network.cc:539).
const RTT_MAX_SAMPLE: u64 = 5000;
/// Last-resort payload MTU after EMSGSIZE (network.cc DEFAULT_SEND_MTU).
const DEFAULT_SEND_MTU: usize = 500;
/// Bursts larger than this are pastes — never predicted (stmclient.cc
/// BULK_INPUT_BYTES); the same constant client.rs re-exports.
pub const PASTE_THRESHOLD: usize = 100;

/// Application datagram MTUs after IP/UDP headers (network.h set_MTU).
fn mtu_for(addr: &SocketAddr) -> usize {
    match addr {
        SocketAddr::V4(_) => 1280 - 20 - 8,
        SocketAddr::V6(_) => 1280 - 40 - 16 - 8,
    }
}

#[derive(Debug)]
enum SessionCommand {
    Input(Vec<u8>),
    Resize { width: i32, height: i32 },
    StartShutdown,
    Terminate,
}

/// What the session loop tells the embedder.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionEvent {
    /// New host state applied — frame_version changed.
    ScreenChanged { host_num: u64 },
    /// The loop ended. `clean` = the shutdown handshake completed.
    Ended { clean: bool, error: Option<String> },
}

/// Link status for UI indicators (spec §8): how long since we heard
/// from the peer at all, and since an ack proved a round trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkHealth {
    pub since_heard_ms: u64,
    pub since_ack_ms: u64,
    /// True until the first authenticated datagram ("still connecting").
    pub never_heard: bool,
    /// The smoothed round-trip estimate, once a genuine timestamp reply
    /// confirmed a sample. `None` = cold start: the RTO rides the
    /// initial constants.
    pub rtt_ms: Option<u64>,
    /// The current retransmission timeout — the clamped
    /// `srtt + 4·rttvar` (50ms floor, 1s ceiling).
    pub rto_ms: u64,
}

/// The display the session's loop drives: the embedder's terminal
/// emulator. The loop replays the synchronized host stream into it —
/// incremental suffix normally, a full-log replay into
/// [`MoshDisplay::new_blank`] when a state branched — and reads
/// geometry from it for the prediction overlay.
pub trait MoshDisplay: Send + 'static {
    /// A blank engine at the given size (used for branch rebuilds).
    fn new_blank(cols: usize, rows: usize) -> Self
    where
        Self: Sized;
    fn feed(&mut self, bytes: &[u8]);
    fn resize(&mut self, cols: usize, rows: usize);
    fn cols(&self) -> usize;
    fn rows(&self) -> usize;
    /// (col, row, visible), 0-based screen coordinates.
    fn cursor(&self) -> (i32, i32, bool);
}

/// One predicted cell on the display (conservative local echo, spec
/// §7.2's echo-ack machinery retired them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PredictedCell {
    pub row: i32,
    pub col: i32,
    pub ch: char,
}

/// The prediction overlay: cells the CLIENT guessed the shell will
/// echo, plus the frame of the user stream each was typed under
/// (echo_ack retires by frame). Loop-side writes, reader-side merges
/// into frame_region — one lock, no cross-thread callbacks.
#[derive(Debug, Default)]
struct PredictionState {
    enabled: bool,
    cells: Vec<PredictedCell>,
    /// the user-stream frame each cell was predicted under, in the
    /// same order as `cells` (non-decreasing: bursts are recorded in
    /// time order and a burst retires whole)
    frames: Vec<u64>,
    /// shadow (col,row) where the NEXT predicted char would land
    cursor: Option<(i32, i32)>,
}

impl PredictionState {
    /// Conservative printable echo: one char per cell, CR moves the
    /// shadow to the next line start, backspace drops the last cell.
    /// Anything else (escape sequences, control bytes) ends the guess
    /// for the burst — mosh's own conservative set.
    fn feed(&mut self, cols: i32, rows: i32, frame: u64, bytes: &[u8]) {
        for &byte in bytes {
            match byte {
                0x0D => {
                    let (_, row) = self.shadow();
                    self.cursor = Some((0, (row + 1).min(rows - 1)));
                }
                0x7F => {
                    if let Some(last) = self.cells.last() {
                        self.cursor = Some((last.col, last.row));
                        self.cells.pop();
                        self.frames.pop();
                    }
                }
                b if (0x20..0x7F).contains(&b) => {
                    let (col, row) = self.shadow();
                    if col < cols - 1 {
                        self.cells.push(PredictedCell {
                            row,
                            col,
                            ch: b as char,
                        });
                        self.frames.push(frame);
                        self.cursor = Some((col + 1, row));
                    }
                }
                _ => break, // not predictable — end the burst's guesses
            }
        }
    }

    fn shadow(&self) -> (i32, i32) {
        self.cursor.unwrap_or((0, 0))
    }

    /// Cells confirmed through `echo_ack`: the prefix predicted under
    /// frames at or below it. Per-cell frames make the retirement exact
    /// where summed per-burst deltas drifted — a retraction pops its
    /// cell for good, and a net-zero burst (backspace then a fresh
    /// char) leaves no bookkeeping to miscount.
    fn confirmed_prefix_len(&self, echo_ack: u64) -> usize {
        self.frames.partition_point(|&f| f <= echo_ack)
    }

    fn clear(&mut self) {
        self.cells.clear();
        self.frames.clear();
        self.cursor = None;
    }
}

/// Loop-side counters shared out to the handle.
struct Shared {
    frame_version: AtomicU64,
    last_heard_ms: AtomicU64,
    last_roundtrip_ms: AtomicU64,
    never_heard: AtomicBool,
    now_ms: AtomicU64,
    /// Total sockets ever bound (1 + roaming hops).
    ports_opened: AtomicU64,
    /// Newest user-stream state the server has acked.
    user_acked: AtomicU64,
    /// Whether host bytes also accumulate for [`MoshSession::take_host_bytes`]
    /// (on by default; display-only embedders turn it off).
    capture_host_bytes: AtomicBool,
    /// The srtt estimate in ms, biased by +1 so 0 means "no sample yet"
    /// (one atomic: a reader must never see known-but-unwritten).
    rtt_ms_biased: AtomicU64,
    /// The current retransmission timeout, stored per tick.
    rto_ms: AtomicU64,
}

impl Shared {
    fn link_health(&self) -> LinkHealth {
        let now = self.now_ms.load(Ordering::Relaxed);
        let rtt = self.rtt_ms_biased.load(Ordering::Relaxed);
        LinkHealth {
            since_heard_ms: now.saturating_sub(self.last_heard_ms.load(Ordering::Relaxed)),
            since_ack_ms: now.saturating_sub(self.last_roundtrip_ms.load(Ordering::Relaxed)),
            never_heard: self.never_heard.load(Ordering::Relaxed),
            rtt_ms: if rtt == 0 { None } else { Some(rtt - 1) },
            rto_ms: self.rto_ms.load(Ordering::Relaxed),
        }
    }
}

/// A client mosh session over UDP with the display engine in-core.
/// Cheap handle; the loop owns the sockets and the timers.
pub struct MoshSession<D: MoshDisplay> {
    commands: Mutex<Option<Sender<SessionCommand>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    shared: Arc<Shared>,
    display: Arc<Mutex<D>>,
    /// host bytes not yet drained by the embedder (see take_host_bytes)
    pending_bytes: Arc<Mutex<Vec<u8>>>,
    /// the conservative-echo overlay (loop writes, frame_region reads)
    prediction: Arc<Mutex<PredictionState>>,
    /// everything the loop thread needs, until start() launches it.
    /// The session is built DEFERRED so the async constructor that
    /// created it can return before any thread exists — a live loop
    /// racing uniffi's async completion wedged the Swift continuation
    /// (the e2e-documented hang; start() is a safe sync FFI context).
    launch: Mutex<Option<SessionLaunch<D>>>,
}

/// The pre-start bundle for [MoshSession::start].
struct SessionLaunch<D: MoshDisplay> {
    socket: UdpSocket,
    target: SocketAddr,
    key: Base64Key,
    display: Arc<Mutex<D>>,
    events: Box<dyn Fn(SessionEvent) + Send + Sync>,
    commands: Receiver<SessionCommand>,
    shared: Arc<Shared>,
    pending: Arc<Mutex<Vec<u8>>>,
    prediction: Arc<Mutex<PredictionState>>,
    hop_interval_ms: u64,
    cols: i32,
    rows: i32,
}

impl<D: MoshDisplay> MoshSession<D> {
    /// Connect to `addr:port` (the UDP target from the bootstrap) with
    /// the `MOSH CONNECT` key. The embedder owns `display` (the same
    /// Arc the session drives) and reads frames from it. Events fire
    /// on the loop thread.
    #[allow(clippy::too_many_arguments)]
    pub fn connect<F>(
        display: Arc<Mutex<D>>,
        addr: &str,
        port: u16,
        key: &Base64Key,
        events: F,
        cols: u32,
        rows: u32,
        prediction_on: bool,
    ) -> Result<Self, String>
    where
        F: Fn(SessionEvent) + Send + Sync + 'static,
    {
        let target = resolve(addr, port)?;
        let socket = bind_for(&target)?;
        Self::connect_on(
            display,
            socket,
            target,
            key,
            events,
            cols,
            rows,
            PORT_HOP_INTERVAL_MS,
            prediction_on,
        )
    }

    /// Bring-your-own-socket entry (tests, embedder-managed sockets).
    /// `hop_interval_ms` is mosh's roaming trigger, overridable so tests
    /// can exercise it quickly.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_on<F>(
        display: Arc<Mutex<D>>,
        socket: UdpSocket,
        target: SocketAddr,
        key: &Base64Key,
        events: F,
        cols: u32,
        rows: u32,
        hop_interval_ms: u64,
        prediction_on: bool,
    ) -> Result<Self, String>
    where
        F: Fn(SessionEvent) + Send + Sync + 'static,
    {
        let session = Self::build_deferred(
            display,
            socket,
            target,
            key,
            events,
            cols,
            rows,
            hop_interval_ms,
            prediction_on,
        )?;
        session.start();
        Ok(session)
    }

    /// Everything [Self::connect_on] does except launching the loop
    /// (see `launch` for why the client defers).
    #[allow(clippy::too_many_arguments)]
    fn build_deferred<F>(
        display: Arc<Mutex<D>>,
        socket: UdpSocket,
        target: SocketAddr,
        key: &Base64Key,
        events: F,
        cols: u32,
        rows: u32,
        hop_interval_ms: u64,
        prediction_on: bool,
    ) -> Result<Self, String>
    where
        F: Fn(SessionEvent) + Send + Sync + 'static,
    {
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let shared = Arc::new(Shared {
            frame_version: AtomicU64::new(1),
            last_heard_ms: AtomicU64::new(0),
            last_roundtrip_ms: AtomicU64::new(0),
            never_heard: AtomicBool::new(true),
            now_ms: AtomicU64::new(0),
            ports_opened: AtomicU64::new(1),
            user_acked: AtomicU64::new(0),
            capture_host_bytes: AtomicBool::new(true),
            rtt_ms_biased: AtomicU64::new(0),
            rto_ms: AtomicU64::new(1000),
        });
        let pending = Arc::new(Mutex::new(Vec::new()));
        let prediction = Arc::new(Mutex::new(PredictionState {
            enabled: prediction_on,
            cells: Vec::new(),
            frames: Vec::new(),
            cursor: None,
        }));

        let session = MoshSession {
            commands: Mutex::new(Some(cmd_tx)),
            thread: Mutex::new(None),
            shared: Arc::clone(&shared),
            display: Arc::clone(&display),
            pending_bytes: Arc::clone(&pending),
            prediction: Arc::clone(&prediction),
            launch: Mutex::new(Some(SessionLaunch {
                socket,
                target,
                key: key.clone(),
                display,
                events: Box::new(events) as Box<dyn Fn(SessionEvent) + Send + Sync>,
                commands: cmd_rx,
                shared,
                pending,
                prediction: Arc::clone(&prediction),
                hop_interval_ms,
                cols: cols as i32,
                rows: rows as i32,
            })),
        };
        Ok(session)
    }

    /// Like [Self::connect] but the UDP loop stays UNSTARTED — the
    /// async constructor must return before any thread exists (see
    /// `launch`). [Self::start] launches it from a safe, synchronous
    /// FFI context.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_deferred<F>(
        display: Arc<Mutex<D>>,
        addr: &str,
        port: u16,
        key: &Base64Key,
        events: F,
        cols: u32,
        rows: u32,
        prediction_on: bool,
    ) -> Result<Self, String>
    where
        F: Fn(SessionEvent) + Send + Sync + 'static,
    {
        let target = resolve(addr, port)?;
        let socket = bind_for(&target)?;
        Self::connect_on_deferred(
            display,
            socket,
            target,
            key,
            events,
            cols,
            rows,
            PORT_HOP_INTERVAL_MS,
            prediction_on,
        )
    }

    /// The deferred twin of [Self::connect_on].
    #[allow(clippy::too_many_arguments)]
    pub fn connect_on_deferred<F>(
        display: Arc<Mutex<D>>,
        socket: UdpSocket,
        target: SocketAddr,
        key: &Base64Key,
        events: F,
        cols: u32,
        rows: u32,
        hop_interval_ms: u64,
        prediction_on: bool,
    ) -> Result<Self, String>
    where
        F: Fn(SessionEvent) + Send + Sync + 'static,
    {
        Self::build_deferred(
            display,
            socket,
            target,
            key,
            events,
            cols,
            rows,
            hop_interval_ms,
            prediction_on,
        )
    }

    /// Launch the UDP loop. Idempotent. Must run OUTSIDE the async
    /// constructor that built the session (see `launch`): a live loop
    /// racing uniffi's async completion wedged the Swift continuation
    /// — start() is a safe, synchronous FFI context.
    pub fn start(&self) {
        let mut thread_slot = self.thread.lock().unwrap();
        if thread_slot.is_some() {
            return;
        }
        let launch = self.launch.lock().unwrap().take();
        let Some(launch) = launch else { return };
        let SessionLaunch {
            socket,
            target,
            key,
            display,
            events,
            commands,
            shared,
            pending,
            prediction,
            hop_interval_ms,
            cols,
            rows,
        } = launch;
        let handle = std::thread::Builder::new()
            .name("mosh-session".into())
            .spawn(move || {
                let mut engine = SessionLoop::new(
                    socket, target, key, display, events, commands, shared, pending, prediction,
                );
                engine.sender.current_state().push_resize(cols, rows);
                engine.hop_interval_ms = hop_interval_ms;
                engine.run();
            })
            .expect("spawn mosh-session");
        *thread_slot = Some(handle);
    }

    /// Queue user bytes. The escape-key/prediction interception lives
    /// one layer up (the embedder); this is the raw stream.
    pub fn send_input(&self, bytes: &[u8]) {
        self.command(SessionCommand::Input(bytes.to_vec()));
    }

    pub fn resize(&self, width: i32, height: i32) {
        // resize locally at once (the UI must not wait an RTT); the
        // server's repaint at the new size follows via the host stream
        if width >= 2 && height >= 2 {
            self.display
                .lock()
                .unwrap()
                .resize(width as usize, height as usize);
            self.shared.frame_version.fetch_add(1, Ordering::Relaxed);
        }
        self.command(SessionCommand::Resize { width, height });
    }

    /// Begin the shutdown handshake; the loop exits when it completes
    /// or times out (SHUTDOWN_RETRIES / ACTIVE_RETRY_TIMEOUT).
    pub fn start_shutdown(&self) {
        self.command(SessionCommand::StartShutdown);
    }

    /// Hard stop (app teardown) — no handshake attempt, no `Ended`
    /// event, joins the loop.
    pub fn terminate(&self) {
        self.command(SessionCommand::Terminate);
        self.join();
    }

    /// Wait for loop exit after an `Ended` event (idempotent).
    pub fn join(&self) {
        if let Some(thread) = self.thread.lock().unwrap().take() {
            let _ = thread.join();
        }
    }

    pub fn link_health(&self) -> LinkHealth {
        self.shared.link_health()
    }

    /// Read the current terminal state (host bytes were replayed here).
    pub fn with_display<R>(&self, read: impl FnOnce(&D) -> R) -> R {
        read(&self.display.lock().unwrap())
    }

    /// The display handle (the embedder's own Arc — typed reads like
    /// frame rendering go straight to it).
    pub fn display(&self) -> &Arc<Mutex<D>> {
        &self.display
    }

    /// Monotonic version of the display (bumped per applied state and
    /// local resize).
    pub fn frame_version(&self) -> u64 {
        self.shared.frame_version.load(Ordering::Relaxed)
    }

    /// Total UDP sockets ever bound (1 + roaming hops).
    pub fn ports_opened(&self) -> u64 {
        self.shared.ports_opened.load(Ordering::Relaxed)
    }

    /// The newest user-stream state number the server has acknowledged
    /// (0 = nothing of ours was processed yet).
    pub fn user_stream_acked(&self) -> u64 {
        self.shared.user_acked.load(Ordering::Relaxed)
    }

    /// Drain host bytes the embedder hasn't consumed yet. The in-loop
    /// display advances independently; on a branch rebuild the buffer
    /// carries a FULL repaint, so a linear consumer stays correct.
    /// Capture can be turned off entirely with
    /// [`MoshSession::set_host_bytes_capture`].
    pub fn take_host_bytes(&self) -> Vec<u8> {
        std::mem::take(&mut *self.pending_bytes.lock().unwrap())
    }

    /// Toggle the host-byte capture behind
    /// [`MoshSession::take_host_bytes`] (on by default). An embedder
    /// that renders through the display alone should turn it off: the
    /// pending buffer is unbounded by design, and without a drainer it
    /// grows with the session's traffic. The display feed is
    /// unaffected either way, and bytes already buffered stay until
    /// the next [`MoshSession::take_host_bytes`] drains them.
    pub fn set_host_bytes_capture(&self, enabled: bool) {
        self.shared
            .capture_host_bytes
            .store(enabled, Ordering::Relaxed);
    }

    /// Toggle conservative local echo (Never/Always; default on).
    pub fn set_prediction(&self, enabled: bool) {
        let mut prediction = self.prediction.lock().unwrap();
        prediction.enabled = enabled;
        if !enabled {
            prediction.clear();
        }
    }

    /// The predicted-cell overlay to merge into your rendering
    /// (underline these — mosh's "this is a guess" mark).
    pub fn prediction_overlay(&self) -> Vec<PredictedCell> {
        self.prediction.lock().unwrap().cells.clone()
    }

    fn command(&self, command: SessionCommand) {
        if let Some(tx) = self.commands.lock().unwrap().as_ref() {
            let _ = tx.send(command);
        }
    }
}

fn resolve(addr: &str, port: u16) -> Result<SocketAddr, String> {
    (addr, port)
        .to_socket_addrs()
        .map_err(|e| format!("mosh: bad address {addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("mosh: no address for {addr}"))
}

fn bind_for(target: &SocketAddr) -> Result<UdpSocket, String> {
    let bind_addr: &str = if target.is_ipv4() { "0.0.0.0" } else { "::" };
    UdpSocket::bind((bind_addr, 0)).map_err(|e| format!("mosh: bind: {e}"))
}

/// std has no stable ErrorKind for EMSGSIZE; compare the raw errno
/// (macOS 40, Linux 90 — the only platforms conch ships on).
fn is_emsgsize(e: &std::io::Error) -> bool {
    #[cfg(target_os = "macos")]
    const EMSGSIZE: i32 = 40;
    #[cfg(all(unix, not(target_os = "macos")))]
    const EMSGSIZE: i32 = 90;
    #[cfg(not(unix))]
    const EMSGSIZE: i32 = -1;
    e.raw_os_error() == Some(EMSGSIZE)
}

// --- the loop ------------------------------------------------------------

/// The receive-side sender updates (upstream networktransport-impl.h
/// `recv()`): what each receiver outcome does to OUR outbound sender.
fn apply_recv_outcome<Sent: SspSentState, Recv>(
    sender: &mut SspSender<Sent>,
    outcome: RecvOutcome<Recv>,
    now: u64,
) {
    match outcome {
        RecvOutcome::Latest { num, had_diff, .. } => {
            sender.set_ack_num(num);
            sender.remote_heard(now);
            if had_diff {
                sender.set_data_ack();
            }
        }
        RecvOutcome::OutOfOrder { .. } => {
            // upstream returns right after inserting (networktransport-
            // impl.h:143-165): an out-of-order state never refreshes the
            // retry window, raises our ack, or schedules a data ack
        }
        RecvOutcome::Duplicate | RecvOutcome::NoReference | RecvOutcome::Quenched => {}
    }
}

struct SessionLoop<D: MoshDisplay> {
    socks: Vec<UdpSocket>, // newest last
    target: SocketAddr,
    mtu: usize,
    sealer: MoshSealer,
    opener: MoshOpener,
    sender: SspSender<UserStream>,
    receiver: SspReceiver<HostStreamState>,
    display: Arc<Mutex<D>>,
    /// the log position the display engine has consumed (an EventLog
    /// node — pointer-compared against newest states)
    engine_at: EventLog,
    fragmenter: Fragmenter,
    assembly: FragmentAssembly,
    commands: Receiver<SessionCommand>,
    shared: Arc<Shared>,
    pending_bytes: Arc<Mutex<Vec<u8>>>,
    prediction: Arc<Mutex<PredictionState>>,
    events: Box<dyn Fn(SessionEvent) + Send + Sync>,
    origin: Instant,
    // connection-layer state (spec §3)
    expected_receiver_seq: u64,
    saved_timestamp: Option<(u16, u64)>, // (ts, received_at ms)
    srtt: f64,
    rttvar: f64,
    rtt_hit: bool,
    last_port_choice: u64,
    last_roundtrip_success: u64,
    hop_interval_ms: u64,
    fatal: Option<String>,
    /// MOSH_TRACE, read once at loop start (the old code re-queried the
    /// environment per datagram and per prediction event)
    trace: bool,
}

impl<D: MoshDisplay> SessionLoop<D> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        socket: UdpSocket,
        target: SocketAddr,
        key: Base64Key,
        display: Arc<Mutex<D>>,
        events: Box<dyn Fn(SessionEvent) + Send + Sync>,
        commands: Receiver<SessionCommand>,
        shared: Arc<Shared>,
        pending_bytes: Arc<Mutex<Vec<u8>>>,
        prediction: Arc<Mutex<PredictionState>>,
    ) -> Self {
        SessionLoop {
            socks: vec![socket],
            target,
            mtu: mtu_for(&target),
            sealer: MoshSealer::new(&key, Direction::ToServer),
            opener: MoshOpener::new(&key, Direction::ToClient),
            sender: SspSender::new(UserStream::new(), 0, 1),
            receiver: SspReceiver::new(HostStreamState::new(), 0),
            display,
            engine_at: EventLog::new(),
            fragmenter: Fragmenter::default(),
            assembly: FragmentAssembly::new(),
            commands,
            shared,
            pending_bytes,
            prediction,
            events,
            origin: Instant::now(),
            expected_receiver_seq: 0,
            saved_timestamp: None,
            srtt: 1000.0,
            rttvar: 500.0,
            rtt_hit: false,
            last_port_choice: 0,
            last_roundtrip_success: 0,
            hop_interval_ms: PORT_HOP_INTERVAL_MS,
            fatal: None,
            trace: std::env::var_os("MOSH_TRACE").is_some(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    fn feed_display(&self, display: &mut D, event: &HostEvent) {
        match event {
            HostEvent::Bytes(bytes) => {
                if self.trace {
                    eprintln!(
                        "[mosh] feed {} bytes: {:?}",
                        bytes.len(),
                        String::from_utf8_lossy(bytes)
                    );
                }
                display.feed(bytes);
                if self.shared.capture_host_bytes.load(Ordering::Relaxed) {
                    self.pending_bytes.lock().unwrap().extend_from_slice(bytes);
                }
            }
            HostEvent::Resize { width, height } => {
                if self.trace {
                    eprintln!("[mosh] host resize {width}x{height}");
                }
                display.resize(*width as usize, *height as usize);
            }
        }
    }

    fn timestamp16(&self) -> u16 {
        let ts = (self.now_ms() % 65_536) as u16;
        if ts == u16::MAX {
            0
        } else {
            ts
        }
    }

    fn rto(&self) -> u64 {
        (self.srtt + 4.0 * self.rttvar).ceil().clamp(50.0, 1000.0) as u64
    }

    fn send_interval(&self) -> u64 {
        send_interval_ms(self.srtt)
    }

    fn fragment_mtu(&self) -> usize {
        // Connection::ADDED_BYTES(12) + the OCB tag(16) come out of the
        // application datagram budget (spec §4)
        self.mtu.saturating_sub(12 + 16)
    }

    fn run(&mut self) {
        loop {
            let now = self.now_ms();
            self.shared.now_ms.store(now, Ordering::Relaxed);

            if !self.drain_commands(now) {
                break;
            }
            if let Some(error) = self.fatal.clone() {
                (self.events)(SessionEvent::Ended {
                    clean: false,
                    error: Some(error),
                });
                break;
            }

            let mut out = Vec::new();
            let rto = self.rto();
            self.shared.rto_ms.store(rto, Ordering::Relaxed);
            self.sender.tick(
                now,
                rto,
                self.send_interval(),
                self.fragment_mtu(),
                &mut self.fragmenter,
                &mut out,
            );
            for fragment in &out {
                self.send_fragment(fragment);
            }

            self.maybe_hop_port(now);
            self.prune_sockets(now);

            // The peer's shutdown was received and our ack carrying it
            // has gone out — the session is over cleanly, whoever
            // started the handshake (upstream stmclient.cc: "quit if we
            // received and acknowledged a shutdown request"; the ack
            // only carries MAX once the peer's shutdown state landed).
            // Deliberate order deviation: upstream checks this LAST,
            // after its own shutdown-acknowledged and timeout breaks —
            // so a timed-out own handshake reports unclean even when
            // the peer demonstrably quit. Here the peer's acknowledged
            // shutdown wins with clean: true; the handshake did
            // complete, on the peer's initiative.
            if self
                .sender
                .counterparty_shutdown_acknowledged(&self.fragmenter)
            {
                (self.events)(SessionEvent::Ended {
                    clean: true,
                    error: None,
                });
                break;
            }

            if self.sender.shutdown_in_progress()
                && (self.sender.shutdown_acknowledged() || self.sender.shutdown_ack_timed_out(now))
            {
                (self.events)(SessionEvent::Ended {
                    clean: self.sender.shutdown_acknowledged(),
                    error: None,
                });
                break;
            }

            // wait for a datagram or the next timer, bounded
            let wait = self
                .sender
                .wait_time(now, self.rto(), self.send_interval())
                .clamp(1, POLL_CAP_MS);
            self.receive(wait);
        }
    }

    /// Returns false when the loop should exit (Terminate).
    fn drain_commands(&mut self, now: u64) -> bool {
        loop {
            match self.commands.try_recv() {
                Ok(SessionCommand::Input(bytes)) => {
                    if !self.sender.shutdown_in_progress() {
                        self.sender.current_state().push_bytes(&bytes);
                        self.predict_input(&bytes);
                    }
                }
                Ok(SessionCommand::Resize { width, height }) => {
                    if !self.sender.shutdown_in_progress() {
                        self.sender.current_state().push_resize(width, height);
                    }
                }
                Ok(SessionCommand::StartShutdown) => self.sender.start_shutdown(now),
                Ok(SessionCommand::Terminate) => return false,
                Err(_) => return true,
            }
        }
    }

    fn send_fragment(&mut self, fragment: &Fragment) {
        let now = self.now_ms();
        // echo the peer's timestamp, advanced by how long we held it,
        // only while it is fresh, and only once (network.cc:99-115)
        let outgoing_reply = match self.saved_timestamp {
            Some((ts, received_at)) if now - received_at < TS_FRESH_MS => {
                let held = (now - received_at) as u16;
                let corrected = ts.wrapping_add(held);
                self.saved_timestamp = None;
                Some(corrected)
            }
            _ => None,
        };
        let header = PacketHeader {
            timestamp: self.timestamp16(),
            timestamp_reply: outgoing_reply.unwrap_or(u16::MAX),
        };
        let datagram = match self.sealer.seal(&header, &fragment.tostring()) {
            Ok(datagram) => datagram,
            Err(_) => {
                self.fatal = Some("mosh: session exhausted its key budget".into());
                return;
            }
        };
        let socket = self.socks.last().expect("always one socket");
        if let Err(e) = socket.send_to(&datagram, self.target) {
            if is_emsgsize(&e) {
                self.mtu = DEFAULT_SEND_MTU;
            }
            // transient errors (unreachable network etc.) are exactly
            // what retransmission and roaming exist for
        }
    }

    /// Blocking-with-timeout receive on the newest socket plus a
    /// non-blocking drain of the old ones.
    fn receive(&mut self, wait_ms: u64) {
        let mut buf = [0u8; 2048];
        let newest = self.socks.len() - 1;
        self.socks[newest]
            .set_read_timeout(Some(Duration::from_millis(wait_ms)))
            .ok();
        match self.socks[newest].recv_from(&mut buf) {
            Ok((len, _)) => self.handle_datagram(&buf[..len]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => {}
        }
        if self.socks.len() > 1 {
            let mut drained = 0;
            for idx in (0..self.socks.len() - 1).rev() {
                self.socks[idx].set_nonblocking(true).ok();
                loop {
                    match self.socks[idx].recv_from(&mut buf) {
                        Ok((len, _)) => {
                            self.handle_datagram(&buf[..len]);
                            drained += 1;
                            if drained >= OLD_SOCKET_DRAIN_CAP {
                                break;
                            }
                        }
                        Err(e)
                            if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                        {
                            break
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }

    fn handle_datagram(&mut self, bytes: &[u8]) {
        let now = self.now_ms();
        let Ok((seq, header, fragment)) = self.opener.open(bytes) else {
            return; // wrong direction, bad tag, or garbage: drop
        };
        // the seq gate: replays still decode but never touch timing
        let seq_ok = seq >= self.expected_receiver_seq;
        if seq_ok {
            self.expected_receiver_seq = seq + 1;
            // any fresh-seq datagram is proof of life, whether or not
            // its fragment assembles (network.cc:556)
            self.shared.last_heard_ms.store(now, Ordering::Relaxed);
            if header.timestamp != u16::MAX {
                self.saved_timestamp = Some((header.timestamp, now));
            }
            if header.timestamp_reply != u16::MAX {
                let sample = self.timestamp16().wrapping_sub(header.timestamp_reply) as u64;
                if sample < RTT_MAX_SAMPLE {
                    let r = sample as f64;
                    if !self.rtt_hit {
                        self.srtt = r;
                        self.rttvar = r / 2.0;
                        self.rtt_hit = true;
                    } else {
                        self.rttvar = 0.75 * self.rttvar + 0.25 * (self.srtt - r).abs();
                        self.srtt = 0.875 * self.srtt + 0.125 * r;
                    }
                    self.shared
                        .rtt_ms_biased
                        .store(self.srtt.round() as u64 + 1, Ordering::Relaxed);
                }
            }
        }

        let Ok(fragment) = Fragment::parse(&fragment) else {
            return;
        };
        let Some(inst) = self.assembly.add_fragment(fragment) else {
            return;
        };

        // the protocol-version gate precedes everything the instruction
        // could touch (§6.2 order) — an ack from a wrong-version peer
        // is not ours to apply. The receiver re-checks as its own
        // invariant; the session dies either way.
        if inst.protocol_version != MOSH_PROTOCOL_VERSION {
            self.fatal = Some(format!(
                "mosh: {}",
                SspError::ProtocolVersion(inst.protocol_version)
            ));
            return;
        }

        self.sender.process_acknowledgment_through(inst.ack_num);
        self.shared
            .user_acked
            .store(self.sender.sent_state_acked(), Ordering::Relaxed);
        self.last_roundtrip_success = self.sender.sent_state_acked_timestamp();
        self.shared
            .last_roundtrip_ms
            .store(self.last_roundtrip_success, Ordering::Relaxed);

        if self.trace {
            eprintln!(
                "[mosh] inst old={} new={} ack={} tw={} diff_len={}",
                inst.old_num,
                inst.new_num,
                inst.ack_num,
                inst.throwaway_num,
                inst.diff.len()
            );
        }
        match self.receiver.process_instruction(&inst, now) {
            Ok(outcome @ RecvOutcome::Latest { num, .. }) => {
                apply_recv_outcome(&mut self.sender, outcome, now);
                // upstream "still connecting" means no appended remote
                // state yet (stmclient.h:81-85) — an appended state ends it
                self.shared.never_heard.store(false, Ordering::Relaxed);
                // advance the engine along the newest state's log: the
                // common case is a pure suffix (feed it); a state that
                // branched from an older base means the diff was a
                // repaint against a different screen — rebuild the
                // engine from the state's full log
                let latest = self.receiver.latest_state();
                let mut fed = false;
                if let Some(suffix) = latest.log.suffix_over(&self.engine_at) {
                    if !suffix.is_empty() {
                        let mut display = self.display.lock().unwrap();
                        for event in suffix {
                            self.feed_display(&mut display, event);
                        }
                        drop(display);
                        self.engine_at = latest.log.clone();
                        fed = true;
                    }
                    // Some(empty): the engine already sits exactly here
                } else {
                    if self.trace {
                        eprintln!(
                            "[mosh] rebuild: state {num} branched (engine at {} of {})",
                            self.engine_at.len(),
                            latest.log.len()
                        );
                    }
                    let (cols, rows) = {
                        let display = self.display.lock().unwrap();
                        (display.cols(), display.rows())
                    };
                    let mut fresh = D::new_blank(cols, rows);
                    for event in latest.log.iter() {
                        self.feed_display(&mut fresh, event);
                    }
                    *self.display.lock().unwrap() = fresh;
                    self.engine_at = latest.log.clone();
                    fed = true;
                }
                // retire AFTER the real bytes landed: a render in between
                // then still shows the guess alongside reality, never an
                // empty slot where the guess used to be. An echoack-only
                // state (nothing fed) retires here too — upstream's
                // echo-ack never waits for the next paint — and that alone
                // is a repaint trigger, or the stale underline lingers.
                let echo_ack = self.receiver.latest_state().echo_ack;
                if self.retire_predictions(echo_ack) || fed {
                    self.shared.frame_version.fetch_add(1, Ordering::Relaxed);
                    (self.events)(SessionEvent::ScreenChanged { host_num: num });
                }
            }
            Ok(outcome @ RecvOutcome::OutOfOrder { .. }) => {
                if self.trace {
                    eprintln!("[mosh]   -> out-of-order insert");
                }
                apply_recv_outcome(&mut self.sender, outcome, now);
            }
            Ok(other) => {
                if self.trace {
                    eprintln!("[mosh]   -> {other:?}");
                }
            }
            Err(e) => {
                self.fatal = Some(format!("mosh: {e}"));
            }
        }
    }

    /// Conservative echo-ahead: guess the printable chars of this
    /// burst at the engine's cursor, tagged with the user-stream frame
    /// they ride (the NEXT state number the sender will assign; several
    /// bursts before a send share it — they coalesce into one state).
    fn predict_input(&mut self, bytes: &[u8]) {
        if bytes.len() > PASTE_THRESHOLD {
            return; // pastes are never predicted
        }
        let (cols, rows, cursor) = {
            let display = self.display.lock().unwrap();
            let (col, row, _) = display.cursor();
            (display.cols(), display.rows(), (col, row))
        };
        let frame = self.sender.sent_state_last() + 1;
        let mut prediction = self.prediction.lock().unwrap();
        if !prediction.enabled {
            return;
        }
        if prediction.cursor.is_none() {
            // a fresh guess run starts where the engine cursor sits
            prediction.cursor = Some(cursor);
        }
        prediction.feed(cols as i32, rows as i32, frame, bytes);
    }

    /// The server echoed everything typed up to `echo_ack` (spec §7.2)
    /// — those guesses are now reality, the real bytes already
    /// rendered. Retire the confirmed prefix. Returns true when any
    /// cell was drained, i.e. the display must repaint to drop the
    /// guess underline.
    fn retire_predictions(&mut self, echo_ack: u64) -> bool {
        let mut prediction = self.prediction.lock().unwrap();
        if self.trace {
            eprintln!(
                "[mosh] retire: echo_ack={echo_ack} frames={:?} cells={}",
                prediction.frames,
                prediction.cells.len()
            );
        }
        let take = prediction.confirmed_prefix_len(echo_ack);
        prediction.cells.drain(..take);
        prediction.frames.drain(..take);
        take > 0
    }

    fn maybe_hop_port(&mut self, now: u64) {
        if now - self.last_port_choice <= self.hop_interval_ms {
            return;
        }
        if now - self.last_roundtrip_success <= self.hop_interval_ms {
            return;
        }
        if let Ok(socket) = bind_for(&self.target) {
            self.socks.push(socket);
            self.last_port_choice = now;
            self.shared.ports_opened.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn prune_sockets(&mut self, now: u64) {
        if self.socks.len() > 1 && now - self.last_port_choice > MAX_OLD_SOCKET_AGE_MS {
            let keep = self.socks.len() - 1;
            self.socks.drain(..keep);
        }
        while self.socks.len() > MAX_PORTS_OPEN {
            self.socks.remove(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinning for the per-cell retirement bookkeeping: cells carry the
    /// frame they were predicted under, so a retraction pops its cell
    /// for good and the confirmed set is exactly the prefix at or under
    /// the echo-ack — a net-zero burst (backspace then a fresh char)
    /// leaves nothing to miscount. The e2e regression
    /// echoack_retires_only_the_confirmed_prefix_of_predictions drove
    /// this through the wire.
    #[test]
    fn prediction_retirement_takes_the_confirmed_prefix() {
        let mut p = PredictionState {
            enabled: true,
            cells: Vec::new(),
            frames: Vec::new(),
            cursor: Some((0, 0)),
        };
        p.feed(20, 4, 5, b"abc");
        p.feed(20, 4, 6, b"\x7fd"); // pops 'c', pushes 'd' — net zero
        let chars = |p: &PredictionState| p.cells.iter().map(|c| c.ch).collect::<String>();
        assert_eq!(chars(&p), "abd");
        assert_eq!(p.confirmed_prefix_len(4), 0, "nothing confirmed yet");
        assert_eq!(
            p.confirmed_prefix_len(5),
            2,
            "\"abc\" confirmed, c already gone"
        );
        assert_eq!(p.confirmed_prefix_len(6), 3, "the edit burst confirmed too");

        let take = p.confirmed_prefix_len(5);
        p.cells.drain(..take);
        p.frames.drain(..take);
        assert_eq!(chars(&p), "d", "the never-echoed guess survives");
    }

    /// B1 regression: an out-of-order insert must NOT refresh the
    /// sender's retry window. Upstream returns from `recv()` right
    /// after inserting (networktransport-impl.h:143-165), before
    /// `remote_heard` (line 162) — only an appended state counts as
    /// heard. Refreshing on out-of-order keeps frame-rate resends
    /// alive longer than stock mosh would.
    #[test]
    fn out_of_order_insert_does_not_refresh_the_resend_window() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        apply_recv_outcome(
            &mut sender,
            RecvOutcome::<UserStream>::OutOfOrder {
                num: 1,
                had_diff: true,
            },
            1234,
        );
        assert_eq!(
            sender.last_heard(),
            0,
            "out-of-order must not count as heard"
        );
    }

    /// Guard for the deletion above: the appended path still refreshes.
    #[test]
    fn latest_append_refreshes_the_resend_window() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        apply_recv_outcome(
            &mut sender,
            RecvOutcome::Latest {
                num: 5,
                had_diff: true,
                state: UserStream::new(),
            },
            777,
        );
        assert_eq!(sender.last_heard(), 777);
    }
}
