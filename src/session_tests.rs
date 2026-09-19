//! S3 acceptance: a real-UDP loopback — [`MoshSession`] as the client,
//! a mirror stack (our own S1+S2 pieces with swapped directions) as the
//! test "server" — covering input both ways, host bytes to the display
//! slot, roaming port-hops on a silent link, and a clean shutdown
//! handshake.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::crypto::{Base64Key, Direction, MoshOpener, MoshSealer, PacketHeader};
use super::fragment::{Fragment, FragmentAssembly, Fragmenter};
use super::session::{MoshDisplay, MoshSession, SessionEvent};
use super::ssp::{RecvOutcome, SspReceiver, SspSender, SspSentState, UserEvent, UserStream};
use super::wire::{HostInstruction, HostMessage, SHUTDOWN_NUM};

/// The server-side sent state: an append-only host-instruction log.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
struct HostLog {
    instructions: Vec<HostInstruction>,
}

impl SspSentState for HostLog {
    fn diff_from(&self, existing: &Self) -> Vec<u8> {
        let from = existing.instructions.len();
        HostMessage {
            instructions: self.instructions[from..].to_vec(),
        }
        .encode()
    }
    fn subtract(&mut self, known: &Self) {
        let n = known.instructions.len().min(self.instructions.len());
        self.instructions.drain(..n);
    }
}

struct ServerHandles {
    addr: std::net::SocketAddr,
    /// host instructions the test wants the server to send
    outbox: Arc<Mutex<Vec<HostInstruction>>>,
    go_silent: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    /// the test wants the SERVER to quit (send new_num = u64::MAX)
    quit: Arc<AtomicBool>,
    /// every client state number the server has appended (Latest)
    nums: Arc<Mutex<Vec<u64>>>,
    /// every user byte the server has received (latest full stream)
    received: Arc<Mutex<Vec<u8>>>,
    /// every user resize the server has received (latest full stream)
    resizes: Arc<Mutex<Vec<(i32, i32)>>>,
    saw_shutdown: Arc<AtomicBool>,
    /// Echo the client's timestamp back as timestamp_reply (feeds the
    /// client's RTT estimator).
    echo_timestamps: Arc<AtomicBool>,
    /// Echo with a 30s offset: every implied sample exceeds the
    /// client's RTT_MAX_SAMPLE gate and must be rejected.
    echo_absurd: Arc<AtomicBool>,
    /// Absurd echoes actually sent (0 would make the absurd test's
    /// no-sample assertion vacuous).
    absurd_echoes: Arc<AtomicU64>,
}

/// A capture display: records fed bytes + resizes at a fixed size.
#[derive(Clone, Default)]
struct TestDisplay {
    state: Arc<Mutex<TestState>>,
    cols: usize,
    rows: usize,
}

#[derive(Clone, Default)]
struct TestState {
    fed: Vec<u8>,
    resizes: Vec<(usize, usize)>,
}
impl TestDisplay {
    fn new(cols: usize, rows: usize) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(TestDisplay {
            state: Arc::new(Mutex::new(TestState::default())),
            cols,
            rows,
        }))
    }
    fn snapshot(&self) -> TestState {
        self.state.lock().unwrap().clone()
    }
}
impl MoshDisplay for TestDisplay {
    fn new_blank(cols: usize, rows: usize) -> Self {
        TestDisplay {
            state: Arc::new(Mutex::new(TestState::default())),
            cols,
            rows,
        }
    }
    fn feed(&mut self, bytes: &[u8]) {
        self.state.lock().unwrap().fed.extend_from_slice(bytes);
    }
    fn resize(&mut self, cols: usize, rows: usize) {
        self.cols = cols;
        self.state.lock().unwrap().resizes.push((cols, rows));
    }
    fn cols(&self) -> usize {
        self.cols
    }
    fn rows(&self) -> usize {
        self.rows
    }
    fn cursor(&self) -> (i32, i32, bool) {
        (0, 0, true)
    }
}

fn spawn_test_server(key: Base64Key) -> ServerHandles {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
    let addr = socket.local_addr().expect("addr");
    let outbox = Arc::new(Mutex::new(Vec::new()));
    let go_silent = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let quit = Arc::new(AtomicBool::new(false));
    let nums = Arc::new(Mutex::new(Vec::new()));
    let received = Arc::new(Mutex::new(Vec::new()));
    let resizes = Arc::new(Mutex::new(Vec::new()));
    let saw_shutdown = Arc::new(AtomicBool::new(false));
    let echo_timestamps = Arc::new(AtomicBool::new(false));
    let echo_absurd = Arc::new(AtomicBool::new(false));
    let absurd_echoes = Arc::new(AtomicU64::new(0));

    let outbox_move = Arc::clone(&outbox);
    let silent_move = Arc::clone(&go_silent);
    let stop_move = Arc::clone(&stop);
    let quit_move = Arc::clone(&quit);
    let nums_move = Arc::clone(&nums);
    let received_move = Arc::clone(&received);
    let resizes_move = Arc::clone(&resizes);
    let shutdown_move = Arc::clone(&saw_shutdown);
    let echo_move = Arc::clone(&echo_timestamps);
    let absurd_move = Arc::clone(&echo_absurd);
    let absurd_count = Arc::clone(&absurd_echoes);
    std::thread::spawn(move || {
        let mut sealer = MoshSealer::new(&key, Direction::ToClient);
        let opener = MoshOpener::new(&key, Direction::ToServer);
        let mut sender: SspSender<HostLog> = SspSender::new(HostLog::default(), 0, 8);
        let mut receiver = SspReceiver::new(UserStream::new(), 0);
        let mut fragmenter = Fragmenter::default();
        let mut assembly = FragmentAssembly::new();
        let mut peer: Option<std::net::SocketAddr> = None;
        // the client timestamp to echo, and whether one has arrived
        // since the last echo went out — re-echoing a stale timestamp
        // forever would inflate every sample by the client's send gap
        let mut peer_ts: u16 = 0;
        let mut peer_ts_fresh = false;
        let origin = Instant::now();
        let now = || origin.elapsed().as_millis() as u64;

        socket.set_read_timeout(Some(Duration::from_millis(5))).ok();
        let mut buf = [0u8; 2048];
        loop {
            if stop_move.load(Ordering::Relaxed) {
                return;
            }
            let t = now();
            let silent = silent_move.load(Ordering::Relaxed);

            // the test wants the server itself to quit
            if quit_move.load(Ordering::Relaxed) && !sender.shutdown_in_progress() {
                sender.start_shutdown(t);
            }

            // adopt any scripted emissions
            for instruction in outbox_move.lock().unwrap().drain(..) {
                sender.current_state().instructions.push(instruction);
            }

            if !silent {
                let mut frags = Vec::new();
                sender.tick(t, 120, 20, 1200 - 12 - 16, &mut fragmenter, &mut frags);
                if let Some(peer_addr) = peer {
                    // timestamp_reply per the test's script: nothing
                    // (MAX), or the client's timestamp — but only one
                    // reply per client datagram, never a re-echo of a
                    // stale one (that would inflate every sample by
                    // the client's send gap). The same computation
                    // drives the immediate echo in the recv branch.
                    let reply = if absurd_move.load(Ordering::Relaxed) {
                        peer_ts.wrapping_sub(30_000)
                    } else if echo_move.load(Ordering::Relaxed) {
                        peer_ts
                    } else {
                        u16::MAX
                    };
                    let echo_wanted =
                        echo_move.load(Ordering::Relaxed) || absurd_move.load(Ordering::Relaxed);
                    if echo_wanted && peer_ts_fresh {
                        peer_ts_fresh = false;
                        for frag in &frags {
                            let header = PacketHeader {
                                timestamp: (t % 65_536) as u16,
                                timestamp_reply: reply,
                            };
                            if let Ok(datagram) = sealer.seal(&header, &frag.tostring()) {
                                let _ = socket.send_to(&datagram, peer_addr);
                            }
                        }
                    } else {
                        for frag in &frags {
                            let header = PacketHeader {
                                timestamp: (t % 65_536) as u16,
                                timestamp_reply: u16::MAX,
                            };
                            if let Ok(datagram) = sealer.seal(&header, &frag.tostring()) {
                                let _ = socket.send_to(&datagram, peer_addr);
                            }
                        }
                    }
                }
            }

            if let Ok((len, src)) = socket.recv_from(&mut buf) {
                {
                    peer = Some(src);
                    if silent {
                        continue; // swallow traffic, never answer
                    }
                    if let Ok((_, header, fragment)) = opener.open(&buf[..len]) {
                        peer_ts = header.timestamp;
                        peer_ts_fresh = true;
                        // a real server answers immediately; echoing at
                        // receive time keeps the client's sample ≈ the
                        // true wire RTT rather than one send gap
                        if echo_move.load(Ordering::Relaxed) || absurd_move.load(Ordering::Relaxed)
                        {
                            let reply = if absurd_move.load(Ordering::Relaxed) {
                                absurd_count.fetch_add(1, Ordering::Relaxed);
                                peer_ts.wrapping_sub(30_000)
                            } else {
                                peer_ts
                            };
                            let reply_header = PacketHeader {
                                timestamp: (t % 65_536) as u16,
                                timestamp_reply: reply,
                            };
                            if let Ok(datagram) = sealer.seal(&reply_header, &[]) {
                                let _ = socket.send_to(&datagram, src);
                            }
                        }
                        if let Ok(fragment) = Fragment::parse(&fragment) {
                            if let Some(inst) = assembly.add_fragment(fragment) {
                                sender.process_acknowledgment_through(inst.ack_num);
                                match receiver.process_instruction(&inst, t) {
                                    Ok(RecvOutcome::Latest { num, had_diff, .. }) => {
                                        sender.set_ack_num(num);
                                        sender.remote_heard(t);
                                        if had_diff {
                                            sender.set_data_ack();
                                        }
                                        nums_move.lock().unwrap().push(num);
                                        let mut log = received_move.lock().unwrap();
                                        log.clear();
                                        let mut got_resizes = resizes_move.lock().unwrap();
                                        got_resizes.clear();
                                        for event in receiver.latest_state().events() {
                                            match event {
                                                UserEvent::Byte(b) => log.push(*b),
                                                UserEvent::Resize { width, height } => {
                                                    got_resizes.push((*width, *height));
                                                }
                                            }
                                        }
                                        if num == SHUTDOWN_NUM {
                                            shutdown_move.store(true, Ordering::Relaxed);
                                            // keep ticking until an ack carrying MAX has
                                            // actually gone out, then stop
                                            let deadline =
                                                Instant::now() + Duration::from_millis(1500);
                                            while Instant::now() < deadline {
                                                let t2 = now();
                                                let mut frags = Vec::new();
                                                sender.tick(
                                                    t2,
                                                    120,
                                                    20,
                                                    1200 - 12 - 16,
                                                    &mut fragmenter,
                                                    &mut frags,
                                                );
                                                if let Some(peer_addr) = peer {
                                                    for frag in &frags {
                                                        let header = PacketHeader {
                                                            timestamp: (t2 % 65_536) as u16,
                                                            timestamp_reply: u16::MAX,
                                                        };
                                                        if let Ok(datagram) =
                                                            sealer.seal(&header, &frag.tostring())
                                                        {
                                                            let _ = socket
                                                                .send_to(&datagram, peer_addr);
                                                        }
                                                    }
                                                }
                                                if sender
                                                    .counterparty_shutdown_acknowledged(&fragmenter)
                                                {
                                                    break;
                                                }
                                                std::thread::sleep(Duration::from_millis(5));
                                            }
                                            stop_move.store(true, Ordering::Relaxed);
                                            return;
                                        }
                                    }
                                    Ok(RecvOutcome::OutOfOrder { .. }) => {
                                        // out-of-order inserts never refresh
                                        // the retry window (upstream returns
                                        // right after inserting)
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    ServerHandles {
        addr,
        outbox,
        go_silent,
        stop,
        quit,
        nums,
        received,
        resizes,
        saw_shutdown,
        echo_timestamps,
        echo_absurd,
        absurd_echoes,
    }
}

fn wait_until(deadline_ms: u64, check: impl Fn() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed().as_millis() < deadline_ms as u128 {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// The display's fed bytes as text (the loopback marker assertions).
fn fed_text(display: &Arc<Mutex<TestDisplay>>) -> String {
    String::from_utf8_lossy(&display.lock().unwrap().snapshot().fed).into_owned()
}

/// The predicted cells' characters, in order.
fn overlay_chars(client: &MoshSession<TestDisplay>) -> String {
    client
        .prediction_overlay()
        .into_iter()
        .map(|c| c.ch)
        .collect()
}

#[test]
fn udp_loopback_input_hostbytes_and_clean_shutdown() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());

    let events: Arc<Mutex<Vec<SessionEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let event_log = Arc::clone(&events);
    let display = TestDisplay::new(80, 24);
    let client = MoshSession::connect(
        Arc::clone(&display),
        "127.0.0.1",
        server.addr.port(),
        &key,
        move |event| event_log.lock().unwrap().push(event),
        80,
        24,
        false, // prediction off in these protocol tests
    )
    .expect("connect");

    // the server's acks reach us (initial resize + association)
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "client must hear the server"
    );

    // keyboard input flows client -> server
    client.send_input(b"hi mosh\r");
    assert!(
        wait_until(3000, || {
            server.received.lock().unwrap().ends_with(b"hi mosh\r")
        }),
        "server must receive the typed bytes"
    );

    // host bytes flow server -> client display engine
    server
        .outbox
        .lock()
        .unwrap()
        .push(HostInstruction::HostBytes(
            b"\x1b[H\x1b[2Jgolden screen".to_vec(),
        ));
    assert!(
        wait_until(4000, || fed_text(&display).contains("golden screen")),
        "client display must contain the server's paint"
    );

    // a host resize instruction reflows the in-core engine
    server.outbox.lock().unwrap().push(HostInstruction::Resize {
        width: 100,
        height: 30,
    });
    assert!(
        wait_until(3000, || {
            display
                .lock()
                .unwrap()
                .snapshot()
                .resizes
                .contains(&(100, 30))
        }),
        "the host resize must reach the display"
    );

    // clean shutdown handshake both ways
    client.start_shutdown();
    assert!(
        wait_until(5000, || server.saw_shutdown.load(Ordering::Relaxed)),
        "server must see the shutdown state"
    );
    assert!(
        wait_until(5000, || {
            events
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, SessionEvent::Ended { clean: true, .. }))
        }),
        "client must end cleanly"
    );
    client.join();
}

/// The `exit` flow: the remote shell quits, mosh-server sends
/// new_num = u64::MAX, and the client must end CLEANLY once its ack
/// carrying MAX has gone out — upstream stmclient.cc: "quit if we
/// received and acknowledged a shutdown request".
#[test]
fn server_initiated_shutdown_ends_the_session() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());

    let events: Arc<Mutex<Vec<SessionEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let event_log = Arc::clone(&events);
    let client = MoshSession::connect(
        TestDisplay::new(80, 24),
        "127.0.0.1",
        server.addr.port(),
        &key,
        move |event| event_log.lock().unwrap().push(event),
        80,
        24,
        false,
    )
    .expect("connect");

    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate before the server quits"
    );

    // the remote side quits
    server.quit.store(true, Ordering::Relaxed);

    assert!(
        wait_until(5000, || {
            events
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, SessionEvent::Ended { clean: true, .. }))
        }),
        "the client must end cleanly when the server shuts down, got {:?}",
        *events.lock().unwrap()
    );
    client.join();
    server.stop.store(true, Ordering::Relaxed);
}

#[test]
fn roaming_hops_ports_when_the_link_goes_silent() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());

    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
    let display = TestDisplay::new(80, 24);
    let client = MoshSession::connect_on(
        display,
        socket,
        server.addr,
        &key,
        |_| {},
        80,
        24,
        200, // tiny hop interval for the test
        false,
    )
    .expect("connect");

    // associate first, then silence the server
    client.send_input(b"x");
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate before going silent"
    );
    server.go_silent.store(true, Ordering::Relaxed);

    // with no round trips, the client must rotate source ports
    assert!(
        wait_until(6000, || client.ports_opened() >= 3),
        "expected at least 3 ports (2 hops) after the link went silent, got {}",
        client.ports_opened()
    );
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}

#[test]
fn terminate_stops_the_loop_without_handshake() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());
    let client = MoshSession::connect(
        TestDisplay::new(80, 24),
        "127.0.0.1",
        server.addr.port(),
        &key,
        |_| {},
        80,
        24,
        false,
    )
    .expect("connect");
    client.terminate(); // must return promptly, no hang
    server.stop.store(true, Ordering::Relaxed);
}

/// B4 regression: upstream refreshes `last_heard` on every packet that
/// decrypts with a fresh sequence number (network.cc:556), whether or
/// not its fragment assembles into an instruction — a stream of torn
/// fragments is still proof the link is alive. But `still_connecting`
/// upstream means "no appended remote state yet", so the connecting
/// flag must NOT clear on torn fragments alone.
#[test]
fn torn_fragments_refresh_heard_but_not_the_connecting_flag() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
    let server_addr = socket.local_addr().expect("addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_move = Arc::clone(&stop);

    // one instruction, deliberately incompressible so it fragments
    let mut mix: u64 = 0x243F_6A88_85A3_08D3;
    let big_diff: Vec<u8> = (0..3000)
        .map(|_| {
            mix = mix
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (mix >> 56) as u8
        })
        .collect();
    let inst = super::wire::TransportInstruction {
        protocol_version: 2,
        old_num: 0,
        new_num: 1,
        ack_num: 0,
        throwaway_num: 0,
        diff: big_diff,
        chaff: Vec::new(),
    };
    let mut fragmenter = Fragmenter::default();
    let mut frags = fragmenter
        .make_fragments(&inst, 1200 - 12 - 16)
        .expect("fragments");
    assert!(
        frags.len() >= 2,
        "instruction must split so we can send a torn piece"
    );
    let torn = frags.remove(0); // fragment 0, final=false — never assembles

    let thread_key = key.clone();
    std::thread::spawn(move || {
        let mut sealer = MoshSealer::new(&thread_key, Direction::ToClient);
        let mut buf = [0u8; 2048];
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .ok();
        let mut peer: Option<std::net::SocketAddr> = None;
        loop {
            if stop_move.load(Ordering::Relaxed) {
                return;
            }
            // adopt the client as peer whenever it talks to us
            if let Ok((_, src)) = socket.recv_from(&mut buf) {
                peer = Some(src);
            }
            if let Some(client_addr) = peer {
                let header = PacketHeader {
                    timestamp: 0,
                    timestamp_reply: u16::MAX,
                };
                if let Ok(datagram) = sealer.seal(&header, &torn.tostring()) {
                    let _ = socket.send_to(&datagram, client_addr);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    let display = TestDisplay::new(80, 24);
    let client = MoshSession::connect(
        display,
        "127.0.0.1",
        server_addr.port(),
        &key,
        |_| {},
        80,
        24,
        false,
    )
    .expect("connect");

    // let the torn fragments flow for a while: if they refresh "heard",
    // the metric stays small; if not, it grows with the clock
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        client.link_health().since_heard_ms < 250,
        "every decrypted datagram must refresh last_heard, got since_heard_ms={}",
        client.link_health().since_heard_ms
    );
    // ... but no instruction ever completed, so we are still connecting
    assert!(
        client.link_health().never_heard,
        "the connecting flag must not clear without an appended state"
    );
    stop.store(true, Ordering::Relaxed);
    client.terminate();
}

/// The host-byte capture is an opt-out: an embedder that renders via
/// the display alone can turn it off so the pending buffer stops
/// growing with the session, while the display feed is untouched.
#[test]
fn host_bytes_capture_can_be_turned_off() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());

    let display = TestDisplay::new(80, 24);
    let client = MoshSession::connect(
        Arc::clone(&display),
        "127.0.0.1",
        server.addr.port(),
        &key,
        |_| {},
        80,
        24,
        false,
    )
    .expect("connect");

    // capture ships ON: bytes accumulate for the drainer (back-compat)
    client.send_input(b"x");
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate first"
    );
    server
        .outbox
        .lock()
        .unwrap()
        .push(HostInstruction::HostBytes(b"hello".to_vec()));
    assert!(
        wait_until(3000, || fed_text(&display).contains("hello")),
        "the display feed is independent of draining"
    );
    assert_eq!(client.take_host_bytes(), b"hello", "capture on by default");

    // turn it off: the display still feeds, the buffer stays empty
    client.set_host_bytes_capture(false);
    server
        .outbox
        .lock()
        .unwrap()
        .push(HostInstruction::HostBytes(b"world".to_vec()));
    assert!(
        wait_until(3000, || fed_text(&display).contains("world")),
        "the display feed must be untouched by the capture flag"
    );
    std::thread::sleep(Duration::from_millis(300)); // let any buggy append land
    let pending = client.take_host_bytes();
    assert!(
        pending.is_empty(),
        "capture off must not accumulate host bytes, got {pending:?}"
    );
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}

/// P6 regression: the server's echo-ack retires predictions on EVERY
/// appended state — an echoack-only instruction (no host bytes) is
/// enough upstream (completeterminal.cc:130-160); the guesses must not
/// linger until the next paint.
#[test]
fn echoack_only_state_retires_predictions() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());

    let client = MoshSession::connect(
        TestDisplay::new(20, 4),
        "127.0.0.1",
        server.addr.port(),
        &key,
        |_| {},
        20,
        4,
        true, // prediction ON
    )
    .expect("connect");

    // associate, then silence so only predictions can paint
    client.send_input(b"x");
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate first"
    );
    server.go_silent.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(300));

    client.send_input(b"hi");
    assert!(
        wait_until(1000, || !client.prediction_overlay().is_empty()),
        "predictions must appear first"
    );
    let frames_before = client.frame_version();

    // the server answers with an ECHOACK ONLY — no host bytes, no paint
    server.go_silent.store(false, Ordering::Relaxed);
    server
        .outbox
        .lock()
        .unwrap()
        .push(HostInstruction::EchoAck(99));
    assert!(
        wait_until(4000, || client.prediction_overlay().is_empty()),
        "an echoack-only state must retire the guesses, got {:?}",
        client.prediction_overlay()
    );
    // retiring cells changes what the embedder must draw: the frame
    // version must move (and ScreenChanged fire) or the stale
    // underline lingers until something else repaints
    assert!(
        wait_until(2000, || client.frame_version() > frames_before),
        "the retirement must signal the embedder (frame_version {} stayed at {frames_before})",
        client.frame_version()
    );
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}

/// The echo-ack must retire exactly the confirmed PREFIX of the
/// predictions. Regression: retirement summed per-burst deltas, so a
/// burst that nets zero cells (backspace then a fresh char) and
/// unconfirmed retractions let the confirmed count spill forward —
/// echoing "abc" also erased the later, never-echoed "d".
#[test]
fn echoack_retires_only_the_confirmed_prefix_of_predictions() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());

    let client = MoshSession::connect(
        TestDisplay::new(20, 4),
        "127.0.0.1",
        server.addr.port(),
        &key,
        |_| {},
        20,
        4,
        true, // prediction ON
    )
    .expect("connect");

    // associate; the server never echoes keystrokes, so predictions
    // only retire through the EchoAck this test scripts
    client.send_input(b"x");
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate first"
    );
    // a clean slate: drop the association keystroke's guess
    client.set_prediction(false);
    client.set_prediction(true);

    // burst 1: "abc" — the live server appends its state; that state's
    // number is exactly the frame the burst was predicted under
    client.send_input(b"abc");
    assert!(
        wait_until(1000, || overlay_chars(&client) == "abc"),
        "abc must be predicted first, got {:?}",
        client.prediction_overlay()
    );
    assert!(
        wait_until(3000, || server.received.lock().unwrap().ends_with(b"abc")),
        "the abc state must reach the server"
    );
    let ack_through = *server.nums.lock().unwrap().last().expect("a client state");

    // burst 2: backspace then "d" — typed after the abc state went out,
    // so it rides a strictly later frame
    client.send_input(b"\x7fd");
    assert!(
        wait_until(1000, || overlay_chars(&client) == "abd"),
        "cells after the edit, got {:?}",
        client.prediction_overlay()
    );

    // the server echoed "abc" only — never the backspace or the "d"
    server
        .outbox
        .lock()
        .unwrap()
        .push(HostInstruction::EchoAck(ack_through));

    assert!(
        wait_until(4000, || overlay_chars(&client) == "d"),
        "the echo-ack must retire exactly a,b — d was never echoed (got {:?})",
        client.prediction_overlay()
    );
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}

/// Conservative local echo (the S5b layer): against a SILENT server,
/// typed printables appear on the core display at once (underlined —
/// the "this is a guess" mark); when the server finally paints and its
/// echo-ack covers the frame, the guesses retire; the never-toggle
/// shows nothing.
#[test]
fn prediction_appears_retires_and_toggles() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());

    let events: Arc<Mutex<Vec<SessionEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let event_log = Arc::clone(&events);
    let client = MoshSession::connect(
        TestDisplay::new(20, 4),
        "127.0.0.1",
        server.addr.port(),
        &key,
        move |event| event_log.lock().unwrap().push(event),
        20,
        4,
        true, // prediction ON
    )
    .expect("connect");

    // associate, then silence the server so only predictions can paint
    client.send_input(b"x");
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate first"
    );
    server.go_silent.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(300)); // let in-flight acks land

    // typing against the silent link produces the guessed cells at once
    client.send_input(b"hi");
    assert!(
        wait_until(1000, || {
            let overlay = client.prediction_overlay();
            overlay.iter().any(|c| c.ch == 'h') && overlay.iter().any(|c| c.ch == 'i')
        }),
        "predicted cells must appear while the link is silent"
    );

    // never-mode: cleared, and stays empty
    client.set_prediction(false);
    assert!(client.prediction_overlay().is_empty(), "toggle clears");
    client.send_input(b"zz");
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        client.prediction_overlay().is_empty(),
        "never-mode predicts nothing"
    );

    // back on: the guess reappears, then retires when the server
    // answers with the real echo + echo-ack
    client.set_prediction(true);
    client.send_input(b"ok");
    assert!(wait_until(1000, || !client.prediction_overlay().is_empty()));
    server.go_silent.store(false, Ordering::Relaxed);
    server
        .outbox
        .lock()
        .unwrap()
        .push(HostInstruction::HostBytes(b"ok".to_vec()));
    server
        .outbox
        .lock()
        .unwrap()
        .push(HostInstruction::EchoAck(99));
    assert!(
        wait_until(4000, || client.prediction_overlay().is_empty()),
        "the real echo must retire the guesses"
    );
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}

// --- the deferred public API ---------------------------------------------

/// The deferred constructor must not spawn the UDP loop: nothing may
/// leave the socket until [MoshSession::start] — that is the whole
/// point of the two-phase API (the async-constructor wedge). start()
/// must then run the normal associate → exchange → clean shutdown.
#[test]
fn deferred_connect_stays_silent_until_start() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());

    let events: Arc<Mutex<Vec<SessionEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let event_log = Arc::clone(&events);
    let client = MoshSession::connect_deferred(
        TestDisplay::new(80, 24),
        "127.0.0.1",
        server.addr.port(),
        &key,
        move |event| event_log.lock().unwrap().push(event),
        80,
        24,
        false,
    )
    .expect("connect_deferred");

    // no loop yet: nothing may have reached the server. A prematurely
    // started loop would at minimum have pushed its initial resize
    // state, so `nums` (every appended client state) is the tell —
    // `received` alone is vacuous before any bytes are typed.
    std::thread::sleep(Duration::from_millis(250));
    assert!(
        server.nums.lock().unwrap().is_empty() && server.resizes.lock().unwrap().is_empty(),
        "the deferred session must not send before start()"
    );
    assert!(
        client.link_health().never_heard,
        "the deferred session must not hear anything before start()"
    );
    assert!(
        events.lock().unwrap().is_empty(),
        "no events may fire before start()"
    );

    // start() launches the loop from the plain synchronous context
    client.start();
    client.send_input(b"hi mosh\r");
    assert!(
        wait_until(3000, || server
            .received
            .lock()
            .unwrap()
            .ends_with(b"hi mosh\r")),
        "after start() the input must flow"
    );
    client.start_shutdown();
    assert!(
        wait_until(5000, || events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, SessionEvent::Ended { clean: true, .. }))),
        "the deferred session must end cleanly once started, got {:?}",
        *events.lock().unwrap()
    );
    client.join();
}

/// start() is documented idempotent: the second call must be a no-op —
/// one loop, one Ended event, a clean handshake. A duplicated loop
/// would race the socket and the sender bookkeeping.
#[test]
fn start_twice_runs_one_loop() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());

    let events: Arc<Mutex<Vec<SessionEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let event_log = Arc::clone(&events);
    let client = MoshSession::connect_deferred(
        TestDisplay::new(80, 24),
        "127.0.0.1",
        server.addr.port(),
        &key,
        move |event| event_log.lock().unwrap().push(event),
        80,
        24,
        false,
    )
    .expect("connect_deferred");
    client.start();
    client.start(); // must be a no-op

    client.send_input(b"hi");
    assert!(
        wait_until(3000, || server.received.lock().unwrap().ends_with(b"hi")),
        "input must flow exactly once through the one loop"
    );
    client.start_shutdown();
    assert!(
        wait_until(5000, || events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, SessionEvent::Ended { clean: true, .. }))),
        "the session must end cleanly"
    );
    std::thread::sleep(Duration::from_millis(200));
    let ended_count = || {
        events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, SessionEvent::Ended { .. }))
            .count()
    };
    assert_eq!(
        ended_count(),
        1,
        "exactly one loop may have run, got {:?}",
        *events.lock().unwrap()
    );
    // and the finished session must not be restartable: a third start()
    // may not resurrect the loop (no new Ended may ever fire)
    client.start();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        ended_count(),
        1,
        "start() after the session ended must be inert, got {:?}",
        *events.lock().unwrap()
    );
    client.join();
}

/// The deferred twin of bring-your-own-socket: connect_on_deferred
/// builds silently on the caller's socket, start() launches there.
#[test]
fn connect_on_deferred_starts_on_the_callers_socket() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind");

    let client = MoshSession::connect_on_deferred(
        TestDisplay::new(80, 24),
        socket,
        server.addr,
        &key,
        |_| {},
        80,
        24,
        200, // hop interval, unused here but exercises the full signature
        false,
    )
    .expect("connect_on_deferred");

    std::thread::sleep(Duration::from_millis(150));
    assert!(
        server.nums.lock().unwrap().is_empty() && server.resizes.lock().unwrap().is_empty(),
        "silent before start(): a live loop would at least push its initial resize state"
    );
    client.start();
    client.send_input(b"x");
    assert!(
        wait_until(3000, || server.received.lock().unwrap().ends_with(b"x")),
        "the caller's socket must carry the session once started"
    );
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}

/// resize() reflows the local display SYNCHRONOUSLY (the UI must not
/// wait an RTT) and reaches the server as a UserStream resize event.
#[test]
fn client_resize_reflows_locally_and_reaches_the_server() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());
    let display = TestDisplay::new(80, 24);
    let client = MoshSession::connect(
        Arc::clone(&display),
        "127.0.0.1",
        server.addr.port(),
        &key,
        |_| {},
        80,
        24,
        false,
    )
    .expect("connect");
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate first"
    );

    let frames_before = client.frame_version();
    client.resize(100, 30);
    // local and synchronous: no waiting allowed here
    assert!(
        display
            .lock()
            .unwrap()
            .snapshot()
            .resizes
            .contains(&(100, 30)),
        "resize() must reflow the display before returning, got {:?}",
        display.lock().unwrap().snapshot().resizes
    );
    assert!(
        client.frame_version() > frames_before,
        "the reflow must signal the embedder (frame_version stayed at {frames_before})"
    );
    assert!(
        wait_until(3000, || server.resizes.lock().unwrap().contains(&(100, 30))),
        "the resize must reach the server's user stream, got {:?}",
        *server.resizes.lock().unwrap()
    );
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}

/// Characterization: a degenerate resize (below 2x2) must not touch
/// the display — the in-core engine cannot render a sub-2 grid — and
/// must not claim a reflow happened.
#[test]
fn degenerate_resize_leaves_the_display_alone() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());
    let display = TestDisplay::new(80, 24);
    let client = MoshSession::connect(
        Arc::clone(&display),
        "127.0.0.1",
        server.addr.port(),
        &key,
        |_| {},
        80,
        24,
        false,
    )
    .expect("connect");
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate first"
    );

    let frames_before = client.frame_version();
    client.resize(1, 1);
    assert!(
        display.lock().unwrap().snapshot().resizes.is_empty(),
        "a sub-2x2 resize must not reflow the display"
    );
    assert_eq!(
        client.frame_version(),
        frames_before,
        "no reflow, no signal"
    );
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}

/// The display accessors give embedders synchronous read access, and
/// user_stream_acked() advances through the server's newest held state
/// as the piggybacked acknowledgments land.
#[test]
fn display_accessors_and_acked_introspection() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());
    let client = MoshSession::connect(
        TestDisplay::new(80, 24),
        "127.0.0.1",
        server.addr.port(),
        &key,
        |_| {},
        80,
        24,
        false,
    )
    .expect("connect");
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate first"
    );

    client.send_input(b"probe");
    assert!(
        wait_until(3000, || server.received.lock().unwrap().ends_with(b"probe")),
        "the input must reach the server"
    );
    let through = *server.nums.lock().unwrap().last().expect("a client state");
    assert!(
        wait_until(3000, || client.user_stream_acked() >= through),
        "acked must advance through the server's newest state (server at {through}), got {}",
        client.user_stream_acked()
    );

    // the two accessors must alias the SAME display: mutate through
    // display() and read it back through with_display (a
    // constant-vs-constant check would pass on any display)
    client.display().lock().unwrap().resize(70, 20);
    assert_eq!(
        client.with_display(|d| d.cols()),
        70,
        "with_display must read the display() the session hands out"
    );
    assert_eq!(client.display().lock().unwrap().cols(), 70);
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}

// --- the RTT machinery ---------------------------------------------------

/// With the server echoing the client's timestamps, the RTT estimate
/// must converge on the (tiny) loopback delay and the retransmission
/// timeout must fall from its 1s cold-start ceiling toward the 50ms
/// floor. This is the adaptive path no earlier test exercised: the
/// mirror server used to send timestamp_reply = u16::MAX forever, so
/// every RTO in the suite silently rode the initial constants.
#[test]
fn rtt_estimate_converges_on_the_server_timestamp_echo() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());
    let client = MoshSession::connect(
        TestDisplay::new(80, 24),
        "127.0.0.1",
        server.addr.port(),
        &key,
        |_| {},
        80,
        24,
        false,
    )
    .expect("connect");
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate first"
    );

    // cold start: the echo is off, so no sample can exist and the
    // srtt/rttvar constants put the RTO at its 1s ceiling
    assert_eq!(
        client.link_health().rtt_ms,
        None,
        "no RTT sample while the server echoes nothing"
    );
    assert_eq!(
        client.link_health().rto_ms,
        1000,
        "cold-start RTO is the 1s ceiling"
    );

    server.echo_timestamps.store(true, Ordering::Relaxed);
    // samples only exist where datagrams flow, and an idle client sits
    // in rto backoff — it can stay silent for seconds. A typing user is
    // the real traffic source: keep typing INSIDE the wait so a slow
    // runner keeps making progress instead of just expiring. Each burst
    // is echoed at once, so the sample tracks the wire and the RTO must
    // end far below its 1s cold start (on an idle host it pins the
    // 50ms clamp floor exactly).
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && client.link_health().rto_ms > 150 {
        client.send_input(b"x");
        std::thread::sleep(Duration::from_millis(12));
    }
    // a few more bursts unconditionally: the loop above stops at the
    // first accepted sample, and the running srtt/rttvar blend (every
    // sample after the first) is its own code path
    for _ in 0..10 {
        client.send_input(b"x");
        std::thread::sleep(Duration::from_millis(12));
    }
    assert!(
        client.link_health().rto_ms <= 150,
        "the RTO must track the echoed samples down from 1s, got {}",
        client.link_health().rto_ms
    );
    let rtt = client.link_health().rtt_ms.expect("an accepted sample");
    assert!(rtt <= 500, "loopback RTT must stay small, got {rtt}ms");
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}

/// A timestamp reply implying an absurd sample (≥ RTT_MAX_SAMPLE) is
/// rejected wholesale: garbage or a long-dead peer must not drag the
/// RTO anywhere. The estimate stays cold while the nonsense replies
/// keep coming.
#[test]
fn absurd_timestamp_reply_does_not_move_the_estimate() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());
    let client = MoshSession::connect(
        TestDisplay::new(80, 24),
        "127.0.0.1",
        server.addr.port(),
        &key,
        |_| {},
        80,
        24,
        false,
    )
    .expect("connect");
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate first"
    );
    assert_eq!(client.link_health().rtt_ms, None);
    assert_eq!(client.link_health().rto_ms, 1000);

    // "echo" with a 30s offset: every implied sample exceeds the 5s
    // RTT_MAX_SAMPLE gate and must be dropped. The typing bursts keep
    // datagrams flowing so the nonsense replies actually reach the
    // estimator; the echo count and the link freshness prove the
    // replies really flew — without them the no-sample assertion would
    // be vacuous.
    server.echo_absurd.store(true, Ordering::Relaxed);
    // cold-start send_interval is 250ms — the bursts coalesce into one
    // datagram per interval — so echoes accrue at ~4/s. Ask for five
    // (≈1.5s of typing) and cap the wait at 6s.
    let mut absurd_rounds = 0;
    while server.absurd_echoes.load(Ordering::Relaxed) < 5 && absurd_rounds < 400 {
        client.send_input(b"y");
        absurd_rounds += 1;
        std::thread::sleep(Duration::from_millis(15));
    }
    assert!(
        server.absurd_echoes.load(Ordering::Relaxed) >= 5,
        "the server must actually have sent absurd echoes, sent {}",
        server.absurd_echoes.load(Ordering::Relaxed)
    );
    assert!(
        client.link_health().since_heard_ms < 500,
        "the client must still be receiving datagrams, last heard {}ms ago",
        client.link_health().since_heard_ms
    );
    assert_eq!(
        client.link_health().rtt_ms,
        None,
        "an absurd sample must never confirm the estimate"
    );
    assert_eq!(
        client.link_health().rto_ms,
        1000,
        "the RTO must not move on rejected samples"
    );
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}
