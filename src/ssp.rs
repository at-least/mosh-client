//! The state-synchronization engine (spec §6-§7) — pure, clock-driven,
//! no sockets. [`SspSender`] owns our outgoing state (the client's
//! [`UserStream`]) and produces encrypted-transport-ready fragments via
//! the caller's [`super::fragment::Fragmenter`]; [`SspReceiver`] owns
//! the peer's incoming state and enforces the idempotency/old-reference
//! rules. The S3 session wires both to a UDP socket and a clock.

use std::collections::VecDeque;
use std::sync::Arc;

use thiserror::Error;

use super::fragment::{Fragment, Fragmenter};
use super::wire::{
    HostInstruction, HostMessage, TransportInstruction, UserInstruction, UserMessage, WireError,
    MOSH_PROTOCOL_VERSION, SHUTDOWN_NUM,
};

/// ms between empty acks (transportsender.h ACK_INTERVAL).
pub const ACK_INTERVAL_MS: u64 = 3000;
/// ms a data ack may be delayed (ACK_DELAY).
pub const ACK_DELAY_MS: u64 = 100;
/// ms of silence after which we stop resending at frame rate
/// (ACTIVE_RETRY_TIMEOUT).
pub const ACTIVE_RETRY_TIMEOUT_MS: u64 = 10_000;
/// Shutdown packets before giving up (SHUTDOWN_RETRIES).
pub const SHUTDOWN_RETRIES: u32 = 16;
/// Cap on the sender's unacked-state queue; culls from the middle so
/// both ends (known receiver state, newest) survive.
const SENT_QUEUE_CAP: usize = 32;
/// Cap on the receiver's state queue before quenching.
const RECEIVED_QUEUE_CAP: usize = 1024;
const QUENCH_WINDOW_MS: u64 = 15_000;
/// Default SEND_MINDELAY; the mosh client sets 1 ms for keystrokes.
pub const SEND_MINDELAY_DEFAULT_MS: u64 = 8;
pub const SEND_MINDELAY_CLIENT_MS: u64 = 1;

/// Clamp of ceil(SRTT/2) — two frames per RTT, bounded (spec §6.1).
pub fn send_interval_ms(srtt_ms: f64) -> u64 {
    (srtt_ms / 2.0).ceil().clamp(20.0, 250.0) as u64
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SspError {
    #[error("peer protocol_version {0} != 2")]
    ProtocolVersion(u32),
    #[error("state diff failed to parse: {0}")]
    BadDiff(String),
}

/// A state we send (client: [`UserStream`]; the test server: any log).
pub trait SspSentState: Clone + PartialEq {
    /// Bytes turning `existing` into `self`.
    fn diff_from(&self, existing: &Self) -> Vec<u8>;
    /// Drop the prefix everyone has acknowledged (rationalization).
    fn subtract(&mut self, known_receiver: &Self);
}

/// A state we receive and apply diffs to (client: [`HostStreamState`]).
pub trait SspReceivedState: Clone {
    fn apply_string(&mut self, diff: &[u8]) -> Result<(), WireError>;
}

#[derive(Clone, Debug)]
pub struct TimestampedState<S> {
    pub timestamp: u64,
    pub num: u64,
    pub state: S,
}

// --- UserStream (spec §7.1) ----------------------------------------------

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UserEvent {
    Byte(u8),
    Resize { width: i32, height: i32 },
}

/// The append-only keystroke/resize log the client synchronizes out.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct UserStream {
    events: Vec<UserEvent>,
}

impl UserStream {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.events
            .extend(bytes.iter().map(|b| UserEvent::Byte(*b)));
    }

    pub fn push_resize(&mut self, width: i32, height: i32) {
        self.events.push(UserEvent::Resize { width, height });
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn events(&self) -> &[UserEvent] {
        &self.events
    }

    fn encode_suffix(&self, from: usize) -> Vec<u8> {
        // consecutive bytes coalesce into one Keystroke instruction
        // (user.cc diff_from)
        let mut instructions = Vec::new();
        for event in &self.events[from..] {
            match *event {
                UserEvent::Byte(b) => match instructions.last_mut() {
                    Some(UserInstruction::Keystroke(keys)) => keys.push(b),
                    _ => instructions.push(UserInstruction::Keystroke(vec![b])),
                },
                UserEvent::Resize { width, height } => {
                    instructions.push(UserInstruction::Resize { width, height })
                }
            }
        }
        UserMessage { instructions }.encode()
    }

    fn common_prefix_len(&self, other: &UserStream) -> usize {
        self.events
            .iter()
            .zip(other.events.iter())
            .take_while(|(a, b)| a == b)
            .count()
    }
}

impl SspSentState for UserStream {
    fn diff_from(&self, existing: &Self) -> Vec<u8> {
        self.encode_suffix(self.common_prefix_len(existing))
    }

    fn subtract(&mut self, known_receiver: &Self) {
        if self == known_receiver {
            self.events.clear();
            return;
        }
        let prefix = self.common_prefix_len(known_receiver);
        self.events.drain(..prefix);
    }
}

impl SspReceivedState for UserStream {
    fn apply_string(&mut self, diff: &[u8]) -> Result<(), WireError> {
        let message = UserMessage::decode(diff)?;
        for instruction in message.instructions {
            match instruction {
                UserInstruction::Keystroke(keys) => {
                    self.push_bytes(&keys);
                }
                UserInstruction::Resize { width, height } => {
                    self.push_resize(width, height);
                }
            }
        }
        Ok(())
    }
}

// --- HostStreamState (spec §7.2) ------------------------------------------

/// One event in the server-synchronized host stream, in order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HostEvent {
    /// Terminal escape bytes for the client's emulator.
    Bytes(Vec<u8>),
    Resize {
        width: i32,
        height: i32,
    },
}

/// A persistent (cons-list) log of host events. The server's state
/// chain BRANCHES: an instruction `[old=>new]` paints from `old`, so
/// the client's states form a tree of byte logs, all sharing the main
/// trunk. Structural sharing keeps per-state clones O(1) (a snapshot
/// per received state, like mosh's per-state emulator copies) while
/// the unique memory stays one copy of the traffic.
#[derive(Clone, Debug)]
pub struct EventLog {
    node: Option<Arc<LogNode>>,
    len: usize,
}

#[derive(Debug)]
struct LogNode {
    parent: Option<Arc<LogNode>>,
    event: HostEvent,
}

impl EventLog {
    pub fn new() -> Self {
        EventLog { node: None, len: 0 }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn push(&mut self, event: HostEvent) {
        self.node = Some(Arc::new(LogNode {
            parent: self.node.clone(),
            event,
        }));
        self.len += 1;
    }

    /// The events in order (rebuild replay order).
    pub fn iter(&self) -> Vec<&HostEvent> {
        let mut out = Vec::with_capacity(self.len);
        let mut cursor = self.node.as_deref();
        while let Some(node) = cursor {
            out.push(&node.event);
            cursor = node.parent.as_deref();
        }
        out.reverse();
        out
    }

    /// The suffix this log carries over `base`, if `base` is an
    /// ancestor (a structural prefix, checked by pointer identity at
    /// the shared depth). None = the logs diverged: rebuild instead.
    pub fn suffix_over<'a>(&'a self, base: &EventLog) -> Option<Vec<&'a HostEvent>> {
        if base.len > self.len {
            return None;
        }
        let mut cursor = self.node.as_deref();
        let mut back = self.len;
        while back > base.len {
            cursor = cursor?.parent.as_deref();
            back -= 1;
        }
        let shares_trunk = match (&base.node, cursor) {
            (None, None) => true,
            (Some(a), Some(b)) => std::ptr::eq(a.as_ref(), b),
            _ => false,
        };
        if !shares_trunk {
            return None;
        }
        let mut suffix = Vec::with_capacity(self.len - base.len);
        let mut cursor = self.node.as_deref();
        let mut back = self.len;
        while back > base.len {
            let node = cursor?;
            suffix.push(&node.event);
            cursor = node.parent.as_deref();
            back -= 1;
        }
        suffix.reverse();
        Some(suffix)
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EventLog {
    fn drop(&mut self) {
        // The default Arc drop glue recurses once per node down the
        // parent chain, and the chain grows with the session — a long
        // session overflowed the loop thread's stack at teardown (the
        // deep_event_log_drop regression aborts there). Unwind by hand:
        // each exclusively-owned node surrenders its parent before it
        // goes, so the walk uses constant stack; a shared node stops
        // the walk (its Arc drop only decrements the count, and the
        // owner that drops last finishes the chain).
        let mut node = self.node.take();
        while let Some(arc) = node {
            if let Ok(mut owned) = Arc::try_unwrap(arc) {
                node = owned.parent.take();
            } else {
                node = None;
            }
        }
    }
}

/// The server-synchronized state as the client holds it (spec §7.2).
///
/// The client's copy of the server state is a pure EVENT LOG (not an
/// emulator snapshot): the server's outgoing states form a TREE of
/// byte logs (an instruction paints from its old_num base, which is
/// not necessarily the previous newest state), all sharing the trunk.
/// Each received state carries its own [`EventLog`] branch — O(1)
/// clones, like mosh's per-state emulator copies — and the display
/// feeds the suffix over its current position, or rebuilds from the
/// full log when the newest state branched elsewhere. `echo_ack`
/// rides along (the server's echo-ack counter, monotonic).
#[derive(Clone, Debug, Default)]
pub struct HostStreamState {
    pub log: EventLog,
    pub echo_ack: u64,
}

impl HostStreamState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total host bytes in the log (test/reporting convenience).
    pub fn byte_len(&self) -> usize {
        self.log
            .iter()
            .iter()
            .map(|e| match e {
                HostEvent::Bytes(b) => b.len(),
                HostEvent::Resize { .. } => 0,
            })
            .sum()
    }
}

impl SspReceivedState for HostStreamState {
    fn apply_string(&mut self, diff: &[u8]) -> Result<(), WireError> {
        let message = HostMessage::decode(diff)?;
        for instruction in message.instructions {
            match instruction {
                HostInstruction::HostBytes(bytes) => {
                    if !bytes.is_empty() {
                        self.log.push(HostEvent::Bytes(bytes));
                    }
                }
                HostInstruction::Resize { width, height } => {
                    self.log.push(HostEvent::Resize { width, height });
                }
                HostInstruction::EchoAck(num) => self.echo_ack = self.echo_ack.max(num),
            }
        }
        Ok(())
    }
}

// --- sender ---------------------------------------------------------------

/// Drives our outgoing state: what to send, when, and against which
/// assumed receiver state (spec §6.1). Pure — the caller owns the clock
/// and delivers fragments.
pub struct SspSender<S: SspSentState> {
    current_state: S,
    sent_states: VecDeque<TimestampedState<S>>,
    assumed_receiver: usize,
    ack_num: u64,
    next_ack_time: u64,
    next_send_time: Option<u64>,
    mindelay_clock: Option<u64>,
    pending_data_ack: bool,
    shutdown_in_progress: bool,
    shutdown_tries: u32,
    shutdown_start: Option<u64>,
    last_heard: u64,
    send_mindelay: u64,
}

impl<S: SspSentState> SspSender<S> {
    pub fn new(initial_state: S, now: u64, send_mindelay: u64) -> Self {
        SspSender {
            current_state: initial_state.clone(),
            sent_states: VecDeque::from([TimestampedState {
                timestamp: now,
                num: 0,
                state: initial_state,
            }]),
            assumed_receiver: 0,
            ack_num: 0,
            next_ack_time: now + ACK_INTERVAL_MS,
            next_send_time: None,
            mindelay_clock: None,
            pending_data_ack: false,
            shutdown_in_progress: false,
            shutdown_tries: 0,
            shutdown_start: None,
            last_heard: now,
            send_mindelay,
        }
    }

    /// The live outgoing state. Pushes after `start_shutdown` are a bug.
    pub fn current_state(&mut self) -> &mut S {
        debug_assert!(!self.shutdown_in_progress, "state frozen during shutdown");
        &mut self.current_state
    }

    pub fn set_current_state(&mut self, state: S) {
        debug_assert!(!self.shutdown_in_progress, "state frozen during shutdown");
        self.current_state = state;
    }

    pub fn start_shutdown(&mut self, now: u64) {
        if !self.shutdown_in_progress {
            self.shutdown_start = Some(now);
            self.shutdown_in_progress = true;
        }
    }

    pub fn shutdown_in_progress(&self) -> bool {
        self.shutdown_in_progress
    }

    /// Our shutdown was acknowledged (the ack culls everything below the
    /// shutdown state, so it sits at the front).
    pub fn shutdown_acknowledged(&self) -> bool {
        self.sent_states.front().map(|s| s.num) == Some(SHUTDOWN_NUM)
    }

    /// We have acknowledged the peer's shutdown (an ack_num of MAX went
    /// out — the receiver raises ack_num to MAX on seeing the peer's
    /// shutdown state).
    pub fn counterparty_shutdown_acknowledged(&self, fragmenter: &Fragmenter) -> bool {
        fragmenter.last_ack_sent() == Some(SHUTDOWN_NUM)
    }

    pub fn shutdown_ack_timed_out(&self, now: u64) -> bool {
        if self.shutdown_in_progress {
            if self.shutdown_tries >= SHUTDOWN_RETRIES {
                return true;
            }
            if let Some(start) = self.shutdown_start {
                return now - start >= ACTIVE_RETRY_TIMEOUT_MS;
            }
        }
        false
    }

    /// Timestamp of the oldest state the peer has acked (round-trip
    /// evidence for roaming, spec §8).
    pub fn sent_state_acked_timestamp(&self) -> u64 {
        self.sent_states.front().map(|s| s.timestamp).unwrap_or(0)
    }

    pub fn sent_state_acked(&self) -> u64 {
        self.sent_states.front().map(|s| s.num).unwrap_or(0)
    }

    pub fn sent_state_last(&self) -> u64 {
        self.sent_states.back().map(|s| s.num).unwrap_or(0)
    }

    /// The peer's ack: drop everything strictly below `ack_num`. An ack
    /// naming a culled state is ignored wholesale (idempotency, §6.2).
    pub fn process_acknowledgment_through(&mut self, ack: u64) {
        if !self.sent_states.iter().any(|s| s.num == ack) {
            return;
        }
        self.sent_states.retain(|s| s.num >= ack);
        debug_assert!(!self.sent_states.is_empty());
        self.assumed_receiver = self.assumed_receiver.min(self.sent_states.len() - 1);
    }

    /// The receiver's newest state number (piggybacked as ack_num).
    pub fn set_ack_num(&mut self, ack: u64) {
        self.ack_num = ack;
    }

    /// A received instruction carried data: schedule a delayed ack.
    pub fn set_data_ack(&mut self) {
        self.pending_data_ack = true;
    }

    /// We heard from the peer at `ts` (feeds the retry-timeout branch).
    pub fn remote_heard(&mut self, ts: u64) {
        self.last_heard = ts;
    }

    /// When the peer last appended a state we hold (introspection).
    #[doc(hidden)]
    pub fn last_heard(&self) -> u64 {
        self.last_heard
    }

    fn update_assumed_receiver_state(&mut self, now: u64, rto: u64) {
        self.assumed_receiver = 0;
        for i in 1..self.sent_states.len() {
            // benefit of the doubt to states sent recently enough
            if now - self.sent_states[i].timestamp < rto + ACK_DELAY_MS {
                self.assumed_receiver = i;
            } else {
                return;
            }
        }
    }

    fn rationalize_states(&mut self) {
        if self.sent_states.len() < 2 {
            return;
        }
        let known = self.sent_states.front().unwrap().state.clone();
        self.current_state.subtract(&known);
        for state in &mut self.sent_states {
            state.state.subtract(&known);
        }
    }

    /// ms until the next send/ack event: 0 when something is already
    /// overdue, `u64::MAX` when nothing is scheduled (mosh's INT_MAX).
    pub fn wait_time(&mut self, now: u64, rto: u64, send_interval: u64) -> u64 {
        let (next_send, next_ack) = self.compute_timers(now, rto, send_interval);
        let earliest = match (next_send, next_ack) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        earliest.map_or(u64::MAX, |t| t.saturating_sub(now))
    }

    /// Timer recomputation shared by `wait_time` and `tick`. Mirrors
    /// mosh's `calculate_timers`: the delayed-ack deadline is PERSISTED
    /// (so it actually fires 100 ms after data arrives, not 3 s later),
    /// and the mindelay clock starts the moment state diverges.
    fn compute_timers(
        &mut self,
        now: u64,
        rto: u64,
        send_interval: u64,
    ) -> (Option<u64>, Option<u64>) {
        if self.pending_data_ack && self.next_ack_time > now + ACK_DELAY_MS {
            self.next_ack_time = now + ACK_DELAY_MS;
        }
        let back = self.sent_states.back().expect("sent_states never empty");
        if self.current_state != back.state && self.mindelay_clock.is_none() {
            self.mindelay_clock = Some(now);
        }
        let next_send = if self.current_state != back.state {
            let floor = self.mindelay_clock.map_or(now, |m| m + self.send_mindelay);
            Some(floor.max(back.timestamp + send_interval))
        } else if self.current_state != self.sent_states[self.assumed_receiver].state
            && self.last_heard + ACTIVE_RETRY_TIMEOUT_MS > now
        {
            let mut t = back.timestamp + send_interval;
            if let Some(m) = self.mindelay_clock {
                t = t.max(m + self.send_mindelay);
            }
            Some(t)
        } else if self.sent_states.len() > 1
            && self.current_state != self.sent_states.front().unwrap().state
            && self.last_heard + ACTIVE_RETRY_TIMEOUT_MS > now
        {
            Some(back.timestamp + rto + ACK_DELAY_MS)
        } else {
            None
        };

        if self.shutdown_in_progress || self.ack_num == SHUTDOWN_NUM {
            self.next_ack_time = back.timestamp + send_interval;
        }
        (next_send, Some(self.next_ack_time))
    }

    /// mosh's `tick`: send a diff or an empty ack if one is due. Due
    /// fragments are appended to `out` (already sliced and identified —
    /// hand them to the crypto layer one datagram each). Infallible, like
    /// upstream's void tick: protocol-version and diff errors belong to
    /// the receive path. `mtu` must leave room for the 10-byte fragment
    /// header — the session's floor is 472; anything smaller is a caller
    /// bug and the instruction is dropped loudly (see send_in_fragments).
    pub fn tick(
        &mut self,
        now: u64,
        rto: u64,
        send_interval: u64,
        mtu: usize,
        fragmenter: &mut Fragmenter,
        out: &mut Vec<Fragment>,
    ) {
        self.update_assumed_receiver_state(now, rto);
        self.rationalize_states();
        let (next_send, next_ack) = self.compute_timers(now, rto, send_interval);

        let due_send = next_send.is_some_and(|t| now >= t);
        let due_ack = next_ack.is_some_and(|t| now >= t);
        if !due_send && !due_ack {
            return;
        }

        let mut diff = self
            .current_state
            .diff_from(&self.sent_states[self.assumed_receiver].state);
        self.attempt_prospective_resend_optimization(&mut diff);

        if diff.is_empty() {
            if due_ack {
                self.send_empty_ack(now, mtu, fragmenter, out);
                self.mindelay_clock = None;
            }
            if due_send {
                self.next_send_time = None;
                self.mindelay_clock = None;
            }
        } else if due_send || due_ack {
            self.send_to_receiver(now, &diff, mtu, fragmenter, out);
            self.mindelay_clock = None;
        }
    }

    fn attempt_prospective_resend_optimization(&mut self, proposed_diff: &mut Vec<u8>) {
        if self.assumed_receiver == 0 || self.sent_states.len() < 2 {
            return;
        }
        let front = self.sent_states.front().unwrap().state.clone();
        let resend_diff = self.current_state.diff_from(&front);
        if resend_diff.len() <= proposed_diff.len()
            || (resend_diff.len() < 1000 && resend_diff.len() - proposed_diff.len() < 100)
        {
            self.assumed_receiver = 0;
            *proposed_diff = resend_diff;
        }
    }

    fn add_sent_state(&mut self, timestamp: u64, num: u64, state: S) {
        self.sent_states.push_back(TimestampedState {
            timestamp,
            num,
            state,
        });
        if self.sent_states.len() > SENT_QUEUE_CAP {
            // cull from the middle, exactly mosh's erase(end()-16): the
            // known-receiver head and the newest 15 states survive
            let idx = self.sent_states.len() - 16;
            self.sent_states.remove(idx);
            // keep the index pointing at the SAME state, like mosh's
            // list iterator, which survives erasing another element
            if self.assumed_receiver > idx {
                self.assumed_receiver -= 1;
            } else if self.assumed_receiver == idx {
                // the assumed state itself was culled — unreachable while
                // assumed is only ever the known-receiver head (0) or the
                // newest (len-1); fall back to the head
                self.assumed_receiver = 0;
            }
        }
    }

    fn send_empty_ack(
        &mut self,
        now: u64,
        mtu: usize,
        fragmenter: &mut Fragmenter,
        out: &mut Vec<Fragment>,
    ) {
        let new_num = if self.shutdown_in_progress {
            SHUTDOWN_NUM
        } else {
            self.sent_states.back().unwrap().num + 1
        };
        let state = self.current_state.clone();
        // the diff (here: empty) pairs with the pre-cull assumed state —
        // capture its num before add_sent_state may shift the indices
        let old_num = self.sent_states[self.assumed_receiver].num;
        self.add_sent_state(now, new_num, state);
        self.send_in_fragments(b"", old_num, new_num, mtu, fragmenter, out);
        self.next_ack_time = now + ACK_INTERVAL_MS;
        self.next_send_time = None;
    }

    fn send_to_receiver(
        &mut self,
        now: u64,
        diff: &[u8],
        mtu: usize,
        fragmenter: &mut Fragmenter,
        out: &mut Vec<Fragment>,
    ) {
        let mut new_num = if self.current_state == self.sent_states.back().unwrap().state {
            self.sent_states.back().unwrap().num
        } else {
            self.sent_states.back().unwrap().num + 1
        };
        if self.shutdown_in_progress {
            new_num = SHUTDOWN_NUM;
        }
        // the diff was computed against the assumed state; capture its
        // num before add_sent_state may cull and shift the indices, so
        // old_num on the wire always names the diff's base
        let old_num = self.sent_states[self.assumed_receiver].num;
        if new_num == self.sent_states.back().unwrap().num {
            self.sent_states.back_mut().unwrap().timestamp = now;
        } else {
            let state = self.current_state.clone();
            self.add_sent_state(now, new_num, state);
        }
        self.send_in_fragments(diff, old_num, new_num, mtu, fragmenter, out);
        self.assumed_receiver = self.sent_states.len() - 1;
        self.next_ack_time = now + ACK_INTERVAL_MS;
        self.next_send_time = None;
    }

    fn send_in_fragments(
        &mut self,
        diff: &[u8],
        old_num: u64,
        new_num: u64,
        mtu: usize,
        fragmenter: &mut Fragmenter,
        out: &mut Vec<Fragment>,
    ) {
        let inst = TransportInstruction {
            protocol_version: MOSH_PROTOCOL_VERSION,
            old_num,
            new_num,
            ack_num: self.ack_num,
            throwaway_num: self.sent_states.front().unwrap().num,
            diff: diff.to_vec(),
            // chaff: conch sends none (spec §9); the field stays default
            chaff: Vec::new(),
        };
        if new_num == SHUTDOWN_NUM {
            self.shutdown_tries += 1;
        }
        let fragments = match fragmenter.make_fragments(&inst, mtu) {
            Ok(fragments) => fragments,
            Err(e) => {
                // unreachable from the session, whose smallest MTU (500)
                // leaves payload budget far above the 10-byte header; a
                // caller passing less is a bug — refuse loudly in debug
                // builds and drop the instruction (unsent, so the data
                // ack stays pending) rather than stall silently
                debug_assert!(false, "make_fragments failed: {e}");
                if std::env::var_os("MOSH_TRACE").is_some() {
                    eprintln!("[mosh] make_fragments failed: {e}");
                }
                return;
            }
        };
        out.extend(fragments);
        self.pending_data_ack = false;
    }
}

// --- receiver -------------------------------------------------------------

/// What the receiver did with an instruction (spec §6.2); the session
/// layer acts on the ack/data-ack hints.
#[derive(Debug, PartialEq, Eq)]
pub enum RecvOutcome<S> {
    /// Newest state appended: raise our outbound ack to `num`.
    Latest { num: u64, had_diff: bool, state: S },
    /// Older state inserted into place (no ack update, no data-ack hint).
    OutOfOrder { num: u64, had_diff: bool },
    /// new_num already known (idempotent retransmission).
    Duplicate,
    /// old_num no longer held (or never seen) — drop, security-sensitive.
    NoReference,
    /// Over the queue cap outside the 15 s admit window.
    Quenched,
}

pub struct SspReceiver<S: SspReceivedState> {
    received: VecDeque<TimestampedState<S>>,
    quench_until: u64,
}

impl<S: SspReceivedState> SspReceiver<S> {
    pub fn new(initial: S, now: u64) -> Self {
        SspReceiver {
            received: VecDeque::from([TimestampedState {
                timestamp: now,
                num: 0,
                state: initial,
            }]),
            quench_until: 0,
        }
    }

    pub fn latest(&self) -> &TimestampedState<S> {
        self.received.back().expect("received never empty")
    }

    pub fn latest_state(&self) -> &S {
        &self.latest().state
    }

    pub fn state_count(&self) -> usize {
        self.received.len()
    }

    fn process_throwaway_until(&mut self, throwaway_num: u64) -> bool {
        // emptying the queue would break the state machine's invariants;
        // a hostile throwaway is refused without culling instead (mosh
        // fatal_asserts here — our hardening difference, spec §9)
        if !self.received.iter().any(|s| s.num >= throwaway_num) {
            return false;
        }
        self.received.retain(|s| s.num >= throwaway_num);
        true
    }

    /// Apply one decoded instruction arriving at time `now`.
    pub fn process_instruction(
        &mut self,
        inst: &TransportInstruction,
        now: u64,
    ) -> Result<RecvOutcome<S>, SspError> {
        if inst.protocol_version != MOSH_PROTOCOL_VERSION {
            return Err(SspError::ProtocolVersion(inst.protocol_version));
        }
        if self.received.iter().any(|s| s.num == inst.new_num) {
            return Ok(RecvOutcome::Duplicate);
        }
        if !self.received.iter().any(|s| s.num == inst.old_num) {
            return Ok(RecvOutcome::NoReference);
        }
        if !self.process_throwaway_until(inst.throwaway_num) {
            return Ok(RecvOutcome::NoReference);
        }
        // re-locate after the cull (indices shifted); a throwaway that
        // culls everything (hostile — a peer never sends one past its own
        // new_num) drops the instruction rather than emptying the queue
        let Some(reference) = self.received.iter().position(|s| s.num == inst.old_num) else {
            return Ok(RecvOutcome::NoReference);
        };

        if self.received.len() > RECEIVED_QUEUE_CAP && now < self.quench_until {
            return Ok(RecvOutcome::Quenched);
        } else if self.received.len() > RECEIVED_QUEUE_CAP {
            self.quench_until = now + QUENCH_WINDOW_MS;
        }

        let mut new_state = self.received[reference].clone();
        new_state.timestamp = now;
        new_state.num = inst.new_num;
        let had_diff = !inst.diff.is_empty();
        if had_diff {
            new_state
                .state
                .apply_string(&inst.diff)
                .map_err(|e| SspError::BadDiff(e.to_string()))?;
        }

        // sorted insert: append if newest, else slot into place
        if self.received.back().is_some_and(|s| s.num < new_state.num) {
            let num = new_state.num;
            self.received.push_back(new_state.clone());
            Ok(RecvOutcome::Latest {
                num,
                had_diff,
                state: new_state.state,
            })
        } else {
            let num = new_state.num;
            let position = self
                .received
                .iter()
                .position(|s| s.num > new_state.num)
                .unwrap_or(self.received.len());
            self.received.insert(position, new_state);
            Ok(RecvOutcome::OutOfOrder { num, had_diff })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragment::{Fragment, FragmentAssembly};

    #[test]
    fn user_stream_diff_subtract_roundtrip() {
        let mut a = UserStream::new();
        a.push_bytes(b"echo hi\r");
        a.push_resize(100, 30);

        let empty = UserStream::new();
        let diff = a.diff_from(&empty);
        let mut b = UserStream::new();
        b.apply_string(&diff).unwrap();
        assert_eq!(a, b, "diff from empty reconstructs the whole stream");

        // incremental diff after the peer holds a prefix
        let mut partial = UserStream::new();
        partial.push_bytes(b"echo ");
        let mut c = a.clone();
        c.subtract(&partial);
        assert_eq!(c.len(), 4, "\"hi\\r\" (3) + the resize remain");
        let delta = a.diff_from(&partial);
        let mut d = partial.clone();
        d.apply_string(&delta).unwrap();
        assert_eq!(a, d);

        // coalescing: one run of bytes becomes one keystroke instruction
        let msg = UserMessage::decode(&a.diff_from(&UserStream::new())).unwrap();
        assert_eq!(msg.instructions.len(), 2, "bytes coalesce; resize separate");
    }

    #[test]
    fn host_stream_state_applies_all_three_instruction_kinds() {
        let mut host = HostStreamState::new();
        let message = HostMessage {
            instructions: vec![
                HostInstruction::Resize {
                    width: 80,
                    height: 24,
                },
                HostInstruction::HostBytes(b"\x1b[1;1Hhi".to_vec()),
                HostInstruction::EchoAck(7),
                HostInstruction::EchoAck(5), // regressions never lower it
                HostInstruction::HostBytes(Vec::new()), // empties are dropped
            ],
        };
        host.apply_string(&message.encode()).unwrap();
        let events = host.log.iter();
        assert_eq!(events.len(), 2, "resize + one byte event, in order");
        assert!(matches!(
            events[0],
            HostEvent::Resize {
                width: 80,
                height: 24
            }
        ));
        assert!(matches!(&events[1], HostEvent::Bytes(b) if b == b"\x1b[1;1Hhi"));
        assert_eq!(host.byte_len(), 8);
        assert_eq!(host.echo_ack, 7);
    }

    /// The delayed-ack deadline must PERSIST (review finding: a local
    /// computation pushed the ack out to the full 3 s interval). Data
    /// arriving at t=0 must produce an ack by t=101, not t=3001.
    #[test]
    fn delayed_ack_fires_100ms_after_data() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        sender.set_data_ack(); // the receiver saw a diff at t=0
                               // mosh anchors the deadline at the first timer pass after the
                               // flag — in the real loop that is the very next tick
        assert_eq!(sender.wait_time(0, 120, 20), 100);

        let wait_at_50 = sender.wait_time(50, 120, 20);
        assert_eq!(wait_at_50, 50, "the deadline persisted, not recomputed");

        let mut fragmenter = Fragmenter::default();
        let mut out = Vec::new();
        sender.tick(101, 120, 20, 1200, &mut fragmenter, &mut out);
        assert!(!out.is_empty(), "the delayed ack went out at t=101");
        // an empty-ack still advances the state number
        let frag = Fragment::parse(&out[0].tostring()).unwrap();
        let mut assembly = FragmentAssembly::new();
        let inst = assembly.add_fragment(frag).unwrap();
        assert_eq!(inst.protocol_version, 2);
        assert_eq!(inst.new_num, 1);
        assert!(inst.diff.is_empty());
    }

    /// The mindelay clock starts the moment state diverges (review
    /// finding: it used to start only once a send was already due). A
    /// change at t=15 (back.ts=0, interval=20, mindelay=8) has floor
    /// max(15+8, 0+20) = 23 — mindelay binds, so a send at t=20..22
    /// proves the bug and one at t=23 proves the fix.
    #[test]
    fn mindelay_batches_a_freshly_changed_state() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 8);
        let mut fragmenter = Fragmenter::default();
        let mut out = Vec::new();
        for t in 0..15u64 {
            sender.tick(t, 120, 20, 1200, &mut fragmenter, &mut out);
        }
        sender.current_state().push_bytes(b"a");
        for t in 15..23u64 {
            sender.tick(t, 120, 20, 1200, &mut fragmenter, &mut out);
        }
        assert!(out.is_empty(), "held past the interval bound (t=20..22)");
        sender.tick(23, 120, 20, 1200, &mut fragmenter, &mut out);
        assert!(!out.is_empty(), "send goes out at the mindelay bound");
    }

    #[test]
    fn receiver_idempotency_and_reference_rules() {
        let mut rx = SspReceiver::new(UserStream::new(), 0);

        let inst = |old: u64, new: u64, diff: &[u8]| TransportInstruction {
            protocol_version: 2,
            old_num: old,
            new_num: new,
            ack_num: 0,
            throwaway_num: 0,
            diff: diff.to_vec(),
            chaff: vec![],
        };
        let hello = UserMessage {
            instructions: vec![UserInstruction::Keystroke(b"hi".to_vec())],
        }
        .encode();

        assert!(matches!(
            rx.process_instruction(&inst(0, 1, &hello), 10).unwrap(),
            RecvOutcome::Latest {
                num: 1,
                had_diff: true,
                ..
            }
        ));
        // same state again: duplicate, not a second application
        assert_eq!(
            rx.process_instruction(&inst(0, 1, &hello), 11).unwrap(),
            RecvOutcome::Duplicate
        );
        // references a state we never held
        assert_eq!(
            rx.process_instruction(&inst(99, 100, &hello), 12).unwrap(),
            RecvOutcome::NoReference
        );
        // wrong protocol version is session-fatal
        let mut old_proto = inst(0, 2, b"");
        old_proto.protocol_version = 0;
        assert_eq!(
            rx.process_instruction(&old_proto, 13).unwrap_err(),
            SspError::ProtocolVersion(0)
        );

        // out-of-order arrival: state 3 first, then the older state 2
        // lands mid-queue without becoming "latest" or re-acking
        let xyz = UserMessage {
            instructions: vec![UserInstruction::Keystroke(b"XYZ".to_vec())],
        }
        .encode();
        let ab = UserMessage {
            instructions: vec![UserInstruction::Keystroke(b"AB".to_vec())],
        }
        .encode();
        assert!(matches!(
            rx.process_instruction(&inst(1, 3, &xyz), 14).unwrap(),
            RecvOutcome::Latest { num: 3, .. }
        ));
        assert!(matches!(
            rx.process_instruction(&inst(0, 2, &ab), 15).unwrap(),
            RecvOutcome::OutOfOrder { num: 2, .. }
        ));
        assert_eq!(rx.latest().num, 3, "3 stays newest");
        assert_eq!(rx.state_count(), 4);
    }

    /// B2 regression: past the 32-entry sent-state cap, every emitted
    /// instruction must stay COHERENT — applying its diff to the receiver
    /// state named by `old_num` must reproduce the sender's current
    /// state. The cull used to reset the assumed-receiver index before
    /// `old_num` was read, pairing a tail diff with a front `old_num`
    /// (silently forking the peer's copy of the stream).
    #[test]
    fn instructions_stay_coherent_past_32_unacked_states() {
        let rto = 1000; // in-spec clamp top; freshness window = rto + ACK_DELAY
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        let mut receiver: SspReceiver<UserStream> = SspReceiver::new(UserStream::new(), 0);
        let mut fragmenter = Fragmenter::default();
        let mut assembly = FragmentAssembly::new();
        let mut now: u64 = 0;
        let mut instructions_checked = 0;

        for i in 0..50u64 {
            sender
                .current_state()
                .push_bytes(format!("k{i:02},").as_bytes());
            loop {
                let mut out = Vec::new();
                sender.tick(now, rto, 20, 1200, &mut fragmenter, &mut out);
                for frag in &out {
                    let Some(inst) =
                        assembly.add_fragment(Fragment::parse(&frag.tostring()).unwrap())
                    else {
                        continue;
                    };
                    // coherence: old_num must NAME the state the diff
                    // was computed against
                    let named = receiver
                        .received
                        .iter()
                        .find(|s| s.num == inst.old_num)
                        .unwrap_or_else(|| {
                            panic!("instruction names unheld state {}", inst.old_num)
                        })
                        .clone();
                    let mut expected = named.state.clone();
                    if !inst.diff.is_empty() {
                        expected.apply_string(&inst.diff).unwrap();
                    }
                    assert_eq!(
                        expected,
                        *sender.current_state(),
                        "incoherent instruction old={} new={} diff_len={} at t={now}",
                        inst.old_num,
                        inst.new_num,
                        inst.diff.len()
                    );
                    receiver.process_instruction(&inst, now).unwrap();
                    instructions_checked += 1;
                }
                if !out.is_empty() {
                    break;
                }
                now += 1;
            }
            now += 1;
        }
        // the queue was saturated on the way (the bug needs >32 states)
        assert_eq!(sender.sent_states.len(), SENT_QUEUE_CAP);
        // and the peer reconstructed the full stream
        assert_eq!(receiver.latest_state().len(), sender.current_state().len());
        assert!(instructions_checked >= 40, "checked {instructions_checked}");

        // shutdown accelerates empty acks to one frame while the queue
        // stays saturated — the empty-ack capture path through the cull
        let frozen = sender.current_state().clone();
        sender.start_shutdown(now);
        let mut empty_shutdown_acks = 0;
        for _ in 0..400 {
            now += 1;
            let mut out = Vec::new();
            sender.tick(now, rto, 20, 1200, &mut fragmenter, &mut out);
            for frag in &out {
                let Some(inst) = assembly.add_fragment(Fragment::parse(&frag.tostring()).unwrap())
                else {
                    continue;
                };
                let named = receiver
                    .received
                    .iter()
                    .find(|s| s.num == inst.old_num)
                    .unwrap_or_else(|| panic!("shutdown names unheld state {}", inst.old_num))
                    .clone();
                // the empty diff still names its base: the assumed state
                assert_eq!(
                    named.state, frozen,
                    "incoherent shutdown instruction old={} new={}",
                    inst.old_num, inst.new_num
                );
                if inst.new_num == SHUTDOWN_NUM && inst.diff.is_empty() {
                    empty_shutdown_acks += 1;
                }
                receiver.process_instruction(&inst, now).unwrap();
            }
            if empty_shutdown_acks >= 3 {
                break;
            }
        }
        assert!(
            empty_shutdown_acks >= 1,
            "shutdown must drive empty acks through the saturated queue"
        );
    }

    /// Dropping a long EventLog chain must not recurse per node. The
    /// default Arc drop glue walks the parent chain one stack frame per
    /// node, and a session's log grows without bound — the loop thread
    /// died with a process-fatal stack overflow at teardown once a
    /// session accumulated enough host events (debug ~7k, release ~60k
    /// on a 2 MiB stack). The deep drop runs in a CHILD PROCESS re-exec
    /// of this suite on a 64 KiB stack: a stack overflow is a fatal
    /// abort, not a catchable panic, so the witness is the child's
    /// exit status.
    #[test]
    fn deep_event_log_drop_does_not_overflow_the_stack() {
        if std::env::var_os("MOSH_ELOG_DEEP_DROP").is_some() {
            let handle = std::thread::Builder::new()
                .stack_size(64 * 1024)
                .spawn(|| {
                    let mut log = EventLog::new();
                    for i in 0..50_000u32 {
                        log.push(HostEvent::Bytes(vec![b'x'; (i % 5) as usize + 1]));
                    }
                    drop(log);
                })
                .unwrap();
            handle.join().expect("deep drop survived a 64 KiB stack");
            println!("deep drop survived");
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let output = std::process::Command::new(exe)
            .args([
                "ssp::tests::deep_event_log_drop_does_not_overflow_the_stack",
                "--exact",
                "--nocapture",
            ])
            .env("MOSH_ELOG_DEEP_DROP", "1")
            .output()
            .expect("re-exec the test binary");
        let ran = String::from_utf8_lossy(&output.stdout).contains("deep drop survived");
        assert!(
            output.status.success() && ran,
            "the child must run the 50k-event drop on a 64 KiB stack and survive \
             (exit: {output:?})"
        );
    }

    #[test]
    fn throwaway_culls_but_never_empties() {
        let mut rx = SspReceiver::new(UserStream::new(), 0);
        let inst = |old: u64, new: u64, tw: u64| TransportInstruction {
            protocol_version: 2,
            old_num: old,
            new_num: new,
            ack_num: 0,
            throwaway_num: tw,
            diff: vec![],
            chaff: vec![],
        };
        rx.process_instruction(&inst(0, 1, 0), 1).unwrap();
        rx.process_instruction(&inst(1, 2, 0), 2).unwrap();
        rx.process_instruction(&inst(2, 3, 1), 3).unwrap(); // cull <1
        assert_eq!(rx.state_count(), 3); // states 1,2,3
                                         // a hostile throwaway that would cull everything drops the
                                         // instruction instead of emptying the queue (mosh aborts here)
        assert_eq!(
            rx.process_instruction(&inst(3, 4, 99), 4).unwrap(),
            RecvOutcome::NoReference
        );
        assert_eq!(rx.latest().num, 3, "the queue survives untouched");
    }

    /// The send schedule's exact boundaries on a manual clock:
    /// a divergent state goes out at `back.timestamp + send_interval`
    /// and not one tick sooner (and the state numbers advance by one);
    /// once the un-acked backlog ages past `rto + ack-delay` the
    /// assumed state falls back to the head and the retry timer
    /// (`back + rto + ack-delay`) takes over; when the peer's last word
    /// ages past ACTIVE_RETRY_TIMEOUT the scheduler stops offering
    /// resends entirely (a dead wire is not retried).
    #[test]
    fn send_schedule_boundaries_are_exact() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        let mut fragmenter = Fragmenter::default();
        let mut out = Vec::new();
        let mut insts = Vec::new();
        let parse = |out: &mut Vec<Fragment>| -> TransportInstruction {
            let mut asm = FragmentAssembly::new();
            for f in out.drain(..) {
                if let Some(inst) = asm.add_fragment(f) {
                    return inst;
                }
            }
            panic!("no instruction assembled");
        };

        // divergence at t=10: due at 0 + interval(20), not at 19
        sender.current_state().push_bytes(b"a");
        sender.tick(10, 120, 20, 1200, &mut fragmenter, &mut out);
        assert!(out.is_empty(), "held before the interval bound");
        sender.tick(19, 120, 20, 1200, &mut fragmenter, &mut out);
        assert!(out.is_empty(), "the interval bound is exact");
        sender.tick(20, 120, 20, 1200, &mut fragmenter, &mut out);
        assert_eq!(out.len(), 1, "out at back.timestamp + send_interval");
        insts.push(parse(&mut out));

        // second divergence at t=21: due at 20 + 20 = 40
        sender.current_state().push_bytes(b"b");
        sender.tick(39, 120, 20, 1200, &mut fragmenter, &mut out);
        assert!(out.is_empty(), "the second send rides the same interval");
        sender.tick(40, 120, 20, 1200, &mut fragmenter, &mut out);
        insts.push(parse(&mut out));

        let nums: Vec<u64> = insts.iter().map(|i| i.new_num).collect();
        assert_eq!(nums, [1, 2], "state numbers advance by exactly one");

        // with current == back and the backlog fresh, the assumed state
        // rides the newest: nothing is resent, and the retry timer
        // (40 + rto + ack-delay = 260) is exactly what wait_time
        // reports — the session polls on it, so it is wire contract
        sender.tick(100, 120, 20, 1200, &mut fragmenter, &mut out);
        assert!(out.is_empty(), "a fresh backlog is not resent early");
        assert_eq!(
            sender.wait_time(100, 120, 20),
            40 + 120 + ACK_DELAY_MS - 100,
            "the fresh-backlog retry timer, as the session's poll sees it"
        );

        // the fallback boundary is exact: state 1 went out at 20, so at
        // 20 + rto + ack-delay - 1 it is one ms inside the freshness
        // window (assumed stays the newest, branch 3 not yet due at
        // 260); at the boundary it goes stale, the assumed state falls
        // back to the head, and the branch-2 retry (back+interval = 60,
        // long overdue) fires at once
        let stale_at = 20 + 120 + ACK_DELAY_MS;
        sender.tick(stale_at - 1, 120, 20, 1200, &mut fragmenter, &mut out);
        assert!(out.is_empty(), "one ms inside the freshness window holds");
        sender.tick(stale_at, 120, 20, 1200, &mut fragmenter, &mut out);
        let retry = parse(&mut out);
        assert_eq!(retry.new_num, 2, "the retry resends the newest state");
        assert_eq!(retry.old_num, 0, "the diff base is the head state");

        // far later, the overdue ack rides along — but it must ride as
        // the SAME state (num 2, timestamp refreshed), not append a new
        // one: the newest state's number is never reused-forward
        sender.tick(5000, 120, 20, 1200, &mut fragmenter, &mut out);
        let ride = parse(&mut out);
        assert_eq!(
            ride.new_num, 2,
            "the ack ride-along refreshes the newest state in place"
        );
        assert_eq!(ride.old_num, 0, "its diff still bases on the head");
    }

    /// The quench gate: overflowing the received queue arms a window of
    /// QUENCH_WINDOW_MS (overflows inside it are answered Quenched,
    /// unsent), and the expiry boundary is exact — `now == quench_until`
    /// flows again.
    #[test]
    fn quench_gate_is_exact() {
        let mut rx = SspReceiver::new(UserStream::new(), 0);
        let diff = crate::wire::UserMessage {
            instructions: vec![crate::wire::UserInstruction::Keystroke(b"x".to_vec())],
        }
        .encode();
        let inst = |old: u64, new: u64| TransportInstruction {
            protocol_version: 2,
            old_num: old,
            new_num: new,
            ack_num: 0,
            throwaway_num: 0,
            diff: diff.clone(),
            chaff: Vec::new(),
        };
        // fill to exactly the cap: state 0 plus RECEIVED_QUEUE_CAP appends
        let cap = RECEIVED_QUEUE_CAP as u64;
        for n in 1..=cap {
            assert!(matches!(
                rx.process_instruction(&inst(0, n), 1000).unwrap(),
                RecvOutcome::Latest { .. }
            ));
        }
        // overflow #1 arms the window and still flows
        assert!(matches!(
            rx.process_instruction(&inst(1024, 1025), 1000).unwrap(),
            RecvOutcome::Latest { .. }
        ));
        // overflow #2 inside the window is quenched — and stays so at
        // the last ms of it
        assert!(matches!(
            rx.process_instruction(&inst(1025, 1026), 1000).unwrap(),
            RecvOutcome::Quenched
        ));
        assert!(matches!(
            rx.process_instruction(&inst(1025, 1027), 1000 + QUENCH_WINDOW_MS - 1)
                .unwrap(),
            RecvOutcome::Quenched
        ));
        // at expiry exactly, the queue flows again (and re-arms)
        assert!(matches!(
            rx.process_instruction(&inst(1025, 1028), 1000 + QUENCH_WINDOW_MS)
                .unwrap(),
            RecvOutcome::Latest { .. }
        ));
    }

    /// The delayed ack has two shapes. A tiny backlog rides the
    /// prospective-resend optimization: the empty diff (vs the assumed
    /// newest state) is swapped for the full suffix based on the head —
    /// a bet that the peer missed everything. A backlog of 1000+ bytes
    /// stands the optimization down, and the ack goes out as a pure
    /// empty state one past the back.
    #[test]
    fn empty_ack_appends_one_state() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        let mut fragmenter = Fragmenter::default();
        let mut out = Vec::new();
        let parse = |out: &mut Vec<Fragment>| -> TransportInstruction {
            let mut asm = FragmentAssembly::new();
            for f in out.drain(..) {
                if let Some(inst) = asm.add_fragment(f) {
                    return inst;
                }
            }
            panic!("no instruction assembled");
        };

        // A tiny backlog: the delayed ack rides the prospective-resend
        // optimization — the empty diff (vs the assumed newest state)
        // is swapped for the full suffix based on the head, betting the
        // peer missed everything. No new state is appended: the resend
        // refreshes state 1's timestamp and re-uses its number.
        sender.current_state().push_bytes(b"a");
        // the mindelay clock anchors at this first divergent pass
        // (floor 19+1), but the interval bound (0+20) binds: due at 20
        sender.tick(19, 120, 20, 1200, &mut fragmenter, &mut out);
        assert!(out.is_empty());
        sender.tick(20, 120, 20, 1200, &mut fragmenter, &mut out);
        assert_eq!(parse(&mut out).new_num, 1);

        sender.set_data_ack();
        // the ack deadline anchors at the first timer pass after the
        // flag (t=21) and fires 100ms later
        sender.tick(21, 120, 20, 1200, &mut fragmenter, &mut out);
        assert!(out.is_empty(), "the ack is delayed, not immediate");
        sender.tick(121, 120, 20, 1200, &mut fragmenter, &mut out);
        let ack = parse(&mut out);
        assert_eq!(ack.new_num, 1, "the optimized resend re-uses state 1");
        assert_eq!(ack.old_num, 0, "its diff bases on the head");
        assert!(!ack.diff.is_empty(), "it carries the full suffix");

        // A backlog of 1000+ bytes: the optimization stands down (it
        // only bets on suffixes under 1000 bytes), so the delayed ack
        // goes out as a pure empty state one past the back.
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        let mut out = Vec::new();
        sender.current_state().push_bytes(&[b'x'; 1001]);
        sender.tick(19, 120, 20, 1200, &mut fragmenter, &mut out);
        sender.tick(20, 120, 20, 1200, &mut fragmenter, &mut out);
        parse(&mut out);

        sender.set_data_ack();
        sender.tick(21, 120, 20, 1200, &mut fragmenter, &mut out);
        sender.tick(121, 120, 20, 1200, &mut fragmenter, &mut out);
        let ack = parse(&mut out);
        assert_eq!(
            ack.new_num, 2,
            "the pure empty ack appends exactly one state"
        );
        assert!(ack.diff.is_empty(), "it carries no diff");
        assert_eq!(ack.old_num, 1, "its base is the assumed state");
    }

    /// The shutdown-retry timeout boundary: a full
    /// ACTIVE_RETRY_TIMEOUT since shutdown started, to the ms.
    #[test]
    fn shutdown_ack_timeout_boundary_is_exact() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        sender.start_shutdown(1000);
        assert!(
            !sender.shutdown_ack_timed_out(1000 + ACTIVE_RETRY_TIMEOUT_MS - 1),
            "one ms short of the timeout is not timed out"
        );
        assert!(
            sender.shutdown_ack_timed_out(1000 + ACTIVE_RETRY_TIMEOUT_MS),
            "the full timeout, to the ms, is timed out"
        );
    }

    /// The introspection accessors say what the bookkeeping did: the
    /// acked timestamp names the oldest held state, and the event log's
    /// size is honest.
    #[test]
    fn accessor_basics_are_honest() {
        let mut stream = UserStream::new();
        assert!(stream.is_empty());
        stream.push_bytes(b"abc");
        assert_eq!(stream.events().len(), 3);
        assert!(!stream.is_empty());

        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        let mut fragmenter = Fragmenter::default();
        let mut out = Vec::new();
        sender.current_state().push_bytes(b"a");
        sender.tick(19, 120, 20, 1200, &mut fragmenter, &mut out);
        sender.tick(20, 120, 20, 1200, &mut fragmenter, &mut out);
        // two states held (0 and 1): the oldest is the t=0 reference
        assert_eq!(sender.sent_state_acked_timestamp(), 0);
        sender.process_acknowledgment_through(1);
        assert_eq!(
            sender.sent_state_acked_timestamp(),
            20,
            "after the ack, the oldest held state is the one sent at 20"
        );
    }

    /// send_interval = ceil(srtt/2) clamped to [20, 250] — two frames
    /// per RTT, bounded (spec §6.1). The clamp points exactly.
    #[test]
    fn send_interval_ms_is_half_srtt_clamped() {
        assert_eq!(send_interval_ms(0.0), 20);
        assert_eq!(send_interval_ms(40.0), 20);
        assert_eq!(send_interval_ms(81.0), 41, "an odd srtt rounds UP");
        assert_eq!(send_interval_ms(100.0), 50);
        assert_eq!(send_interval_ms(1000.0), 250);
        assert_eq!(send_interval_ms(5000.0), 250);
    }

    /// EventLog bookkeeping: len/emptiness are honest, iter() is in
    /// replay order, and suffix_over returns the exact suffix — the
    /// extension, the equal-log (Some(empty), not None), the diverged
    /// trunk, and the longer base each have one answer. The empty-base
    /// over empty-log case is the (None, None) trunk arm.
    #[test]
    fn event_log_suffix_and_order_are_exact() {
        let ev = |b: u8| HostEvent::Bytes(vec![b]);
        let mut a = EventLog::new();
        assert!(a.is_empty());
        assert_eq!(a.len(), 0);
        for b in b'1'..=b'3' {
            a.push(ev(b));
        }
        assert_eq!(a.len(), 3);
        assert!(!a.is_empty());
        assert_eq!(
            a.iter()
                .iter()
                .map(|e| match e {
                    HostEvent::Bytes(v) => v[0],
                    _ => 0,
                })
                .collect::<Vec<_>>(),
            b"123",
            "iter() is replay order"
        );

        // extension: b = a + e4 + e5 → the exact two events, in order
        let mut b = a.clone();
        b.push(ev(b'4'));
        b.push(ev(b'5'));
        let suffix = b.suffix_over(&a).expect("an extension carries a suffix");
        assert_eq!(
            suffix
                .iter()
                .map(|e| match e {
                    HostEvent::Bytes(v) => v[0],
                    _ => 0,
                })
                .collect::<Vec<_>>(),
            b"45",
            "the suffix is the extension's events, in replay order"
        );

        // equal logs: the empty suffix IS a suffix (None means diverged)
        assert_eq!(
            a.suffix_over(&a.clone()).map(|v| v.len()),
            Some(0),
            "an identical log carries an EMPTY suffix, not a divergence"
        );
        // diverged at equal depth: no suffix, rebuild required
        let mut c = a.clone();
        c.push(ev(b'4'));
        let mut d = a.clone();
        d.push(ev(b'9'));
        assert!(
            c.suffix_over(&d).is_none(),
            "diverged trunks have no suffix"
        );
        // a longer base is never a suffix of a shorter log
        assert!(a.suffix_over(&b).is_none());
        // the empty/empty trunk
        assert_eq!(
            EventLog::new()
                .suffix_over(&EventLog::new())
                .map(|v| v.len()),
            Some(0)
        );
    }

    /// Ack semantics: an ack naming a state we never held (a future
    /// number) is ignored wholesale — the queue survives untouched and
    /// the session keeps working. And after an ack shrinks the queue,
    /// the assumed index must stay IN BOUNDS for the next timer read.
    #[test]
    fn unknown_acks_are_ignored_and_assumed_stays_in_bounds() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        let mut fragmenter = Fragmenter::default();
        let mut out = Vec::new();
        for i in 0..3u8 {
            sender.current_state().push_bytes(&[b'a' + i]);
            sender.tick(20 * i as u64 + 1, 120, 20, 1200, &mut fragmenter, &mut out);
            sender.tick(
                20 * (i as u64 + 1),
                120,
                20,
                1200,
                &mut fragmenter,
                &mut out,
            );
        }
        out.clear();

        // the ack drops states 0..1; the assumed index (pointing at the
        // newest, index 3) must clamp to the new length
        sender.process_acknowledgment_through(1);
        assert_eq!(
            sender.sent_state_acked_timestamp(),
            20,
            "front is now the state sent at 20"
        );
        // with the clamped index the assumed state IS the newest
        // (== current): the full-suffix retry timer answers, and the
        // index stays in bounds for the read
        assert_eq!(sender.wait_time(61, 120, 20), 60 + 120 + ACK_DELAY_MS - 61);

        // an ack for a state that was never sent: ignored, nothing moves
        sender.process_acknowledgment_through(99);
        assert_eq!(
            sender.sent_state_acked_timestamp(),
            20,
            "an unknown ack must not touch the queue"
        );
        assert_eq!(sender.wait_time(61, 120, 20), 60 + 120 + ACK_DELAY_MS - 61);
    }

    /// Past SENT_QUEUE_CAP the middle of the queue is culled (mosh's
    /// erase(end()-16)): the head and the newest 16 survive. An ack
    /// naming a culled state is IGNORED (idempotency), one naming a
    /// survivor is processed.
    #[test]
    fn cull_drops_the_middle_and_its_ack_is_ignored() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        let mut fragmenter = Fragmenter::default();
        let mut out = Vec::new();
        for i in 0..33u8 {
            sender.current_state().push_bytes(&[b'a' + i % 26]);
            sender.tick(3 * i as u64 + 1, 120, 3, 1200, &mut fragmenter, &mut out);
            sender.tick(3 * (i as u64 + 1), 120, 3, 1200, &mut fragmenter, &mut out);
        }
        out.clear();

        // states 17 and 18 were culled from the middle; state 0 (t=0)
        // is still the front
        assert_eq!(sender.sent_state_acked_timestamp(), 0);
        sender.process_acknowledgment_through(17);
        assert_eq!(
            sender.sent_state_acked_timestamp(),
            0,
            "an ack naming a culled state is ignored"
        );
        sender.process_acknowledgment_through(19);
        assert_eq!(
            sender.sent_state_acked_timestamp(),
            3 * 19,
            "an ack naming a survivor drops the head (state 19 sent at t=57)"
        );
    }

    /// The empty-ack path has no post-send index fixup, so the cull's
    /// assumed-index adjustment is load-bearing there: the ack appends
    /// state 33 and culls back to 32, and the adjusted index must stay
    /// in bounds for the next timer read. To actually reach the path,
    /// the pending full suffix must be ≥100 bytes — otherwise the
    /// prospective-resend optimization swaps the empty diff for the
    /// small suffix and the send rides the timestamp-refresh branch
    /// (no append, no cull). Four-byte chunks put the suffix at 137.
    ///
    /// The two comparison operators in the fixup itself are equivalent
    /// under every reachable configuration: the freshness walk returns
    /// only 0 or len-1 (timestamps are monotonic, so only index 1 can
    /// be the first stale state), and after an empty ack the two
    /// newest states both equal `current`, so len-2 vs len-1 select
    /// the same timer.
    #[test]
    fn empty_ack_cull_keeps_assumed_coherent() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        let mut fragmenter = Fragmenter::default();
        let mut out = Vec::new();
        // 32 states at a 3ms cadence — everything stays inside the
        // rto + ack-delay freshness window (220ms), so the assumed
        // state rides the newest
        for i in 0..32u8 {
            let chunk = [b'a' + i % 26; 4];
            sender.current_state().push_bytes(&chunk);
            sender.tick(3 * i as u64 + 1, 120, 3, 1200, &mut fragmenter, &mut out);
            sender.tick(3 * (i as u64 + 1), 120, 3, 1200, &mut fragmenter, &mut out);
        }
        out.clear();

        sender.set_data_ack();
        sender.tick(97, 120, 3, 1200, &mut fragmenter, &mut out); // anchors 197
        assert!(out.is_empty(), "the ack is delayed");
        sender.tick(197, 120, 3, 1200, &mut fragmenter, &mut out); // fires + culls
        assert!(!out.is_empty(), "the empty ack went out");

        // the adjusted index (30) names num 32, which still equals
        // current — the full-suffix retry timer answers, and the index
        // stays IN BOUNDS (an unadjusted or wrong adjustment reads past
        // the 32-state queue)
        assert_eq!(
            sender.wait_time(198, 120, 3),
            197 + 120 + ACK_DELAY_MS - 198,
            "the cull must keep the assumed index coherent for the timer read"
        );
    }

    /// The optimization swaps on EQUAL full-suffix sizes: a ≥1000-byte
    /// divergence computed against a newest state identical to the head
    /// (an empty-ack duplicate) — equal length still bets on the head.
    #[test]
    fn optimization_swaps_on_equal_full_suffixes() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        let mut fragmenter = Fragmenter::default();
        let mut out = Vec::new();
        let parse = |out: &mut Vec<Fragment>| -> TransportInstruction {
            let mut asm = FragmentAssembly::new();
            for f in out.drain(..) {
                if let Some(inst) = asm.add_fragment(f) {
                    return inst;
                }
            }
            panic!("no instruction assembled");
        };

        // an empty-ack duplicate of the empty head (state 1)
        sender.set_data_ack();
        sender.tick(1, 120, 20, 1200, &mut fragmenter, &mut out);
        sender.tick(101, 120, 20, 1200, &mut fragmenter, &mut out);
        parse(&mut out);

        // a 1001-byte divergence: proposed (vs newest, empty) and
        // resend (vs head, empty) are BOTH 1010 bytes — equal still
        // swaps to the head base
        sender.current_state().push_bytes(&[b'x'; 1001]);
        sender.tick(102, 120, 20, 1200, &mut fragmenter, &mut out);
        sender.tick(121, 120, 20, 1200, &mut fragmenter, &mut out);
        let inst = parse(&mut out);
        assert_eq!(inst.old_num, 0, "equal sizes swap to the head base");
        assert_eq!(inst.diff.len(), 1010, "the full suffix rides");
    }

    /// The optimization holds at the exact 100-byte boundary: when the
    /// resend wins by exactly 100 bytes (and stays under 1000), the
    /// bet is NOT taken — the diff against the newest goes out.
    /// Sizes: newest = 97 bytes; +31 more → resend = enc(128) = 137,
    /// proposed = enc(31) = 37, difference exactly 100.
    #[test]
    fn optimization_holds_at_the_100_byte_boundary() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        let mut fragmenter = Fragmenter::default();
        let mut out = Vec::new();
        let parse = |out: &mut Vec<Fragment>| -> TransportInstruction {
            let mut asm = FragmentAssembly::new();
            for f in out.drain(..) {
                if let Some(inst) = asm.add_fragment(f) {
                    return inst;
                }
            }
            panic!("no instruction assembled");
        };

        sender.current_state().push_bytes(&[b'y'; 97]);
        sender.tick(1, 120, 20, 1200, &mut fragmenter, &mut out);
        sender.tick(20, 120, 20, 1200, &mut fragmenter, &mut out);
        parse(&mut out);

        sender.current_state().push_bytes(&[b'z'; 31]);
        sender.tick(21, 120, 20, 1200, &mut fragmenter, &mut out);
        sender.tick(40, 120, 20, 1200, &mut fragmenter, &mut out);
        let inst = parse(&mut out);
        assert_eq!(inst.old_num, 1, "a 100-byte win is not worth the resend");
        assert_eq!(inst.diff.len(), 37, "the 31-byte suffix goes out");
    }

    /// The second condition compares the byte DIFFERENCE, not the
    /// ratio: a 401-byte gap (resend 503 vs proposed 102, both under
    /// the 1000 ceiling) holds — a ratio test (503/102 ≈ 5) would call
    /// this a tiny win and wrongly resend.
    #[test]
    fn optimization_holds_when_the_resend_wins_by_400() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        let mut fragmenter = Fragmenter::default();
        let mut out = Vec::new();
        let parse = |out: &mut Vec<Fragment>| -> TransportInstruction {
            let mut asm = FragmentAssembly::new();
            for f in out.drain(..) {
                if let Some(inst) = asm.add_fragment(f) {
                    return inst;
                }
            }
            panic!("no instruction assembled");
        };

        sender.current_state().push_bytes(&[b'y'; 398]);
        sender.tick(1, 120, 20, 1200, &mut fragmenter, &mut out);
        sender.tick(20, 120, 20, 1200, &mut fragmenter, &mut out);
        parse(&mut out);

        sender.current_state().push_bytes(&[b'z'; 96]);
        sender.tick(21, 120, 20, 1200, &mut fragmenter, &mut out);
        sender.tick(40, 120, 20, 1200, &mut fragmenter, &mut out);
        let inst = parse(&mut out);
        assert_eq!(inst.old_num, 1, "a 400-byte gap is not a small win");
        assert_eq!(inst.diff.len(), 102);
    }

    /// The shutdown retry counter, not just the wall clock, bounds the
    /// give-up: 16 shutdown sends (well inside ACTIVE_RETRY_TIMEOUT)
    /// must time out, while one send after a long healthy exchange
    /// must not.
    #[test]
    fn shutdown_retry_counter_bounds_the_timeout() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        let mut fragmenter = Fragmenter::default();
        let mut out = Vec::new();
        for i in 0..20u8 {
            sender.current_state().push_bytes(&[b'a' + i % 26]);
            sender.tick(20 * i as u64 + 1, 120, 20, 1200, &mut fragmenter, &mut out);
            sender.tick(
                20 * (i as u64 + 1),
                120,
                20,
                1200,
                &mut fragmenter,
                &mut out,
            );
        }
        out.clear();

        sender.start_shutdown(401);
        // one shutdown send: nowhere near the retry ceiling or the
        // wall-clock timeout
        sender.tick(420, 120, 20, 1200, &mut fragmenter, &mut out);
        assert!(!out.is_empty(), "the shutdown state goes out");
        assert!(
            !sender.shutdown_ack_timed_out(430),
            "one try after a healthy exchange must not time out"
        );

        // drive the retry cadence (every interval) to the ceiling well
        // inside ACTIVE_RETRY_TIMEOUT
        for t in (440..=720u64).step_by(20) {
            sender.tick(t, 120, 20, 1200, &mut fragmenter, &mut out);
        }
        assert!(
            sender.shutdown_ack_timed_out(721),
            "SHUTDOWN_RETRIES shutdown sends must time out (721-401 = 320ms << ART)"
        );
    }

    /// set_current_state replaces the working state wholesale (the
    /// embedder's escape hatch from current_state() borrowing).
    #[test]
    fn set_current_state_replaces_the_working_state() {
        let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
        let mut fresh = UserStream::new();
        fresh.push_bytes(b"xyz");
        sender.set_current_state(fresh);
        assert_eq!(sender.current_state().events().len(), 3);

        let mut fragmenter = Fragmenter::default();
        let mut out = Vec::new();
        sender.tick(1, 120, 20, 1200, &mut fragmenter, &mut out);
        sender.tick(20, 120, 20, 1200, &mut fragmenter, &mut out);
        assert!(!out.is_empty(), "the replaced state must send");
    }
}
