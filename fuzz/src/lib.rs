//! The fuzz harness bodies, shared with the reachability test so the
//! input format can never drift between what is fuzzed and what is
//! checked, plus the seed shapes the generator writes.

use mosh_client::ssp::HostStreamState;
use mosh_client::{
    Fragment, FragmentAssembly, Fragmenter, HostInstruction, HostMessage, RecvOutcome, SspReceiver,
    SspSender, TransportInstruction, UserInstruction, UserMessage, UserStream,
    MOSH_PROTOCOL_VERSION, SHUTDOWN_NUM,
};

// --- the shared harness bodies -------------------------------------------

/// What one `ssp_receive` input drove: fragments parsed, instructions
/// assembled (multi = completed by a fragment_num ≥ 1 fragment — the
/// actual reassembly property, not a fed-fragment proxy), and Latest
/// outcomes on each receiver.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct SspReceiveCounts {
    pub parsed_fragments: u32,
    pub assembled: u32,
    pub multi_fragment_completions: u32,
    pub user_latest: u32,
    pub host_latest: u32,
}

pub fn drive_ssp_receive(data: &[u8]) -> SspReceiveCounts {
    let mut counts = SspReceiveCounts::default();
    let mut assembly = FragmentAssembly::new();
    let mut user_rx = SspReceiver::new(UserStream::new(), 0);
    let mut host_rx = SspReceiver::new(HostStreamState::new(), 0);
    for fragment in parse_chunks(data) {
        counts.parsed_fragments += 1;
        let completing = fragment.fragment_num >= 1;
        if let Some(inst) = assembly.add_fragment(fragment) {
            counts.assembled += 1;
            if completing {
                counts.multi_fragment_completions += 1;
            }
            if let Ok(RecvOutcome::Latest { .. }) = user_rx.process_instruction(&inst, 0) {
                counts.user_latest += 1;
            }
            if let Ok(RecvOutcome::Latest { .. }) = host_rx.process_instruction(&inst, 0) {
                counts.host_latest += 1;
            }
        }
    }
    counts
}

/// The `fragment_assembly` harness body: parse + assembly only.
pub fn drive_fragment_assembly(data: &[u8]) -> (u32, u32, u32) {
    let (mut parsed, mut assembled, mut multi) = (0, 0, 0);
    let mut assembly = FragmentAssembly::new();
    for fragment in parse_chunks(data) {
        parsed += 1;
        let completing = fragment.fragment_num >= 1;
        if assembly.add_fragment(fragment).is_some() {
            assembled += 1;
            if completing {
                multi += 1;
            }
        }
    }
    (parsed, assembled, multi)
}

/// The sequence targets' input shape: 2-byte little-endian length-
/// prefixed fragments. u16 (not u8) so a full MTU-sized fragment fits
/// in one chunk — that is the whole point.
fn parse_chunks(data: &[u8]) -> impl Iterator<Item = Fragment> + '_ {
    let mut pos = 0;
    std::iter::from_fn(move || {
        while pos + 2 <= data.len() {
            let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if pos + len > data.len() {
                return None;
            }
            let bytes = &data[pos..pos + len];
            pos += len;
            if let Ok(fragment) = Fragment::parse(bytes) {
                return Some(fragment);
            }
        }
        None
    })
}

/// The `wire_decode` harness body: the three schema decoders on raw
/// bytes. Total on hostile input is the wire layer's contract (§5).
#[derive(Default, Debug, PartialEq, Eq)]
pub struct WireDecodeCounts {
    pub user: u32,
    pub host: u32,
    pub transport: u32,
}

pub fn drive_wire_decode(data: &[u8]) -> WireDecodeCounts {
    let mut counts = WireDecodeCounts::default();
    if mosh_client::UserMessage::decode(data).is_ok() {
        counts.user += 1;
    }
    if mosh_client::HostMessage::decode(data).is_ok() {
        counts.host += 1;
    }
    if mosh_client::TransportInstruction::decode(data).is_ok() {
        counts.transport += 1;
    }
    counts
}

// --- the seed shapes ------------------------------------------------------

fn user_diff(bytes: &[u8]) -> Vec<u8> {
    UserMessage {
        instructions: vec![UserInstruction::Keystroke(bytes.to_vec())],
    }
    .encode()
}

fn host_diff() -> Vec<u8> {
    HostMessage {
        instructions: vec![
            HostInstruction::HostBytes(b"\x1b[H\x1b[2Jgolden$ ".to_vec()),
            HostInstruction::Resize {
                width: 100,
                height: 30,
            },
            HostInstruction::EchoAck(4),
        ],
    }
    .encode()
}

fn inst(diff: Vec<u8>, old: u64, new: u64, ack: u64, throwaway: u64) -> TransportInstruction {
    TransportInstruction {
        protocol_version: MOSH_PROTOCOL_VERSION,
        old_num: old,
        new_num: new,
        ack_num: ack,
        throwaway_num: throwaway,
        diff,
        chaff: Vec::new(),
    }
}

/// A sender's own wire output — seeds straight from the engine. The
/// mindelay clock anchors at the first divergent tick, so the send
/// lands at back.timestamp + send_interval (t=20), not earlier.
fn sender_shaped_fragments() -> Vec<Vec<u8>> {
    let mut sender: SspSender<UserStream> = SspSender::new(UserStream::new(), 0, 1);
    let mut fragmenter = Fragmenter::default();
    let mut out = Vec::new();
    for chunk in [
        b"echo golden\r".as_slice(),
        b"\x7f".as_slice(),
        b"more\x1b[A".as_slice(),
    ] {
        sender.current_state().push_bytes(chunk);
    }
    let _ = sender.tick(1, 120, 20, 1200, &mut fragmenter, &mut out);
    let _ = sender.tick(20, 120, 20, 1200, &mut fragmenter, &mut out);
    out.iter().map(|f| f.tostring()).collect()
}

pub fn prefix_chunk(bytes: &[u8]) -> Vec<u8> {
    let take = bytes.len().min(u16::MAX as usize);
    let mut out = Vec::with_capacity(2 + take);
    out.extend_from_slice(&(take as u16).to_le_bytes());
    out.extend_from_slice(&bytes[..take]);
    out
}

/// Raw schema bytes for the `wire_decode` corpus.
pub fn wire_seeds() -> Vec<Vec<u8>> {
    vec![
        UserMessage::default().encode(),
        user_diff(b"hi mosh\r"),
        HostMessage::default().encode(),
        host_diff(),
        inst(Vec::new(), 0, 0, 0, 0).encode(),
        inst(user_diff(b"echo golden\r"), 0, 1, 1, 0).encode(),
        inst(Vec::new(), 3, SHUTDOWN_NUM, 4, 1).encode(),
        inst(host_diff(), 0, 1, 0, 0).encode(),
    ]
}

/// Chunked fragment sequences for the assembly/receive corpora. The
/// big diff is 3KB of LCG output — genuinely incompressible, so zlib
/// stays above the 1190-byte MTU budget and slicing is forced.
pub fn sequence_seeds() -> Vec<Vec<u8>> {
    let mut mix: u64 = 0x243F_6A88_85A3_08D3;
    let big: Vec<u8> = (0..3000)
        .map(|_| {
            mix = mix
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (mix >> 56) as u8
        })
        .collect();
    let big_inst = inst(big, 0, 1, 0, 0);

    let mut sequence = Vec::new();
    let mut fragmenter = Fragmenter::default();
    for i in [
        inst(Vec::new(), 0, 0, 0, 0),
        inst(user_diff(b"echo golden\r"), 0, 1, 1, 0),
        inst(Vec::new(), 3, SHUTDOWN_NUM, 4, 1),
        inst(host_diff(), 0, 1, 0, 0),
        big_inst,
    ] {
        if let Ok(frags) = fragmenter.make_fragments(&i, 1200) {
            for f in frags {
                sequence.push(f.tostring());
            }
        }
    }
    for f in sender_shaped_fragments() {
        sequence.push(f);
    }

    let mut out: Vec<Vec<u8>> = sequence.iter().map(|b| prefix_chunk(b)).collect();
    let mut all = Vec::new();
    for bytes in &sequence {
        all.extend(prefix_chunk(bytes));
    }
    out.push(all); // one whole exchange as a single sequence input
    out
}
