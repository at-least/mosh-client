//! Seed shapes shared by the generator example and the reachability
//! test: instructions encoded by the crate's own encoder, wrapped in
//! the sequence targets' 2-byte-LE length-prefixed chunk format.

use mosh_client::{
    Fragmenter, HostInstruction, HostMessage, SspSender, TransportInstruction, UserInstruction,
    UserMessage, UserStream, MOSH_PROTOCOL_VERSION, SHUTDOWN_NUM,
};

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

/// The chunk wrapper of the sequence targets: a u16 little-endian
/// length, then the bytes. u16 (not u8) so a full MTU-sized fragment
/// fits — that is the whole point.
pub fn prefix_chunk(bytes: &[u8]) -> Vec<u8> {
    let take = bytes.len().min(u16::MAX as usize);
    let mut out = Vec::with_capacity(2 + take);
    out.extend_from_slice(&(take as u16).to_le_bytes());
    out.extend_from_slice(&bytes[..take]);
    out
}

pub fn seeds() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();

    // raw schema bytes for the wire_decode corpus
    out.push(UserMessage::default().encode());
    out.push(user_diff(b"hi mosh\r"));
    out.push(HostMessage::default().encode());
    out.push(host_diff());

    // instructions: minimal, typical, shutdown, hostile-looking edges
    let minimal = inst(Vec::new(), 0, 0, 0, 0);
    out.push(minimal.encode());
    let typical = inst(user_diff(b"echo golden\r"), 0, 1, 1, 0);
    out.push(typical.encode());
    let shutdown = inst(Vec::new(), 3, SHUTDOWN_NUM, 4, 1);
    out.push(shutdown.encode());
    let host_inst = inst(host_diff(), 0, 1, 0, 0);
    out.push(host_inst.encode());

    // multi-fragment: 3KB of LCG output — genuinely incompressible,
    // so zlib stays above the 1190-byte MTU budget and slicing is forced
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
    out.push(big_inst.encode());

    // fragment-layer bytes for the sequence targets, wrapped as chunks
    let mut sequence = Vec::new();
    let mut fragmenter = Fragmenter::default();
    for i in [minimal, typical, shutdown, big_inst] {
        if let Ok(frags) = fragmenter.make_fragments(&i, 1200) {
            for f in frags {
                sequence.push(f.tostring());
            }
        }
    }
    for f in sender_shaped_fragments() {
        sequence.push(f);
    }
    for bytes in &sequence {
        out.push(prefix_chunk(bytes));
    }
    let mut all = Vec::new();
    for bytes in &sequence {
        all.extend(prefix_chunk(bytes));
    }
    out.push(all); // one whole exchange as a single sequence input
    out
}
