//! Seeds the fuzz corpora with real-shaped inputs: instructions
//! encoded by the crate's own encoder (valid fields, valid inner
//! diffs), single- and multi-fragment, engine-produced fragments, and
//! a full length-prefixed exchange for the sequence targets. Run:
//! `cargo run --manifest-path fuzz/Cargo.toml --example gen_seeds`

use std::fs;
use std::path::Path;

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

/// A sender's own wire output — seeds straight from the engine.
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
    // the mindelay clock anchors at the first divergent tick, so the
    // send lands at back.timestamp + send_interval (t=20), not earlier
    let _ = sender.tick(1, 120, 20, 1200, &mut fragmenter, &mut out);
    let _ = sender.tick(20, 120, 20, 1200, &mut fragmenter, &mut out);
    out.iter().map(|f| f.tostring()).collect()
}

fn seeds() -> Vec<Vec<u8>> {
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
    let host_inst = inst(host_diff(), 1, 2, 2, 1);
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

    // fragment-layer bytes for the sequence targets, wrapped as
    // length-prefixed chunks (their input shape)
    let mut sequence = Vec::new();
    let mut fragmenter = Fragmenter::default();
    for i in [
        minimal.clone(),
        typical.clone(),
        shutdown.clone(),
        big_inst.clone(),
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

fn prefix_chunk(bytes: &[u8]) -> Vec<u8> {
    let take = bytes.len().min(255);
    let mut out = Vec::with_capacity(1 + take);
    out.push(take as u8);
    out.extend_from_slice(&bytes[..take]);
    out
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let seeds = seeds();
    for target in ["wire_decode", "fragment_assembly", "ssp_receive"] {
        let dir = root.join(target);
        fs::create_dir_all(&dir).expect("corpus dir");
        for (i, seed) in seeds.iter().enumerate() {
            fs::write(dir.join(format!("seed-{i:02}")), seed).expect("seed write");
        }
        println!("{target}: {} seeds", seeds.len());
    }
}
