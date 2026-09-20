//! The post-decrypt datagram bodies, as SEQUENCES: the input is
//! 2-byte-LE length-prefixed chunks fed to ONE persistent assembly —
//! so multi-fragment reassembly, duplicate and conflicting
//! retransmissions, id bumps, and hole resets (spec §4) are all
//! reachable, not just the single-fragment happy path. The u16 prefix
//! matters: an MTU-sized fragment must fit in one chunk.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosh_client::{Fragment, FragmentAssembly};

fuzz_target!(|data: &[u8]| {
    let mut assembly = FragmentAssembly::new();
    let mut pos = 0;
    while pos + 2 <= data.len() {
        let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + len > data.len() {
            break;
        }
        if let Ok(fragment) = Fragment::parse(&data[pos..pos + len]) {
            let _ = assembly.add_fragment(fragment);
        }
        pos += len;
    }
});
