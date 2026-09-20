//! The post-decrypt datagram bodies, as SEQUENCES: the input is
//! length-prefixed chunks ([len u8][bytes]...) fed to ONE persistent
//! assembly — so multi-fragment reassembly, duplicate and conflicting
//! retransmissions, id bumps, and hole resets (spec §4) are all
//! reachable, not just the single-fragment happy path.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosh_client::{Fragment, FragmentAssembly};

fuzz_target!(|data: &[u8]| {
    let mut assembly = FragmentAssembly::new();
    let mut pos = 0;
    while pos < data.len() {
        let len = data[pos] as usize;
        pos += 1;
        if pos + len > data.len() {
            break;
        }
        if let Ok(fragment) = Fragment::parse(&data[pos..pos + len]) {
            let _ = assembly.add_fragment(fragment);
        }
        pos += len;
    }
});
