//! The post-decrypt datagram body: fragment framing, zlib inflation,
//! and the transport-instruction decode of the inflated bytes — the
//! whole §4 path a hostile plaintext exercises before SSP ever sees it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosh_client::{Fragment, FragmentAssembly};

fuzz_target!(|data: &[u8]| {
    if let Ok(fragment) = Fragment::parse(data) {
        let mut assembly = FragmentAssembly::new();
        let _ = assembly.add_fragment(fragment);
    }
    // torn tails (a truncated datagram must fail the same way)
    if data.len() > 1 {
        if let Ok(fragment) = Fragment::parse(&data[..data.len() - 1]) {
            let mut assembly = FragmentAssembly::new();
            let _ = assembly.add_fragment(fragment);
        }
    }
});
