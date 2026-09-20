//! The post-decrypt datagram bodies, as SEQUENCES fed to ONE
//! persistent assembly — multi-fragment reassembly, duplicate and
//! conflicting retransmissions, id bumps, hole resets (spec §4). The
//! body lives in the crate lib, shared with the reachability test.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mosh_client_fuzz::drive_fragment_assembly(data);
});
