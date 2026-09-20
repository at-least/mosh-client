//! The full hostile receive path: chunked fragments into one assembly,
//! every assembled instruction into BOTH receivers — the server-side
//! UserStream and the client-side HostStreamState. One input carries a
//! whole hostile exchange (reference states, throwaways, out-of-order
//! inserts, duplicates, spec §6.2). The body lives in the crate lib,
//! shared with the reachability test.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mosh_client_fuzz::drive_ssp_receive(data);
});
