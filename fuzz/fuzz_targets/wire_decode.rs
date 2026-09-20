//! The three proto2-subset schemas, decoded on arbitrary bytes — total
//! on hostile input is the wire layer's contract (spec §5). The body
//! lives in the crate lib, shared with the reachability test.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mosh_client_fuzz::drive_wire_decode(data);
});
