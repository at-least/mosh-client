//! The three proto2-subset schemas, decoded on arbitrary bytes.
//! Total on hostile input is the wire layer's contract (spec §5).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosh_client::{HostMessage, TransportInstruction, UserMessage};

fuzz_target!(|data: &[u8]| {
    let _ = TransportInstruction::decode(data);
    let _ = UserMessage::decode(data);
    let _ = HostMessage::decode(data);
});
