//! The full hostile receive path, as SEQUENCES: 2-byte-LE
//! length-prefixed fragments feed one persistent assembly, and every
//! assembled instruction hits BOTH receivers — the server-side
//! UserStream and the client-side HostStreamState (HostMessage decode,
//! the event log, echo-ack merging). One input can carry a whole
//! hostile exchange: reference states, throwaways, out-of-order
//! inserts, duplicates (spec §6.2).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosh_client::ssp::HostStreamState;
use mosh_client::{Fragment, FragmentAssembly, SspReceiver, UserStream};

fuzz_target!(|data: &[u8]| {
    let mut assembly = FragmentAssembly::new();
    let mut user_rx = SspReceiver::new(UserStream::new(), 0);
    let mut host_rx = SspReceiver::new(HostStreamState::new(), 0);
    let mut pos = 0;
    while pos + 2 <= data.len() {
        let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + len > data.len() {
            break;
        }
        if let Ok(fragment) = Fragment::parse(&data[pos..pos + len]) {
            if let Some(inst) = assembly.add_fragment(fragment) {
                let _ = user_rx.process_instruction(&inst, 0);
                let _ = host_rx.process_instruction(&inst, 0);
            }
        }
        pos += len;
    }
});
