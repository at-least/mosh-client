//! The full hostile receive path: decrypted bytes → fragment →
//! assembly/inflate → SSP receiver — where a valid-framing instruction
//! with hostile field numbers (old/new/ack/throwaway) or a hostile
//! diff hits the idempotency rules and the state machines (spec §6.2,
//! §7).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosh_client::{Fragment, FragmentAssembly, SspReceiver, UserStream};

fuzz_target!(|data: &[u8]| {
    if let Ok(fragment) = Fragment::parse(data) {
        let mut assembly = FragmentAssembly::new();
        if let Some(inst) = assembly.add_fragment(fragment) {
            let mut receiver = SspReceiver::new(UserStream::new(), 0);
            let _ = receiver.process_instruction(&inst, 0);
        }
    }
});
