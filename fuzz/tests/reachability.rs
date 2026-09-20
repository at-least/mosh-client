//! Reachability, as a check rather than a claim: the seed corpus must
//! actually drive the paths the fuzz targets exist for. Twice a
//! harness shipped with a path asserted reachable that nothing could
//! reach (a one-shot assembly that never reassembled; a chunk prefix
//! too small for an MTU fragment). This test runs the ssp_receive
//! harness body over every seed and asserts the counts.

use mosh_client::ssp::HostStreamState;
use mosh_client::{Fragment, FragmentAssembly, RecvOutcome, SspReceiver, UserStream};

#[test]
fn seeds_reach_assembly_reassembly_and_both_receivers() {
    let mut assembled = 0;
    let mut multi_fragment_completions = 0;
    let mut user_latest = 0;
    let mut host_latest = 0;

    for seed in mosh_client_fuzz::seeds() {
        let mut assembly = FragmentAssembly::new();
        let mut user_rx = SspReceiver::new(UserStream::new(), 0);
        let mut host_rx = SspReceiver::new(HostStreamState::new(), 0);
        let mut fragments_since_completion = 0;
        let mut pos = 0;
        while pos + 2 <= seed.len() {
            let len = u16::from_le_bytes([seed[pos], seed[pos + 1]]) as usize;
            pos += 2;
            if pos + len > seed.len() {
                break;
            }
            if let Ok(fragment) = Fragment::parse(&seed[pos..pos + len]) {
                fragments_since_completion += 1;
                if let Some(inst) = assembly.add_fragment(fragment) {
                    assembled += 1;
                    if fragments_since_completion >= 2 {
                        multi_fragment_completions += 1;
                    }
                    fragments_since_completion = 0;
                    if let Ok(RecvOutcome::Latest { .. }) = user_rx.process_instruction(&inst, 0) {
                        user_latest += 1;
                    }
                    if let Ok(RecvOutcome::Latest { .. }) = host_rx.process_instruction(&inst, 0) {
                        host_latest += 1;
                    }
                }
            }
            pos += len;
        }
    }

    assert!(
        assembled > 0,
        "seeds must assemble at least one instruction"
    );
    assert!(
        multi_fragment_completions > 0,
        "seeds must complete at least one MULTI-fragment reassembly"
    );
    assert!(
        user_latest > 0,
        "seeds must drive the UserStream receiver to a Latest outcome"
    );
    assert!(
        host_latest > 0,
        "seeds must drive the HostStreamState receiver to a Latest outcome"
    );
}
