//! Reachability, as a check rather than a claim: the seed corpus must
//! actually drive the paths the fuzz targets exist for, through the
//! SAME driver bodies the targets call. Twice a harness shipped with
//! a path asserted reachable that nothing could reach (a one-shot
//! assembly that never reassembled; a chunk prefix too small for an
//! MTU fragment).

#[test]
fn seeds_reach_assembly_reassembly_and_both_receivers() {
    let mut user_latest = 0;
    let mut host_latest = 0;
    let mut assembled = 0;
    let mut multi = 0;
    for seed in mosh_client_fuzz::sequence_seeds() {
        let counts = mosh_client_fuzz::drive_ssp_receive(&seed);
        assembled += counts.assembled;
        multi += counts.multi_fragment_completions;
        user_latest += counts.user_latest;
        host_latest += counts.host_latest;

        let (parsed, completed, seq_multi) = mosh_client_fuzz::drive_fragment_assembly(&seed);
        assert!(
            completed <= parsed,
            "cannot complete more instructions than fragments parsed"
        );
        assert_eq!(
            seq_multi, counts.multi_fragment_completions,
            "both drivers must agree on the reassembly property"
        );
    }

    assert!(
        assembled > 0,
        "seeds must assemble at least one instruction"
    );
    assert!(
        multi > 0,
        "seeds must complete at least one MULTI-fragment reassembly (completing fragment_num >= 1)"
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

/// The wire corpus must decode: every schema seed parses under its own
/// decoder (or the wire_decode target starts from nothing).
#[test]
fn wire_seeds_decode() {
    use mosh_client::{HostMessage, TransportInstruction, UserMessage};
    let mut user = 0;
    let mut host = 0;
    let mut transport = 0;
    for seed in mosh_client_fuzz::wire_seeds() {
        if UserMessage::decode(&seed).is_ok() {
            user += 1;
        }
        if HostMessage::decode(&seed).is_ok() {
            host += 1;
        }
        if TransportInstruction::decode(&seed).is_ok() {
            transport += 1;
        }
    }
    assert!(user > 0, "at least one UserMessage seed must decode");
    assert!(host > 0, "at least one HostMessage seed must decode");
    assert!(
        transport > 0,
        "at least one TransportInstruction seed must decode"
    );
}
