use stellar_consensus_verifier::{
    error::ScpError,
    primitives::{
        execution::results::{verify_result_set_hash, MAX_RESULT_PAIRS},
        scp::envelope::{authenticate, MAX_ENVELOPES, MAX_QUORUM_SETS},
    },
};

#[test]
fn authenticate_rejects_too_many_envelopes() {
    let envelopes = vec![Vec::new(); MAX_ENVELOPES + 1];

    let err =
        authenticate(&[0u8; 32], 1, &envelopes, &[]).expect_err("too many envelopes is refused");

    assert_eq!(
        err,
        ScpError::InputTooLarge {
            what: "envelopes",
            limit: MAX_ENVELOPES,
        }
    );
}

#[test]
fn authenticate_rejects_too_many_quorum_sets() {
    let quorum_sets = vec![Vec::new(); MAX_QUORUM_SETS + 1];

    let err = authenticate(&[0u8; 32], 1, &[], &quorum_sets)
        .expect_err("too many quorum sets is refused");

    assert_eq!(
        err,
        ScpError::InputTooLarge {
            what: "quorum sets",
            limit: MAX_QUORUM_SETS,
        }
    );
}

#[test]
fn verify_result_set_hash_rejects_too_many_pairs() {
    let pairs = vec![Vec::new(); MAX_RESULT_PAIRS + 1];

    let err =
        verify_result_set_hash(&pairs, &[0u8; 32]).expect_err("too many result pairs is refused");

    assert_eq!(
        err,
        ScpError::InputTooLarge {
            what: "result pairs",
            limit: MAX_RESULT_PAIRS,
        }
    );
}
