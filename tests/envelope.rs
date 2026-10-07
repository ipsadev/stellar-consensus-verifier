use stellar_consensus_verifier::{envelope::*, error::ScpError};

fn statement(kind: i32, value: &[u8]) -> Vec<u8> {
    ballot_statement(kind, value, 1, 1)
}

fn var_value(value: &[u8]) -> Vec<u8> {
    let mut out = (value.len() as u32).to_be_bytes().to_vec();
    let pad = (4 - (value.len() % 4)) % 4;

    out.extend_from_slice(value);
    out.extend_from_slice(&vec![0u8; pad]);

    out
}

fn ballot_statement(kind: i32, value: &[u8], counter: u32, highest: u32) -> Vec<u8> {
    let mut out = 0u32.to_be_bytes().to_vec();

    out.extend_from_slice(&[0xaau8; 32]);
    out.extend_from_slice(&4_160_279u64.to_be_bytes());
    out.extend_from_slice(&kind.to_be_bytes());

    match kind {
        SCP_ST_EXTERNALIZE => {
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&var_value(value));
            out.extend_from_slice(&highest.to_be_bytes());
            out.extend_from_slice(&[0xbbu8; 32]);
        }
        SCP_ST_CONFIRM => {
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&var_value(value));
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&[0xbbu8; 32]);
        }
        SCP_ST_PREPARE => {
            out.extend_from_slice(&[0xbbu8; 32]);
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&var_value(value));
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
        }
        _ => {
            out.extend_from_slice(&[0xbbu8; 32]);
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
        }
    }

    out
}

fn ballot_envelope(value: &[u8], counter: u32, highest: u32) -> Vec<u8> {
    let mut out = ballot_statement(SCP_ST_EXTERNALIZE, value, counter, highest);

    out.extend_from_slice(&64u32.to_be_bytes());
    out.extend_from_slice(&[0xccu8; 64]);

    out
}

fn envelope(kind: i32, value: &[u8]) -> (Vec<u8>, usize) {
    let stmt = statement(kind, value);
    let len = stmt.len();
    let mut out = stmt;

    out.extend_from_slice(&64u32.to_be_bytes());
    out.extend_from_slice(&[0xccu8; 64]);
    (out, len)
}

#[test]
fn an_externalize_envelope_decodes() {
    let value = [0x11u8; 152];
    let (raw, _) = envelope(SCP_ST_EXTERNALIZE, &value);
    let env = Envelope::decode(&raw).expect("decodes");

    assert_eq!(env.node_id, [0xaau8; 32]);
    assert_eq!(env.slot_index, 4_160_279);
    assert_eq!(env.externalize().unwrap().commit.counter, 1);
    assert_eq!(env.externalize().unwrap().commit.value, value.to_vec());
    assert_eq!(
        env.externalize().unwrap().commit_quorum_set_hash,
        [0xbbu8; 32]
    );
    assert_eq!(env.signature, [0xccu8; 64]);
}

#[test]
fn statement_bytes_are_the_exact_signed_slice() {
    let value = [0x11u8; 152];
    let (raw, stmt_len) = envelope(SCP_ST_EXTERNALIZE, &value);
    let env = Envelope::decode(&raw).expect("decodes");

    assert_eq!(env.statement_bytes, raw[..stmt_len].to_vec());
    assert_eq!(env.statement_bytes.len(), 244);
}

#[test]
fn a_value_needing_padding_keeps_the_span_exact() {
    let value = [0x11u8; 150];
    let (raw, stmt_len) = envelope(SCP_ST_EXTERNALIZE, &value);
    let env = Envelope::decode(&raw).expect("decodes");

    assert_eq!(env.externalize().unwrap().commit.value.len(), 150);
    assert_eq!(env.statement_bytes, raw[..stmt_len].to_vec());
}

#[test]
fn the_signing_payload_is_network_then_type_then_statement() {
    let (raw, stmt_len) = envelope(SCP_ST_EXTERNALIZE, &[0x11u8; 152]);
    let env = Envelope::decode(&raw).expect("decodes");
    let net = [0x77u8; 32];
    let payload = env.signing_payload(&net);

    assert_eq!(&payload[..32], &net);
    assert_eq!(&payload[32..36], &[0, 0, 0, 1]);
    assert_eq!(&payload[36..], &raw[..stmt_len]);
}

#[test]
fn the_other_ballot_protocol_statements_decode() {
    for kind in [SCP_ST_PREPARE, SCP_ST_CONFIRM] {
        let (raw, _) = envelope(kind, &[0x11u8; 152]);
        let env = Envelope::decode(&raw).expect("a ballot statement decodes");

        assert_eq!(env.statement.value(), &[0x11u8; 152]);
        assert_eq!(env.statement.quorum_set_hash(), [0xbbu8; 32]);
        assert_eq!(
            env.externalize().expect_err("not an EXTERNALIZE"),
            ScpError::NotExternalize
        );
    }
}

#[test]
fn a_nomination_is_refused() {
    let (raw, _) = envelope(SCP_ST_NOMINATE, &[]);
    let err = Envelope::decode(&raw).expect_err("nomination is a different protocol");

    assert_eq!(err, ScpError::NominationStatement);
}

#[test]
fn the_working_ballot_follows_stellar_core() {
    let (prepare, _) = envelope(SCP_ST_PREPARE, &[0x11u8; 152]);
    let (confirm, _) = envelope(SCP_ST_CONFIRM, &[0x11u8; 152]);
    let (externalize, _) = envelope(SCP_ST_EXTERNALIZE, &[0x11u8; 152]);

    assert_eq!(
        Envelope::decode(&prepare)
            .unwrap()
            .statement
            .working_ballot()
            .counter,
        1
    );
    assert_eq!(
        Envelope::decode(&confirm)
            .unwrap()
            .statement
            .working_ballot()
            .counter,
        1
    );
    assert_eq!(
        Envelope::decode(&externalize)
            .unwrap()
            .statement
            .working_ballot()
            .counter,
        1
    );
}

#[test]
fn an_unknown_statement_type_is_refused() {
    let (raw, _) = envelope(9, &[]);

    assert!(Envelope::decode(&raw).is_err());
}

#[test]
fn trailing_bytes_after_the_signature_are_refused() {
    let (mut raw, _) = envelope(SCP_ST_EXTERNALIZE, &[0x11u8; 152]);

    raw.push(0);
    assert!(Envelope::decode(&raw).is_err());
}

#[test]
fn a_commit_ballot_with_counter_zero_is_refused() {
    let raw = ballot_envelope(&[0x11u8; 152], 0, 0);
    let err = Envelope::decode(&raw).expect_err("stellar-core requires commit.counter > 0");

    assert_eq!(err, ScpError::CommitCounterZero);
}

#[test]
fn a_highest_confirmed_counter_below_the_commit_counter_is_refused() {
    let raw = ballot_envelope(&[0x11u8; 152], 4, 3);
    let err = Envelope::decode(&raw).expect_err("stellar-core requires nH >= commit.counter");

    assert_eq!(
        err,
        ScpError::HighestConfirmedBelowCommit {
            highest: 3,
            commit: 4,
        }
    );
}

#[test]
fn a_highest_confirmed_counter_equal_to_the_commit_counter_is_accepted() {
    let raw = ballot_envelope(&[0x11u8; 152], 4, 4);
    let env = Envelope::decode(&raw).expect("nH == commit.counter is sane");

    assert_eq!(env.externalize().unwrap().commit.counter, 4);
    assert_eq!(
        env.externalize().unwrap().highest_confirmed_ballot_counter,
        4
    );
}

#[test]
fn the_highest_confirmed_counter_may_sit_at_the_ceiling() {
    let raw = ballot_envelope(&[0x11u8; 152], 1, u32::MAX);
    let env = Envelope::decode(&raw).expect("stellar-core writes UINT32_MAX when externalizing");

    assert_eq!(
        env.externalize().unwrap().highest_confirmed_ballot_counter,
        u32::MAX
    );
}

#[test]
fn an_empty_commit_value_is_refused() {
    let raw = ballot_envelope(&[], 1, 1);
    let err = Envelope::decode(&raw).expect_err("an empty value is never a StellarValue");

    assert_eq!(err, ScpError::EmptyCommitValue);
}
