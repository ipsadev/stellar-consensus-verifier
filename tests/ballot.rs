use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use stellar_consensus_verifier::ballot::*;
use stellar_consensus_verifier::envelope::{Ballot, Confirm, Externalize, Prepare, Statement};
use stellar_consensus_verifier::error::ScpError;
use stellar_consensus_verifier::quorum::{NodeId, QuorumSet};

const NETWORK: [u8; 32] = [0x77; 32];
const SLOT: u64 = 4_160_279;

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn var_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = (value.len() as u32).to_be_bytes().to_vec();
    let pad = (4 - (value.len() % 4)) % 4;

    out.extend_from_slice(value);
    out.extend_from_slice(&vec![0u8; pad]);

    out
}

fn envelope_xdr(seed: u8, slot: u64, statement: &Statement, qset_hash: [u8; 32]) -> Vec<u8> {
    signed_by(seed, seed, slot, statement, qset_hash)
}

fn signed_by(
    node_seed: u8,
    signer_seed: u8,
    slot: u64,
    statement: &Statement,
    qset_hash: [u8; 32],
) -> Vec<u8> {
    let mut out = 0u32.to_be_bytes().to_vec();

    out.extend_from_slice(&node(node_seed));
    out.extend_from_slice(&slot.to_be_bytes());

    match statement {
        Statement::Prepare(p) => {
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&qset_hash);
            out.extend_from_slice(&p.ballot.counter.to_be_bytes());
            out.extend_from_slice(&var_bytes(&p.ballot.value));
            out.extend_from_slice(&1u32.to_be_bytes());
            out.extend_from_slice(&p.ballot.counter.to_be_bytes());
            out.extend_from_slice(&var_bytes(&p.ballot.value));
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&p.commit_counter.to_be_bytes());
            out.extend_from_slice(&p.highest_confirmed_ballot_counter.to_be_bytes());
        }
        Statement::Confirm(c) => {
            out.extend_from_slice(&1u32.to_be_bytes());
            out.extend_from_slice(&c.ballot.counter.to_be_bytes());
            out.extend_from_slice(&var_bytes(&c.ballot.value));
            out.extend_from_slice(&c.prepared_counter.to_be_bytes());
            out.extend_from_slice(&c.commit_counter.to_be_bytes());
            out.extend_from_slice(&c.highest_confirmed_ballot_counter.to_be_bytes());
            out.extend_from_slice(&qset_hash);
        }
        Statement::Externalize(e) => {
            out.extend_from_slice(&2u32.to_be_bytes());
            out.extend_from_slice(&e.commit.counter.to_be_bytes());
            out.extend_from_slice(&var_bytes(&e.commit.value));
            out.extend_from_slice(&e.highest_confirmed_ballot_counter.to_be_bytes());
            out.extend_from_slice(&qset_hash);
        }
    }

    let mut payload = NETWORK.to_vec();

    payload.extend_from_slice(&[0, 0, 0, 1]);
    payload.extend_from_slice(&out);
    let signature = signing_key(signer_seed).sign(&payload).to_bytes();

    out.extend_from_slice(&64u32.to_be_bytes());
    out.extend_from_slice(&signature);

    out
}

fn evidence(members: &[(u8, Statement)], qset: &QuorumSet) -> Vec<Authenticated> {
    let raw = encode_set(qset);
    let hash = QuorumSet::hash(&raw);
    let envelopes: Vec<Vec<u8>> = members
        .iter()
        .map(|(seed, statement)| envelope_xdr(*seed, SLOT, statement, hash))
        .collect();

    authenticate(&NETWORK, SLOT, &envelopes, &[raw]).expect("authenticates")
}

fn evidence_per_node(members: &[(u8, Statement)], qset: &QuorumSet) -> Vec<Authenticated> {
    let raw = encode_set(qset);
    let hash = QuorumSet::hash(&raw);

    members
        .iter()
        .flat_map(|(seed, statement)| {
            let envelope = envelope_xdr(*seed, SLOT, statement, hash);

            authenticate(
                &NETWORK,
                SLOT,
                core::slice::from_ref(&envelope),
                core::slice::from_ref(&raw),
            )
            .expect("authenticates")
        })
        .collect()
}

fn encode_set(qset: &QuorumSet) -> Vec<u8> {
    let mut out = qset.threshold.to_be_bytes().to_vec();

    out.extend_from_slice(&(qset.validators.len() as u32).to_be_bytes());
    for v in &qset.validators {
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(v);
    }
    out.extend_from_slice(&(qset.inner_sets.len() as u32).to_be_bytes());
    for inner in &qset.inner_sets {
        out.extend_from_slice(&encode_set(inner));
    }

    out
}

const VALUE: &[u8] = b"the value this ledger closed on";
const OTHER: &[u8] = b"a value the network never closed";

fn node(n: u8) -> NodeId {
    signing_key(n).verifying_key().to_bytes()
}

fn ballot(counter: u32, value: &[u8]) -> Ballot {
    Ballot {
        counter,
        value: value.to_vec(),
    }
}

fn confirm(commit: u32, highest: u32, value: &[u8]) -> Statement {
    confirm_under(commit, highest, value, [0x11; 32])
}

fn confirm_under(commit: u32, highest: u32, value: &[u8], hash: [u8; 32]) -> Statement {
    Statement::Confirm(Confirm {
        ballot: ballot(highest.max(commit), value),
        prepared_counter: commit,
        commit_counter: commit,
        highest_confirmed_ballot_counter: highest,
        quorum_set_hash: hash,
    })
}

fn externalize(counter: u32, highest: u32, value: &[u8]) -> Statement {
    Statement::Externalize(Externalize {
        commit: ballot(counter, value),
        highest_confirmed_ballot_counter: highest,
        commit_quorum_set_hash: [0x11; 32],
    })
}

fn prepare(commit: u32, highest: u32, value: &[u8]) -> Statement {
    Statement::Prepare(Prepare {
        quorum_set_hash: [0x11; 32],
        ballot: ballot(highest.max(1), value),
        prepared: Some(ballot(highest.max(1), value)),
        prepared_prime: None,
        commit_counter: commit,
        highest_confirmed_ballot_counter: highest,
    })
}

fn flat(validators: &[u8], threshold: u32) -> QuorumSet {
    QuorumSet {
        threshold,
        validators: validators.iter().map(|n| node(*n)).collect(),
        inner_sets: Vec::new(),
    }
}

#[test]
fn a_prepare_never_satisfies_the_commit_predicate() {
    assert!(!commit_predicate(
        &ballot(0, VALUE),
        (1, 1),
        &prepare(1, 1, VALUE)
    ));
}

#[test]
fn a_confirm_satisfies_the_predicate_only_when_its_range_contains_the_interval() {
    let b = ballot(0, VALUE);

    assert!(commit_predicate(&b, (2, 4), &confirm(2, 4, VALUE)));
    assert!(commit_predicate(&b, (3, 4), &confirm(2, 5, VALUE)));
    assert!(!commit_predicate(&b, (1, 4), &confirm(2, 4, VALUE)));
    assert!(!commit_predicate(&b, (2, 5), &confirm(2, 4, VALUE)));
    assert!(!commit_predicate(&b, (2, 4), &confirm(2, 4, OTHER)));
}

#[test]
fn an_externalize_satisfies_the_predicate_without_consulting_its_highest_counter() {
    let b = ballot(0, VALUE);

    assert!(commit_predicate(
        &b,
        (1, u32::MAX),
        &externalize(1, 1, VALUE)
    ));
    assert!(!commit_predicate(&b, (1, 1), &externalize(2, 2, VALUE)));
    assert!(!commit_predicate(&b, (1, 1), &externalize(1, 1, OTHER)));
}

#[test]
fn the_boundaries_come_from_every_compatible_statement() {
    let b = ballot(0, VALUE);
    let statements = [
        confirm(2, 5, VALUE),
        prepare(3, 7, VALUE),
        externalize(1, 9, VALUE),
        confirm(4, 4, OTHER),
    ];
    let refs: Vec<&Statement> = statements.iter().collect();

    assert_eq!(
        commit_boundaries(&b, &refs),
        vec![1, 2, 3, 5, 7, 9, u32::MAX]
    );
}

#[test]
fn a_prepare_with_no_commit_counter_contributes_no_boundaries() {
    let b = ballot(0, VALUE);
    let statements = [prepare(0, 7, VALUE)];
    let refs: Vec<&Statement> = statements.iter().collect();

    assert!(commit_boundaries(&b, &refs).is_empty());
}

#[test]
fn the_interval_search_takes_the_widest_interval_the_predicate_accepts() {
    let found = find_extended_interval(&[1, 2, 5, 9], |(low, high)| low >= 1 && high <= 5);

    assert_eq!(found, Some((1, 5)));
}

#[test]
fn the_interval_search_fixes_the_high_bound_before_extending_downwards() {
    let found = find_extended_interval(&[1, 2, 5, 9], |(low, high)| low <= 2 && high <= 5);

    assert_eq!(found, Some((1, 2)));
}

#[test]
fn the_interval_search_returns_nothing_when_no_boundary_works() {
    assert!(find_extended_interval(&[1, 2, 3], |_| false).is_none());
}

#[test]
fn a_quorum_of_confirm_statements_reaches_confirm_commit() {
    let local = flat(&[1, 2, 3, 4], 3);
    let members = [
        (1, confirm(1, 1, VALUE)),
        (2, confirm(1, 1, VALUE)),
        (3, confirm(1, 1, VALUE)),
    ];

    assert_eq!(
        confirmed_commit(&local, &evidence(&members, &local), VALUE),
        Some((1, 1))
    );
}

#[test]
fn a_v_blocking_set_of_confirm_statements_is_not_enough() {
    let local = flat(&[1, 2, 3, 4], 3);
    let members = [(1, confirm(1, 1, VALUE)), (2, confirm(1, 1, VALUE))];

    assert!(confirmed_commit(&local, &evidence(&members, &local), VALUE).is_none());
}

#[test]
fn confirm_ranges_that_do_not_overlap_do_not_confirm() {
    let local = flat(&[1, 2, 3, 4], 3);
    let members = [
        (1, confirm(1, 1, VALUE)),
        (2, confirm(3, 3, VALUE)),
        (3, confirm(5, 5, VALUE)),
    ];

    assert!(confirmed_commit(&local, &evidence(&members, &local), VALUE).is_none());
}

#[test]
fn an_externalize_is_counted_without_its_quorum_set_preimage() {
    let local = flat(&[1, 2, 3, 4], 3);
    let members = [
        (1, externalize(1, 1, VALUE)),
        (2, externalize(1, 1, VALUE)),
        (3, externalize(1, 1, VALUE)),
    ];
    let envelopes: Vec<Vec<u8>> = members
        .iter()
        .map(|(n, s)| envelope_xdr(*n, SLOT, s, [0x11; 32]))
        .collect();
    let evidence =
        authenticate(&NETWORK, SLOT, &envelopes, &[]).expect("an EXTERNALIZE needs no preimage");

    assert_eq!(
        confirmed_commit(&local, &evidence, VALUE),
        Some((1, u32::MAX))
    );
}

#[test]
fn a_confirm_without_its_quorum_set_preimage_is_dropped_not_refused() {
    let local = flat(&[1, 2, 3, 4], 3);
    let members = [
        (1, confirm(1, 1, VALUE)),
        (2, confirm(1, 1, VALUE)),
        (3, confirm(1, 1, VALUE)),
    ];
    let envelopes: Vec<Vec<u8>> = members
        .iter()
        .map(|(seed, s)| envelope_xdr(*seed, SLOT, s, [0x11; 32]))
        .collect();
    let evidence = authenticate(&NETWORK, SLOT, &envelopes, &[])
        .expect("stellar-core drops an unresolvable node rather than refusing the slot");

    assert_eq!(evidence.len(), 3);
    assert!(evidence.iter().all(|item| item.quorum_set().is_none()));
    assert!(confirmed_commit(&local, &evidence, VALUE).is_none());
}

#[test]
fn only_the_newest_statement_from_a_node_counts() {
    let local = flat(&[1, 2, 3, 4], 3);
    let members = [
        (1, prepare(1, 1, VALUE)),
        (1, externalize(1, 1, VALUE)),
        (1, confirm(1, 1, VALUE)),
        (2, confirm(1, 1, VALUE)),
    ];
    let latest = latest_statements(&evidence_per_node(&members, &local));

    assert_eq!(latest.len(), 2);
    assert!(latest[0].statement().as_externalize().is_some());
}

#[test]
fn a_newer_confirm_replaces_an_older_one() {
    let local = flat(&[1, 2, 3, 4], 3);
    let members = [(1, confirm(1, 1, VALUE)), (1, confirm(1, 4, VALUE))];
    let latest = latest_statements(&evidence_per_node(&members, &local));

    assert_eq!(latest.len(), 1);
    assert!(commit_predicate(
        &ballot(0, VALUE),
        (1, 4),
        latest[0].statement()
    ));
}

#[test]
fn an_older_statement_does_not_displace_a_newer_one() {
    let local = flat(&[1, 2, 3, 4], 3);
    let members = [(1, externalize(1, 1, VALUE)), (1, prepare(1, 1, VALUE))];
    let latest = latest_statements(&evidence_per_node(&members, &local));

    assert_eq!(latest.len(), 1);
    assert!(latest[0].statement().as_externalize().is_some());
}

#[test]
fn the_confirmed_value_is_returned_when_one_value_is_backed() {
    let local = flat(&[1, 2, 3, 4], 3);
    let members = [
        (1, confirm(1, 1, VALUE)),
        (2, confirm(1, 1, VALUE)),
        (3, confirm(1, 1, VALUE)),
        (4, confirm(1, 1, OTHER)),
    ];
    let value = confirmed_value(&local, &evidence(&members, &local)).expect("one value confirms");

    assert_eq!(value, VALUE);
}

#[test]
fn no_confirmed_value_is_an_error_rather_than_a_guess() {
    let local = flat(&[1, 2, 3, 4], 3);
    let members = [(1, confirm(1, 1, VALUE))];
    let err = confirmed_value(&local, &evidence(&members, &local)).expect_err("no quorum");

    assert_eq!(err, ScpError::NoConfirmedCommit);
}

#[test]
fn two_confirmed_values_are_reported_as_fork_evidence() {
    let local = flat(&[1, 2], 1);
    let both = QuorumSet {
        threshold: 1,
        validators: vec![node(1), node(2)],
        inner_sets: Vec::new(),
    };
    let members = [(1, confirm(1, 1, VALUE)), (2, confirm(1, 1, OTHER))];
    let err = confirmed_value(&local, &evidence(&members, &both)).expect_err("two values confirm");

    assert_eq!(err, ScpError::ForkedConfirmCommit);
}

#[test]
fn a_singleton_quorum_set_names_only_its_node() {
    let qset = singleton_quorum_set(node(7));

    assert_eq!(qset.threshold, 1);
    assert_eq!(qset.validators, vec![node(7)]);
    assert!(qset.inner_sets.is_empty());
}

#[test]
fn a_node_that_signs_twice_keeps_only_its_newest_statement() {
    let local = flat(&[1, 2, 3, 4], 3);
    let raw = encode_set(&local);
    let hash = QuorumSet::hash(&raw);
    let envelopes = vec![
        envelope_xdr(1, SLOT, &prepare(1, 1, VALUE), hash),
        envelope_xdr(1, SLOT, &externalize(1, 1, VALUE), hash),
    ];
    let evidence = authenticate(&NETWORK, SLOT, &envelopes, &[raw])
        .expect("stellar-core keeps the newest statement per node");
    let latest = latest_statements(&evidence);

    assert_eq!(evidence.len(), 2);
    assert_eq!(latest.len(), 1);
    assert!(latest[0].statement().as_externalize().is_some());
}

#[test]
fn a_repeated_node_cannot_inflate_a_quorum() {
    let local = flat(&[1, 2, 3, 4], 3);
    let raw = encode_set(&local);
    let hash = QuorumSet::hash(&raw);
    let statement = confirm(1, 1, VALUE);
    let envelopes = vec![
        envelope_xdr(1, SLOT, &statement, hash),
        envelope_xdr(1, SLOT, &statement, hash),
        envelope_xdr(1, SLOT, &statement, hash),
    ];
    let evidence = authenticate(&NETWORK, SLOT, &envelopes, &[raw]).expect("authenticates");

    assert!(confirmed_commit(&local, &evidence, VALUE).is_none());
}

#[test]
fn a_nomination_is_skipped_rather_than_refused() {
    let local = flat(&[1, 2, 3, 4], 3);
    let raw = encode_set(&local);
    let hash = QuorumSet::hash(&raw);
    let mut nomination = 0u32.to_be_bytes().to_vec();

    nomination.extend_from_slice(&node(1));
    nomination.extend_from_slice(&SLOT.to_be_bytes());
    nomination.extend_from_slice(&3u32.to_be_bytes());
    nomination.extend_from_slice(&hash);
    nomination.extend_from_slice(&0u32.to_be_bytes());
    nomination.extend_from_slice(&0u32.to_be_bytes());
    nomination.extend_from_slice(&64u32.to_be_bytes());
    nomination.extend_from_slice(&[0xcc; 64]);

    let envelopes = vec![
        envelope_xdr(1, SLOT, &confirm(1, 1, VALUE), hash),
        nomination,
        envelope_xdr(2, SLOT, &confirm(1, 1, VALUE), hash),
        envelope_xdr(3, SLOT, &confirm(1, 1, VALUE), hash),
    ];
    let evidence = authenticate(&NETWORK, SLOT, &envelopes, &[raw])
        .expect("nomination belongs to the other protocol and is routed away");

    assert_eq!(evidence.len(), 3);
    assert_eq!(confirmed_commit(&local, &evidence, VALUE), Some((1, 1)));
}

#[test]
fn a_signature_from_the_wrong_key_stops_authentication() {
    let local = flat(&[1, 2, 3, 4], 3);
    let raw = encode_set(&local);
    let hash = QuorumSet::hash(&raw);
    let envelopes = vec![signed_by(1, 9, SLOT, &confirm(1, 1, VALUE), hash)];
    let err = authenticate(&NETWORK, SLOT, &envelopes, &[raw])
        .expect_err("an unverified signature must not become evidence");

    assert!(matches!(err, ScpError::UnauthenticatedEnvelope { .. }));
}

#[test]
fn a_signature_over_another_network_stops_authentication() {
    let local = flat(&[1, 2, 3, 4], 3);
    let raw = encode_set(&local);
    let hash = QuorumSet::hash(&raw);
    let envelopes = vec![envelope_xdr(1, SLOT, &confirm(1, 1, VALUE), hash)];
    let err = authenticate(&[0x88; 32], SLOT, &envelopes, &[raw])
        .expect_err("the network id is inside the signed payload");

    assert!(matches!(err, ScpError::UnauthenticatedEnvelope { .. }));
}
