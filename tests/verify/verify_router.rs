use serde::Deserialize;
use sha2::{Digest, Sha256};
use stellar_consensus_verifier::{
    error::ScpError,
    primitives::stellar::{chain::MAX_WALK_BACK_STEPS, txset::MAX_TRANSACTION_SET_BYTES},
    verify::{
        bind_successor, verify_consensus, verify_header, verify_router_root, verify_update,
        walk_back, ConfirmedValue, TrustRoot, UpdateEvidence,
    },
};

#[derive(Deserialize)]
struct Router {
    slot: u64,
    envelopes: Vec<String>,
    quorum_sets: Vec<String>,
    header: String,
    result_pairs: Vec<String>,
    result_index: u32,
    success_preimage_xdr: String,
    router_contract_id: String,
    root_event_topic: String,
    expected_root: String,
}

#[derive(Deserialize)]
struct Successor {
    slot: u64,
    envelopes: Vec<String>,
    quorum_sets: Vec<String>,
    tx_set: String,
}

#[derive(Deserialize)]
struct Fixture {
    network_id: String,
    local_quorum_set: String,
    router: Router,
    successor: Successor,
}

#[derive(Deserialize)]
struct MainnetValue {
    network_id: String,
    local_quorum_set: String,
    slot: u64,
    header: String,
    envelopes: Vec<String>,
    quorum_sets: Vec<String>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn h32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

fn hexvec(items: &[String]) -> Vec<Vec<u8>> {
    items.iter().map(|s| unhex(s)).collect()
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("../fixtures/testnet-router-chain.json")).expect("fixture")
}

fn trust_root(fx: &Fixture) -> TrustRoot {
    let xdr = unhex(&fx.local_quorum_set);
    let fingerprint: [u8; 32] = Sha256::digest(&xdr).into();

    TrustRoot::from_pinned(&xdr, &fingerprint).expect("pinned sound trust root")
}

fn successor_value(fx: &Fixture, nid: &[u8; 32], local: &TrustRoot) -> ConfirmedValue {
    verify_consensus(
        nid,
        local,
        fx.successor.slot,
        &hexvec(&fx.successor.envelopes),
        &hexvec(&fx.successor.quorum_sets),
    )
    .expect("the successor's value is confirmed")
}

#[test]
fn the_typed_pipeline_extracts_a_router_root_from_a_real_testnet_ledger() {
    let fx = fixture();
    let nid = h32(&fx.network_id);
    let local = trust_root(&fx);
    let r = &fx.router;

    let router_bound = verify_header(
        &nid,
        &local,
        r.slot,
        &hexvec(&r.envelopes),
        &hexvec(&r.quorum_sets),
        &unhex(&r.header),
    )
    .expect("the router ledger binds to consensus");

    let anchored = bind_successor(
        &router_bound,
        &successor_value(&fx, &nid, &local),
        &unhex(&fx.successor.tx_set),
    )
    .expect("the successor's transaction set pins the router ledger");

    let router_id = h32(&r.router_contract_id);

    let verified = verify_router_root(
        &anchored,
        &hexvec(&r.result_pairs),
        r.result_index,
        &unhex(&r.success_preimage_xdr),
        &router_id,
        &unhex(&r.root_event_topic),
    )
    .expect("the router's ibc_root is extracted from an authenticated header");

    assert_eq!(verified.root(), &h32(&r.expected_root));
    assert_eq!(verified.ledger_seq(), r.slot as u32);
    assert_eq!(verified.router_id(), &router_id);
}

#[test]
fn verify_update_authenticates_the_router_ledger_in_one_call() {
    let fx = fixture();
    let nid = h32(&fx.network_id);
    let local = trust_root(&fx);
    let r = &fx.router;

    let header = unhex(&r.header);
    let envelopes = hexvec(&r.envelopes);
    let quorum_sets = hexvec(&r.quorum_sets);
    let successor_envelopes = hexvec(&fx.successor.envelopes);
    let successor_quorum_sets = hexvec(&fx.successor.quorum_sets);
    let successor_tx_set = unhex(&fx.successor.tx_set);

    let anchored = verify_update(
        &local,
        &UpdateEvidence {
            network_id: &nid,
            slot: r.slot,
            header_xdr: &header,
            envelopes_xdr: &envelopes,
            quorum_sets_xdr: &quorum_sets,
            successor_envelopes_xdr: &successor_envelopes,
            successor_quorum_sets_xdr: &successor_quorum_sets,
            successor_tx_set_xdr: &successor_tx_set,
        },
    )
    .expect("the router ledger authenticates end to end");

    let router_id = h32(&r.router_contract_id);
    let verified = verify_router_root(
        &anchored,
        &hexvec(&r.result_pairs),
        r.result_index,
        &unhex(&r.success_preimage_xdr),
        &router_id,
        &unhex(&r.root_event_topic),
    )
    .expect("the router root extracts from the one-call anchor");

    assert_eq!(verified.root(), &h32(&r.expected_root));
    assert_eq!(verified.ledger_seq(), r.slot as u32);
}

#[test]
fn verify_update_rejects_reusing_the_ledger_evidence_for_its_successor() {
    let fx = fixture();
    let nid = h32(&fx.network_id);
    let local = trust_root(&fx);
    let r = &fx.router;

    let header = unhex(&r.header);
    let envelopes = hexvec(&r.envelopes);
    let quorum_sets = hexvec(&r.quorum_sets);
    let successor_tx_set = unhex(&fx.successor.tx_set);

    let err = verify_update(
        &local,
        &UpdateEvidence {
            network_id: &nid,
            slot: r.slot,
            header_xdr: &header,
            envelopes_xdr: &envelopes,
            quorum_sets_xdr: &quorum_sets,
            successor_envelopes_xdr: &envelopes,
            successor_quorum_sets_xdr: &quorum_sets,
            successor_tx_set_xdr: &successor_tx_set,
        },
    )
    .expect_err("ledger N's envelopes are not evidence for the next slot");

    assert_eq!(
        err,
        ScpError::EnvelopeSlotMismatch {
            expected: r.slot + 1,
            found: r.slot,
        }
    );
}

#[test]
fn verify_update_rejects_the_wrong_network() {
    let fx = fixture();
    let local = trust_root(&fx);
    let r = &fx.router;

    let header = unhex(&r.header);
    let envelopes = hexvec(&r.envelopes);
    let quorum_sets = hexvec(&r.quorum_sets);
    let successor_envelopes = hexvec(&fx.successor.envelopes);
    let successor_quorum_sets = hexvec(&fx.successor.quorum_sets);
    let successor_tx_set = unhex(&fx.successor.tx_set);

    let err = verify_update(
        &local,
        &UpdateEvidence {
            network_id: &[0u8; 32],
            slot: r.slot,
            header_xdr: &header,
            envelopes_xdr: &envelopes,
            quorum_sets_xdr: &quorum_sets,
            successor_envelopes_xdr: &successor_envelopes,
            successor_quorum_sets_xdr: &successor_quorum_sets,
            successor_tx_set_xdr: &successor_tx_set,
        },
    )
    .expect_err("evidence does not verify under the wrong network");

    assert!(matches!(err, ScpError::UnauthenticatedEnvelope { .. }));
}

#[test]
fn bind_successor_rejects_a_tampered_successor_tx_set() {
    let fx = fixture();
    let nid = h32(&fx.network_id);
    let local = trust_root(&fx);

    let router_bound = verify_header(
        &nid,
        &local,
        fx.router.slot,
        &hexvec(&fx.router.envelopes),
        &hexvec(&fx.router.quorum_sets),
        &unhex(&fx.router.header),
    )
    .expect("the router ledger binds");

    let mut tx_set = unhex(&fx.successor.tx_set);
    tx_set[40] ^= 0x01;

    let err = bind_successor(&router_bound, &successor_value(&fx, &nid, &local), &tx_set)
        .expect_err("a transaction set that no longer hashes to the signed value is refused");

    assert_eq!(err, ScpError::SuccessorTxSetMismatch);
}

#[test]
fn bind_successor_rejects_a_successor_from_another_network() {
    let mn: MainnetValue = serde_json::from_str(include_str!("../fixtures/mainnet-value.json"))
        .expect("mainnet fixture");
    let mn_nid = h32(&mn.network_id);
    let mn_xdr = unhex(&mn.local_quorum_set);
    let mn_fingerprint: [u8; 32] = Sha256::digest(&mn_xdr).into();
    let mn_root = TrustRoot::from_pinned(&mn_xdr, &mn_fingerprint).expect("mainnet trust root");

    let mainnet_bound = verify_header(
        &mn_nid,
        &mn_root,
        mn.slot,
        &hexvec(&mn.envelopes),
        &hexvec(&mn.quorum_sets),
        &unhex(&mn.header),
    )
    .expect("the mainnet ledger value-binds");

    let fx = fixture();
    let successor = successor_value(&fx, &h32(&fx.network_id), &trust_root(&fx));

    let err = bind_successor(&mainnet_bound, &successor, &unhex(&fx.successor.tx_set))
        .expect_err("a successor from a different network is refused");

    assert_eq!(err, ScpError::NetworkMismatch);
}

#[test]
fn bind_successor_rejects_an_oversized_transaction_set() {
    let fx = fixture();
    let nid = h32(&fx.network_id);
    let local = trust_root(&fx);
    let r = &fx.router;

    let router_bound = verify_header(
        &nid,
        &local,
        r.slot,
        &hexvec(&r.envelopes),
        &hexvec(&r.quorum_sets),
        &unhex(&r.header),
    )
    .expect("the router ledger binds");

    let oversized = vec![0u8; MAX_TRANSACTION_SET_BYTES + 1];

    let err = bind_successor(
        &router_bound,
        &successor_value(&fx, &nid, &local),
        &oversized,
    )
    .expect_err("an oversized transaction set is refused");

    assert!(matches!(
        err,
        ScpError::InputTooLarge {
            what: "transaction set",
            ..
        }
    ));
}

#[test]
fn walk_back_rejects_too_long_a_span() {
    let fx = fixture();
    let nid = h32(&fx.network_id);
    let local = trust_root(&fx);
    let r = &fx.router;

    let header = unhex(&r.header);
    let envelopes = hexvec(&r.envelopes);
    let quorum_sets = hexvec(&r.quorum_sets);
    let successor_envelopes = hexvec(&fx.successor.envelopes);
    let successor_quorum_sets = hexvec(&fx.successor.quorum_sets);
    let successor_tx_set = unhex(&fx.successor.tx_set);

    let anchor = verify_update(
        &local,
        &UpdateEvidence {
            network_id: &nid,
            slot: r.slot,
            header_xdr: &header,
            envelopes_xdr: &envelopes,
            quorum_sets_xdr: &quorum_sets,
            successor_envelopes_xdr: &successor_envelopes,
            successor_quorum_sets_xdr: &successor_quorum_sets,
            successor_tx_set_xdr: &successor_tx_set,
        },
    )
    .expect("anchor authenticates");

    let target = anchor.header().ledger_seq - (MAX_WALK_BACK_STEPS as u32 + 1);

    let err = walk_back(&anchor, &[], target).expect_err("too long a walk-back span is refused");

    assert!(matches!(
        err,
        ScpError::InputTooLarge {
            what: "walk-back steps",
            ..
        }
    ));
}
