use serde::Deserialize;
use stellar_consensus_verifier::{
    primitives::scp::quorum::QuorumSet,
    verify::{bind_successor, verify_header, verify_router_root},
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
    header: String,
}

#[derive(Deserialize)]
struct Fixture {
    network_id: String,
    local_quorum_set: String,
    router: Router,
    successor: Successor,
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
    serde_json::from_str(include_str!("fixtures/testnet-router-chain.json")).expect("fixture")
}

// The whole typed pipeline on a real testnet ledger: authenticate both slots,
// pin the router ledger with its successor, then extract its router state root.
// verify_router_root only accepts an AuthenticatedHeader, so the un-pinned
// ValueBoundHeader from bind_header cannot reach it; that gate is a compile-time
// guarantee, not something this test can exercise at runtime.
#[test]
fn the_typed_pipeline_extracts_a_router_root_from_a_real_testnet_ledger() {
    let fx = fixture();
    let nid = h32(&fx.network_id);
    let local = QuorumSet::decode(&unhex(&fx.local_quorum_set)).expect("local quorum set");
    let r = &fx.router;
    let s = &fx.successor;

    assert_eq!(
        s.slot,
        r.slot + 1,
        "the fixture must carry consecutive ledgers"
    );

    let router_bound = verify_header(
        &nid,
        &local,
        r.slot,
        &hexvec(&r.envelopes),
        &hexvec(&r.quorum_sets),
        &unhex(&r.header),
    )
    .expect("the router ledger binds to consensus");

    let successor_bound = verify_header(
        &nid,
        &local,
        s.slot,
        &hexvec(&s.envelopes),
        &hexvec(&s.quorum_sets),
        &unhex(&s.header),
    )
    .expect("the successor ledger binds to consensus");

    let anchored = bind_successor(&router_bound, &successor_bound)
        .expect("the successor pins the router ledger's whole header");

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
