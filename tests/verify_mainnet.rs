use serde::Deserialize;
use stellar_consensus_verifier::{
    error::ScpError,
    primitives::scp::quorum::QuorumSet,
    verify::{bind_successor, verify_header, walk_back, ValueBoundHeader},
};

#[derive(Deserialize)]
struct Ledger {
    slot: u64,
    quorum_sets: Vec<String>,
    envelopes: Vec<String>,
    header: String,
}

#[derive(Deserialize)]
struct PriorHeader {
    slot: u64,
    header: String,
}

#[derive(Deserialize)]
struct Fixture {
    network_id: String,
    local_quorum_set: String,
    ledgers: Vec<Ledger>,
    prior_header: PriorHeader,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hexvec(items: &[String]) -> Vec<Vec<u8>> {
    items.iter().map(|s| unhex(s)).collect()
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/mainnet-consecutive.json")).expect("fixture")
}

fn network_id(fx: &Fixture) -> [u8; 32] {
    unhex(&fx.network_id)
        .try_into()
        .expect("32-byte network id")
}

fn bound(fx: &Fixture, nid: &[u8; 32], local: &QuorumSet, l: &Ledger) -> ValueBoundHeader {
    let _ = fx;
    verify_header(
        nid,
        local,
        l.slot,
        &hexvec(&l.envelopes),
        &hexvec(&l.quorum_sets),
        &unhex(&l.header),
    )
    .unwrap_or_else(|e| panic!("ledger {} did not bind: {e}", l.slot))
}

#[test]
fn bind_successor_pins_a_header_with_the_next_slot() {
    let fx = fixture();
    let nid = network_id(&fx);
    let local = QuorumSet::decode(&unhex(&fx.local_quorum_set)).expect("local quorum set");

    let a = &fx.ledgers[0];
    let b = &fx.ledgers[1];
    assert_eq!(
        b.slot,
        a.slot + 1,
        "the fixture must carry two consecutive ledgers"
    );

    let value_bound_a = bound(&fx, &nid, &local, a);
    let value_bound_b = bound(&fx, &nid, &local, b);

    let anchored = bind_successor(&value_bound_a, &value_bound_b)
        .expect("the next slot names this header as its predecessor");

    assert_eq!(u64::from(anchored.header().ledger_seq), a.slot);
    assert_eq!(
        anchored.header().ledger_hash,
        value_bound_a.header().ledger_hash
    );
}

#[test]
fn bind_successor_rejects_a_non_successor() {
    let fx = fixture();
    let nid = network_id(&fx);
    let local = QuorumSet::decode(&unhex(&fx.local_quorum_set)).expect("local quorum set");

    let value_bound_a = bound(&fx, &nid, &local, &fx.ledgers[0]);
    let value_bound_b = bound(&fx, &nid, &local, &fx.ledgers[1]);

    let err = bind_successor(&value_bound_b, &value_bound_a)
        .expect_err("ledger N does not follow ledger N+1");

    assert!(
        matches!(err, ScpError::SuccessorNotNext { .. }),
        "expected a successor-order error, got {err:?}"
    );
}

#[test]
fn walk_back_reaches_an_older_ledger_from_an_authenticated_anchor() {
    let fx = fixture();
    let nid = network_id(&fx);
    let local = QuorumSet::decode(&unhex(&fx.local_quorum_set)).expect("local quorum set");

    let anchor = bind_successor(
        &bound(&fx, &nid, &local, &fx.ledgers[0]),
        &bound(&fx, &nid, &local, &fx.ledgers[1]),
    )
    .expect("the anchor is authenticated by its successor");

    let prior = unhex(&fx.prior_header.header);
    let descending: Vec<&[u8]> = vec![&prior];

    let reached = walk_back(&anchor, &descending, fx.prior_header.slot as u32)
        .expect("the anchor's predecessor is reached by the chain");

    assert_eq!(u64::from(reached.header().ledger_seq), fx.prior_header.slot);
}
