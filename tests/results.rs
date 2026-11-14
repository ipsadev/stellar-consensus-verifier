use serde::Deserialize;
use stellar_consensus_verifier::{
    error::ScpError,
    primitives::execution::results::{verify_state_root, Inputs},
};

#[derive(Deserialize)]
struct Fixture {
    tx_set_result_hash: String,
    result_pairs: Vec<String>,
    result_index: u32,
    success_preimage_xdr: String,
    router_contract_id: String,
    root_event_topic: String,
    expected_root: String,
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

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/testnet-router-root.json")).expect("fixture")
}

#[test]
fn verify_state_root_extracts_the_router_root_from_a_real_testnet_ledger() {
    let fx = fixture();
    let pairs: Vec<Vec<u8>> = fx.result_pairs.iter().map(|s| unhex(s)).collect();
    let tx_set_result_hash = h32(&fx.tx_set_result_hash);
    let router = h32(&fx.router_contract_id);
    let topic = unhex(&fx.root_event_topic);
    let preimage = unhex(&fx.success_preimage_xdr);

    let root = verify_state_root(&Inputs {
        tx_set_result_hash: &tx_set_result_hash,
        result_pairs: &pairs,
        result_index: fx.result_index,
        success_preimage_xdr: &preimage,
        router_contract_id: &router,
        root_event_topic: &topic,
    })
    .expect("the router's ibc_root event is extracted");

    assert_eq!(root, h32(&fx.expected_root));
}

#[test]
fn verify_state_root_rejects_a_tampered_result_set() {
    let fx = fixture();
    let mut pairs: Vec<Vec<u8>> = fx.result_pairs.iter().map(|s| unhex(s)).collect();
    pairs[0][0] ^= 0x01;
    let tx_set_result_hash = h32(&fx.tx_set_result_hash);
    let router = h32(&fx.router_contract_id);
    let topic = unhex(&fx.root_event_topic);
    let preimage = unhex(&fx.success_preimage_xdr);

    let err = verify_state_root(&Inputs {
        tx_set_result_hash: &tx_set_result_hash,
        result_pairs: &pairs,
        result_index: fx.result_index,
        success_preimage_xdr: &preimage,
        router_contract_id: &router,
        root_event_topic: &topic,
    })
    .expect_err("a flipped result pair must not hash to txSetResultHash");

    assert_eq!(err, ScpError::TxResultSetMismatch);
}

#[test]
fn verify_state_root_rejects_a_symbol_that_is_not_the_sole_topic() {
    // "recv_packet" really appears in this ledger, but as the first of three
    // topics on a different event. The fixed-layout rule requires the matched
    // topic to be the event's only one, so it must not be accepted as a root.
    let fx = fixture();
    let pairs: Vec<Vec<u8>> = fx.result_pairs.iter().map(|s| unhex(s)).collect();
    let tx_set_result_hash = h32(&fx.tx_set_result_hash);
    let router = h32(&fx.router_contract_id);
    let not_sole = b"recv_packet";
    let preimage = unhex(&fx.success_preimage_xdr);

    let err = verify_state_root(&Inputs {
        tx_set_result_hash: &tx_set_result_hash,
        result_pairs: &pairs,
        result_index: fx.result_index,
        success_preimage_xdr: &preimage,
        router_contract_id: &router,
        root_event_topic: not_sole,
    })
    .expect_err("a symbol that is not the event's only topic is not a root event");

    assert_eq!(err, ScpError::RouterEventMissing);
}

#[test]
fn verify_state_root_finds_no_root_for_a_different_router() {
    let fx = fixture();
    let pairs: Vec<Vec<u8>> = fx.result_pairs.iter().map(|s| unhex(s)).collect();
    let tx_set_result_hash = h32(&fx.tx_set_result_hash);
    let mut router = h32(&fx.router_contract_id);
    router[0] ^= 0x01;
    let topic = unhex(&fx.root_event_topic);
    let preimage = unhex(&fx.success_preimage_xdr);

    let err = verify_state_root(&Inputs {
        tx_set_result_hash: &tx_set_result_hash,
        result_pairs: &pairs,
        result_index: fx.result_index,
        success_preimage_xdr: &preimage,
        router_contract_id: &router,
        root_event_topic: &topic,
    })
    .expect_err("no ibc_root event from the wrong contract");

    assert_eq!(err, ScpError::RouterEventMissing);
}
