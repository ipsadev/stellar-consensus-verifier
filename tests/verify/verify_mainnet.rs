use serde::Deserialize;
use sha2::{Digest, Sha256};
use stellar_consensus_verifier::verify::{verify_header, TrustRoot};

#[derive(Deserialize)]
struct Fixture {
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
    serde_json::from_str(include_str!("../fixtures/mainnet-value.json")).expect("fixture")
}

#[test]
fn a_real_mainnet_ledger_authenticates_and_value_binds() {
    let fx = fixture();
    let nid = h32(&fx.network_id);

    let local_xdr = unhex(&fx.local_quorum_set);
    let fingerprint: [u8; 32] = Sha256::digest(&local_xdr).into();
    let root = TrustRoot::from_pinned(&local_xdr, &fingerprint).expect("pinned sound trust root");

    let bound = verify_header(
        &nid,
        &root,
        fx.slot,
        &hexvec(&fx.envelopes),
        &hexvec(&fx.quorum_sets),
        &unhex(&fx.header),
    )
    .expect("the mainnet ledger authenticates and binds to its value");

    assert_eq!(u64::from(bound.header().ledger_seq), fx.slot);
    assert_eq!(bound.network_id(), &nid);
}
