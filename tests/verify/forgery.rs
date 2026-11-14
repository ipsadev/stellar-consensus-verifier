use serde::Deserialize;
use sha2::{Digest, Sha256};
use stellar_consensus_verifier::{
    error::ScpError,
    primitives::stellar::header::LedgerHeader,
    verify::{bind_successor, verify_consensus, verify_header, TrustRoot},
};

#[derive(Deserialize)]
struct Router {
    slot: u64,
    envelopes: Vec<String>,
    quorum_sets: Vec<String>,
    header: String,
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

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn h32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}
fn hexvec(items: &[String]) -> Vec<Vec<u8>> {
    items.iter().map(|s| unhex(s)).collect()
}

#[test]
fn a_forged_header_is_not_authenticated_by_its_successor() {
    let fx: Fixture =
        serde_json::from_str(include_str!("../fixtures/testnet-router-chain.json")).unwrap();
    let nid = h32(&fx.network_id);
    let local_xdr = unhex(&fx.local_quorum_set);
    let fingerprint: [u8; 32] = Sha256::digest(&local_xdr).into();
    let local = TrustRoot::from_pinned(&local_xdr, &fingerprint).unwrap();
    let r = &fx.router;

    let mut header_n = unhex(&r.header);
    let real = LedgerHeader::decode(&header_n).unwrap();
    let off = 4 + 32 + real.scp_value_bytes.len();
    header_n[off..off + 32].copy_from_slice(&[0x66u8; 32]);
    assert_ne!(
        <[u8; 32]>::from(Sha256::digest(&header_n)),
        <[u8; 32]>::from(Sha256::digest(unhex(&r.header))),
        "the forgery must change the header hash"
    );

    let forged = verify_header(
        &nid,
        &local,
        r.slot,
        &hexvec(&r.envelopes),
        &hexvec(&r.quorum_sets),
        &header_n,
    )
    .expect("a forged-but-value-consistent header still value-binds");

    let successor = verify_consensus(
        &nid,
        &local,
        fx.successor.slot,
        &hexvec(&fx.successor.envelopes),
        &hexvec(&fx.successor.quorum_sets),
    )
    .unwrap();

    let err = bind_successor(&forged, &successor, &unhex(&fx.successor.tx_set))
        .expect_err("a forged header must not be authenticated");

    assert!(
        matches!(err, ScpError::ChainBroken { .. }),
        "expected the header-hash link to be refused, got {err:?}"
    );
}
