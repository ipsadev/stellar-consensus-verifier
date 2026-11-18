use serde::Deserialize;
use sha2::{Digest, Sha256};
use stellar_consensus_verifier::{error::ScpError, verify::TrustRoot};

#[derive(Deserialize)]
struct Archived {
    network: String,
    xdr: String,
    threshold: u32,
    inner_sets: usize,
}

#[derive(Deserialize)]
struct Fixture {
    quorum_sets: Vec<Archived>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("../fixtures/mainnet-quorum-sets.json")).expect("fixture")
}

fn node(n: u8) -> [u8; 32] {
    [n; 32]
}

fn qset_xdr(threshold: u32, validators: &[[u8; 32]], inner: &[Vec<u8>]) -> Vec<u8> {
    let mut out = threshold.to_be_bytes().to_vec();

    out.extend_from_slice(&(validators.len() as u32).to_be_bytes());

    for v in validators {
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(v);
    }

    out.extend_from_slice(&(inner.len() as u32).to_be_bytes());

    for i in inner {
        out.extend_from_slice(i);
    }

    out
}

fn pin(xdr: &[u8]) -> [u8; 32] {
    Sha256::digest(xdr).into()
}

fn pinned(xdr: &[u8], min_orgs: usize) -> Result<TrustRoot, ScpError> {
    TrustRoot::from_pinned(xdr, &pin(xdr), min_orgs)
}

#[test]
fn a_one_of_one_root_is_refused() {
    let xdr = qset_xdr(1, &[node(1)], &[]);

    assert_eq!(
        pinned(&xdr, 2).unwrap_err(),
        ScpError::TrustRootTooFewOrgs { have: 1, need: 2 },
        "a single-validator root is not a distributed trust root"
    );
}

#[test]
fn a_two_of_three_root_is_refused_below_the_required_org_count() {
    let xdr = qset_xdr(2, &[node(1), node(2), node(3)], &[]);

    assert_eq!(
        pinned(&xdr, 4).unwrap_err(),
        ScpError::TrustRootTooFewOrgs { have: 3, need: 4 },
        "three orgs is below a caller that demands four"
    );
}

#[test]
fn a_top_level_threshold_below_two_thirds_is_refused() {
    let validators = [node(1), node(2), node(3), node(4), node(5)];
    let xdr = qset_xdr(3, &validators, &[]);

    assert_eq!(
        pinned(&xdr, 1).unwrap_err(),
        ScpError::TrustRootThresholdBelowTwoThirds {
            threshold: 3,
            entries: 5,
        },
        "three of five is a strict majority but below two thirds"
    );
}

#[test]
fn the_testnet_tier_one_root_passes() {
    let testnet = fixture()
        .quorum_sets
        .into_iter()
        .find(|q| q.network == "test")
        .expect("a testnet quorum set");

    assert_eq!(testnet.threshold, 2);

    let xdr = unhex(&testnet.xdr);

    pinned(&xdr, 3).expect("the testnet 2-of-3 tier-1 root passes with a three-org floor");
}

#[test]
fn the_mainnet_tier_one_root_passes_despite_a_sub_two_thirds_org() {
    let mainnet = fixture()
        .quorum_sets
        .into_iter()
        .find(|q| q.network == "live" && q.threshold == 5 && q.inner_sets == 7)
        .expect("a mainnet 5-of-7 root");

    let xdr = unhex(&mainnet.xdr);

    pinned(&xdr, 4).expect(
        "the mainnet 5-of-7 root passes: an org that is internally 3-of-5 does not sink it",
    );
}

#[test]
fn the_fingerprint_is_checked_before_the_floor() {
    let xdr = qset_xdr(1, &[node(1)], &[]);

    assert_eq!(
        TrustRoot::from_pinned(&xdr, &[0u8; 32], 2).unwrap_err(),
        ScpError::TrustRootFingerprintMismatch,
        "a wrong fingerprint is refused before the floor is reached"
    );
}
