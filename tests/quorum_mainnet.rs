use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;
use stellar_consensus_verifier::quorum::QuorumSet;

#[derive(Deserialize)]
struct Archived {
    network: String,
    hash: String,
    xdr: String,
    threshold: u32,
    validators: usize,
    inner_sets: usize,
    total_validators: usize,
    depth: u32,
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/mainnet-quorum-sets.json")).expect("fixture")
}

fn total(qset: &QuorumSet) -> usize {
    qset.validators.len() + qset.inner_sets.iter().map(total).sum::<usize>()
}

fn depth(qset: &QuorumSet) -> u32 {
    qset.inner_sets
        .iter()
        .map(|inner| 1 + depth(inner))
        .max()
        .unwrap_or(0)
}

#[test]
fn every_archived_quorum_set_decodes_to_what_the_archive_recorded() {
    let f = fixture();

    assert!(!f.quorum_sets.is_empty());

    for a in &f.quorum_sets {
        let qset = QuorumSet::decode(&unhex(&a.xdr))
            .unwrap_or_else(|e| panic!("{} {} failed to decode: {e}", a.network, &a.hash[..8]));

        assert_eq!(qset.threshold, a.threshold, "{}", &a.hash[..8]);
        assert_eq!(qset.validators.len(), a.validators, "{}", &a.hash[..8]);
        assert_eq!(qset.inner_sets.len(), a.inner_sets, "{}", &a.hash[..8]);
        assert_eq!(total(&qset), a.total_validators, "{}", &a.hash[..8]);
        assert_eq!(depth(&qset), a.depth, "{}", &a.hash[..8]);
    }
}

#[test]
fn the_quorum_set_hash_is_plain_sha256_over_the_encoded_bytes() {
    for a in &fixture().quorum_sets {
        assert_eq!(
            hex(&QuorumSet::hash(&unhex(&a.xdr))),
            hex(&Sha256::digest(unhex(&a.xdr))),
            "stellar-core hashes with getHashOf, which adds no domain separation"
        );
    }
}

#[test]
fn every_archived_quorum_set_is_sane_as_a_peers_declared_set() {
    for a in &fixture().quorum_sets {
        let qset = QuorumSet::decode(&unhex(&a.xdr)).expect("decodes");

        qset.check_sane(false).unwrap_or_else(|e| {
            panic!("{} {} is not sane: {e}", a.network, &a.hash[..8]);
        });
    }
}

#[test]
fn the_extra_checks_are_strictly_stronger_than_what_the_network_ran() {
    let f = fixture();
    let refused: Vec<&Archived> = f
        .quorum_sets
        .iter()
        .filter(|a| {
            QuorumSet::decode(&unhex(&a.xdr))
                .expect("decodes")
                .check_sane(true)
                .is_err()
        })
        .collect();

    assert_eq!(
        refused.len(),
        1,
        "exactly one archived set is below its v-blocking size"
    );
    assert_eq!(refused[0].threshold, 2);
    assert_eq!(refused[0].validators, 4);
}

#[test]
fn no_archived_quorum_set_nests_more_than_one_level() {
    for a in &fixture().quorum_sets {
        assert!(
            a.depth <= 1,
            "{} nests {} levels; the nesting cap is only ever exercised synthetically",
            &a.hash[..8],
            a.depth
        );
    }
}

#[test]
fn a_flipped_byte_changes_the_quorum_set_hash() {
    for a in &fixture().quorum_sets {
        let mut raw = unhex(&a.xdr);

        raw[0] ^= 0x01;
        assert_ne!(hex(&QuorumSet::hash(&raw)), a.hash);
    }
}
