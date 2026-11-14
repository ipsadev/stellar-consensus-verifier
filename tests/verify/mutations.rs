use serde::Deserialize;
use sha2::{Digest, Sha256};
use stellar_consensus_verifier::{
    error::ScpError,
    primitives::stellar::header::LedgerHeader,
    verify::{verify_update, TrustRoot, UpdateEvidence},
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
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn h32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

fn hexvec(items: &[String]) -> Vec<Vec<u8>> {
    items.iter().map(|s| unhex(s)).collect()
}

#[derive(Clone)]
struct Evidence {
    network_id: [u8; 32],
    slot: u64,
    header: Vec<u8>,
    envelopes: Vec<Vec<u8>>,
    quorum_sets: Vec<Vec<u8>>,
    successor_envelopes: Vec<Vec<u8>>,
    successor_quorum_sets: Vec<Vec<u8>>,
    successor_tx_set: Vec<u8>,
    trust_root_xdr: Vec<u8>,
}

impl Evidence {
    fn baseline() -> Self {
        let fx: Fixture =
            serde_json::from_str(include_str!("../fixtures/testnet-router-chain.json"))
                .expect("fixture");

        Self {
            network_id: h32(&fx.network_id),
            slot: fx.router.slot,
            header: unhex(&fx.router.header),
            envelopes: hexvec(&fx.router.envelopes),
            quorum_sets: hexvec(&fx.router.quorum_sets),
            successor_envelopes: hexvec(&fx.successor.envelopes),
            successor_quorum_sets: hexvec(&fx.successor.quorum_sets),
            successor_tx_set: unhex(&fx.successor.tx_set),
            trust_root_xdr: unhex(&fx.local_quorum_set),
        }
    }

    fn run(&self) -> Result<(), ScpError> {
        let fingerprint: [u8; 32] = Sha256::digest(&self.trust_root_xdr).into();
        let root = TrustRoot::from_pinned(&self.trust_root_xdr, &fingerprint)?;

        verify_update(
            &root,
            &UpdateEvidence {
                network_id: &self.network_id,
                slot: self.slot,
                header_xdr: &self.header,
                envelopes_xdr: &self.envelopes,
                quorum_sets_xdr: &self.quorum_sets,
                successor_envelopes_xdr: &self.successor_envelopes,
                successor_quorum_sets_xdr: &self.successor_quorum_sets,
                successor_tx_set_xdr: &self.successor_tx_set,
            },
        )
        .map(|_| ())
    }
}

fn strangers_quorum_set() -> Vec<u8> {
    let mut out = 3u32.to_be_bytes().to_vec();

    out.extend_from_slice(&3u32.to_be_bytes());

    for seed in [0xa1u8, 0xa2, 0xa3] {
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&[seed; 32]);
    }

    out.extend_from_slice(&0u32.to_be_bytes());

    out
}

fn flip_inside_scp_value(evidence: &mut Evidence) {
    let header = LedgerHeader::decode(&evidence.header).expect("the baseline header decodes");

    let position = evidence
        .header
        .windows(header.scp_value_bytes.len())
        .position(|window| window == header.scp_value_bytes.as_slice())
        .expect("the signed value is a run of bytes inside the header");

    evidence.header[position] ^= 0x01;
}

#[test]
fn the_unmutated_update_authenticates() {
    assert!(
        Evidence::baseline().run().is_ok(),
        "the baseline fixture must authenticate, or the mutations below prove nothing"
    );
}

#[test]
fn every_attack_on_the_update_is_rejected() {
    type Mutate = fn(&mut Evidence);

    let attacks: &[(&str, Mutate)] = &[
        ("wrong network", |e| e.network_id[0] ^= 0x01),
        ("wrong slot", |e| e.slot += 1),
        ("tampered signed value", flip_inside_scp_value),
        ("tampered previous-ledger hash", |e| e.header[4] ^= 0x01),
        ("foreign trust root", |e| {
            e.trust_root_xdr = strangers_quorum_set()
        }),
        ("no envelopes", |e| e.envelopes.clear()),
        ("no successor envelopes", |e| e.successor_envelopes.clear()),
        ("tampered successor tx set", |e| {
            e.successor_tx_set[40] ^= 0x01
        }),
    ];

    for (name, mutate) in attacks {
        let mut evidence = Evidence::baseline();

        mutate(&mut evidence);

        assert!(
            evidence.run().is_err(),
            "{name}: verify_update accepted a mutated update"
        );
    }
}

#[test]
fn a_duplicated_envelope_is_redundant_not_fatal() {
    let mut evidence = Evidence::baseline();

    evidence.envelopes.push(evidence.envelopes[0].clone());

    assert!(
        evidence.run().is_ok(),
        "a repeated envelope adds no information; core accepts the ledger a quorum still externalized"
    );
}
