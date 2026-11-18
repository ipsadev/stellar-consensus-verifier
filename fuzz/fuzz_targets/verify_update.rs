#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use stellar_consensus_verifier::verify::{verify_update, TrustRoot, UpdateEvidence};

#[derive(Deserialize)]
struct Router {
    slot: u64,
    envelopes: Vec<String>,
    quorum_sets: Vec<String>,
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

struct Baseline {
    network_id: [u8; 32],
    slot: u64,
    envelopes: Vec<Vec<u8>>,
    quorum_sets: Vec<Vec<u8>>,
    successor_envelopes: Vec<Vec<u8>>,
    successor_quorum_sets: Vec<Vec<u8>>,
    successor_tx_set: Vec<u8>,
    trust_root_xdr: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex in fixture"))
        .collect()
}

fn baseline() -> &'static Baseline {
    static BASELINE: OnceLock<Baseline> = OnceLock::new();

    BASELINE.get_or_init(|| {
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../tests/fixtures/testnet-router-chain.json"
        ))
        .expect("the committed fixture parses");

        Baseline {
            network_id: unhex(&fixture.network_id).try_into().expect("32 bytes"),
            slot: fixture.router.slot,
            envelopes: fixture.router.envelopes.iter().map(|s| unhex(s)).collect(),
            quorum_sets: fixture.router.quorum_sets.iter().map(|s| unhex(s)).collect(),
            successor_envelopes: fixture.successor.envelopes.iter().map(|s| unhex(s)).collect(),
            successor_quorum_sets: fixture
                .successor
                .quorum_sets
                .iter()
                .map(|s| unhex(s))
                .collect(),
            successor_tx_set: unhex(&fixture.successor.tx_set),
            trust_root_xdr: unhex(&fixture.local_quorum_set),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let baseline = baseline();

    let fingerprint: [u8; 32] = Sha256::digest(&baseline.trust_root_xdr).into();

    let Ok(trust_root) = TrustRoot::from_pinned(&baseline.trust_root_xdr, &fingerprint, 1) else {
        return;
    };

    let _ = verify_update(
        &trust_root,
        &UpdateEvidence {
            network_id: &baseline.network_id,
            slot: baseline.slot,
            header_xdr: data,
            envelopes_xdr: &baseline.envelopes,
            quorum_sets_xdr: &baseline.quorum_sets,
            successor_envelopes_xdr: &baseline.successor_envelopes,
            successor_quorum_sets_xdr: &baseline.successor_quorum_sets,
            successor_tx_set_xdr: &baseline.successor_tx_set,
        },
    );
});
