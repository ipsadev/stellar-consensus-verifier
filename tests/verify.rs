use serde::Deserialize;
use sha2::{Digest, Sha256};
use stellar_consensus_verifier::{
    error::ScpError,
    primitives::scp::quorum::QuorumSet,
    verify::{verify_consensus, verify_header},
};

const LIVE_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
const TEST_PASSPHRASE: &str = "Test SDF Network ; September 2015";

#[derive(Deserialize)]
struct Slot {
    network: String,
    slot: u64,
    local_quorum_set: String,
    quorum_sets: Vec<String>,
    envelopes: Vec<String>,
    expected_value: String,
}

#[derive(Deserialize)]
struct Slots {
    slots: Vec<Slot>,
}

#[derive(Deserialize)]
struct Archived {
    network: String,
    ledger_seq: u32,
    header: String,
}

#[derive(Deserialize)]
struct Headers {
    headers: Vec<Archived>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn slots() -> Slots {
    serde_json::from_str(include_str!("fixtures/mainnet-slots.json")).expect("slots fixture")
}

fn headers() -> Headers {
    serde_json::from_str(include_str!("fixtures/mainnet-ledger-headers.json"))
        .expect("headers fixture")
}

fn network_id(network: &str) -> [u8; 32] {
    let passphrase = if network == "live" {
        LIVE_PASSPHRASE
    } else {
        TEST_PASSPHRASE
    };

    Sha256::digest(passphrase.as_bytes()).into()
}

fn local_of(slot: &Slot) -> QuorumSet {
    QuorumSet::decode(&unhex(&slot.local_quorum_set)).expect("local quorum set")
}

fn header_for(slot: &Slot) -> Option<Vec<u8>> {
    headers()
        .headers
        .into_iter()
        .find(|a| a.network == slot.network && u64::from(a.ledger_seq) == slot.slot)
        .map(|a| unhex(&a.header))
}

#[test]
fn verify_consensus_verifies_sound_roots_and_refuses_weak_ones() {
    let mut sound = 0;

    for slot in &slots().slots {
        let local = local_of(slot);
        let result = verify_consensus(
            &network_id(&slot.network),
            &local,
            slot.slot,
            &slot.envelopes.iter().map(|s| unhex(s)).collect::<Vec<_>>(),
            &slot
                .quorum_sets
                .iter()
                .map(|s| unhex(s))
                .collect::<Vec<_>>(),
        );

        if local.check_sane(true).is_ok() {
            let confirmed =
                result.unwrap_or_else(|e| panic!("{} slot {}: {e}", slot.network, slot.slot));

            assert_eq!(
                confirmed.value_bytes(),
                unhex(&slot.expected_value).as_slice(),
                "{} slot {}",
                slot.network,
                slot.slot
            );
            assert_eq!(confirmed.slot(), slot.slot);
            sound += 1;
        } else {
            assert!(
                matches!(result, Err(ScpError::InvalidWire(_))),
                "{} slot {}: a sub-majority trust root must be refused by the strict gate",
                slot.network,
                slot.slot
            );
        }
    }

    assert!(
        sound > 0,
        "at least one fixture slot must carry a BFT-sound trust root"
    );
}

#[test]
fn verify_header_binds_the_value_to_its_ledger() {
    let mut checked = 0;

    for slot in &slots().slots {
        if local_of(slot).check_sane(true).is_err() {
            continue;
        }

        let Some(header_xdr) = header_for(slot) else {
            continue;
        };

        let bound = verify_header(
            &network_id(&slot.network),
            &local_of(slot),
            slot.slot,
            &slot.envelopes.iter().map(|s| unhex(s)).collect::<Vec<_>>(),
            &slot
                .quorum_sets
                .iter()
                .map(|s| unhex(s))
                .collect::<Vec<_>>(),
            &header_xdr,
        )
        .unwrap_or_else(|e| {
            panic!(
                "{} slot {} header did not bind: {e}",
                slot.network, slot.slot
            )
        });

        assert_eq!(bound.header().scp_value_bytes, unhex(&slot.expected_value));
        assert_eq!(u64::from(bound.header().ledger_seq), slot.slot);
        checked += 1;
    }

    assert!(
        checked > 0,
        "the fixtures must share at least one BFT-sound ledger for this to prove anything"
    );
}

#[test]
fn verify_header_rejects_a_header_from_another_ledger() {
    let slots = slots();
    let slot = slots
        .slots
        .iter()
        .find(|s| local_of(s).check_sane(true).is_ok())
        .expect("a BFT-sound slot to test the binding step rather than the trust-root gate");

    let wrong = headers()
        .headers
        .into_iter()
        .find(|a| a.network == slot.network && u64::from(a.ledger_seq) != slot.slot)
        .map(|a| unhex(&a.header))
        .expect("another ledger's header on the same network");

    let err = verify_header(
        &network_id(&slot.network),
        &local_of(slot),
        slot.slot,
        &slot.envelopes.iter().map(|s| unhex(s)).collect::<Vec<_>>(),
        &slot
            .quorum_sets
            .iter()
            .map(|s| unhex(s))
            .collect::<Vec<_>>(),
        &wrong,
    )
    .expect_err("a header from a different ledger must not bind");

    assert!(
        matches!(
            err,
            ScpError::HeaderSlotMismatch { .. } | ScpError::HeaderValueMismatch
        ),
        "a header from another ledger must be refused by the binding step, got {err:?}"
    );
}

#[test]
fn verify_consensus_refuses_an_unsound_trust_root() {
    let slots = slots();
    let slot = &slots.slots[0];

    let unsound = QuorumSet {
        threshold: 1,
        validators: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        inner_sets: Vec::new(),
    };

    let err = verify_consensus(
        &network_id(&slot.network),
        &unsound,
        slot.slot,
        &slot.envelopes.iter().map(|s| unhex(s)).collect::<Vec<_>>(),
        &slot
            .quorum_sets
            .iter()
            .map(|s| unhex(s))
            .collect::<Vec<_>>(),
    )
    .expect_err("a trust root below its v-blocking size must be refused");

    assert!(matches!(err, ScpError::InvalidWire(_)));
}
