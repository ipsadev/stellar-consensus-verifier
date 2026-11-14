use serde::Deserialize;
use sha2::{Digest, Sha256};
use stellar_consensus_verifier::{
    error::ScpError,
    verify::{verify_consensus, verify_header, TrustRoot},
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

fn hexvec(items: &[String]) -> Vec<Vec<u8>> {
    items.iter().map(|s| unhex(s)).collect()
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

fn trust_root(slot: &Slot) -> Result<TrustRoot, ScpError> {
    let xdr = unhex(&slot.local_quorum_set);
    let fingerprint: [u8; 32] = Sha256::digest(&xdr).into();

    TrustRoot::from_pinned(&xdr, &fingerprint)
}

fn header_for(slot: &Slot) -> Option<Vec<u8>> {
    headers()
        .headers
        .into_iter()
        .find(|a| a.network == slot.network && u64::from(a.ledger_seq) == slot.slot)
        .map(|a| unhex(&a.header))
}

#[test]
fn a_pinned_sound_root_verifies_and_a_weak_one_is_refused_at_pinning() {
    let mut sound = 0;

    for slot in &slots().slots {
        match trust_root(slot) {
            Ok(root) => {
                let confirmed = verify_consensus(
                    &network_id(&slot.network),
                    &root,
                    slot.slot,
                    &hexvec(&slot.envelopes),
                    &hexvec(&slot.quorum_sets),
                )
                .unwrap_or_else(|e| panic!("{} slot {}: {e}", slot.network, slot.slot));

                assert_eq!(
                    confirmed.value_bytes(),
                    unhex(&slot.expected_value).as_slice()
                );
                assert_eq!(confirmed.slot(), slot.slot);
                sound += 1;
            }
            Err(e) => assert!(
                matches!(e, ScpError::InvalidWire(_)),
                "{} slot {}: a sub-majority trust root must be refused when pinned",
                slot.network,
                slot.slot
            ),
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
        let Ok(root) = trust_root(slot) else {
            continue;
        };
        let Some(header_xdr) = header_for(slot) else {
            continue;
        };

        let bound = verify_header(
            &network_id(&slot.network),
            &root,
            slot.slot,
            &hexvec(&slot.envelopes),
            &hexvec(&slot.quorum_sets),
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
        assert_eq!(bound.network_id(), &network_id(&slot.network));
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
        .find(|s| trust_root(s).is_ok())
        .expect("a BFT-sound slot to test the binding step rather than the trust-root gate");
    let root = trust_root(slot).unwrap();

    let wrong = headers()
        .headers
        .into_iter()
        .find(|a| a.network == slot.network && u64::from(a.ledger_seq) != slot.slot)
        .map(|a| unhex(&a.header))
        .expect("another ledger's header on the same network");

    let err = verify_header(
        &network_id(&slot.network),
        &root,
        slot.slot,
        &hexvec(&slot.envelopes),
        &hexvec(&slot.quorum_sets),
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
fn from_pinned_refuses_a_quorum_set_that_is_not_the_pinned_one() {
    let slots = slots();
    let slot = slots
        .slots
        .iter()
        .find(|s| trust_root(s).is_ok())
        .expect("a BFT-sound slot");

    let xdr = unhex(&slot.local_quorum_set);
    let err = TrustRoot::from_pinned(&xdr, &[0u8; 32])
        .expect_err("a quorum set that does not match the pinned fingerprint is refused");

    assert_eq!(err, ScpError::TrustRootFingerprintMismatch);
}
