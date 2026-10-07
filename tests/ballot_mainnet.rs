use serde::Deserialize;
use sha2::{Digest, Sha256};
use stellar_consensus_verifier::{
    ballot::{authenticate, confirmed_commit, confirmed_value, Authenticated},
    envelope::Envelope,
    error::ScpError,
    quorum::QuorumSet,
};

const LIVE_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
const TEST_PASSPHRASE: &str = "Test SDF Network ; September 2015";

#[derive(Deserialize)]
struct Slot {
    network: String,
    closed: String,
    slot: u64,
    local_quorum_set: String,
    quorum_sets: Vec<String>,
    envelopes: Vec<String>,
    expected_value: String,
    expected_interval: (u32, u32),
    externalize_only_confirms: bool,
}

#[derive(Deserialize)]
struct Fixture {
    slots: Vec<Slot>,
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
    serde_json::from_str(include_str!("fixtures/mainnet-slots.json")).expect("fixture")
}

fn network_id(network: &str) -> [u8; 32] {
    let passphrase = if network == "live" {
        LIVE_PASSPHRASE
    } else {
        TEST_PASSPHRASE
    };

    Sha256::digest(passphrase.as_bytes()).into()
}

fn parts(slot: &Slot) -> (QuorumSet, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let local = QuorumSet::decode(&unhex(&slot.local_quorum_set)).expect("local quorum set");
    let sets = slot.quorum_sets.iter().map(|s| unhex(s)).collect();
    let envelopes = slot.envelopes.iter().map(|s| unhex(s)).collect();

    (local, sets, envelopes)
}

fn evidence(slot: &Slot) -> Vec<Authenticated> {
    let (_, sets, envelopes) = parts(slot);

    authenticate(&network_id(&slot.network), slot.slot, &envelopes, &sets).unwrap_or_else(|e| {
        panic!(
            "{} slot {} ({}) failed to authenticate: {e}",
            slot.network, slot.slot, slot.closed
        )
    })
}

#[test]
fn every_archived_envelope_carries_a_signature_that_verifies() {
    let f = fixture();

    assert_eq!(f.slots.len(), 8);

    for slot in &f.slots {
        let authenticated = evidence(slot);

        assert_eq!(authenticated.len(), slot.envelopes.len());
    }
}

#[test]
fn a_tampered_envelope_cannot_be_authenticated() {
    for slot in &fixture().slots {
        let (_, sets, mut envelopes) = parts(slot);
        let target = envelopes
            .iter()
            .position(|raw| {
                stellar_consensus_verifier::envelope::Envelope::decode(raw)
                    .expect("decodes")
                    .externalize()
                    .is_ok()
            })
            .expect("every archived slot carries an EXTERNALIZE");
        let last_statement_byte = envelopes[target].len() - 69;

        envelopes[target][last_statement_byte] ^= 0x01;
        let err = authenticate(&network_id(&slot.network), slot.slot, &envelopes, &sets)
            .expect_err("a tampered statement must not authenticate");

        assert!(
            matches!(err, ScpError::UnauthenticatedEnvelope { .. }),
            "slot {} gave {err}",
            slot.slot
        );
    }
}

#[test]
fn an_envelope_from_another_network_cannot_be_authenticated() {
    for slot in fixture().slots.iter().filter(|s| s.network == "live") {
        let (_, sets, envelopes) = parts(slot);
        let err = authenticate(&network_id("test"), slot.slot, &envelopes, &sets)
            .expect_err("the network id is inside the signed payload");

        assert!(matches!(err, ScpError::UnauthenticatedEnvelope { .. }));
    }
}

#[test]
fn an_envelope_for_another_slot_is_refused() {
    for slot in &fixture().slots {
        let (_, sets, envelopes) = parts(slot);
        let err = authenticate(&network_id(&slot.network), slot.slot + 1, &envelopes, &sets)
            .expect_err("the slot must match");

        assert!(matches!(err, ScpError::EnvelopeSlotMismatch { .. }));
    }
}

#[test]
fn every_archived_slot_reaches_confirm_commit() {
    for slot in &fixture().slots {
        let (local, _, _) = parts(slot);
        let value = unhex(&slot.expected_value);
        let interval = confirmed_commit(&local, &evidence(slot), &value).unwrap_or_else(|| {
            panic!(
                "{} slot {} ({}) does not reach confirm commit",
                slot.network, slot.slot, slot.closed
            )
        });

        assert_eq!(
            interval, slot.expected_interval,
            "{} slot {} ({})",
            slot.network, slot.slot, slot.closed
        );
    }
}

#[test]
fn the_confirmed_value_is_the_one_the_ledger_closed_on() {
    for slot in &fixture().slots {
        let (local, _, _) = parts(slot);
        let value = confirmed_value(&local, &evidence(slot)).unwrap_or_else(|e| {
            panic!("{} slot {} ({}): {e}", slot.network, slot.slot, slot.closed)
        });

        assert_eq!(hex(&value), slot.expected_value, "slot {}", slot.slot);
    }
}

#[test]
fn the_ballot_protocol_reaches_slots_externalize_alone_cannot() {
    let f = fixture();
    let unreachable: Vec<&Slot> = f
        .slots
        .iter()
        .filter(|s| !s.externalize_only_confirms)
        .collect();

    assert_eq!(
        unreachable.len(),
        5,
        "the archive holds one EXTERNALIZE per slot before November 2023"
    );

    for slot in unreachable {
        let (local, sets, envelopes) = parts(slot);
        let value = unhex(&slot.expected_value);
        let all = evidence(slot);
        let only: Vec<Vec<u8>> = envelopes
            .iter()
            .filter(|raw| {
                stellar_consensus_verifier::envelope::Envelope::decode(raw)
                    .expect("decodes")
                    .externalize()
                    .is_ok()
            })
            .cloned()
            .collect();
        let externalize_only = authenticate(&network_id(&slot.network), slot.slot, &only, &sets)
            .expect("authenticates");

        assert!(
            confirmed_commit(&local, &externalize_only, &value).is_none(),
            "slot {} ({}) should not confirm from EXTERNALIZE alone",
            slot.slot,
            slot.closed
        );
        assert!(
            confirmed_commit(&local, &all, &value).is_some(),
            "slot {} ({}) should confirm once CONFIRM evidence is counted",
            slot.slot,
            slot.closed
        );
    }
}

#[test]
fn a_value_no_one_committed_never_confirms() {
    for slot in &fixture().slots {
        let (local, _, _) = parts(slot);
        let mut value = unhex(&slot.expected_value);

        value[0] ^= 0x01;
        assert!(
            confirmed_commit(&local, &evidence(slot), &value).is_none(),
            "slot {} must not confirm a value no node committed",
            slot.slot
        );
    }
}

#[test]
fn dropping_evidence_below_a_quorum_stops_the_confirmation() {
    for slot in fixture().slots.iter().filter(|s| s.envelopes.len() > 3) {
        let (local, _, _) = parts(slot);
        let value = unhex(&slot.expected_value);
        let mut shrinking = evidence(slot);

        while !shrinking.is_empty() {
            shrinking.pop();

            if confirmed_commit(&local, &shrinking, &value).is_none() {
                break;
            }
        }

        assert!(
            confirmed_commit(&local, &shrinking, &value).is_none(),
            "slot {} confirmed with every statement removed",
            slot.slot
        );
    }
}

#[test]
fn every_named_quorum_set_hash_resolves_to_a_supplied_preimage() {
    let mut bindings = 0;

    for slot in &fixture().slots {
        let (_, sets, envelopes) = parts(slot);

        for raw in &envelopes {
            let envelope = Envelope::decode(raw).expect("decodes");

            if envelope.externalize().is_ok() {
                continue;
            }

            let named = envelope.statement.quorum_set_hash();
            let matching = sets
                .iter()
                .filter(|preimage| QuorumSet::hash(preimage) == named)
                .count();

            assert_eq!(
                matching,
                1,
                "{} slot {}: the hash node {} signed resolves to {matching} preimages",
                slot.network,
                slot.slot,
                hex(&envelope.node_id)
            );
            bindings += 1;
        }
    }

    assert!(
        bindings > 0,
        "the fixture must carry statements whose quorum set is actually consulted"
    );
}

#[test]
fn a_tampered_quorum_set_preimage_stops_the_confirmation() {
    for slot in fixture()
        .slots
        .iter()
        .filter(|s| !s.externalize_only_confirms)
    {
        let (local, mut sets, envelopes) = parts(slot);

        for preimage in sets.iter_mut() {
            preimage[0] ^= 0x01;
        }

        let evidence = authenticate(&network_id(&slot.network), slot.slot, &envelopes, &sets)
            .expect("a node whose quorum set will not resolve is dropped, not refused");
        let value = unhex(&slot.expected_value);

        assert!(
            confirmed_commit(&local, &evidence, &value).is_none(),
            "slot {} confirmed without any resolvable quorum set",
            slot.slot
        );
    }
}

#[test]
fn an_externalize_quorum_set_hash_is_never_authenticated() {
    for slot in fixture()
        .slots
        .iter()
        .filter(|s| s.externalize_only_confirms)
    {
        let (local, _, envelopes) = parts(slot);
        let value = unhex(&slot.expected_value);
        let evidence = authenticate(&network_id(&slot.network), slot.slot, &envelopes, &[])
            .expect("stellar-core substitutes a singleton and never reads the named hash");

        assert!(confirmed_commit(&local, &evidence, &value).is_some());

        for item in &evidence {
            let qset = item.quorum_set().expect("an EXTERNALIZE always resolves");

            assert_eq!(qset.validators, vec![item.node_id()]);
            assert_eq!(qset.threshold, 1);
        }
    }
}

#[test]
fn a_different_but_valid_quorum_set_does_not_bind() {
    let f = fixture();
    let donor = f
        .slots
        .iter()
        .flat_map(|s| s.quorum_sets.iter())
        .map(|s| unhex(s))
        .max_by_key(|raw| raw.len())
        .expect("the fixture carries quorum sets");

    for slot in f.slots.iter().filter(|s| !s.externalize_only_confirms) {
        let (local, sets, envelopes) = parts(slot);

        if sets.contains(&donor) {
            continue;
        }

        let evidence = authenticate(
            &network_id(&slot.network),
            slot.slot,
            &envelopes,
            core::slice::from_ref(&donor),
        )
        .expect("a node whose quorum set will not resolve is dropped");
        let value = unhex(&slot.expected_value);

        assert!(
            evidence
                .iter()
                .filter(|item| item.statement().as_externalize().is_none())
                .all(|item| item.quorum_set().is_none()),
            "slot {}: a sane quorum set that hashes to something else must not bind",
            slot.slot
        );
        assert!(
            confirmed_commit(&local, &evidence, &value).is_none(),
            "slot {} confirmed on a substituted quorum set",
            slot.slot
        );
    }
}

#[test]
fn every_counted_node_carries_a_quorum_set_bound_to_what_it_signed() {
    for slot in &fixture().slots {
        let (_, sets, _) = parts(slot);
        let evidence = evidence(slot);

        for item in &evidence {
            let Some(bound) = item.quorum_set() else {
                continue;
            };

            match item.statement().as_externalize() {
                Some(_) => {
                    assert_eq!(bound.validators, vec![item.node_id()]);
                    assert_eq!(bound.threshold, 1);
                }
                None => {
                    let named = item.statement().quorum_set_hash();
                    let preimage = sets
                        .iter()
                        .find(|raw| QuorumSet::hash(raw) == named)
                        .expect("bound only through a preimage that hashes to the named value");

                    assert_eq!(
                        *bound,
                        QuorumSet::decode(preimage).expect("decodes"),
                        "slot {}: the bound set is not the one the hash names",
                        slot.slot
                    );
                }
            }
        }
    }
}
