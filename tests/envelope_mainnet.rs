use serde::Deserialize;
use sha2::{Digest, Sha256};
use stellar_consensus_verifier::envelope::{Envelope, ENVELOPE_TYPE_SCP};

const LIVE_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
const TEST_PASSPHRASE: &str = "Test SDF Network ; September 2015";

#[derive(Deserialize)]
struct Specimen {
    network: String,
    closed: String,
    slot: u64,
    node: String,
    commit_counter: u32,
    n_h: u32,
    value: String,
    quorum_set_hash: String,
    signing_payload_sha256: String,
    envelope: String,
}

#[derive(Deserialize)]
struct Rejected {
    kind: String,
    slot: u64,
    envelope: String,
}

#[derive(Deserialize)]
struct Fixture {
    externalize: Vec<Specimen>,
    rejected: Vec<Rejected>,
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
    serde_json::from_str(include_str!("fixtures/mainnet-scp-envelopes.json")).expect("fixture")
}

fn network_id(network: &str) -> [u8; 32] {
    let passphrase = if network == "live" {
        LIVE_PASSPHRASE
    } else {
        TEST_PASSPHRASE
    };

    Sha256::digest(passphrase.as_bytes()).into()
}

#[test]
fn every_archived_externalize_decodes_to_what_the_archive_recorded() {
    let f = fixture();

    assert!(!f.externalize.is_empty());

    for s in &f.externalize {
        let env = Envelope::decode(&unhex(&s.envelope))
            .unwrap_or_else(|e| panic!("slot {} ({}) failed to decode: {e}", s.slot, s.closed));

        assert_eq!(hex(&env.node_id), s.node, "slot {}", s.slot);
        assert_eq!(env.slot_index, s.slot);
        assert_eq!(
            env.externalize().unwrap().commit.counter,
            s.commit_counter,
            "slot {}",
            s.slot
        );
        assert_eq!(
            env.externalize().unwrap().highest_confirmed_ballot_counter,
            s.n_h,
            "slot {}",
            s.slot
        );
        assert_eq!(
            hex(&env.externalize().unwrap().commit.value),
            s.value,
            "slot {}",
            s.slot
        );
        assert_eq!(
            hex(&env.externalize().unwrap().commit_quorum_set_hash),
            s.quorum_set_hash,
            "slot {}",
            s.slot
        );
    }
}

#[test]
fn the_signed_payload_matches_what_the_validators_actually_signed() {
    for s in &fixture().externalize {
        let env = Envelope::decode(&unhex(&s.envelope)).expect("decodes");
        let payload = env.signing_payload(&network_id(&s.network));
        let digest: [u8; 32] = Sha256::digest(&payload).into();

        assert_eq!(
            hex(&digest),
            s.signing_payload_sha256,
            "slot {} ({}) on {}",
            s.slot,
            s.closed,
            s.network
        );
    }
}

#[test]
fn the_statement_span_is_the_envelope_minus_its_signature() {
    for s in &fixture().externalize {
        let raw = unhex(&s.envelope);
        let env = Envelope::decode(&raw).expect("decodes");

        assert_eq!(env.statement_bytes, raw[..raw.len() - 68]);
        assert_eq!(&raw[raw.len() - 68..raw.len() - 64], &[0, 0, 0, 64]);
        assert_eq!(env.signature, raw[raw.len() - 64..]);
    }
}

#[test]
fn the_signing_payload_is_the_network_id_then_the_envelope_type() {
    for s in &fixture().externalize {
        let env = Envelope::decode(&unhex(&s.envelope)).expect("decodes");
        let id = network_id(&s.network);
        let payload = env.signing_payload(&id);

        assert_eq!(&payload[..32], &id);
        assert_eq!(&payload[32..36], &ENVELOPE_TYPE_SCP);
        assert_eq!(&payload[36..], &env.statement_bytes[..]);
    }
}

#[test]
fn real_values_are_the_two_shapes_stellar_has_used() {
    for s in &fixture().externalize {
        let env = Envelope::decode(&unhex(&s.envelope)).expect("decodes");
        let len = env.externalize().unwrap().commit.value.len();

        assert!(
            len == 48 || len == 152,
            "slot {} value is {len} bytes",
            s.slot
        );
    }
}

#[test]
fn real_ballot_protocol_statements_decode_and_pass_the_sanity_rules() {
    let f = fixture();

    assert!(!f.rejected.is_empty());

    for r in &f.rejected {
        let env = Envelope::decode(&unhex(&r.envelope))
            .unwrap_or_else(|e| panic!("slot {} {} failed to decode: {e}", r.slot, r.kind));

        assert!(
            env.externalize().is_err(),
            "slot {} {} is not an EXTERNALIZE",
            r.slot,
            r.kind
        );
        assert!(
            !env.statement.value().is_empty(),
            "slot {} {} carries a value",
            r.slot,
            r.kind
        );
    }
}

#[test]
fn the_archive_carries_externalize_statements_with_n_h_at_the_ceiling() {
    let f = fixture();
    let ceiling = f
        .externalize
        .iter()
        .find(|s| s.n_h == u32::MAX)
        .expect("the fixture must keep a specimen with nH = UINT32_MAX");
    let env = Envelope::decode(&unhex(&ceiling.envelope)).expect("the ceiling value is sane");

    assert_eq!(
        env.externalize().unwrap().highest_confirmed_ballot_counter,
        u32::MAX
    );
}

#[test]
fn every_archived_externalize_passes_the_sanity_rules_stellar_core_applies() {
    for s in &fixture().externalize {
        let env = Envelope::decode(&unhex(&s.envelope)).expect("decodes");

        assert!(
            env.externalize().unwrap().commit.counter > 0,
            "slot {}",
            s.slot
        );
        assert!(
            env.externalize().unwrap().highest_confirmed_ballot_counter
                >= env.externalize().unwrap().commit.counter,
            "slot {}",
            s.slot
        );
    }
}
