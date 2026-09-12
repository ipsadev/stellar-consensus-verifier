use serde::Deserialize;
use stellar_consensus_verifier::ledger::tx_set_hash_of_value;
use stellar_consensus_verifier::ledger::LedgerHeader;

#[derive(Deserialize)]
struct Archived {
    network: String,
    ledger_seq: u32,
    protocol: u32,
    closed: String,
    recorded_hash: String,
    previous_ledger_hash: String,
    tx_set_hash: String,
    close_time: u64,
    tx_set_result_hash: String,
    bucket_list_hash: String,
    scp_value: String,
    scp_value_ext: i32,
    header_ext: i32,
    upgrades: Vec<String>,
    header: String,
}

#[derive(Deserialize)]
struct Fixture {
    headers: Vec<Archived>,
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
    serde_json::from_str(include_str!("fixtures/mainnet-ledger-headers.json")).expect("fixture")
}

#[test]
fn every_archived_header_decodes_to_what_the_archive_recorded() {
    let f = fixture();

    assert_eq!(f.headers.len(), 8);

    for a in &f.headers {
        let header = LedgerHeader::decode(&unhex(&a.header)).unwrap_or_else(|e| {
            panic!(
                "{} ledger {} (protocol {}, {}) failed to decode: {e}",
                a.network, a.ledger_seq, a.protocol, a.closed
            )
        });

        assert_eq!(header.ledger_seq, a.ledger_seq);
        assert_eq!(header.ledger_version, a.protocol);
        assert_eq!(hex(&header.previous_ledger_hash), a.previous_ledger_hash);
        assert_eq!(hex(&header.tx_set_hash), a.tx_set_hash);
        assert_eq!(header.close_time, a.close_time);
        assert_eq!(hex(&header.tx_set_result_hash), a.tx_set_result_hash);
        assert_eq!(hex(&header.bucket_list_hash), a.bucket_list_hash);
    }
}

#[test]
fn the_ledger_hash_is_sha256_over_the_whole_header() {
    for a in &fixture().headers {
        let header = LedgerHeader::decode(&unhex(&a.header)).expect("decodes");

        assert_eq!(
            hex(&header.ledger_hash),
            a.recorded_hash,
            "{} ledger {} ({})",
            a.network,
            a.ledger_seq,
            a.closed
        );
    }
}

#[test]
fn the_scp_value_span_is_exactly_the_value_consensus_agreed() {
    for a in &fixture().headers {
        let header = LedgerHeader::decode(&unhex(&a.header)).expect("decodes");

        assert_eq!(
            hex(&header.scp_value_bytes),
            a.scp_value,
            "ledger {}",
            a.ledger_seq
        );
        assert_eq!(
            tx_set_hash_of_value(&header.scp_value_bytes).expect("reads the tx set hash"),
            header.tx_set_hash
        );
    }
}

#[test]
fn a_header_carrying_a_protocol_upgrade_decodes() {
    let f = fixture();
    let upgraded = f
        .headers
        .iter()
        .find(|a| !a.upgrades.is_empty())
        .expect("the fixture must carry a real upgrade ledger");

    assert_eq!(upgraded.ledger_seq, 50_457_424);
    assert_eq!(upgraded.upgrades, vec!["0000000100000014"]);

    let header = LedgerHeader::decode(&unhex(&upgraded.header)).expect("decodes");

    assert_eq!(header.ledger_version, 20);
    assert_eq!(hex(&header.ledger_hash), upgraded.recorded_hash);
}

#[test]
fn both_stellar_value_shapes_the_network_has_used_decode() {
    let f = fixture();
    let basic = f.headers.iter().filter(|a| a.scp_value_ext == 0).count();
    let signed = f.headers.iter().filter(|a| a.scp_value_ext == 1).count();

    assert!(basic > 0, "pre-protocol-11 headers carry a basic value");
    assert!(signed > 0, "protocol 11 and later carry a signed value");

    for a in &f.headers {
        LedgerHeader::decode(&unhex(&a.header)).expect("decodes");
    }
}

#[test]
fn no_archived_header_has_ever_set_the_header_extension() {
    for a in &fixture().headers {
        assert_eq!(
            a.header_ext, 0,
            "ledger {} carries LedgerHeader.ext.v = {}; the decoder must handle it",
            a.ledger_seq, a.header_ext
        );
    }
}

#[test]
fn a_flipped_byte_changes_the_ledger_hash() {
    for a in &fixture().headers {
        let mut raw = unhex(&a.header);

        raw[0] ^= 0x01;
        match LedgerHeader::decode(&raw) {
            Ok(header) => assert_ne!(hex(&header.ledger_hash), a.recorded_hash),
            Err(_) => continue,
        }
    }
}

#[test]
fn a_truncated_header_is_refused_at_every_length() {
    for a in &fixture().headers {
        let raw = unhex(&a.header);

        for cut in 0..raw.len() {
            assert!(
                LedgerHeader::decode(&raw[..cut]).is_err(),
                "ledger {} decoded from {cut} of {} bytes",
                a.ledger_seq,
                raw.len()
            );
        }
    }
}
