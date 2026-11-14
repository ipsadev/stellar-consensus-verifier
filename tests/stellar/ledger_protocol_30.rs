use serde::Deserialize;
use stellar_consensus_verifier::primitives::stellar::header::LedgerHeader;

#[derive(Deserialize)]
struct Recorded {
    ledger: u32,
    hash: String,
    header_xdr: String,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn recorded() -> Vec<Recorded> {
    serde_json::from_str(include_str!("../fixtures/testnet-protocol-30-headers.json")).unwrap()
}

#[test]
fn testnet_headers_across_the_protocol_30_upgrade_decode_to_their_recorded_hashes() {
    for header in recorded() {
        let decoded = LedgerHeader::decode(&unhex(&header.header_xdr)).expect("decodes");

        assert_eq!(decoded.ledger_seq, header.ledger);
        assert_eq!(decoded.ledger_version, 30);
        assert_eq!(decoded.ledger_hash.to_vec(), unhex(&header.hash));
    }
}

#[test]
fn the_upgrade_ledger_keeps_whole_seconds_and_the_next_one_records_milliseconds() {
    let headers = recorded();
    let upgrade = LedgerHeader::decode(&unhex(&headers[0].header_xdr)).unwrap();
    let next = LedgerHeader::decode(&unhex(&headers[1].header_xdr)).unwrap();

    assert_eq!(upgrade.ledger_seq, 5_540_313);
    assert_eq!(upgrade.close_time_ms, None);

    assert_eq!(next.ledger_seq, 5_540_314);
    let ms = next.close_time_ms.expect("records milliseconds");

    assert_eq!(ms / 1000, next.close_time);
    assert!(ms > upgrade.close_time * 1000);
    assert_eq!(next.previous_ledger_hash, upgrade.ledger_hash);
}
