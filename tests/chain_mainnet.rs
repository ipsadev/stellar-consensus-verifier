use serde::Deserialize;
use stellar_consensus_verifier::{chain::walk_back, error::ScpError, ledger::LedgerHeader};

#[derive(Deserialize)]
struct Fixture {
    headers_ascending: Vec<String>,
    recorded_hashes: Vec<String>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn fixture() -> (Vec<Vec<u8>>, Vec<[u8; 32]>) {
    let f: Fixture =
        serde_json::from_str(include_str!("fixtures/testnet-header-chain.json")).expect("fixture");
    let headers = f.headers_ascending.iter().map(|h| unhex(h)).collect();
    let hashes = f
        .recorded_hashes
        .iter()
        .map(|h| {
            let v = unhex(h);
            let mut out = [0u8; 32];
            out.copy_from_slice(&v);
            out
        })
        .collect();
    (headers, hashes)
}

#[test]
fn the_archived_headers_are_consecutive_and_self_describing() {
    let (headers, hashes) = fixture();
    let decoded: Vec<LedgerHeader> = headers
        .iter()
        .map(|h| LedgerHeader::decode(h).expect("archived header decodes"))
        .collect();

    for (i, header) in decoded.iter().enumerate() {
        assert_eq!(
            header.ledger_hash, hashes[i],
            "header {} does not hash to the archive's recorded hash",
            header.ledger_seq
        );
        if i > 0 {
            assert_eq!(header.ledger_seq, decoded[i - 1].ledger_seq + 1);
            assert_eq!(header.previous_ledger_hash, decoded[i - 1].ledger_hash);
        }
    }
}

#[test]
fn a_real_chain_folds_from_the_anchor_back_to_the_target() {
    let (headers, hashes) = fixture();
    let decoded: Vec<LedgerHeader> = headers
        .iter()
        .map(|h| LedgerHeader::decode(h).expect("decodes"))
        .collect();

    let anchor = decoded.last().expect("anchor");
    let target = decoded.first().expect("target");

    let descending: Vec<&[u8]> = headers[..headers.len() - 1]
        .iter()
        .rev()
        .map(|h| h.as_slice())
        .collect();

    let out = walk_back(
        anchor.ledger_seq,
        &anchor.previous_ledger_hash,
        &descending,
        target.ledger_seq,
    )
    .expect("the archived chain folds back");

    assert_eq!(out.ledger_seq, target.ledger_seq);
    assert_eq!(out.ledger_hash, hashes[0]);
    assert_eq!(out.links, (anchor.ledger_seq - target.ledger_seq) as usize);
    assert_eq!(out.close_time, target.close_time);
}

#[test]
fn one_flipped_bit_in_a_real_header_breaks_the_real_chain() {
    let (headers, _) = fixture();
    let decoded: Vec<LedgerHeader> = headers
        .iter()
        .map(|h| LedgerHeader::decode(h).expect("decodes"))
        .collect();

    let anchor = decoded.last().expect("anchor");
    let target = decoded.first().expect("target");

    let mut tampered = headers.clone();
    let middle = tampered.len() / 2;
    let last = tampered[middle].len() - 1;

    tampered[middle][last] ^= 0x01;

    let descending: Vec<&[u8]> = tampered[..tampered.len() - 1]
        .iter()
        .rev()
        .map(|h| h.as_slice())
        .collect();

    let err = walk_back(
        anchor.ledger_seq,
        &anchor.previous_ledger_hash,
        &descending,
        target.ledger_seq,
    )
    .expect_err("a tampered header must not fold");

    assert!(
        matches!(err, ScpError::ChainBroken { .. } | ScpError::InvalidWire(_)),
        "expected the chain to break, got {err:?}"
    );
}
