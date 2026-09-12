use sha2::{Digest, Sha256};
use stellar_consensus_verifier::{chain::*, error::ScpError, ledger::SKIP_LIST_LEN};

fn header(seq: u32, previous_ledger_hash: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(&27u32.to_be_bytes());
    out.extend_from_slice(&previous_ledger_hash);
    out.extend_from_slice(&[0x22u8; 32]);
    out.extend_from_slice(&(1_700_000_000u64 + u64::from(seq)).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&0i32.to_be_bytes());
    out.extend_from_slice(&[0x33u8; 32]);
    out.extend_from_slice(&[0x44u8; 32]);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());

    for _ in 0..SKIP_LIST_LEN {
        out.extend_from_slice(&[0u8; 32]);
    }

    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

struct Chain {
    headers: Vec<Vec<u8>>,
    anchor_seq: u32,
    anchor_previous: [u8; 32],
    target_seq: u32,
}

fn chain(target_seq: u32, len: u32) -> Chain {
    let mut headers = Vec::new();
    let mut previous = [0x99u8; 32];

    for seq in target_seq..=(target_seq + len) {
        let raw = header(seq, previous);
        previous = hash(&raw);
        headers.push(raw);
    }

    let anchor = headers.pop().expect("anchor");
    let anchor_seq = target_seq + len;

    headers.reverse();

    Chain {
        headers,
        anchor_seq,
        anchor_previous: stellar_consensus_verifier::ledger::LedgerHeader::decode(&anchor)
            .expect("anchor decodes")
            .previous_ledger_hash,
        target_seq,
    }
}

fn refs(headers: &[Vec<u8>]) -> Vec<&[u8]> {
    headers.iter().map(|h| h.as_slice()).collect()
}

#[test]
fn a_chain_folds_back_to_the_target() {
    let c = chain(4_160_000, 5);
    let out = walk_back(
        c.anchor_seq,
        &c.anchor_previous,
        &refs(&c.headers),
        c.target_seq,
    )
    .expect("walks");

    assert_eq!(out.ledger_seq, c.target_seq);
    assert_eq!(out.links, 5);
    assert_eq!(out.ledger_hash, hash(&c.headers[c.headers.len() - 1]));
}

#[test]
fn one_link_is_the_shortest_walk() {
    let c = chain(100, 1);
    let out = walk_back(c.anchor_seq, &c.anchor_previous, &refs(&c.headers), 100).expect("walks");

    assert_eq!(out.ledger_seq, 100);
    assert_eq!(out.links, 1);
}

#[test]
fn a_target_that_is_not_behind_the_anchor_is_refused() {
    let c = chain(100, 2);
    let err = walk_back(50, &c.anchor_previous, &refs(&c.headers), 100).unwrap_err();

    assert!(matches!(
        err,
        ScpError::ChainNotDescending {
            anchor: 50,
            target: 100
        }
    ));
}

#[test]
fn too_few_headers_are_refused() {
    let c = chain(4_160_000, 5);
    let short = &refs(&c.headers)[..3];
    let err = walk_back(c.anchor_seq, &c.anchor_previous, short, c.target_seq).unwrap_err();

    assert!(matches!(
        err,
        ScpError::ChainLengthMismatch {
            expected: 5,
            found: 3,
            ..
        }
    ));
}

#[test]
fn a_missing_ledger_in_the_middle_is_refused() {
    let c = chain(4_160_000, 5);
    let mut headers = c.headers.clone();

    headers.remove(2);

    let err = walk_back(
        c.anchor_seq,
        &c.anchor_previous,
        &refs(&headers),
        c.target_seq,
    )
    .unwrap_err();

    assert!(matches!(err, ScpError::ChainLengthMismatch { .. }));
}

#[test]
fn a_substituted_header_breaks_the_chain() {
    let c = chain(4_160_000, 5);
    let mut headers = c.headers.clone();

    headers[2] = header(c.target_seq + 2, [0xeeu8; 32]);

    let err = walk_back(
        c.anchor_seq,
        &c.anchor_previous,
        &refs(&headers),
        c.target_seq,
    )
    .unwrap_err();

    assert!(
        matches!(err, ScpError::ChainBroken { .. }),
        "expected ChainBroken, got {err:?}"
    );
}

#[test]
fn a_reordered_chain_is_refused() {
    let c = chain(4_160_000, 5);
    let mut headers = c.headers.clone();

    headers.swap(1, 3);

    let err = walk_back(
        c.anchor_seq,
        &c.anchor_previous,
        &refs(&headers),
        c.target_seq,
    )
    .unwrap_err();

    assert!(
        matches!(
            err,
            ScpError::ChainGap { .. } | ScpError::ChainBroken { .. }
        ),
        "expected a gap or a break, got {err:?}"
    );
}

#[test]
fn a_forked_anchor_does_not_reach_the_target() {
    let c = chain(4_160_000, 5);
    let err = walk_back(c.anchor_seq, &[0xabu8; 32], &refs(&c.headers), c.target_seq).unwrap_err();

    assert!(
        matches!(err, ScpError::ChainBroken { .. }),
        "a chain that does not descend from the anchor must not verify, got {err:?}"
    );
}
