use stellar_consensus_verifier::txset::*;

#[test]
fn a_v1_set_names_its_predecessor() {
    let mut raw = GENERALIZED_TX_SET_V1.to_be_bytes().to_vec();

    raw.extend_from_slice(&[0x5au8; 32]);
    raw.extend_from_slice(&[0xffu8; 16]);
    assert_eq!(previous_ledger_hash(&raw).unwrap(), [0x5au8; 32]);
}

#[test]
fn an_unsupported_version_is_refused() {
    let mut raw = 0i32.to_be_bytes().to_vec();

    raw.extend_from_slice(&[0x5au8; 32]);
    assert!(previous_ledger_hash(&raw).is_err());
}

#[test]
fn a_truncated_set_is_refused() {
    let raw = GENERALIZED_TX_SET_V1.to_be_bytes().to_vec();

    assert!(previous_ledger_hash(&raw).is_err());
}

#[test]
fn the_hash_covers_every_byte() {
    let raw = [1u8, 2, 3, 4];
    let mut mutated = raw;

    mutated[3] ^= 1;
    assert_ne!(hash(&raw), hash(&mutated));
    assert_eq!(hash(&raw), hash(&raw));
}
