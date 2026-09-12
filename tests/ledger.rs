use stellar_consensus_verifier::ledger::*;

fn header_with_ext(ext: i32, arm: &[u8]) -> Vec<u8> {
    build_header(27, 4_264_884, [0x22u8; 32], ext, arm)
}

fn header_with_ext_v(ext_v: i32, tail: &[u8]) -> Vec<u8> {
    build_full(27, 4_264_884, [0x22u8; 32], 0, &[], &[], ext_v, tail)
}

fn header_ext_v1(flags: u32) -> Vec<u8> {
    let mut out = 1i32.to_be_bytes().to_vec();

    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&0i32.to_be_bytes());

    out
}

fn header_with_upgrade(upgrade: &[u8]) -> Vec<u8> {
    build_full(27, 4_264_884, [0x22u8; 32], 0, &[], &[upgrade], 0, &[])
}

fn build_header(version: u32, seq: u32, tx_set_hash: [u8; 32], ext: i32, arm: &[u8]) -> Vec<u8> {
    build_full(version, seq, tx_set_hash, ext, arm, &[], 0, &[])
}

fn build_full(
    version: u32,
    seq: u32,
    tx_set_hash: [u8; 32],
    ext: i32,
    arm: &[u8],
    upgrades: &[&[u8]],
    header_ext_v: i32,
    header_ext_tail: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&[0x11u8; 32]);
    out.extend_from_slice(&tx_set_hash);
    out.extend_from_slice(&1_700_000_000u64.to_be_bytes());
    out.extend_from_slice(&(upgrades.len() as u32).to_be_bytes());

    for upgrade in upgrades {
        out.extend_from_slice(&(upgrade.len() as u32).to_be_bytes());
        out.extend_from_slice(upgrade);
        let pad = (4 - (upgrade.len() % 4)) % 4;

        out.extend_from_slice(&vec![0u8; pad]);
    }

    out.extend_from_slice(&ext.to_be_bytes());
    out.extend_from_slice(arm);
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

    if header_ext_tail.is_empty() {
        out.extend_from_slice(&header_ext_v.to_be_bytes());
    } else {
        out.extend_from_slice(header_ext_tail);
    }

    out
}

fn close_value_signature() -> Vec<u8> {
    let mut out = 0u32.to_be_bytes().to_vec();

    out.extend_from_slice(&[0x55u8; 32]);
    out.extend_from_slice(&64u32.to_be_bytes());
    out.extend_from_slice(&[0x66u8; 64]);
    out
}

#[test]
fn a_basic_header_decodes() {
    let raw = header_with_ext(STELLAR_VALUE_BASIC, &[]);
    let header = LedgerHeader::decode(&raw).expect("decodes");

    assert_eq!(header.ledger_seq, 4_264_884);
    assert_eq!(header.close_time, 1_700_000_000);
    assert_eq!(header.scp_value_bytes.len(), 32 + 8 + 4 + 4);
}

#[test]
fn a_signed_header_decodes() {
    let raw = header_with_ext(STELLAR_VALUE_SIGNED, &close_value_signature());
    let header = LedgerHeader::decode(&raw).expect("decodes");

    assert_eq!(header.ledger_seq, 4_264_884);
    assert_eq!(header.scp_value_bytes.len(), 32 + 8 + 4 + 4 + 36 + 68);
}

fn empty_arm(proposed_prev_hash: [u8; 32], proposed_version: u32) -> Vec<u8> {
    let mut arm = [0x99u8; 32].to_vec();

    arm.extend_from_slice(&proposed_prev_hash);
    arm.extend_from_slice(&proposed_version.to_be_bytes());
    arm.extend_from_slice(&close_value_signature());
    arm
}

#[test]
fn an_empty_tx_set_header_decodes() {
    let arm = empty_arm([0x11u8; 32], 28);
    let raw = build_header(28, 4_264_884, [0u8; 32], STELLAR_VALUE_EMPTY_TX_SET, &arm);
    let header = LedgerHeader::decode(&raw).expect("a CAP-0083 header decodes");

    assert_eq!(header.ledger_seq, 4_264_884);
    assert_eq!(header.tx_set_hash, [0u8; 32]);
    let info = header.empty_tx_set.expect("carries the proposed value");

    assert_eq!(info.proposed_tx_set_hash, [0x99u8; 32]);
    assert_eq!(info.proposed_previous_ledger_hash, [0x11u8; 32]);
    assert_eq!(info.proposed_previous_ledger_version, 28);
}

#[test]
fn the_empty_tx_set_span_covers_the_whole_proposed_value() {
    let arm = empty_arm([0x11u8; 32], 28);
    let raw = build_header(28, 4_264_884, [0u8; 32], STELLAR_VALUE_EMPTY_TX_SET, &arm);
    let header = LedgerHeader::decode(&raw).expect("decodes");

    assert_eq!(
        header.scp_value_bytes.len(),
        32 + 8 + 4 + 4 + 32 + 32 + 4 + 36 + 68
    );
}

#[test]
fn an_unknown_ext_arm_is_refused() {
    let raw = header_with_ext(3, &[]);

    assert!(LedgerHeader::decode(&raw).is_err());
}

#[test]
fn the_value_names_its_tx_set_hash() {
    let raw = header_with_ext(STELLAR_VALUE_BASIC, &[]);
    let header = LedgerHeader::decode(&raw).expect("decodes");

    assert_eq!(
        tx_set_hash_of_value(&header.scp_value_bytes).expect("reads the hash"),
        [0x22u8; 32]
    );
}

#[test]
fn the_header_extension_v1_is_accepted() {
    let raw = header_with_ext_v(1, &header_ext_v1(3));

    LedgerHeader::decode(&raw).expect("a LEDGER_UPGRADE_FLAGS header must still decode");
}

#[test]
fn an_unknown_header_extension_is_refused() {
    let raw = header_with_ext_v(2, &[]);

    assert!(LedgerHeader::decode(&raw).is_err());
}

#[test]
fn an_upgrade_entry_longer_than_the_xdr_permits_is_refused() {
    let raw = header_with_upgrade(&[0u8; 132]);

    assert!(LedgerHeader::decode(&raw).is_err());
}

#[test]
fn an_upgrade_entry_at_the_limit_is_accepted() {
    let raw = header_with_upgrade(&[0u8; 128]);

    LedgerHeader::decode(&raw).expect("128 bytes is the XDR maximum");
}

#[test]
fn an_empty_tx_set_arm_requires_the_zero_tx_set_hash() {
    let raw = build_header(28, 9, [7u8; 32], 2, &empty_arm([0x11u8; 32], 28));

    assert!(
        LedgerHeader::decode(&raw).is_err(),
        "CAP-0083 sets txSetHash to 0x0 for an empty-tx-set value"
    );
}

#[test]
fn a_zero_tx_set_hash_without_the_arm_is_refused() {
    let raw = build_header(28, 9, [0u8; 32], 0, &[]);

    assert!(
        LedgerHeader::decode(&raw).is_err(),
        "a zero txSetHash only occurs with the empty-tx-set arm"
    );
}

#[test]
fn genesis_may_carry_a_zero_tx_set_hash() {
    let raw = build_header(28, 1, [0u8; 32], 0, &[]);

    LedgerHeader::decode(&raw).expect("the genesis ledger predates any tx set");
}

#[test]
fn an_empty_tx_set_arm_before_the_protocol_boundary_is_refused() {
    let raw = build_header(27, 9, [0u8; 32], 2, &empty_arm([0x11u8; 32], 27));

    assert!(
        LedgerHeader::decode(&raw).is_err(),
        "CAP-0083 values become valid at the protocol boundary"
    );
}

#[test]
fn the_proposed_predecessor_must_be_the_headers_own() {
    let raw = build_header(28, 9, [0u8; 32], 2, &empty_arm([0x99u8; 32], 28));

    assert!(
        LedgerHeader::decode(&raw).is_err(),
        "CAP-0083: proposedValue.previousLedgerHash is the hash of the ledger prior to this one"
    );
}

#[test]
fn a_proposed_predecessor_before_the_boundary_is_refused() {
    let raw = build_header(28, 9, [0u8; 32], 2, &empty_arm([0x11u8; 32], 27));

    assert!(
        LedgerHeader::decode(&raw).is_err(),
        "core requires the predecessor to already allow empty-tx-set values, so the \
         activation ledger itself cannot carry the arm"
    );
}

#[test]
fn a_well_formed_empty_tx_set_arm_decodes_and_is_exposed() {
    let raw = build_header(28, 9, [0u8; 32], 2, &empty_arm([0x11u8; 32], 28));
    let header = LedgerHeader::decode(&raw).expect("decodes");
    let arm = header.empty_tx_set.expect("carries the proposed value");

    assert_eq!(arm.proposed_previous_ledger_hash, [0x11u8; 32]);
    assert_eq!(arm.proposed_previous_ledger_version, 28);
    assert_eq!(header.tx_set_hash, [0u8; 32]);
}
