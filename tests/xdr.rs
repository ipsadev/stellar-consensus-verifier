use stellar_consensus_verifier::xdr::*;

#[test]
fn integers_are_big_endian() {
    let raw = [0x00, 0x00, 0x01, 0x02, 0xff, 0xff, 0xff, 0xff];
    let mut d = Decoder::new(&raw);

    assert_eq!(d.u32().unwrap(), 0x0102);
    assert_eq!(d.i32().unwrap(), -1);
    let raw = [0, 0, 0, 1, 0, 0, 0, 2];

    assert_eq!(Decoder::new(&raw).u64().unwrap(), (1u64 << 32) | 2);
}

#[test]
fn fixed_fields_consume_their_padding() {
    let mut raw = b"a".to_vec();

    raw.extend_from_slice(&[0, 0, 0]);
    let mut d = Decoder::new(&raw);

    assert_eq!(d.fixed(1).unwrap(), b"a");
    assert!(d.finish().is_ok());
}

#[test]
fn non_zero_padding_is_refused() {
    let mut raw = b"a".to_vec();

    raw.extend_from_slice(&[0, 1, 0]);
    assert!(Decoder::new(&raw).fixed(1).is_err());
}

#[test]
fn a_thirty_two_byte_field_has_no_padding() {
    let raw = [7u8; 32];
    let mut d = Decoder::new(&raw);

    assert_eq!(d.fixed32().unwrap(), raw);
    assert!(d.finish().is_ok());
}

#[test]
fn trailing_bytes_are_refused() {
    let raw = [0u8; 8];
    let mut d = Decoder::new(&raw);

    d.u32().unwrap();
    assert!(d.finish().is_err());
}

#[test]
fn reading_past_the_end_is_refused() {
    let raw = [0u8; 3];

    assert!(Decoder::new(&raw).u32().is_err());
}

#[test]
fn a_variable_field_longer_than_the_input_is_refused() {
    let mut raw = 64u32.to_be_bytes().to_vec();

    raw.extend_from_slice(&[0u8; 8]);
    assert!(Decoder::new(&raw).var_bytes().is_err());
}

#[test]
fn a_variable_field_over_the_cap_is_refused() {
    let raw = ((MAX_VAR_LEN + 1) as u32).to_be_bytes().to_vec();

    assert!(Decoder::new(&raw).var_bytes().is_err());
}

#[test]
fn an_array_longer_than_permitted_is_refused() {
    let raw = 5u32.to_be_bytes().to_vec();

    assert!(Decoder::new(&raw).vec_len(4).is_err());
}

#[test]
fn an_array_longer_than_the_remaining_input_is_refused() {
    let mut raw = 100u32.to_be_bytes().to_vec();

    raw.extend_from_slice(&[0u8; 8]);
    assert!(Decoder::new(&raw).vec_len(1000).is_err());
}

#[test]
fn only_ed25519_public_keys_are_accepted() {
    let mut ok = 0u32.to_be_bytes().to_vec();

    ok.extend_from_slice(&[9u8; 32]);
    assert_eq!(Decoder::new(&ok).node_id().unwrap(), [9u8; 32]);
    let mut bad_type = 1u32.to_be_bytes().to_vec();

    bad_type.extend_from_slice(&[9u8; 32]);
    assert!(Decoder::new(&bad_type).node_id().is_err());
}

#[test]
fn a_signature_must_be_exactly_sixty_four_bytes() {
    let mut ok = 64u32.to_be_bytes().to_vec();

    ok.extend_from_slice(&[3u8; 64]);
    assert_eq!(Decoder::new(&ok).signature().unwrap(), [3u8; 64]);
    let mut short = 32u32.to_be_bytes().to_vec();

    short.extend_from_slice(&[3u8; 32]);
    assert!(Decoder::new(&short).signature().is_err());
}

#[test]
fn slice_from_returns_the_exact_bytes_consumed() {
    let raw = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut d = Decoder::new(&raw);
    let start = d.position();

    d.u32().unwrap();
    assert_eq!(d.slice_from(start), &raw[..4]);
    assert_eq!(d.remaining(), 4);
}
