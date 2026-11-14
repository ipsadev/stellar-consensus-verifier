use ed25519_dalek::{Signer, SigningKey};
use stellar_consensus_verifier::primitives::scp::envelope::verify_signature;

const NETWORK: [u8; 32] = [0x11; 32];

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sign(seed: u8, message: &[u8]) -> ([u8; 32], [u8; 64]) {
    let k = key(seed);
    let sig = k.sign(message).to_bytes();

    (k.verifying_key().to_bytes(), sig)
}

#[test]
fn a_genuine_signature_verifies() {
    let message = b"consensus message";
    let (node, sig) = sign(7, message);

    assert!(verify_signature(&node, message, &sig));
}

#[test]
fn a_different_message_is_rejected() {
    let (node, sig) = sign(7, b"consensus message");

    assert!(!verify_signature(&node, b"a different message", &sig));
}

#[test]
fn the_wrong_signer_is_rejected() {
    let message = b"consensus message";
    let (_node, sig) = sign(7, message);
    let other = key(8).verifying_key().to_bytes();

    assert!(!verify_signature(&other, message, &sig));
}

#[test]
fn an_all_zero_signature_is_rejected() {
    let node = key(7).verifying_key().to_bytes();

    assert!(!verify_signature(&node, b"consensus message", &[0u8; 64]));
}

#[test]
fn a_public_key_that_is_not_a_point_is_rejected() {
    // 0xff..ff is not a valid Edwards point encoding; strict verification must
    // refuse rather than treat it as some other key.
    let (_node, sig) = sign(7, b"consensus message");

    assert!(!verify_signature(&[0xff; 32], b"consensus message", &sig));
}

#[test]
fn a_flipped_signature_byte_is_rejected() {
    let message = b"consensus message";
    let (node, mut sig) = sign(7, message);
    sig[0] ^= 0x01;

    assert!(!verify_signature(&node, message, &sig));
}

#[test]
fn the_signature_is_bound_to_its_payload() {
    // The payload a validator signs includes the network id; a signature over one
    // payload must not verify against another.
    let one = [NETWORK.as_slice(), b"slot"].concat();
    let two = [[0x22u8; 32].as_slice(), b"slot"].concat();
    let (node, sig) = sign(7, &one);

    assert!(verify_signature(&node, &one, &sig));
    assert!(!verify_signature(&node, &two, &sig));
}
