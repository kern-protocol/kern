//! Golden vectors for the V1 lease protocol.
//!
//! These bytes are the protocol. If a change to a Rust field order, an enum
//! variant order, an integer representation, or a serializer setting alters
//! them, that is a protocol compatibility change requiring a version decision
//! and a new set of vectors — not a refactor that happens to fail a test.
//!
//! Every input is fixed: a development seed, a `TestClock`, a counting nonce
//! source, and a sequential id source. Nothing here samples the environment.

mod support;

use kern_core::wire::{decode_body, encode, encode_body, parse, signing_input};
use kern_core::{
    CapabilityName, DeviceId, IssuerId, KeyId, LeaseId, Nonce, ProtocolVersion, SubjectId,
    Timestamp, Ttl,
};
use support::*;

const GOLDEN_BODY: &str = "000000000000000000000000000000ab0a6973737565725f646576056465762d3109706c616e6e65725f610b636166655f626f745f3031086e6176696761746501020b64657374696e6174696f6e01020463616665056c6f626279096d61785f737065656400ffffffffffffffffff01e80780d095ffbc3188f795ffbc31011111111111111111111111111111111111111111111111111111111111111111";

const GOLDEN_SIGNING_INPUT: &str = "4b45524e2d4c454153452d563101009f000000000000000000000000000000000000ab0a6973737565725f646576056465762d3109706c616e6e65725f610b636166655f626f745f3031086e6176696761746501020b64657374696e6174696f6e01020463616665056c6f626279096d61785f737065656400ffffffffffffffffff01e80780d095ffbc3188f795ffbc31011111111111111111111111111111111111111111111111111111111111111111";

const GOLDEN_SIGNATURE: &str = "e74a56ef77c60bef7313159e6cad2b7c70d9d93f9e5d6f602960b8a35784bf423111641ba13f5eda192d6d64d6a324a0136e780a7a5fdd4ea7dd3bd8db4af405";

const GOLDEN_ENVELOPE: &str = "01009f000000000000000000000000000000000000ab0a6973737565725f646576056465762d3109706c616e6e65725f610b636166655f626f745f3031086e6176696761746501020b64657374696e6174696f6e01020463616665056c6f626279096d61785f737065656400ffffffffffffffffff01e80780d095ffbc3188f795ffbc31011111111111111111111111111111111111111111111111111111111111111111e74a56ef77c60bef7313159e6cad2b7c70d9d93f9e5d6f602960b8a35784bf423111641ba13f5eda192d6d64d6a324a0136e780a7a5fdd4ea7dd3bd8db4af405";

const GOLDEN_VERIFYING_KEY: &str =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

fn golden_lease() -> kern_core::SignedLease {
    issuer()
        .issue_v1(&authorized_operation(), Ttl::from_millis(5_000), session())
        .expect("issued")
}

#[test]
fn body_bytes_match_the_golden_vector() {
    let bytes = encode_body(&golden_lease().body).expect("encodes");

    assert_eq!(hex(&bytes), GOLDEN_BODY);
}

#[test]
fn signing_input_matches_the_golden_vector() {
    let body = encode_body(&golden_lease().body).expect("encodes");
    let input = signing_input(ProtocolVersion::V1, &body);

    assert_eq!(hex(&input), GOLDEN_SIGNING_INPUT);
}

#[test]
fn signature_matches_the_golden_vector() {
    assert_eq!(hex(golden_lease().signature.as_bytes()), GOLDEN_SIGNATURE);
}

#[test]
fn envelope_matches_the_golden_vector() {
    assert_eq!(
        hex(&encode(&golden_lease()).expect("encodes")),
        GOLDEN_ENVELOPE
    );
}

/// The golden bytes decode to the semantic value they are supposed to represent.
#[test]
fn golden_bytes_decode_to_the_expected_semantics() {
    let body = decode_body(&unhex(GOLDEN_BODY)).expect("decodes");

    assert_eq!(body.id, LeaseId::from_bytes(0xABu128.to_be_bytes()));
    assert_eq!(body.issuer, IssuerId::new("issuer_dev"));
    assert_eq!(body.key_id, KeyId::new("dev-1"));
    assert_eq!(body.subject, SubjectId::new("planner_a"));
    assert_eq!(body.device, DeviceId::new("cafe_bot_01"));
    assert_eq!(body.capability, CapabilityName::new("navigate").unwrap());
    assert_eq!(body.issued_at, Timestamp::from_millis(ISSUED_AT_MS));
    assert_eq!(
        body.expires_at,
        Timestamp::from_millis(ISSUED_AT_MS + 5_000)
    );
    assert_eq!(body.nonce, Nonce::new(1));
    assert_eq!(body.enforcer_session, session());
    assert_eq!(body.constraints, *authorized_operation().constraints());
}

/// Decoding then re-encoding the golden bytes reproduces them exactly.
#[test]
fn golden_bytes_reencode_identically() {
    let bytes = unhex(GOLDEN_BODY);
    let decoded = decode_body(&bytes).expect("decodes");

    assert_eq!(encode_body(&decoded).expect("re-encodes"), bytes);
}

#[test]
fn golden_envelope_parses_to_the_golden_parts() {
    let bytes = unhex(GOLDEN_ENVELOPE);
    let parsed = parse(&bytes).expect("parses");

    assert_eq!(parsed.version(), ProtocolVersion::V1);
    assert_eq!(hex(parsed.body_bytes()), GOLDEN_BODY);
    assert_eq!(hex(parsed.signature().as_bytes()), GOLDEN_SIGNATURE);
    assert_eq!(hex(&parsed.signing_input()), GOLDEN_SIGNING_INPUT);
}

/// The development key is part of the fixture, so a change to it would silently
/// invalidate every signature vector above.
#[test]
fn development_key_matches_the_golden_vector() {
    use kern_authority::Ed25519Signer;

    let signer = Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED);

    assert_eq!(hex(&signer.verifying_key_bytes()), GOLDEN_VERIFYING_KEY);
}

/// A test-only cross-check that the golden signature is a real Ed25519 signature
/// over the golden signing input, not merely 64 bytes that happen to be stable.
///
/// This is an assertion, not a verifier: no trust store, no key resolution, no
/// installation. Phase 4 owns verification.
#[test]
fn golden_signature_verifies_against_the_development_key() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key_bytes: [u8; 32] = unhex(GOLDEN_VERIFYING_KEY).try_into().expect("32 bytes");
    let signature_bytes: [u8; 64] = unhex(GOLDEN_SIGNATURE).try_into().expect("64 bytes");

    let key = VerifyingKey::from_bytes(&key_bytes).expect("valid key");
    let signature = Signature::from_bytes(&signature_bytes);

    assert!(key.verify(&unhex(GOLDEN_SIGNING_INPUT), &signature).is_ok());
}

/// The signature covers the body. Flipping one byte of it must break the check.
#[test]
fn a_tampered_body_breaks_the_golden_signature() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key_bytes: [u8; 32] = unhex(GOLDEN_VERIFYING_KEY).try_into().expect("32 bytes");
    let signature_bytes: [u8; 64] = unhex(GOLDEN_SIGNATURE).try_into().expect("64 bytes");

    let mut input = unhex(GOLDEN_SIGNING_INPUT);
    let last = input.len() - 1;
    input[last] ^= 0x01;

    let key = VerifyingKey::from_bytes(&key_bytes).expect("valid key");
    let signature = Signature::from_bytes(&signature_bytes);

    assert!(key.verify(&input, &signature).is_err());
}
