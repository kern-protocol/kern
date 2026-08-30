//! Golden vectors for the V2 lease protocol.
//!
//! V2 is V1 plus a signed per-request challenge. These bytes are the protocol:
//! a change to field order, variant order, integer representation, or serializer
//! settings that alters them is a compatibility change requiring a version
//! decision and new vectors, not a refactor.
//!
//! The V1 vectors in `golden.rs` remain byte-identical and untouched. V1 is a
//! frozen, still-valid signed format; it simply carries no challenge, and so
//! cannot support freshness at first installation.

mod support;

use kern_core::wire::{decode_body_v2, encode_body_v2, encode_v2, parse, signing_input};
use kern_core::{
    AuthorityArtifactId, CapabilityName, Challenge, ChallengeTicket, DeviceId, IssuerId,
    ProtocolVersion, SignedLeaseV2, SubjectId, Ttl,
};
use support::*;

const GOLDEN_CHALLENGE: [u8; 32] = [0x5Au8; 32];

/// Byte-identical to the V1 golden body, with the challenge appended.
const GOLDEN_BODY_V2: &str = "000000000000000000000000000000ab0a6973737565725f646576056465762d3109706c616e6e65725f610b636166655f626f745f3031086e6176696761746501020b64657374696e6174696f6e01020463616665056c6f626279096d61785f737065656400ffffffffffffffffff01e80780d095ffbc3188f795ffbc310111111111111111111111111111111111111111111111111111111111111111115a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

const GOLDEN_SIGNING_INPUT_V2: &str = "4b45524e2d4c454153452d56320200bf000000000000000000000000000000000000ab0a6973737565725f646576056465762d3109706c616e6e65725f610b636166655f626f745f3031086e6176696761746501020b64657374696e6174696f6e01020463616665056c6f626279096d61785f737065656400ffffffffffffffffff01e80780d095ffbc3188f795ffbc310111111111111111111111111111111111111111111111111111111111111111115a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

const GOLDEN_SIGNATURE_V2: &str = "39e2c8c345071953e57c6eeddf6da9b9c3c8f36cc08380fda67290ee559306d15014ddfdef24f12cc3b04763349d2ede0d354ea335502677b5a894066dfa2e06";

const GOLDEN_ENVELOPE_V2: &str = "0200bf000000000000000000000000000000000000ab0a6973737565725f646576056465762d3109706c616e6e65725f610b636166655f626f745f3031086e6176696761746501020b64657374696e6174696f6e01020463616665056c6f626279096d61785f737065656400ffffffffffffffffff01e80780d095ffbc3188f795ffbc310111111111111111111111111111111111111111111111111111111111111111115a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a39e2c8c345071953e57c6eeddf6da9b9c3c8f36cc08380fda67290ee559306d15014ddfdef24f12cc3b04763349d2ede0d354ea335502677b5a894066dfa2e06";

const GOLDEN_ARTIFACT_V2: &str = "f023fa39e8c86ed9eb8e98347bec5074663a9c50af1433a1d257c049781d03fb";

/// Byte-identical to the V1 golden body vector in `golden.rs`.
const GOLDEN_BODY_V1: &str = "000000000000000000000000000000ab0a6973737565725f646576056465762d3109706c616e6e65725f610b636166655f626f745f3031086e6176696761746501020b64657374696e6174696f6e01020463616665056c6f626279096d61785f737065656400ffffffffffffffffff01e80780d095ffbc3188f795ffbc31011111111111111111111111111111111111111111111111111111111111111111";

fn golden_ticket() -> ChallengeTicket {
    ChallengeTicket {
        issuer: IssuerId::new("issuer_dev"),
        session: session(),
        challenge: Challenge::from_bytes(GOLDEN_CHALLENGE),
        subject: SubjectId::new("planner_a"),
        device: DeviceId::new("cafe_bot_01"),
        capability: CapabilityName::new("navigate").expect("valid"),
    }
}

fn golden_lease() -> SignedLeaseV2 {
    issuer()
        .issue_v2(
            &authorized_operation(),
            Ttl::from_millis(5_000),
            &golden_ticket(),
        )
        .expect("issued")
}

#[test]
fn body_bytes_match_the_golden_vector() {
    let bytes = encode_body_v2(&golden_lease().body).expect("encodes");

    assert_eq!(hex(&bytes), GOLDEN_BODY_V2);
}

/// The structural claim behind nesting the V1 body: V2 bytes are V1 bytes
/// followed by the challenge, so the V1 encoding is reused rather than
/// reimplemented.
#[test]
fn v2_bytes_are_v1_bytes_followed_by_the_challenge() {
    let expected = format!("{GOLDEN_BODY_V1}{}", hex(&GOLDEN_CHALLENGE));

    assert_eq!(GOLDEN_BODY_V2, expected);
}

#[test]
fn signing_input_matches_the_golden_vector() {
    let body = encode_body_v2(&golden_lease().body).expect("encodes");

    assert_eq!(
        hex(&signing_input(ProtocolVersion::V2, &body)),
        GOLDEN_SIGNING_INPUT_V2
    );
}

/// V2 signs under its own domain separator, so a V1 verifier cannot be induced
/// to check a V2 body — the signing inputs differ.
#[test]
fn v2_signs_under_its_own_domain() {
    let body = encode_body_v2(&golden_lease().body).expect("encodes");

    assert!(hex(&signing_input(ProtocolVersion::V2, &body)).starts_with(&hex(b"KERN-LEASE-V2")));
    assert_ne!(
        signing_input(ProtocolVersion::V2, &body),
        signing_input(ProtocolVersion::V1, &body)
    );
}

#[test]
fn signature_matches_the_golden_vector() {
    assert_eq!(
        hex(golden_lease().signature.as_bytes()),
        GOLDEN_SIGNATURE_V2
    );
}

#[test]
fn envelope_matches_the_golden_vector() {
    assert_eq!(
        hex(&encode_v2(&golden_lease()).expect("encodes")),
        GOLDEN_ENVELOPE_V2
    );
}

#[test]
fn artifact_identity_matches_the_golden_vector() {
    let body = encode_body_v2(&golden_lease().body).expect("encodes");
    let artifact = AuthorityArtifactId::compute(
        ProtocolVersion::V2,
        &signing_input(ProtocolVersion::V2, &body),
    );

    assert_eq!(hex(artifact.as_bytes()), GOLDEN_ARTIFACT_V2);
}

/// The artifact digest identifies the authenticated authority, not the signature
/// instance, so signature bytes are deliberately not an input.
#[test]
fn artifact_identity_excludes_the_signature() {
    let body = encode_body_v2(&golden_lease().body).expect("encodes");
    let input = signing_input(ProtocolVersion::V2, &body);

    let from_input = AuthorityArtifactId::compute(ProtocolVersion::V2, &input);
    let mut with_signature = input.clone();
    with_signature.extend_from_slice(golden_lease().signature.as_bytes());

    assert_ne!(
        from_input,
        AuthorityArtifactId::compute(ProtocolVersion::V2, &with_signature)
    );
    assert_eq!(hex(from_input.as_bytes()), GOLDEN_ARTIFACT_V2);
}

/// Distinct authority gets a distinct identity.
#[test]
fn artifact_identity_separates_distinct_authority() {
    let body = encode_body_v2(&golden_lease().body).expect("encodes");
    let mut altered = body.clone();
    let last = altered.len() - 1;
    altered[last] ^= 0x01;

    assert_ne!(
        AuthorityArtifactId::compute(
            ProtocolVersion::V2,
            &signing_input(ProtocolVersion::V2, &body)
        ),
        AuthorityArtifactId::compute(
            ProtocolVersion::V2,
            &signing_input(ProtocolVersion::V2, &altered)
        )
    );
}

#[test]
fn golden_bytes_decode_to_the_expected_semantics() {
    let body = decode_body_v2(&unhex(GOLDEN_BODY_V2)).expect("decodes");

    assert_eq!(body.challenge, Challenge::from_bytes(GOLDEN_CHALLENGE));
    assert_eq!(body.core.issuer, IssuerId::new("issuer_dev"));
    assert_eq!(body.core.subject, SubjectId::new("planner_a"));
    assert_eq!(
        body.core.capability,
        CapabilityName::new("navigate").unwrap()
    );
    assert_eq!(body.core.enforcer_session, session());
}

#[test]
fn golden_bytes_reencode_identically() {
    let bytes = unhex(GOLDEN_BODY_V2);
    let decoded = decode_body_v2(&bytes).expect("decodes");

    assert_eq!(encode_body_v2(&decoded).expect("re-encodes"), bytes);
}

#[test]
fn golden_envelope_parses_to_the_golden_parts() {
    let bytes = unhex(GOLDEN_ENVELOPE_V2);
    let parsed = parse(&bytes).expect("parses");

    assert_eq!(parsed.version(), ProtocolVersion::V2);
    assert_eq!(hex(parsed.body_bytes()), GOLDEN_BODY_V2);
    assert_eq!(hex(parsed.signature().as_bytes()), GOLDEN_SIGNATURE_V2);
    assert_eq!(hex(&parsed.signing_input()), GOLDEN_SIGNING_INPUT_V2);
}

#[test]
fn golden_signature_verifies_against_the_development_key() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key_bytes: [u8; 32] =
        unhex("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")
            .try_into()
            .expect("32 bytes");
    let signature_bytes: [u8; 64] = unhex(GOLDEN_SIGNATURE_V2).try_into().expect("64 bytes");

    let key = VerifyingKey::from_bytes(&key_bytes).expect("valid key");
    let signature = Signature::from_bytes(&signature_bytes);

    assert!(key
        .verify(&unhex(GOLDEN_SIGNING_INPUT_V2), &signature)
        .is_ok());
}

// -- ticket validation --------------------------------------------------------

#[test]
fn a_misrouted_ticket_is_refused_before_a_lease_exists() {
    use kern_authority::IssueError;

    let ticket = ChallengeTicket {
        issuer: IssuerId::new("issuer_other"),
        ..golden_ticket()
    };

    assert_eq!(
        issuer().issue_v2(&authorized_operation(), Ttl::from_millis(5_000), &ticket),
        Err(IssueError::TicketIssuerMismatch)
    );
}

#[test]
fn a_ticket_for_another_slot_is_refused() {
    use kern_authority::IssueError;

    for ticket in [
        ChallengeTicket {
            subject: SubjectId::new("planner_b"),
            ..golden_ticket()
        },
        ChallengeTicket {
            device: DeviceId::new("cafe_bot_02"),
            ..golden_ticket()
        },
        ChallengeTicket {
            capability: CapabilityName::new("speak").expect("valid"),
            ..golden_ticket()
        },
    ] {
        assert_eq!(
            issuer().issue_v2(&authorized_operation(), Ttl::from_millis(5_000), &ticket),
            Err(IssueError::TicketBindingMismatch)
        );
    }
}

#[test]
fn v2_issuance_takes_the_session_from_the_ticket() {
    let lease = golden_lease();

    assert_eq!(lease.body.core.enforcer_session, golden_ticket().session);
}

#[test]
fn zero_ttl_is_refused_for_v2_too() {
    use kern_authority::IssueError;

    assert_eq!(
        issuer().issue_v2(
            &authorized_operation(),
            Ttl::from_millis(0),
            &golden_ticket()
        ),
        Err(IssueError::ZeroTtl)
    );
}
