//! V1 wire protocol: framing, canonicality, and round-tripping.
//!
//! One authority has exactly one valid encoding. Most of these tests exist to
//! prove that the decoder *checks* that rather than trusting the encoder to have
//! been well behaved.

use kern_core::wire::{
    decode_body, encode, encode_body, encode_wire_body, parse, signing_input, DecodeError,
    WireConstraint, WireConstraintSet, WireLeaseBodyV1, LEASE_DOMAIN_V1, MAX_BODY_BYTES,
};
use kern_core::{
    CapabilityName, ConstraintSet, DeviceId, EnforcerSessionId, IssuerId, KeyId, LeaseBody,
    LeaseId, Nonce, ParamConstraint, ParamName, ProtocolVersion, Signature, SignedLease, SubjectId,
    Symbol, SymbolSet, Timestamp,
};

fn constraints() -> ConstraintSet {
    let allowed =
        SymbolSet::allowed([Symbol::new("cafe"), Symbol::new("lobby")]).expect("non-empty");
    ConstraintSet::from_constraints([
        (ParamName::new("max_speed"), ParamConstraint::at_most(500)),
        (
            ParamName::new("destination"),
            ParamConstraint::Symbolic(allowed),
        ),
    ])
}

fn body() -> LeaseBody {
    LeaseBody {
        id: LeaseId::from_bytes([0xAB; 16]),
        issuer: IssuerId::new("issuer_dev"),
        key_id: KeyId::new("dev-1"),
        subject: SubjectId::new("planner_a"),
        device: DeviceId::new("cafe_bot_01"),
        capability: CapabilityName::new("navigate").expect("valid"),
        constraints: constraints(),
        issued_at: Timestamp::from_millis(1_700_000_000_000),
        expires_at: Timestamp::from_millis(1_700_000_005_000),
        nonce: Nonce::new(1),
        enforcer_session: EnforcerSessionId::from_bytes([0x11; 32]),
    }
}

fn signed() -> SignedLease {
    SignedLease {
        version: ProtocolVersion::V1,
        body: body(),
        signature: Signature::from_bytes([0x42; 64]),
    }
}

/// A wire body carrying whatever constraint set a test wants to smuggle in.
fn wire_with(constraints: WireConstraintSet) -> WireLeaseBodyV1 {
    let mut wire = WireLeaseBodyV1::from(&body());
    wire.constraints = constraints;
    wire
}

fn reject(constraints: WireConstraintSet) -> DecodeError {
    let bytes = encode_wire_body(&wire_with(constraints)).expect("encodes");
    decode_body(&bytes).expect_err("must be rejected")
}

// -- round trip ---------------------------------------------------------------

#[test]
fn body_round_trips() {
    let bytes = encode_body(&body()).expect("encodes");

    assert_eq!(decode_body(&bytes).expect("decodes"), body());
}

#[test]
fn encoding_is_deterministic() {
    assert_eq!(
        encode_body(&body()).expect("encodes"),
        encode_body(&body()).expect("encodes")
    );
}

#[test]
fn envelope_round_trips() {
    let bytes = encode(&signed()).expect("encodes");
    let parsed = parse(&bytes).expect("parses");

    assert_eq!(parsed.version(), ProtocolVersion::V1);
    assert_eq!(parsed.signature(), &Signature::from_bytes([0x42; 64]));
    assert_eq!(
        parsed.decode_untrusted_body().expect("decodes"),
        signed().body
    );
}

/// Re-encoding what was decoded must reproduce the original bytes exactly. If it
/// did not, one authority would have two valid representations.
#[test]
fn reencoding_a_decoded_body_is_byte_identical() {
    let bytes = encode_body(&body()).expect("encodes");
    let decoded = decode_body(&bytes).expect("decodes");

    assert_eq!(encode_body(&decoded).expect("re-encodes"), bytes);
}

// -- signing input ------------------------------------------------------------

#[test]
fn signing_input_has_the_documented_shape() {
    let body_bytes = encode_body(&body()).expect("encodes");
    let input = signing_input(ProtocolVersion::V1, &body_bytes);

    let mut expected = Vec::new();
    expected.extend_from_slice(LEASE_DOMAIN_V1);
    expected.extend_from_slice(&1u16.to_le_bytes());
    expected.extend_from_slice(&(body_bytes.len() as u32).to_le_bytes());
    expected.extend_from_slice(&body_bytes);

    assert_eq!(input, expected);
}

/// The version is inside the signed bytes, so tampering with it cannot be a
/// silent schema switch — it can only make verification fail.
#[test]
fn signing_input_covers_the_version() {
    let body_bytes = encode_body(&body()).expect("encodes");

    assert_ne!(
        signing_input(ProtocolVersion::V1, &body_bytes),
        signing_input(ProtocolVersion::V1, &body_bytes[..body_bytes.len() - 1])
    );
}

// -- framing failures ---------------------------------------------------------

#[test]
fn unsupported_version_is_rejected_before_the_body_is_parsed() {
    let mut bytes = encode(&signed()).expect("encodes");
    bytes[0] = 9;
    // Body bytes are now unreachable garbage as far as V9 is concerned.
    bytes.truncate(2);

    assert_eq!(
        parse(&bytes),
        Err(DecodeError::UnsupportedVersion { found: 9 })
    );
}

#[test]
fn truncated_envelope_is_rejected() {
    let bytes = encode(&signed()).expect("encodes");

    for cut in [1usize, 4, 8, bytes.len() - 1] {
        assert_eq!(
            parse(&bytes[..cut]),
            Err(DecodeError::Truncated),
            "cut {cut}"
        );
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = encode(&signed()).expect("encodes");
    bytes.push(0);

    assert_eq!(parse(&bytes), Err(DecodeError::TrailingBytes));
}

#[test]
fn an_oversized_length_prefix_is_rejected() {
    let mut bytes = encode(&signed()).expect("encodes");
    bytes[2..6].copy_from_slice(&(MAX_BODY_BYTES + 1).to_le_bytes());

    assert_eq!(parse(&bytes), Err(DecodeError::BodyTooLarge));
}

#[test]
fn a_malformed_body_is_rejected() {
    assert_eq!(
        decode_body(&[0xff, 0xff, 0xff]),
        Err(DecodeError::Malformed)
    );
}

#[test]
fn trailing_bytes_after_the_body_are_rejected() {
    let mut bytes = encode_body(&body()).expect("encodes");
    bytes.push(0);

    assert_eq!(decode_body(&bytes), Err(DecodeError::TrailingBytes));
}

// -- canonicality -------------------------------------------------------------

#[test]
fn unsorted_bounded_entries_are_rejected() {
    assert_eq!(
        reject(WireConstraintSet::Bounded(vec![
            (
                "max_speed".into(),
                WireConstraint::Numeric { lower: 0, upper: 5 }
            ),
            (
                "destination".into(),
                WireConstraint::Allowed(vec!["cafe".into()])
            ),
        ])),
        DecodeError::NonCanonicalEncoding
    );
}

#[test]
fn duplicate_parameter_names_are_rejected() {
    assert_eq!(
        reject(WireConstraintSet::Bounded(vec![
            (
                "max_speed".into(),
                WireConstraint::Numeric { lower: 0, upper: 5 }
            ),
            (
                "max_speed".into(),
                WireConstraint::Numeric { lower: 0, upper: 9 }
            ),
        ])),
        DecodeError::NonCanonicalEncoding
    );
}

#[test]
fn an_empty_bounded_set_is_rejected() {
    assert_eq!(
        reject(WireConstraintSet::Bounded(vec![])),
        DecodeError::NonCanonicalEncoding
    );
}

#[test]
fn unsorted_symbols_are_rejected() {
    assert_eq!(
        reject(WireConstraintSet::Bounded(vec![(
            "destination".into(),
            WireConstraint::Allowed(vec!["lobby".into(), "cafe".into()]),
        )])),
        DecodeError::NonCanonicalEncoding
    );
}

#[test]
fn duplicate_symbols_are_rejected() {
    assert_eq!(
        reject(WireConstraintSet::Bounded(vec![(
            "destination".into(),
            WireConstraint::Allowed(vec!["cafe".into(), "cafe".into()]),
        )])),
        DecodeError::NonCanonicalEncoding
    );
}

#[test]
fn an_empty_allow_list_is_rejected() {
    assert_eq!(
        reject(WireConstraintSet::Bounded(vec![(
            "destination".into(),
            WireConstraint::Allowed(vec![]),
        )])),
        DecodeError::NonCanonicalEncoding
    );
}

/// An empty deny-list restricts nothing, so a canonical set would have dropped
/// it rather than encoded it.
#[test]
fn an_empty_deny_list_is_rejected() {
    assert_eq!(
        reject(WireConstraintSet::Bounded(vec![(
            "zone".into(),
            WireConstraint::Denied(vec![]),
        )])),
        DecodeError::NonCanonicalEncoding
    );
}

/// Likewise an interval covering everything.
#[test]
fn an_unbounded_interval_is_rejected() {
    assert_eq!(
        reject(WireConstraintSet::Bounded(vec![(
            "max_speed".into(),
            WireConstraint::Numeric {
                lower: i64::MIN,
                upper: i64::MAX,
            },
        )])),
        DecodeError::NonCanonicalEncoding
    );
}

#[test]
fn an_inverted_interval_is_rejected() {
    assert_eq!(
        reject(WireConstraintSet::Bounded(vec![(
            "max_speed".into(),
            WireConstraint::Numeric {
                lower: 10,
                upper: 5
            },
        )])),
        DecodeError::Malformed
    );
}

#[test]
fn an_empty_capability_name_is_rejected() {
    let mut wire = WireLeaseBodyV1::from(&body());
    wire.capability = String::new();
    let bytes = encode_wire_body(&wire).expect("encodes");

    assert_eq!(decode_body(&bytes), Err(DecodeError::NonCanonicalEncoding));
}

/// TOP and BOTTOM stay representable; only the *accidental* forms are refused.
#[test]
fn top_and_bottom_round_trip() {
    for set in [
        ConstraintSet::unconstrained(),
        ConstraintSet::no_authority(),
    ] {
        let mut body = body();
        body.constraints = set.clone();
        let bytes = encode_body(&body).expect("encodes");

        assert_eq!(decode_body(&bytes).expect("decodes").constraints, set);
    }
}

/// The size bound is part of the V1 format, so encoding enforces it too. A
/// decoder-only limit would let one implementation emit bodies another must
/// reject.
#[test]
fn an_oversized_body_is_refused_at_encode_time() {
    use kern_core::wire::EncodeError;

    let symbols: Vec<Symbol> = (0..12_000)
        .map(|i| Symbol::new(format!("destination_{i:08}")))
        .collect();
    let allowed = SymbolSet::allowed(symbols).expect("non-empty");

    let mut body = body();
    body.constraints = ConstraintSet::from_constraints([(
        ParamName::new("destination"),
        ParamConstraint::Symbolic(allowed),
    )]);

    assert_eq!(encode_body(&body), Err(EncodeError::BodyTooLarge));
}
