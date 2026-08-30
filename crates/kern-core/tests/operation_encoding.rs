//! Canonical encoding of a normalized operation.
//!
//! These bytes are a digest preimage, not authority. Nothing signs them and
//! nothing parses them back — but one operation must have exactly one encoding,
//! or a digest over them would not name it.

use kern_core::wire::encode_operation;
use kern_core::{
    ActionProposal, CapabilityName, CapabilitySchema, DeviceId, NormalizedActionProposal,
    ParamDomain, ParamName, ParamSpec, ParamValue, SubjectId, Symbol,
};

fn schema() -> CapabilitySchema {
    CapabilitySchema::new(
        CapabilityName::new("navigate").expect("valid"),
        [
            (
                ParamName::new("destination"),
                ParamSpec::required(ParamDomain::Symbol),
            ),
            (
                ParamName::new("max_speed"),
                ParamSpec::required(ParamDomain::Scalar),
            ),
            (
                ParamName::new("approach"),
                ParamSpec::defaulted(
                    ParamDomain::Symbol,
                    ParamValue::Symbol(Symbol::new("front")),
                ),
            ),
        ],
    )
    .expect("well-formed schema")
}

/// Parameters are supplied in the opposite order to the one they encode in, so
/// the test would fail if encoding followed insertion order.
fn operation(speed: i64, destination: &str) -> NormalizedActionProposal {
    let proposal = ActionProposal::new(
        SubjectId::new("planner_a"),
        DeviceId::new("cafe_bot_01"),
        CapabilityName::new("navigate").expect("valid"),
    )
    .with_param(ParamName::new("max_speed"), ParamValue::Scalar(speed))
    .with_param(
        ParamName::new("destination"),
        ParamValue::Symbol(Symbol::new(destination)),
    );
    schema().normalize(&proposal).expect("schema-valid")
}

#[test]
fn encoding_is_deterministic_and_order_independent() {
    let first = encode_operation(&operation(400, "cafe")).expect("encodes");
    let second = encode_operation(&operation(400, "cafe")).expect("encodes");
    assert_eq!(first, second);
}

/// Frozen. Changing these bytes changes every command digest ever recorded.
#[test]
fn the_operation_encoding_is_a_golden_vector() {
    let bytes = encode_operation(&operation(400, "cafe")).expect("encodes");
    assert_eq!(
        bytes,
        vec![
            0x09, 0x70, 0x6c, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x5f, 0x61, 0x0b, 0x63, 0x61, 0x66,
            0x65, 0x5f, 0x62, 0x6f, 0x74, 0x5f, 0x30, 0x31, 0x08, 0x6e, 0x61, 0x76, 0x69, 0x67,
            0x61, 0x74, 0x65, 0x03, 0x08, 0x61, 0x70, 0x70, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x01,
            0x05, 0x66, 0x72, 0x6f, 0x6e, 0x74, 0x0b, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61,
            0x74, 0x69, 0x6f, 0x6e, 0x01, 0x04, 0x63, 0x61, 0x66, 0x65, 0x09, 0x6d, 0x61, 0x78,
            0x5f, 0x73, 0x70, 0x65, 0x65, 0x64, 0x00, 0xa0, 0x06,
        ]
    );
}

/// A schema default is part of what the operation means, so it is part of what
/// the encoding names.
#[test]
fn defaults_are_part_of_the_encoding() {
    let with_default = operation(400, "cafe");
    let explicit = {
        let proposal = ActionProposal::new(
            SubjectId::new("planner_a"),
            DeviceId::new("cafe_bot_01"),
            CapabilityName::new("navigate").expect("valid"),
        )
        .with_param(ParamName::new("max_speed"), ParamValue::Scalar(400))
        .with_param(
            ParamName::new("destination"),
            ParamValue::Symbol(Symbol::new("cafe")),
        )
        .with_param(
            ParamName::new("approach"),
            ParamValue::Symbol(Symbol::new("rear")),
        );
        schema().normalize(&proposal).expect("schema-valid")
    };

    assert_ne!(
        encode_operation(&with_default).expect("encodes"),
        encode_operation(&explicit).expect("encodes")
    );
}

#[test]
fn every_identity_field_changes_the_encoding() {
    let base = encode_operation(&operation(400, "cafe")).expect("encodes");
    assert_ne!(
        base,
        encode_operation(&operation(401, "cafe")).expect("encodes")
    );
    assert_ne!(
        base,
        encode_operation(&operation(400, "lobby")).expect("encodes")
    );
}

#[test]
fn the_golden_vector_is_not_vacuous() {
    let bytes = encode_operation(&operation(400, "cafe")).expect("encodes");
    assert_eq!(bytes.len(), 79);
    assert_eq!(&bytes[..10], b"\x09planner_a");
}
