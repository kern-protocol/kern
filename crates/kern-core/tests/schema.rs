//! Schema definition and normalization examples.
//!
//! Normalization is authority-neutral: it decides whether a request describes a
//! real operation, never whether anyone may perform it. Every failure here is a
//! malformed request, not a denial.

use kern_core::{
    ActionProposal, CapabilityName, CapabilitySchema, DeviceId, InvalidId, ParamDomain, ParamName,
    ParamSpec, ParamValue, Requirement, SchemaDefinitionError, SchemaError, SubjectId, Symbol,
};

fn param(name: &str) -> ParamName {
    ParamName::new(name)
}

/// `navigate(destination: Symbol, max_speed: Scalar)`, with an optional
/// `patience` and a defaulted `announce`.
fn navigate_schema() -> CapabilitySchema {
    CapabilitySchema::new(
        CapabilityName::new("navigate").expect("valid capability name"),
        [
            (
                param("destination"),
                ParamSpec::required(ParamDomain::Symbol),
            ),
            (param("max_speed"), ParamSpec::required(ParamDomain::Scalar)),
            (param("patience"), ParamSpec::optional(ParamDomain::Scalar)),
            (
                param("announce"),
                ParamSpec::defaulted(ParamDomain::Symbol, ParamValue::Symbol(Symbol::new("off"))),
            ),
        ],
    )
    .expect("well-formed schema")
}

fn navigate_proposal() -> ActionProposal {
    ActionProposal::new(
        SubjectId::new("planner_a"),
        DeviceId::new("cafe_bot_01"),
        CapabilityName::new("navigate").expect("valid capability name"),
    )
    .with_param(
        param("destination"),
        ParamValue::Symbol(Symbol::new("cafe")),
    )
    .with_param(param("max_speed"), ParamValue::Scalar(400))
}

// -- schema definition --------------------------------------------------------

/// The invariant lives at the identifier boundary, so an invalid
/// `CapabilityName` never exists for a schema or a registry to re-check.
#[test]
fn empty_capability_name_cannot_be_constructed() {
    assert_eq!(CapabilityName::new(""), Err(InvalidId::Empty));
}

#[test]
fn duplicate_parameter_is_rejected() {
    let result = CapabilitySchema::new(
        CapabilityName::new("navigate").expect("valid capability name"),
        [
            (param("max_speed"), ParamSpec::required(ParamDomain::Scalar)),
            (param("max_speed"), ParamSpec::optional(ParamDomain::Scalar)),
        ],
    );

    assert_eq!(
        result,
        Err(SchemaDefinitionError::DuplicateParameter {
            param: param("max_speed")
        })
    );
}

/// A default from the wrong domain is caught when the schema is defined, not
/// when a request arrives. An unusable schema can never reach a registry.
#[test]
fn default_from_the_wrong_domain_is_rejected() {
    let result = CapabilitySchema::new(
        CapabilityName::new("navigate").expect("valid capability name"),
        [(
            param("max_speed"),
            ParamSpec::defaulted(
                ParamDomain::Scalar,
                ParamValue::Symbol(Symbol::new("quickly")),
            ),
        )],
    );

    assert_eq!(
        result,
        Err(SchemaDefinitionError::DefaultDomainMismatch {
            param: param("max_speed"),
            expected: ParamDomain::Scalar,
        })
    );
}

// -- normalization ------------------------------------------------------------

#[test]
fn valid_proposal_normalizes() {
    let normalized = navigate_schema()
        .normalize(&navigate_proposal())
        .expect("valid proposal");

    assert_eq!(normalized.actor(), &SubjectId::new("planner_a"));
    assert_eq!(normalized.device(), &DeviceId::new("cafe_bot_01"));
    assert_eq!(
        normalized.capability(),
        &CapabilityName::new("navigate").expect("valid capability name")
    );
}

/// Defaults are capability semantics. Normalization inserts them, and policy
/// then checks the inserted value exactly as if the caller had supplied it.
#[test]
fn omitted_default_is_inserted_during_normalization() {
    let normalized = navigate_schema()
        .normalize(&navigate_proposal())
        .expect("valid proposal");

    assert_eq!(
        normalized.params().get(&param("announce")),
        Some(&ParamValue::Symbol(Symbol::new("off")))
    );
}

/// A supplied value wins over the default. Normalization never overwrites.
#[test]
fn supplied_value_overrides_the_default() {
    let proposal =
        navigate_proposal().with_param(param("announce"), ParamValue::Symbol(Symbol::new("chime")));

    let normalized = navigate_schema().normalize(&proposal).expect("valid");

    assert_eq!(
        normalized.params().get(&param("announce")),
        Some(&ParamValue::Symbol(Symbol::new("chime")))
    );
}

/// An omitted optional parameter stays omitted. It is not defaulted, and it is
/// not silently treated as satisfying anything.
#[test]
fn omitted_optional_stays_absent() {
    let normalized = navigate_schema()
        .normalize(&navigate_proposal())
        .expect("valid proposal");

    assert!(!normalized.params().contains_key(&param("patience")));
}

#[test]
fn missing_required_parameter_is_rejected() {
    let proposal = ActionProposal::new(
        SubjectId::new("planner_a"),
        DeviceId::new("cafe_bot_01"),
        CapabilityName::new("navigate").expect("valid capability name"),
    )
    .with_param(
        param("destination"),
        ParamValue::Symbol(Symbol::new("cafe")),
    );

    assert_eq!(
        navigate_schema().normalize(&proposal),
        Err(SchemaError::MissingRequiredParameter {
            param: param("max_speed")
        })
    );
}

/// A parameter no schema declares is a parameter no policy constrains, so it is
/// refused rather than ignored.
#[test]
fn unknown_parameter_is_rejected() {
    let proposal = navigate_proposal().with_param(param("motor_voltage"), ParamValue::Scalar(24));

    assert_eq!(
        navigate_schema().normalize(&proposal),
        Err(SchemaError::UnknownParameter {
            param: param("motor_voltage")
        })
    );
}

#[test]
fn wrong_parameter_domain_is_rejected() {
    let proposal =
        navigate_proposal().with_param(param("max_speed"), ParamValue::Symbol(Symbol::new("fast")));

    assert_eq!(
        navigate_schema().normalize(&proposal),
        Err(SchemaError::WrongDomain {
            param: param("max_speed"),
            expected: ParamDomain::Scalar,
        })
    );
}

#[test]
fn capability_mismatch_is_rejected() {
    let proposal = ActionProposal::new(
        SubjectId::new("planner_a"),
        DeviceId::new("arm_01"),
        CapabilityName::new("pick").expect("valid capability name"),
    );

    assert_eq!(
        navigate_schema().normalize(&proposal),
        Err(SchemaError::CapabilityMismatch {
            expected: CapabilityName::new("navigate").expect("valid capability name"),
            found: CapabilityName::new("pick").expect("valid capability name"),
        })
    );
}

/// Normalization is pure: the same schema and proposal always give the same
/// answer, and nothing about the subject, the policies, or the time of day
/// enters into it.
#[test]
fn normalization_is_deterministic() {
    let schema = navigate_schema();
    let proposal = navigate_proposal();

    assert_eq!(schema.normalize(&proposal), schema.normalize(&proposal));
}

/// One schema, many devices. Device identity lives in the registry, never here.
#[test]
fn one_schema_serves_many_devices() {
    let schema = navigate_schema();

    let first = schema.normalize(&navigate_proposal()).expect("valid");
    let mut raw = navigate_proposal();
    raw.device = DeviceId::new("cafe_bot_02");
    let second = schema.normalize(&raw).expect("valid");

    assert_eq!(first.params(), second.params());
    assert_ne!(first.device(), second.device());
}

/// The declaration round-trips, so a registry can key on what the schema says
/// about itself.
#[test]
fn schema_reports_its_own_identity_and_parameters() {
    let schema = navigate_schema();

    assert_eq!(
        schema.name(),
        &CapabilityName::new("navigate").expect("valid capability name")
    );
    assert_eq!(schema.params().count(), 4);
    assert_eq!(
        schema
            .params()
            .find(|(name, _)| *name == &param("patience"))
            .map(|(_, spec)| &spec.requirement),
        Some(&Requirement::Optional)
    );
}
