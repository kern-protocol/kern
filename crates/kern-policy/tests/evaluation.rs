//! End-to-end evaluation examples: proposal in, decision out.

use kern_core::{
    ActionProposal, CapabilityName, CapabilitySchema, ConstraintSet, DeviceId, ParamConstraint,
    ParamDomain, ParamName, ParamSpec, ParamValue, PolicyDecision, SchemaError, SubjectId, Symbol,
    SymbolSet,
};
use kern_policy::{
    Authority, CapabilityRegistry, Policy, PolicyError, PolicyId, PolicySet, PolicySetError,
    RegistryError, Selector,
};

fn param(name: &str) -> ParamName {
    ParamName::new(name)
}

fn sym(name: &str) -> Symbol {
    Symbol::new(name)
}

fn subject(name: &str) -> SubjectId {
    SubjectId::new(name)
}

fn device(name: &str) -> DeviceId {
    DeviceId::new(name)
}

fn capability(name: &str) -> CapabilityName {
    CapabilityName::new(name).expect("valid capability name")
}

/// `navigate(destination: Symbol, max_speed: Scalar, announce: Symbol = off,
/// patience: Scalar?)`
fn navigate_schema() -> CapabilitySchema {
    CapabilitySchema::new(
        capability("navigate"),
        [
            (
                param("destination"),
                ParamSpec::required(ParamDomain::Symbol),
            ),
            (param("max_speed"), ParamSpec::required(ParamDomain::Scalar)),
            (
                param("announce"),
                ParamSpec::defaulted(ParamDomain::Symbol, ParamValue::Symbol(sym("off"))),
            ),
            (param("patience"), ParamSpec::optional(ParamDomain::Scalar)),
        ],
    )
    .expect("well-formed schema")
}

fn wait_schema() -> CapabilitySchema {
    CapabilitySchema::new(
        capability("wait"),
        [(
            param("duration_ms"),
            ParamSpec::required(ParamDomain::Scalar),
        )],
    )
    .expect("well-formed schema")
}

/// Two mobile robots understanding `navigate` and `wait`, and an arm that does
/// not. Understanding an operation is not authority to request it.
fn registry() -> CapabilityRegistry {
    let mut registry = CapabilityRegistry::new();
    registry
        .register(device("cafe_bot_01"), navigate_schema())
        .expect("first registration");
    registry
        .register(device("cafe_bot_01"), wait_schema())
        .expect("distinct capability");
    registry
        .register(device("cafe_bot_02"), navigate_schema())
        .expect("one schema, many devices");
    registry
}

fn authority(policies: Vec<Policy>) -> Authority {
    Authority::new(
        registry(),
        PolicySet::from_policies(policies).expect("distinct policy ids"),
    )
}

/// `max_speed <= limit`, plus an allow-list of destinations.
fn navigate_policy(id: &str, actor: &str, max_speed: i64, destinations: &[&str]) -> Policy {
    let allowed =
        SymbolSet::allowed(destinations.iter().map(|d| sym(d))).expect("non-empty allow-list");
    Policy::new(
        PolicyId::new(id),
        Selector::Exactly(subject(actor)),
        Selector::Exactly(device("cafe_bot_01")),
        Selector::Exactly(capability("navigate")),
        ConstraintSet::from_constraints([
            (param("max_speed"), ParamConstraint::at_most(max_speed)),
            (param("destination"), ParamConstraint::Symbolic(allowed)),
        ]),
    )
    .expect("constrained policy")
}

fn navigate_proposal(actor: &str, dev: &str, speed: i64, destination: &str) -> ActionProposal {
    ActionProposal::new(subject(actor), device(dev), capability("navigate"))
        .with_param(param("destination"), ParamValue::Symbol(sym(destination)))
        .with_param(param("max_speed"), ParamValue::Scalar(speed))
}

// -- invalid requests are not denials -----------------------------------------

#[test]
fn unknown_device_is_an_error_not_a_denial() {
    let result =
        authority(vec![]).evaluate(&navigate_proposal("planner_a", "ghost_bot", 400, "cafe"));

    assert_eq!(
        result,
        Err(RegistryError::UnknownDevice {
            device: device("ghost_bot")
        }
        .into())
    );
}

#[test]
fn unknown_capability_is_an_error_not_a_denial() {
    let proposal = ActionProposal::new(
        subject("planner_a"),
        device("cafe_bot_01"),
        capability("pick"),
    );

    assert_eq!(
        authority(vec![]).evaluate(&proposal),
        Err(RegistryError::UnknownCapability {
            device: device("cafe_bot_01"),
            capability: capability("pick"),
        }
        .into())
    );
}

#[test]
fn missing_required_parameter_is_an_error() {
    let proposal = ActionProposal::new(
        subject("planner_a"),
        device("cafe_bot_01"),
        capability("navigate"),
    )
    .with_param(param("destination"), ParamValue::Symbol(sym("cafe")));

    assert_eq!(
        authority(vec![]).evaluate(&proposal),
        Err(SchemaError::MissingRequiredParameter {
            param: param("max_speed")
        }
        .into())
    );
}

#[test]
fn unknown_parameter_is_an_error() {
    let proposal = navigate_proposal("planner_a", "cafe_bot_01", 400, "cafe")
        .with_param(param("motor_voltage"), ParamValue::Scalar(24));

    assert_eq!(
        authority(vec![]).evaluate(&proposal),
        Err(SchemaError::UnknownParameter {
            param: param("motor_voltage")
        }
        .into())
    );
}

#[test]
fn wrong_parameter_type_is_an_error() {
    let proposal = ActionProposal::new(
        subject("planner_a"),
        device("cafe_bot_01"),
        capability("navigate"),
    )
    .with_param(param("destination"), ParamValue::Symbol(sym("cafe")))
    .with_param(param("max_speed"), ParamValue::Symbol(sym("quickly")));

    assert_eq!(
        authority(vec![]).evaluate(&proposal),
        Err(SchemaError::WrongDomain {
            param: param("max_speed"),
            expected: ParamDomain::Scalar,
        }
        .into())
    );
}

// -- fail closed --------------------------------------------------------------

/// The device understands `navigate`. Nobody is authorized to ask for it.
#[test]
fn no_applicable_policy_denies() {
    let evaluation = authority(vec![])
        .evaluate(&navigate_proposal("planner_a", "cafe_bot_01", 400, "cafe"))
        .expect("well-formed request");

    assert_eq!(evaluation.decision(), &PolicyDecision::Denied);
    assert!(evaluation.applied().is_empty());
}

/// The two denial causes are distinguishable, which a later trace will need.
#[test]
fn denial_causes_are_distinguishable() {
    let no_grant = authority(vec![])
        .evaluate(&navigate_proposal("planner_a", "cafe_bot_01", 400, "cafe"))
        .expect("well-formed");
    assert!(no_grant.applied().is_empty());

    let contradictory = authority(vec![
        navigate_policy("speed_cap", "planner_a", 500, &["cafe"]),
        navigate_policy("night_shift", "planner_a", 500, &["lobby"]),
    ])
    .evaluate(&navigate_proposal("planner_a", "cafe_bot_01", 400, "cafe"))
    .expect("well-formed");

    assert_eq!(contradictory.decision(), &PolicyDecision::Denied);
    assert_eq!(
        contradictory.applied().to_vec(),
        vec![PolicyId::new("night_shift"), PolicyId::new("speed_cap")]
    );
}

#[test]
fn subject_mismatch_denies() {
    let evaluation = authority(vec![navigate_policy(
        "delivery",
        "planner_a",
        500,
        &["cafe"],
    )])
    .evaluate(&navigate_proposal("planner_b", "cafe_bot_01", 400, "cafe"))
    .expect("well-formed");

    assert_eq!(evaluation.decision(), &PolicyDecision::Denied);
    assert!(evaluation.applied().is_empty());
}

#[test]
fn device_mismatch_denies() {
    let evaluation = authority(vec![navigate_policy(
        "delivery",
        "planner_a",
        500,
        &["cafe"],
    )])
    .evaluate(&navigate_proposal("planner_a", "cafe_bot_02", 400, "cafe"))
    .expect("well-formed");

    assert_eq!(evaluation.decision(), &PolicyDecision::Denied);
}

#[test]
fn capability_mismatch_denies() {
    let proposal = ActionProposal::new(
        subject("planner_a"),
        device("cafe_bot_01"),
        capability("wait"),
    )
    .with_param(param("duration_ms"), ParamValue::Scalar(1000));

    let evaluation = authority(vec![navigate_policy(
        "delivery",
        "planner_a",
        500,
        &["cafe"],
    )])
    .evaluate(&proposal)
    .expect("well-formed");

    assert_eq!(evaluation.decision(), &PolicyDecision::Denied);
}

#[test]
fn non_applicable_policy_is_ignored() {
    let with_extra = authority(vec![
        navigate_policy("delivery", "planner_a", 500, &["cafe", "lobby"]),
        navigate_policy("other_subject", "planner_b", 100, &["cafe"]),
    ])
    .evaluate(&navigate_proposal("planner_a", "cafe_bot_01", 400, "cafe"))
    .expect("well-formed");

    assert!(with_extra.decision().is_authorized());
    assert_eq!(
        with_extra.applied().to_vec(),
        vec![PolicyId::new("delivery")]
    );
}

// -- authorization ------------------------------------------------------------

#[test]
fn one_applicable_policy_authorizes_within_bounds() {
    let evaluation = authority(vec![navigate_policy(
        "delivery",
        "planner_a",
        500,
        &["cafe", "lobby"],
    )])
    .evaluate(&navigate_proposal("planner_a", "cafe_bot_01", 400, "cafe"))
    .expect("well-formed");

    assert!(evaluation.decision().is_authorized());
    assert_eq!(
        evaluation.applied().to_vec(),
        vec![PolicyId::new("delivery")]
    );
}

#[test]
fn multiple_applicable_policies_compose_to_the_tightest() {
    let evaluator = authority(vec![
        navigate_policy("delivery", "planner_a", 500, &["cafe", "lobby"]),
        navigate_policy("night_shift", "planner_a", 200, &["cafe"]),
    ]);

    let within = evaluator
        .evaluate(&navigate_proposal("planner_a", "cafe_bot_01", 150, "cafe"))
        .expect("well-formed");
    assert!(within.decision().is_authorized());

    // Allowed by `delivery` alone, refused once `night_shift` composes in.
    let over = evaluator
        .evaluate(&navigate_proposal("planner_a", "cafe_bot_01", 400, "cafe"))
        .expect("well-formed");
    assert!(!over.decision().is_authorized());
    assert_eq!(
        over.applied().to_vec(),
        vec![PolicyId::new("delivery"), PolicyId::new("night_shift")]
    );
}

/// Over-reaching returns the bounds that would be granted. It is advisory: the
/// proposal is not rewritten to fit.
#[test]
fn proposal_outside_authority_returns_grantable_bounds() {
    let evaluation = authority(vec![navigate_policy(
        "delivery",
        "planner_a",
        500,
        &["cafe"],
    )])
    .evaluate(&navigate_proposal("planner_a", "cafe_bot_01", 900, "cafe"))
    .expect("well-formed");

    match evaluation.decision() {
        PolicyDecision::NotAuthorizedAsProposed { grantable } => {
            assert_eq!(
                grantable.get(&param("max_speed")),
                Some(&ParamConstraint::at_most(500))
            );
        }
        other => panic!("expected NotAuthorizedAsProposed, got {other:?}"),
    }
}

#[test]
fn out_of_scope_destination_is_not_authorized() {
    let evaluation = authority(vec![navigate_policy(
        "delivery",
        "planner_a",
        500,
        &["cafe"],
    )])
    .evaluate(&navigate_proposal(
        "planner_a",
        "cafe_bot_01",
        400,
        "storage",
    ))
    .expect("well-formed");

    assert!(!evaluation.decision().is_authorized());
}

// -- ordering and determinism -------------------------------------------------

#[test]
fn policy_insertion_order_does_not_change_the_decision() {
    let forward = authority(vec![
        navigate_policy("delivery", "planner_a", 500, &["cafe", "lobby"]),
        navigate_policy("night_shift", "planner_a", 200, &["cafe"]),
    ])
    .evaluate(&navigate_proposal("planner_a", "cafe_bot_01", 400, "cafe"))
    .expect("well-formed");

    let reversed = authority(vec![
        navigate_policy("night_shift", "planner_a", 200, &["cafe"]),
        navigate_policy("delivery", "planner_a", 500, &["cafe", "lobby"]),
    ])
    .evaluate(&navigate_proposal("planner_a", "cafe_bot_01", 400, "cafe"))
    .expect("well-formed");

    assert_eq!(forward, reversed);
}

// -- schema and policy interaction --------------------------------------------

/// A schema default is checked by policy exactly as a supplied value would be.
#[test]
fn schema_default_is_subject_to_policy() {
    let deny_announce = Policy::new(
        PolicyId::new("quiet_hours"),
        Selector::Exactly(subject("planner_a")),
        Selector::Exactly(device("cafe_bot_01")),
        Selector::Exactly(capability("navigate")),
        ConstraintSet::from_constraints([(
            param("announce"),
            ParamConstraint::Symbolic(SymbolSet::denied([sym("off")])),
        )]),
    )
    .expect("constrained policy");

    // `announce` was never supplied; normalization inserted `off`, and policy
    // refuses it just as if the caller had written it.
    let evaluation = authority(vec![deny_announce])
        .evaluate(&navigate_proposal("planner_a", "cafe_bot_01", 400, "cafe"))
        .expect("well-formed");

    assert!(!evaluation.decision().is_authorized());
    assert_eq!(
        evaluation.proposal().params().get(&param("announce")),
        Some(&ParamValue::Symbol(sym("off")))
    );
}

/// Schema optionality is not a policy exemption. `patience` may be omitted as
/// far as the schema is concerned, and a policy constraining it still refuses
/// the proposal that omits it.
#[test]
fn optional_parameter_absent_is_refused_by_a_constraint_on_it() {
    let bound_patience = Policy::new(
        PolicyId::new("patience_cap"),
        Selector::Exactly(subject("planner_a")),
        Selector::Exactly(device("cafe_bot_01")),
        Selector::Exactly(capability("navigate")),
        ConstraintSet::from_constraints([(param("patience"), ParamConstraint::at_most(5000))]),
    )
    .expect("constrained policy");

    let evaluation = authority(vec![bound_patience])
        .evaluate(&navigate_proposal("planner_a", "cafe_bot_01", 400, "cafe"))
        .expect("well-formed");

    assert!(!evaluation
        .proposal()
        .params()
        .contains_key(&param("patience")));
    assert!(!evaluation.decision().is_authorized());
}

// -- unbounded authority ------------------------------------------------------

/// An empty bounds block must not become "everything permitted".
#[test]
fn implicitly_unbounded_policy_is_rejected() {
    let result = Policy::new(
        PolicyId::new("oops"),
        Selector::Any,
        Selector::Any,
        Selector::Any,
        ConstraintSet::from_constraints([]),
    );

    assert_eq!(
        result,
        Err(PolicyError::ImplicitUnboundedAuthority {
            id: PolicyId::new("oops")
        })
    );
}

/// Unbounded authority stays expressible, but only on purpose.
#[test]
fn explicit_unbounded_policy_grants_within_the_schema() {
    let evaluation = authority(vec![Policy::unbounded(
        PolicyId::new("operator_override"),
        Selector::Exactly(subject("planner_a")),
        Selector::Any,
        Selector::Any,
    )])
    .evaluate(&navigate_proposal(
        "planner_a",
        "cafe_bot_01",
        9_000,
        "storage",
    ))
    .expect("well-formed");

    assert!(evaluation.decision().is_authorized());
}

/// Even an unbounded grant cannot authorize a malformed request. Schema
/// validation happens first and is authority-neutral.
#[test]
fn unbounded_policy_does_not_bypass_schema_validation() {
    let proposal = navigate_proposal("planner_a", "cafe_bot_01", 400, "cafe")
        .with_param(param("motor_voltage"), ParamValue::Scalar(24));

    let result = authority(vec![Policy::unbounded(
        PolicyId::new("operator_override"),
        Selector::Any,
        Selector::Any,
        Selector::Any,
    )])
    .evaluate(&proposal);

    assert!(result.is_err());
}

// -- registry and policy set invariants ---------------------------------------

#[test]
fn duplicate_registration_is_rejected() {
    let mut registry = registry();

    assert_eq!(
        registry.register(device("cafe_bot_01"), navigate_schema()),
        Err(RegistryError::DuplicateRegistration {
            device: device("cafe_bot_01"),
            capability: capability("navigate"),
        })
    );
}

/// The registry key comes from the schema, so a binding cannot claim one
/// capability name while holding another's schema.
#[test]
fn registry_key_comes_from_the_schema() {
    let registry = registry();

    let navigate = registry
        .resolve(&device("cafe_bot_01"), &capability("navigate"))
        .expect("registered");
    assert_eq!(navigate.name(), &capability("navigate"));

    let wait = registry
        .resolve(&device("cafe_bot_01"), &capability("wait"))
        .expect("registered");
    assert_eq!(wait.name(), &capability("wait"));
}

#[test]
fn duplicate_policy_id_is_rejected() {
    let result = PolicySet::from_policies(vec![
        navigate_policy("delivery", "planner_a", 500, &["cafe"]),
        navigate_policy("delivery", "planner_b", 200, &["lobby"]),
    ]);

    assert_eq!(
        result,
        Err(PolicySetError::DuplicatePolicyId {
            id: PolicyId::new("delivery")
        })
    );
}

// -- selectors ----------------------------------------------------------------

#[test]
fn any_of_selector_covers_each_named_subject() {
    let shared = Policy::new(
        PolicyId::new("shared_fleet"),
        Selector::any_of([subject("planner_a"), subject("planner_b")]).expect("non-empty"),
        Selector::Exactly(device("cafe_bot_01")),
        Selector::Exactly(capability("navigate")),
        ConstraintSet::from_constraints([(param("max_speed"), ParamConstraint::at_most(500))]),
    )
    .expect("constrained policy");

    let evaluator = authority(vec![shared]);

    for actor in ["planner_a", "planner_b"] {
        let evaluation = evaluator
            .evaluate(&navigate_proposal(actor, "cafe_bot_01", 400, "cafe"))
            .expect("well-formed");
        assert!(evaluation.decision().is_authorized(), "actor {actor}");
    }

    let stranger = evaluator
        .evaluate(&navigate_proposal("planner_c", "cafe_bot_01", 400, "cafe"))
        .expect("well-formed");
    assert_eq!(stranger.decision(), &PolicyDecision::Denied);
}

/// An empty `AnyOf` could never match, so it is a configuration mistake rather
/// than a policy that silently does nothing.
#[test]
fn empty_any_of_selector_is_rejected() {
    assert!(Selector::<SubjectId>::any_of([]).is_none());
}
