//! Issuance behaviour: what gets signed, and what refuses to be signed.

mod support;

use kern_authority::{
    AuthorizedOperation, CountingNonces, Ed25519Signer, IssueError, LeaseIssuer, NonceSource,
    SequentialLeaseIds, SignError, Signer, Slot,
};
use kern_core::{
    ConstraintSet, DeviceId, EnforcerSessionId, IssuerId, KeyId, Nonce, ParamConstraint, ParamName,
    ProtocolVersion, Signature, SubjectId, TestClock, Timestamp, Ttl,
};
use kern_policy::Authority;
use support::*;

fn ttl() -> Ttl {
    Ttl::from_millis(5_000)
}

// -- the authorization boundary -----------------------------------------------

/// The lease carries exactly the bounds policy granted, not the bounds the
/// caller proposed.
#[test]
fn lease_constraints_come_from_the_authorization() {
    let operation = authorized_operation();
    let lease = issuer()
        .issue_v1(&operation, ttl(), session())
        .expect("issued");

    assert_eq!(&lease.body.constraints, operation.constraints());
    assert_eq!(
        lease.body.constraints.get(&param("max_speed")),
        Some(&ParamConstraint::at_most(500))
    );
}

/// A proposal policy refused cannot become an operation, so it can never be
/// signed. `NotAuthorizedAsProposed` carries advisory bounds; advisory bounds
/// are not authority.
#[test]
fn an_over_reaching_proposal_yields_no_authorized_operation() {
    let evaluation = authority()
        .evaluate(&proposal("planner_a", 900, "cafe"))
        .expect("well-formed");

    assert!(!evaluation.decision().is_authorized());
    assert!(AuthorizedOperation::from_evaluation(evaluation).is_none());
}

#[test]
fn a_denied_proposal_yields_no_authorized_operation() {
    let evaluation = authority()
        .evaluate(&proposal("stranger", 400, "cafe"))
        .expect("well-formed");

    assert!(AuthorizedOperation::from_evaluation(evaluation).is_none());
}

/// An unresolvable request never reaches an authority decision at all.
#[test]
fn an_unknown_capability_never_reaches_issuance() {
    assert!(Authority::default()
        .evaluate(&proposal("planner_a", 400, "cafe"))
        .is_err());
}

#[test]
fn bindings_are_copied_from_the_authorized_proposal() {
    let lease = issuer()
        .issue_v1(&authorized_operation(), ttl(), session())
        .expect("issued");

    assert_eq!(lease.body.subject, SubjectId::new("planner_a"));
    assert_eq!(lease.body.device, DeviceId::new("cafe_bot_01"));
    assert_eq!(lease.body.capability, capability("navigate"));
    assert_eq!(lease.body.issuer, IssuerId::new("issuer_dev"));
    assert_eq!(lease.body.key_id, KeyId::new("dev-1"));
}

// -- lifetime -----------------------------------------------------------------

#[test]
fn expiry_is_issuance_plus_ttl() {
    let lease = issuer()
        .issue_v1(&authorized_operation(), ttl(), session())
        .expect("issued");

    assert_eq!(lease.body.issued_at, Timestamp::from_millis(ISSUED_AT_MS));
    assert_eq!(
        lease.body.expires_at,
        Timestamp::from_millis(ISSUED_AT_MS + 5_000)
    );
}

/// A zero-length lease authorizes nothing, so asking for one is a mistake rather
/// than a degenerate but valid request.
#[test]
fn zero_ttl_is_refused() {
    assert_eq!(
        issuer().issue_v1(&authorized_operation(), Ttl::from_millis(0), session()),
        Err(IssueError::ZeroTtl)
    );
}

/// Checked, never saturated. Clamping would hand back a lease outliving every
/// bound the caller believed they had set.
#[test]
fn ttl_overflow_is_refused() {
    let mut issuer = LeaseIssuer::new(
        IssuerId::new("issuer_dev"),
        Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED),
        TestClock::new(Timestamp::from_millis(u64::MAX - 10)),
        CountingNonces::new(),
        SequentialLeaseIds::new(),
    );

    assert_eq!(
        issuer.issue_v1(&authorized_operation(), Ttl::from_millis(1_000), session()),
        Err(IssueError::TtlOverflow)
    );
}

/// The clock is injected, so issuance is reproducible.
#[test]
fn issuance_follows_the_injected_clock() {
    let clock = TestClock::new(Timestamp::from_millis(ISSUED_AT_MS));
    let mut issuer = LeaseIssuer::new(
        IssuerId::new("issuer_dev"),
        Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED),
        clock.clone(),
        CountingNonces::new(),
        SequentialLeaseIds::new(),
    );

    let first = issuer
        .issue_v1(&authorized_operation(), ttl(), session())
        .expect("issued");
    clock.advance(1_000);
    let second = issuer
        .issue_v1(&authorized_operation(), ttl(), session())
        .expect("issued");

    assert_eq!(
        second.body.issued_at.as_millis(),
        first.body.issued_at.as_millis() + 1_000
    );
}

// -- supersession -------------------------------------------------------------

#[test]
fn nonces_increase_within_a_slot() {
    let mut issuer = issuer();
    let operation = authorized_operation();

    let first = issuer
        .issue_v1(&operation, ttl(), session())
        .expect("issued");
    let second = issuer
        .issue_v1(&operation, ttl(), session())
        .expect("issued");

    assert_eq!(first.body.nonce, Nonce::new(1));
    assert_eq!(second.body.nonce, Nonce::new(2));
}

/// The example that motivated the slot design: a `speak` lease must not be able
/// to invalidate a concurrent `navigate` lease. Different capability, different
/// slot, independent counters.
#[test]
fn concurrent_capabilities_do_not_share_a_nonce_sequence() {
    let mut nonces = CountingNonces::new();
    let slot = |capability_name: &str| Slot {
        issuer: IssuerId::new("issuer_dev"),
        enforcer_session: session(),
        subject: SubjectId::new("agent_1"),
        device: DeviceId::new("robot_1"),
        capability: capability(capability_name),
    };

    assert_eq!(nonces.next_nonce(&slot("navigate")).unwrap(), Nonce::new(1));
    assert_eq!(nonces.next_nonce(&slot("speak")).unwrap(), Nonce::new(1));
    assert_eq!(nonces.next_nonce(&slot("navigate")).unwrap(), Nonce::new(2));
    assert_eq!(nonces.next_nonce(&slot("speak")).unwrap(), Nonce::new(2));
}

/// Each of the five slot components separates a sequence.
#[test]
fn every_slot_component_separates_the_sequence() {
    let base = Slot {
        issuer: IssuerId::new("issuer_dev"),
        enforcer_session: session(),
        subject: SubjectId::new("planner_a"),
        device: DeviceId::new("cafe_bot_01"),
        capability: capability("navigate"),
    };

    let variants = [
        Slot {
            issuer: IssuerId::new("issuer_other"),
            ..base.clone()
        },
        Slot {
            enforcer_session: EnforcerSessionId::from_bytes([0x22; 32]),
            ..base.clone()
        },
        Slot {
            subject: SubjectId::new("planner_b"),
            ..base.clone()
        },
        Slot {
            device: DeviceId::new("cafe_bot_02"),
            ..base.clone()
        },
        Slot {
            capability: capability("speak"),
            ..base.clone()
        },
    ];

    for variant in variants {
        let mut nonces = CountingNonces::new();
        nonces.next_nonce(&base).unwrap();

        assert_eq!(
            nonces.next_nonce(&variant).unwrap(),
            Nonce::new(1),
            "slot component did not separate the sequence"
        );
    }
}

/// A new enforcer session restarts the sequence, because every lease from the
/// previous session is already dead.
#[test]
fn a_new_session_restarts_the_sequence() {
    let mut issuer = issuer();
    let operation = authorized_operation();

    let first = issuer
        .issue_v1(&operation, ttl(), session())
        .expect("issued");
    let rebooted = issuer
        .issue_v1(&operation, ttl(), EnforcerSessionId::from_bytes([0x22; 32]))
        .expect("issued");

    assert_eq!(first.body.nonce, Nonce::new(1));
    assert_eq!(rebooted.body.nonce, Nonce::new(1));
}

// -- identity -----------------------------------------------------------------

#[test]
fn each_lease_gets_a_distinct_id() {
    let mut issuer = issuer();
    let operation = authorized_operation();

    let first = issuer
        .issue_v1(&operation, ttl(), session())
        .expect("issued");
    let second = issuer
        .issue_v1(&operation, ttl(), session())
        .expect("issued");

    assert_ne!(first.body.id, second.body.id);
}

// -- signing ------------------------------------------------------------------

#[test]
fn issuance_stamps_the_protocol_version() {
    let lease = issuer()
        .issue_v1(&authorized_operation(), ttl(), session())
        .expect("issued");

    assert_eq!(lease.version, ProtocolVersion::V1);
}

/// A refusing backend surfaces as an error, never as an unsigned lease.
#[test]
fn a_failing_signer_fails_the_issuance() {
    struct RefusingSigner(KeyId);

    impl Signer for RefusingSigner {
        fn key_id(&self) -> &KeyId {
            &self.0
        }
        fn sign(&self, _message: &[u8]) -> Result<Signature, SignError> {
            Err(SignError::Unavailable)
        }
    }

    let mut issuer = LeaseIssuer::new(
        IssuerId::new("issuer_dev"),
        RefusingSigner(KeyId::new("hsm-1")),
        TestClock::new(Timestamp::from_millis(ISSUED_AT_MS)),
        CountingNonces::new(),
        SequentialLeaseIds::new(),
    );

    assert_eq!(
        issuer.issue_v1(&authorized_operation(), ttl(), session()),
        Err(IssueError::Signing(SignError::Unavailable))
    );
}

/// Unbounded authority is representable, and reaches a lease only when a policy
/// granted it on purpose.
#[test]
fn an_unbounded_grant_produces_an_unconstrained_lease() {
    use kern_policy::{CapabilityRegistry, Policy, PolicyId, PolicySet, Selector};

    let mut registry = CapabilityRegistry::new();
    registry
        .register(DeviceId::new("cafe_bot_01"), navigate_schema())
        .expect("registered");

    let authority = Authority::new(
        registry,
        PolicySet::from_policies([Policy::unbounded(
            PolicyId::new("operator_override"),
            Selector::Exactly(SubjectId::new("planner_a")),
            Selector::Any,
            Selector::Any,
        )])
        .expect("distinct ids"),
    );

    let evaluation = authority
        .evaluate(&proposal("planner_a", 9_000, "storage"))
        .expect("well-formed");
    let operation = AuthorizedOperation::from_evaluation(evaluation).expect("authorized");

    let lease = issuer()
        .issue_v1(&operation, ttl(), session())
        .expect("issued");

    assert_eq!(lease.body.constraints, ConstraintSet::unconstrained());
}

/// Nothing in the issuance API accepts a caller-supplied constraint set, so the
/// only way a bound reaches a lease is through an authorization.
#[test]
fn issuance_exposes_no_constraint_parameter() {
    let operation = authorized_operation();
    let widened = ConstraintSet::from_constraints([(
        ParamName::new("max_speed"),
        ParamConstraint::at_most(10_000),
    )]);

    let lease = issuer()
        .issue_v1(&operation, ttl(), session())
        .expect("issued");

    assert_ne!(lease.body.constraints, widened);
    assert_eq!(&lease.body.constraints, operation.constraints());
}

// -- exhaustion ---------------------------------------------------------------

/// The identifier space runs out rather than starting over. A source that
/// wrapped would silently reissue an identifier it had already used, corrupting
/// provenance and audit correlation even though signature security is untouched.
#[test]
fn lease_ids_are_exhausted_rather_than_reused() {
    use kern_authority::{LeaseIdError, LeaseIdSource};

    let mut ids = SequentialLeaseIds::starting_at(u128::MAX);

    assert_eq!(
        ids.next_lease_id(),
        Ok(kern_core::LeaseId::from_bytes(u128::MAX.to_be_bytes()))
    );
    assert_eq!(ids.next_lease_id(), Err(LeaseIdError::Exhausted));
    // Still exhausted, not back at the start.
    assert_eq!(ids.next_lease_id(), Err(LeaseIdError::Exhausted));
}

#[test]
fn lease_id_exhaustion_fails_the_issuance() {
    use kern_authority::LeaseIdError;

    let mut issuer = LeaseIssuer::new(
        IssuerId::new("issuer_dev"),
        Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED),
        TestClock::new(Timestamp::from_millis(ISSUED_AT_MS)),
        CountingNonces::new(),
        SequentialLeaseIds::starting_at(u128::MAX),
    );
    let operation = authorized_operation();

    assert!(issuer.issue_v1(&operation, ttl(), session()).is_ok());
    assert_eq!(
        issuer.issue_v1(&operation, ttl(), session()),
        Err(IssueError::LeaseId(LeaseIdError::Exhausted))
    );
}

/// Nonces strictly increase and never wrap. A wrapped nonce would break the
/// ordering the supersession scheme rests on.
#[test]
fn nonces_are_exhausted_rather_than_wrapped() {
    use kern_authority::NonceError;

    let slot = Slot {
        issuer: IssuerId::new("issuer_dev"),
        enforcer_session: session(),
        subject: SubjectId::new("planner_a"),
        device: DeviceId::new("cafe_bot_01"),
        capability: capability("navigate"),
    };

    let mut nonces = CountingNonces::new();
    nonces.resume(slot.clone(), Nonce::new(u64::MAX - 1));

    assert_eq!(nonces.next_nonce(&slot), Ok(Nonce::new(u64::MAX)));
    assert_eq!(nonces.next_nonce(&slot), Err(NonceError::Exhausted));
    // Never zero, never a repeat.
    assert_eq!(nonces.next_nonce(&slot), Err(NonceError::Exhausted));
}

#[test]
fn nonce_exhaustion_fails_the_issuance() {
    use kern_authority::NonceError;

    let mut nonces = CountingNonces::new();
    nonces.resume(
        Slot {
            issuer: IssuerId::new("issuer_dev"),
            enforcer_session: session(),
            subject: SubjectId::new("planner_a"),
            device: DeviceId::new("cafe_bot_01"),
            capability: capability("navigate"),
        },
        Nonce::new(u64::MAX),
    );

    let mut issuer = LeaseIssuer::new(
        IssuerId::new("issuer_dev"),
        Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED),
        TestClock::new(Timestamp::from_millis(ISSUED_AT_MS)),
        nonces,
        SequentialLeaseIds::new(),
    );

    assert_eq!(
        issuer.issue_v1(&authorized_operation(), ttl(), session()),
        Err(IssueError::Nonce(NonceError::Exhausted))
    );
}

// -- TTL representability -----------------------------------------------------

/// The case that would otherwise be silent: a positive duration shorter than the
/// protocol's resolution must not become a zero-millisecond lease.
#[test]
fn a_sub_millisecond_duration_is_refused() {
    use core::time::Duration;
    use kern_core::TtlError;

    assert_eq!(
        Ttl::try_from_duration(Duration::from_nanos(1)),
        Err(TtlError::SubMillisecond)
    );
    assert_eq!(
        Ttl::try_from_duration(Duration::from_micros(999)),
        Err(TtlError::SubMillisecond)
    );
}

/// Rejected rather than rounded: rounding down shortens authority and rounding
/// up extends it.
#[test]
fn a_fractional_millisecond_duration_is_refused() {
    use core::time::Duration;
    use kern_core::TtlError;

    assert_eq!(
        Ttl::try_from_duration(Duration::from_micros(1_500)),
        Err(TtlError::NotWholeMilliseconds)
    );
}

#[test]
fn an_unrepresentable_duration_is_refused() {
    use core::time::Duration;
    use kern_core::TtlError;

    assert_eq!(
        Ttl::try_from_duration(Duration::from_secs(u64::MAX)),
        Err(TtlError::NotRepresentable)
    );
}

/// Whole milliseconds convert exactly, and zero survives to be refused by
/// issuance so that one place owns that rule.
#[test]
fn whole_millisecond_durations_convert_exactly() {
    use core::time::Duration;

    assert_eq!(
        Ttl::try_from_duration(Duration::from_millis(5_000)),
        Ok(Ttl::from_millis(5_000))
    );
    assert_eq!(
        Ttl::try_from_duration(Duration::ZERO),
        Ok(Ttl::from_millis(0))
    );
    assert_eq!(
        issuer().issue_v1(
            &authorized_operation(),
            Ttl::try_from_duration(Duration::ZERO).unwrap(),
            session()
        ),
        Err(IssueError::ZeroTtl)
    );
}
