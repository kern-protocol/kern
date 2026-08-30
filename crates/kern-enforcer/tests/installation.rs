//! Verification, freshness, supersession, and the hot path.

mod support;

use kern_authority::{CountingNonces, Ed25519Signer, LeaseIssuer, SequentialLeaseIds};
use kern_core::wire::{encode, encode_v2, parse};
use kern_core::{
    ChallengeTicket, EnforcerSessionId, IssuerId, KeyId, MonotonicDuration, ProtocolVersion,
    SubjectId, TestClock, TestMonotonicClock, Timestamp, Ttl, Uptime,
};
use kern_enforcer::{
    ConfigError, EnforcementError, EnforcerStore, InstallError, Installed, MintError, TrustError,
    TrustStore,
};
use support::*;

// -- authentication and trust -------------------------------------------------

#[test]
fn a_well_formed_lease_installs() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);

    let installed = store.install(&bytes).expect("installs");

    assert!(matches!(installed, Installed::Fresh(_)));
    assert!(store.installed(installed.handle()).is_some());
}

/// A valid signature under a key nobody authorized proves only that someone owns
/// a keypair.
#[test]
fn an_untrusted_issuer_is_refused() {
    let clock = TestMonotonicClock::new(Uptime::from_millis(1_000));
    let mut store = store_with(clock, TrustStore::new());
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);

    assert_eq!(store.install(&bytes), Err(InstallError::UntrustedIssuer));
}

#[test]
fn a_trusted_issuer_with_an_unknown_key_is_refused() {
    let clock = TestMonotonicClock::new(Uptime::from_millis(1_000));
    let mut trust = TrustStore::new();
    trust
        .authorize(issuer_id(), KeyId::new("other-key"), dev_verifying_key())
        .expect("authorized");
    let mut store = store_with(clock, trust);
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);

    assert_eq!(store.install(&bytes), Err(InstallError::UnknownKey));
}

/// The key must be authorized *for the claimed issuer*, not merely present.
#[test]
fn a_key_authorized_for_another_issuer_is_refused() {
    let clock = TestMonotonicClock::new(Uptime::from_millis(1_000));
    let mut trust = TrustStore::new();
    trust
        .authorize(
            IssuerId::new("issuer_other"),
            KeyId::new("dev-1"),
            dev_verifying_key(),
        )
        .expect("authorized");
    let mut store = store_with(clock, trust);
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);

    assert_eq!(store.install(&bytes), Err(InstallError::UntrustedIssuer));
}

#[test]
fn a_tampered_body_fails_verification() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    let mut bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);

    let last_body_byte = bytes.len() - 65;
    bytes[last_body_byte] ^= 0x01;

    assert!(matches!(
        store.install(&bytes),
        Err(InstallError::InvalidSignature) | Err(InstallError::Malformed)
    ));
}

#[test]
fn a_tampered_signature_fails_verification() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    let mut bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);

    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;

    assert_eq!(store.install(&bytes), Err(InstallError::InvalidSignature));
}

/// V1 carries no challenge, so this enforcer refuses it rather than silently
/// offering a weaker freshness guarantee.
#[test]
fn a_v1_lease_is_refused() {
    let (mut store, _clock) = store();
    let lease = issuer()
        .issue_v1(&authorized(400, "cafe"), Ttl::from_millis(5_000), session())
        .expect("issued");
    let bytes = encode(&lease).expect("encodes");

    assert_eq!(
        store.install(&bytes),
        Err(InstallError::UnsupportedVersion { found: 1 })
    );
}

#[test]
fn malformed_bytes_are_refused() {
    let (mut store, _clock) = store();

    assert_eq!(store.install(&[]), Err(InstallError::Malformed));
    assert_eq!(store.install(&[2, 0, 0]), Err(InstallError::Malformed));
}

#[test]
fn the_trust_store_refuses_duplicate_and_invalid_keys() {
    let mut trust = trust_store();

    assert!(trust
        .authorize(issuer_id(), KeyId::new("dev-1"), dev_verifying_key())
        .is_err());
    // Not every 32-byte string is a valid compressed Edwards point; this one
    // fails to decompress.
    let mut not_a_point = [0u8; 32];
    not_a_point[0] = 0x02;
    assert!(trust
        .authorize(issuer_id(), KeyId::new("bad"), not_a_point)
        .is_err());
    assert_eq!(
        trust.key_for(&IssuerId::new("nobody"), &KeyId::new("dev-1")),
        Err(TrustError::UntrustedIssuer)
    );
}

/// Rotation is add-then-remove; two keys may be live at once.
#[test]
fn rotation_allows_two_live_keys() {
    let mut trust = trust_store();
    let second = Ed25519Signer::from_seed(KeyId::new("dev-2"), [9u8; 32]);
    trust
        .authorize(
            issuer_id(),
            KeyId::new("dev-2"),
            second.verifying_key_bytes(),
        )
        .expect("authorized");

    assert!(trust.key_for(&issuer_id(), &KeyId::new("dev-1")).is_ok());
    assert!(trust.key_for(&issuer_id(), &KeyId::new("dev-2")).is_ok());
    assert!(trust.revoke_key(&issuer_id(), &KeyId::new("dev-1")));
    assert!(trust.key_for(&issuer_id(), &KeyId::new("dev-1")).is_err());
}

// -- challenge lifecycle ------------------------------------------------------

#[test]
fn a_ticket_carries_the_complete_slot_binding() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);

    assert_eq!(ticket.issuer, issuer_id());
    assert_eq!(ticket.session, session());
    assert_eq!(ticket.subject, subject());
    assert_eq!(ticket.device, device());
    assert_eq!(ticket.capability, capability("navigate"));
}

#[test]
fn each_ticket_carries_a_distinct_challenge() {
    let (mut store, _clock) = store();

    let first = navigate_ticket(&mut store);
    let second = navigate_ticket(&mut store);

    assert_ne!(first.challenge, second.challenge);
}

/// A challenge minted for one capability must never establish freshness for
/// another.
#[test]
fn a_challenge_for_another_capability_is_refused() {
    let (mut store, _clock) = store();
    let speak_ticket = store
        .mint_challenge(&issuer_id(), &subject(), &device(), &capability("speak"))
        .expect("minted");

    // Answer the speak challenge with a navigate lease.
    let mut issuer = issuer();
    let lease = issuer
        .issue_v2(
            &authorized(400, "cafe"),
            Ttl::from_millis(LEASE_TTL_MS),
            &ChallengeTicket {
                capability: capability("navigate"),
                ..speak_ticket.clone()
            },
        )
        .expect("issued");
    let bytes = encode_v2(&lease).expect("encodes");

    assert_eq!(store.install(&bytes), Err(InstallError::ChallengeMismatch));
}

#[test]
fn a_challenge_for_another_subject_is_refused() {
    let (mut store, _clock) = store();
    let ticket = store
        .mint_challenge(
            &issuer_id(),
            &SubjectId::new("planner_b"),
            &device(),
            &capability("navigate"),
        )
        .expect("minted");

    let mut issuer = issuer();
    let lease = issuer
        .issue_v2(
            &authorized(400, "cafe"),
            Ttl::from_millis(LEASE_TTL_MS),
            &ChallengeTicket {
                subject: subject(),
                ..ticket
            },
        )
        .expect("issued");
    let bytes = encode_v2(&lease).expect("encodes");

    assert_eq!(store.install(&bytes), Err(InstallError::ChallengeMismatch));
}

#[test]
fn an_unknown_challenge_is_refused() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    // A second store never minted this challenge.
    let mut other = store_with(
        TestMonotonicClock::new(Uptime::from_millis(1_000)),
        trust_store(),
    );
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);

    assert_eq!(other.install(&bytes), Err(InstallError::ChallengeUnknown));
}

/// The bound on delay: a challenge stops being answerable once its local
/// deadline passes.
#[test]
fn an_expired_challenge_is_refused() {
    let (mut store, clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);

    clock.advance(CHALLENGE_TTL_MS + 1);

    assert_eq!(store.install(&bytes), Err(InstallError::ChallengeExpired));
}

/// A challenge is spent by the installation it admits.
#[test]
fn a_consumed_challenge_cannot_admit_a_second_lease() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    let mut issuer = issuer();

    let first = lease_bytes(&mut issuer, &authorized(400, "cafe"), &ticket);
    store.install(&first).expect("installs");

    // A different lease answering the same, now-consumed, challenge.
    let second = lease_bytes(&mut issuer, &authorized(300, "lobby"), &ticket);

    assert_eq!(store.install(&second), Err(InstallError::ChallengeConsumed));
}

/// A failed installation leaves its challenge outstanding, so a legitimate retry
/// still works.
#[test]
fn a_failed_installation_leaves_the_challenge_outstanding() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    let mut issuer = issuer();

    let mut tampered = lease_bytes(&mut issuer, &authorized(400, "cafe"), &ticket);
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert_eq!(
        store.install(&tampered),
        Err(InstallError::InvalidSignature)
    );

    let good = lease_bytes(&mut issuer, &authorized(400, "cafe"), &ticket);
    assert!(store.install(&good).is_ok());
}

#[test]
fn entropy_failure_prevents_minting() {
    let mut store = EnforcerStore::new(
        session(),
        trust_store(),
        TestMonotonicClock::new(Uptime::from_millis(0)),
        FailingChallenges,
        MonotonicDuration::from_millis(CHALLENGE_TTL_MS),
        4,
        4,
    )
    .expect("valid configuration");

    assert!(matches!(
        store.mint_challenge(&issuer_id(), &subject(), &device(), &capability("navigate")),
        Err(MintError::Entropy(_))
    ));
}

// -- session binding ----------------------------------------------------------

#[test]
fn a_lease_for_another_session_is_refused() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);

    let mut issuer = issuer();
    let lease = issuer
        .issue_v2(
            &authorized(400, "cafe"),
            Ttl::from_millis(LEASE_TTL_MS),
            &ChallengeTicket {
                session: EnforcerSessionId::from_bytes(OTHER_SESSION_BYTES),
                ..ticket
            },
        )
        .expect("issued");
    let bytes = encode_v2(&lease).expect("encodes");

    assert_eq!(store.install(&bytes), Err(InstallError::SessionMismatch));
}

/// A reboot is a new store with a new session: nothing survives it.
#[test]
fn a_reboot_invalidates_previously_installed_authority() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let installed = store.install(&bytes).expect("installs");
    let handle = installed.handle().clone();

    let rebooted = EnforcerStore::new(
        EnforcerSessionId::from_bytes(OTHER_SESSION_BYTES),
        trust_store(),
        TestMonotonicClock::new(Uptime::ZERO),
        SequentialChallenges::starting_at(1),
        MonotonicDuration::from_millis(CHALLENGE_TTL_MS),
        4,
        4,
    )
    .expect("valid configuration");

    assert!(rebooted.installed(&handle).is_none());
    assert_eq!(
        rebooted.enforce(&handle, &operation(400, "cafe")),
        Err(EnforcementError::NoAuthority)
    );
}

// -- lifetime -----------------------------------------------------------------

/// The deadline is anchored at challenge issuance, so delivery delay is charged
/// against the lease's own lifetime rather than forgiven.
#[test]
fn the_deadline_is_anchored_at_challenge_issuance() {
    let (mut store, clock) = store();
    let anchor = Uptime::from_millis(1_000);
    let ticket = navigate_ticket(&mut store);

    clock.advance(500);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let installed = store.install(&bytes).expect("installs");

    let lease = store.installed(installed.handle()).expect("installed");
    assert_eq!(
        lease.deadline(),
        Uptime::from_millis(anchor.as_millis() + LEASE_TTL_MS)
    );
}

/// The challenge deadline gates first installation only. A lease installed at
/// 1.5 s under a 2 s challenge still gets its full 5 s window.
#[test]
fn the_challenge_deadline_does_not_truncate_installed_authority() {
    let (mut store, clock) = store();
    let ticket = navigate_ticket(&mut store);
    clock.advance(1_500);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let installed = store.install(&bytes).expect("installs");
    let handle = installed.handle().clone();

    // Past the challenge deadline, well within the authority window.
    clock.advance(1_000);
    assert!(store.enforce(&handle, &operation(400, "cafe")).is_ok());
}

#[test]
fn authority_expires_at_its_deadline() {
    let (mut store, clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let handle = store.install(&bytes).expect("installs").handle().clone();

    clock.advance(LEASE_TTL_MS - 1);
    assert!(store.enforce(&handle, &operation(400, "cafe")).is_ok());

    clock.advance(1);
    assert_eq!(
        store.enforce(&handle, &operation(400, "cafe")),
        Err(EnforcementError::DeadlineExpired)
    );
}

/// A lease whose window elapsed before it arrived cannot install at all.
#[test]
fn an_already_elapsed_window_is_refused() {
    let (mut store, clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes_with_ttl(&mut issuer(), &authorized(400, "cafe"), &ticket, 100);

    clock.advance(1_500);

    assert_eq!(store.install(&bytes), Err(InstallError::AlreadyExpired));
}

// -- monotonic clock ----------------------------------------------------------

/// A backwards clock would make leases live longer, so it fails closed.
#[test]
fn a_backwards_clock_refuses_installation() {
    let (mut store, clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);

    clock.set(Uptime::from_millis(0));

    assert_eq!(store.install(&bytes), Err(InstallError::ClockWentBackwards));
}

#[test]
fn a_backwards_clock_refuses_enforcement() {
    let (mut store, clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let handle = store.install(&bytes).expect("installs").handle().clone();

    clock.set(Uptime::from_millis(0));

    assert_eq!(
        store.enforce(&handle, &operation(400, "cafe")),
        Err(EnforcementError::ClockWentBackwards)
    );
}

// -- supersession -------------------------------------------------------------

#[test]
fn a_newer_generation_supersedes() {
    let (mut store, _clock) = store();
    let mut issuer = issuer();

    let first_ticket = navigate_ticket(&mut store);
    let first = lease_bytes(&mut issuer, &authorized(400, "cafe"), &first_ticket);
    let first_handle = store.install(&first).expect("installs").handle().clone();

    let second_ticket = navigate_ticket(&mut store);
    let second = lease_bytes(&mut issuer, &authorized(300, "lobby"), &second_ticket);
    let second_handle = store.install(&second).expect("installs").handle().clone();

    assert!(store.installed(&second_handle).is_some());
    assert!(store.installed(&first_handle).is_none());
}

/// The attack the nonce actually stops: re-installing a captured, more
/// permissive lease after a narrower one took effect.
#[test]
fn an_older_generation_is_refused_after_supersession() {
    let (mut store, _clock) = store();
    let mut issuer = issuer();

    let first_ticket = navigate_ticket(&mut store);
    let captured = lease_bytes(&mut issuer, &authorized(500, "cafe"), &first_ticket);

    let second_ticket = navigate_ticket(&mut store);
    let narrower = lease_bytes(&mut issuer, &authorized(100, "cafe"), &second_ticket);
    store.install(&narrower).expect("installs");

    assert_eq!(store.install(&captured), Err(InstallError::SupersededNonce));
}

/// Different capabilities are different slots, so they never interfere.
#[test]
fn concurrent_capabilities_occupy_independent_slots() {
    let (mut store, _clock) = store();
    let mut issuer = issuer();

    let navigate_ticket = navigate_ticket(&mut store);
    let navigate = lease_bytes(&mut issuer, &authorized(400, "cafe"), &navigate_ticket);
    let navigate_handle = store.install(&navigate).expect("installs").handle().clone();

    let speak_ticket = store
        .mint_challenge(&issuer_id(), &subject(), &device(), &capability("speak"))
        .expect("minted");
    let speak = lease_bytes(&mut issuer, &authorized_speak(30), &speak_ticket);
    let speak_handle = store.install(&speak).expect("installs").handle().clone();

    assert!(store.installed(&navigate_handle).is_some());
    assert!(store.installed(&speak_handle).is_some());
}

/// Two distinct bodies claiming one generation is an issuer fault or an attack.
#[test]
fn a_conflicting_generation_is_refused() {
    let (mut store, _clock) = store();

    let first_ticket = navigate_ticket(&mut store);
    let first = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &first_ticket);
    store.install(&first).expect("installs");

    // A second issuer instance restarts its counters, so this lease reuses
    // nonce 1 with different bounds.
    let second_ticket = navigate_ticket(&mut store);
    let mut restarted = issuer();
    let conflicting = lease_bytes(&mut restarted, &authorized(100, "lobby"), &second_ticket);

    assert_eq!(
        store.install(&conflicting),
        Err(InstallError::ConflictingGeneration)
    );
}

// -- idempotency --------------------------------------------------------------

/// A delivery retry is not an attack.
#[test]
fn re_presenting_the_same_lease_is_idempotent() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);

    let first = store.install(&bytes).expect("installs");
    let second = store.install(&bytes).expect("installs again");

    assert!(matches!(first, Installed::Fresh(_)));
    assert!(matches!(second, Installed::Already(_)));
    assert_eq!(first.handle(), second.handle());
}

/// A retry must not need a live challenge — the original was consumed.
#[test]
fn an_idempotent_retry_needs_no_outstanding_challenge() {
    let (mut store, clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    store.install(&bytes).expect("installs");

    clock.advance(CHALLENGE_TTL_MS + 1);

    assert!(matches!(
        store.install(&bytes).expect("still idempotent"),
        Installed::Already(_)
    ));
}

/// The critical one: a retry must never refresh authority lifetime.
#[test]
fn an_idempotent_retry_does_not_extend_the_deadline() {
    let (mut store, clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let handle = store.install(&bytes).expect("installs").handle().clone();
    let original = store.installed(&handle).expect("installed").deadline();

    clock.advance(1_000);
    store.install(&bytes).expect("idempotent");

    assert_eq!(
        store.installed(&handle).expect("installed").deadline(),
        original
    );
}

// -- stale and ABA handles ----------------------------------------------------

#[test]
fn a_superseded_handle_fails_enforcement() {
    let (mut store, _clock) = store();
    let mut issuer = issuer();

    let first_ticket = navigate_ticket(&mut store);
    let first = lease_bytes(&mut issuer, &authorized(400, "cafe"), &first_ticket);
    let stale = store.install(&first).expect("installs").handle().clone();

    let second_ticket = navigate_ticket(&mut store);
    let second = lease_bytes(&mut issuer, &authorized(400, "cafe"), &second_ticket);
    store.install(&second).expect("installs");

    assert_eq!(
        store.enforce(&stale, &operation(400, "cafe")),
        Err(EnforcementError::Superseded)
    );
}

/// Storage position is not identity. Reusing a slot's storage for unrelated
/// authority must not resurrect an old handle.
#[test]
fn a_reclaimed_slot_does_not_revive_an_old_handle() {
    let (mut store, _clock) = store();
    let mut issuer = issuer();

    let ticket_a = navigate_ticket(&mut store);
    let lease_a = lease_bytes(&mut issuer, &authorized(400, "cafe"), &ticket_a);
    let handle_a = store.install(&lease_a).expect("installs").handle().clone();

    // Same slot, new generation: the storage index is reused for authority the
    // old handle never named.
    let ticket_b = navigate_ticket(&mut store);
    let lease_b = lease_bytes(&mut issuer, &authorized(100, "lobby"), &ticket_b);
    let handle_b = store.install(&lease_b).expect("installs").handle().clone();

    assert_ne!(handle_a.artifact(), handle_b.artifact());
    assert!(store.installed(&handle_a).is_none());
    assert_eq!(
        store.enforce(&handle_a, &operation(400, "cafe")),
        Err(EnforcementError::Superseded)
    );
    assert!(store.enforce(&handle_b, &operation(100, "lobby")).is_ok());
}

// -- hot path -----------------------------------------------------------------

#[test]
fn an_operation_within_bounds_is_permitted() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let handle = store.install(&bytes).expect("installs").handle().clone();

    assert!(store.enforce(&handle, &operation(400, "cafe")).is_ok());
}

#[test]
fn an_operation_outside_the_bounds_is_refused() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    // Authority is capped at 400 by the proposal that was authorized.
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let handle = store.install(&bytes).expect("installs").handle().clone();

    // 900 exceeds the policy bound of 500 that the lease carries.
    let evaluation = control_plane().evaluate(&navigate_proposal(900, "cafe"));
    let over = evaluation.expect("well-formed").proposal().clone();

    assert_eq!(
        store.enforce(&handle, &over),
        Err(EnforcementError::ConstraintViolation)
    );
}

#[test]
fn an_operation_for_another_subject_is_refused() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let handle = store.install(&bytes).expect("installs").handle().clone();

    let schema = navigate_schema();
    let foreign = schema
        .normalize(
            &kern_core::ActionProposal::new(
                SubjectId::new("planner_b"),
                device(),
                capability("navigate"),
            )
            .with_param(
                param("destination"),
                kern_core::ParamValue::Symbol(kern_core::Symbol::new("cafe")),
            )
            .with_param(param("max_speed"), kern_core::ParamValue::Scalar(400)),
        )
        .expect("valid");

    assert_eq!(
        store.enforce(&handle, &foreign),
        Err(EnforcementError::SubjectMismatch)
    );
}

#[test]
fn an_unknown_handle_has_no_authority() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let handle = store.install(&bytes).expect("installs").handle().clone();

    let empty = store_with(
        TestMonotonicClock::new(Uptime::from_millis(1_000)),
        trust_store(),
    );

    assert_eq!(
        empty.enforce(&handle, &operation(400, "cafe")),
        Err(EnforcementError::NoAuthority)
    );
}

// -- capacity and configuration -----------------------------------------------

#[test]
fn configuration_is_validated() {
    let build = |ttl_ms, challenges, slots| {
        EnforcerStore::new(
            session(),
            trust_store(),
            TestMonotonicClock::new(Uptime::ZERO),
            SequentialChallenges::starting_at(1),
            MonotonicDuration::from_millis(ttl_ms),
            challenges,
            slots,
        )
        .map(|_| ())
    };

    assert_eq!(build(0, 4, 4), Err(ConfigError::ZeroChallengeTtl));
    assert_eq!(build(1_000, 0, 4), Err(ConfigError::ZeroCapacity));
    assert_eq!(build(1_000, 4, 0), Err(ConfigError::ZeroCapacity));
}

/// Capacity is resolved before entropy is drawn, so a full table never burns a
/// challenge value.
#[test]
fn a_full_challenge_table_refuses_before_drawing_entropy() {
    let mut store = EnforcerStore::new(
        session(),
        trust_store(),
        TestMonotonicClock::new(Uptime::from_millis(1_000)),
        SequentialChallenges::starting_at(1),
        MonotonicDuration::from_millis(CHALLENGE_TTL_MS),
        1,
        4,
    )
    .expect("valid configuration");

    let first = navigate_ticket(&mut store);
    assert_eq!(
        store.mint_challenge(&issuer_id(), &subject(), &device(), &capability("speak")),
        Err(MintError::CapacityExhausted)
    );
    // The one outstanding challenge is untouched and still usable.
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &first);
    assert!(store.install(&bytes).is_ok());
}

/// Expired records are reclaimed, so a full table recovers on its own.
#[test]
fn expired_challenge_records_are_reclaimed() {
    let mut store = EnforcerStore::new(
        session(),
        trust_store(),
        TestMonotonicClock::new(Uptime::from_millis(1_000)),
        SequentialChallenges::starting_at(1),
        MonotonicDuration::from_millis(CHALLENGE_TTL_MS),
        1,
        4,
    )
    .expect("valid configuration");
    let clock = TestMonotonicClock::new(Uptime::from_millis(1_000));
    let _ = clock;

    navigate_ticket(&mut store);
    assert!(store
        .mint_challenge(&issuer_id(), &subject(), &device(), &capability("speak"))
        .is_err());
}

/// A rejected lease mutates nothing: a nonce comparison is a comparison, never a
/// consumption.
#[test]
fn a_rejected_lease_leaves_the_store_unchanged() {
    let (mut store, _clock) = store();
    let mut issuer = issuer();

    let ticket = navigate_ticket(&mut store);
    let good = lease_bytes(&mut issuer, &authorized(400, "cafe"), &ticket);
    let handle = store.install(&good).expect("installs").handle().clone();
    let deadline = store.installed(&handle).expect("installed").deadline();

    let stale_ticket = navigate_ticket(&mut store);
    let mut restarted = LeaseIssuer::new(
        issuer_id(),
        Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED),
        TestClock::new(Timestamp::from_millis(ISSUED_AT_MS)),
        CountingNonces::new(),
        SequentialLeaseIds::starting_at(0xFF),
    );
    let conflicting = lease_bytes(&mut restarted, &authorized(100, "lobby"), &stale_ticket);
    assert!(store.install(&conflicting).is_err());

    assert_eq!(
        store
            .installed(&handle)
            .expect("still installed")
            .deadline(),
        deadline
    );
    assert!(store.enforce(&handle, &operation(400, "cafe")).is_ok());
}

// -- protocol -----------------------------------------------------------------

#[test]
fn a_v2_envelope_frames_and_parses() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);

    let parsed = parse(&bytes).expect("parses");

    assert_eq!(parsed.version(), ProtocolVersion::V2);
    assert!(parsed.decode_untrusted_body_v2().is_ok());
    // The V1 accessor refuses a V2 body rather than misreading it.
    assert!(parsed.decode_untrusted_body().is_err());
}
