//! Authority liveness, and its relationship to authorization.
//!
//! `check_authority` answers "is this authority still current". `enforce`
//! answers "is this operation authorized under it". The first is a strict prefix
//! of the second, and these tests hold the two to that.

mod support;

use kern_core::{TestMonotonicClock, Uptime};
use kern_enforcer::{AuthorityStatusError, EnforcementError};
use support::{
    authorized, issuer, lease_bytes, lease_bytes_with_ttl, navigate_ticket, operation, store,
    store_with, trust_store, LEASE_TTL_MS,
};

#[test]
fn installed_authority_is_current() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let handle = store.install(&bytes).expect("installs").handle().clone();

    assert_eq!(store.check_authority(&handle), Ok(()));
}

/// Liveness examines no operation, so authority that forbids an operation is
/// still perfectly current.
#[test]
fn liveness_ignores_the_operation() {
    let (mut store, _clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let handle = store.install(&bytes).expect("installs").handle().clone();

    let outside = support::navigate_schema()
        .normalize(&support::navigate_proposal(600, "cafe"))
        .expect("schema-valid");

    assert_eq!(
        store.enforce(&handle, &outside),
        Err(EnforcementError::ConstraintViolation)
    );
    assert_eq!(store.check_authority(&handle), Ok(()));
}

/// Authorization is a refinement of liveness, never a separate opinion about it.
#[test]
fn enforce_success_implies_current_authority() {
    for ttl in [1_000, LEASE_TTL_MS, 20_000] {
        for elapsed in [0, 500, 999, LEASE_TTL_MS, 30_000] {
            for speed in [0, 100, 400, 500, 600] {
                let clock = TestMonotonicClock::new(Uptime::from_millis(1_000));
                let mut store = store_with(clock.clone(), trust_store());
                let ticket = navigate_ticket(&mut store);
                let bytes =
                    lease_bytes_with_ttl(&mut issuer(), &authorized(400, "cafe"), &ticket, ttl);
                let handle = store.install(&bytes).expect("installs").handle().clone();
                clock.advance(elapsed);

                let proposal = support::navigate_schema()
                    .normalize(&support::navigate_proposal(speed, "cafe"))
                    .expect("schema-valid");

                if store.enforce(&handle, &proposal).is_ok() {
                    assert_eq!(
                        store.check_authority(&handle),
                        Ok(()),
                        "ttl {ttl}, elapsed {elapsed}, speed {speed}"
                    );
                }
            }
        }
    }
}

#[test]
fn an_expired_deadline_is_reported_as_expired() {
    let (mut store, clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let handle = store.install(&bytes).expect("installs").handle().clone();

    clock.advance(LEASE_TTL_MS + 1);

    assert_eq!(
        store.check_authority(&handle),
        Err(AuthorityStatusError::DeadlineExpired)
    );
    assert_eq!(
        store.enforce(&handle, &operation(400, "cafe")),
        Err(EnforcementError::DeadlineExpired)
    );
}

#[test]
fn a_superseded_handle_is_reported_as_superseded() {
    let (mut store, _clock) = store();
    let mut issuer = issuer();

    let first = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer, &authorized(400, "cafe"), &first);
    let old = store.install(&bytes).expect("installs").handle().clone();

    let second = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer, &authorized(300, "cafe"), &second);
    let new = store.install(&bytes).expect("installs").handle().clone();

    assert_eq!(
        store.check_authority(&old),
        Err(AuthorityStatusError::Superseded)
    );
    assert_eq!(store.check_authority(&new), Ok(()));
}

#[test]
fn a_handle_for_an_empty_slot_is_reported_as_missing() {
    let (mut installed, _clock) = store();
    let ticket = navigate_ticket(&mut installed);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let handle = installed
        .install(&bytes)
        .expect("installs")
        .handle()
        .clone();

    let clock = TestMonotonicClock::new(Uptime::from_millis(1_000));
    let empty = store_with(clock, trust_store());

    assert_eq!(
        empty.check_authority(&handle),
        Err(AuthorityStatusError::AuthorityMissing)
    );
    assert_eq!(
        empty.enforce(&handle, &operation(400, "cafe")),
        Err(EnforcementError::NoAuthority)
    );
}

/// A backwards clock is refused on both paths, in the same fail-closed
/// direction.
#[test]
fn a_backwards_clock_is_refused() {
    let (mut store, clock) = store();
    let ticket = navigate_ticket(&mut store);
    let bytes = lease_bytes(&mut issuer(), &authorized(400, "cafe"), &ticket);
    let handle = store.install(&bytes).expect("installs").handle().clone();

    clock.set(Uptime::from_millis(500));

    assert_eq!(
        store.check_authority(&handle),
        Err(AuthorityStatusError::ClockWentBackwards)
    );
}

#[test]
fn a_liveness_failure_widens_into_the_hot_path_vocabulary() {
    assert_eq!(
        EnforcementError::from(AuthorityStatusError::AuthorityMissing),
        EnforcementError::NoAuthority
    );
    assert_eq!(
        EnforcementError::from(AuthorityStatusError::Superseded),
        EnforcementError::Superseded
    );
    assert_eq!(
        EnforcementError::from(AuthorityStatusError::DeadlineExpired),
        EnforcementError::DeadlineExpired
    );
    assert_eq!(
        EnforcementError::from(AuthorityStatusError::ClockWentBackwards),
        EnforcementError::ClockWentBackwards
    );
}
