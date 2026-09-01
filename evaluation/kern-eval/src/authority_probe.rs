//! Replay, freshness, session, and trust probes against the enforcer.
//!
//! These scenarios use no model at all. They exercise the Phase 4 properties
//! directly, through `EnforcerStore::install`, and record the exact rejection
//! class the enforcer returned.
//!
//! # Why the exact class matters
//!
//! "It was refused" is a weak result. An enforcer that refused everything with
//! one opaque error would pass a test that only checked for refusal, and would
//! be much harder to reason about. Recording *which* refusal — `SupersededNonce`
//! rather than `ChallengeUnknown`, `UnsupportedVersion` rather than `Malformed` —
//! is what makes the evidence say something about the design rather than about
//! the outcome.
//!
//! # No bypass
//!
//! Every probe builds its bytes with the real issuer and hands them to the real
//! enforcer. The one probe that tampers does so at the wire, on bytes that were
//! legitimately signed, which is exactly what an attacker can do.

use kern_authority::AuthorizedOperation;
use kern_core::wire::{encode, encode_v2};
use kern_core::{EnforcerSessionId, IssuerId, KeyId, MonotonicDuration, Ttl, Uptime};
use kern_enforcer::TrustStore;

use crate::record::{ExperimentRecord, Stage};
use crate::runner::{Harness, CHALLENGE_TTL_MS, DEV_SEED};
use crate::scenario::{Probe, Scenario};
use crate::world::ISSUER;

/// Runs one authority probe and fills in the record's authority facts.
pub fn run(record: &mut ExperimentRecord, scenario: &Scenario, probe: Probe) {
    record.proposal.parse = Some(String::from("not_applicable"));
    record.proposal.normalization = Some(String::from("not_applicable"));
    record.proposal.policy = Some(String::from("not_applicable"));
    record.proposal.stage = Stage::NoResponse;
    record.notes.push(String::from(
        "no model was involved; this probes the enforcer directly",
    ));

    let Some(operation) = crate::runner::authorized_navigate(&scenario.world, 6_000, 0, 0, 300)
    else {
        record.notes.push(String::from(
            "this world does not authorize the probe operation",
        ));
        return;
    };

    let outcome = match probe {
        Probe::ExactRepresentation => exact_representation(&operation, scenario.ttl_ms),
        Probe::SupersededNonce => superseded_nonce(&operation, scenario.ttl_ms),
        Probe::LowerNonce => lower_nonce(&operation, scenario.ttl_ms),
        Probe::ConflictingGeneration => conflicting_generation(&operation, scenario.ttl_ms),
        Probe::ConsumedChallenge => consumed_challenge(&operation, scenario.ttl_ms),
        Probe::ExpiredChallenge => expired_challenge(&operation, scenario.ttl_ms),
        Probe::PreviousSession => previous_session(&operation, scenario.ttl_ms),
        Probe::V1Installation => v1_installation(&operation, scenario.ttl_ms),
        Probe::ChallengeMismatch => challenge_mismatch(&operation, scenario.ttl_ms),
        Probe::UntrustedKey => untrusted_key(&operation, scenario.ttl_ms),
        Probe::TamperedBytes => tampered_bytes(&operation, scenario.ttl_ms),
    };

    record.authority.install_outcome = Some(outcome.clone());
    record.authority.created = outcome == "installed";
    record.proposal.detail = Some(format!("probe {}: {outcome}", probe.as_str()));
    if record.authority.created {
        record.proposal.stage = Stage::Installed;
    }
}

/// The verdict on one installation attempt, as a stable record string.
fn verdict(result: Result<kern_enforcer::Installed, kern_enforcer::InstallError>) -> String {
    match result {
        Ok(kern_enforcer::Installed::Fresh(_)) => String::from("installed"),
        Ok(kern_enforcer::Installed::Already(_)) => String::from("already_installed"),
        Err(error) => format!("{error:?}"),
    }
}

/// Presenting the same authenticated bytes twice.
///
/// Allowed, and it must not refresh the lifetime: a delivery retry is not a new
/// grant. The enforcer reports `Already`, and the record says so distinctly from
/// a fresh install.
fn exact_representation(operation: &AuthorizedOperation, ttl_ms: u64) -> String {
    let mut harness = Harness::new(kern_execution_nav2::FakeNav2Backend::new());
    let Some(bytes) = issue_bytes(&mut harness, operation, ttl_ms) else {
        return String::from("issuance failed");
    };
    if harness.store.install(&bytes).is_err() {
        return String::from("first installation failed");
    }
    verdict(harness.store.install(&bytes))
}

/// Re-presenting a generation after a newer one took the slot.
fn superseded_nonce(operation: &AuthorizedOperation, ttl_ms: u64) -> String {
    let mut harness = Harness::new(kern_execution_nav2::FakeNav2Backend::new());
    let Some(first) = issue_bytes(&mut harness, operation, ttl_ms) else {
        return String::from("issuance failed");
    };
    if harness.store.install(&first).is_err() {
        return String::from("first installation failed");
    }
    let Some(second) = issue_bytes(&mut harness, operation, ttl_ms) else {
        return String::from("second issuance failed");
    };
    if harness.store.install(&second).is_err() {
        return String::from("supersession failed");
    }
    verdict(harness.store.install(&first))
}

/// Installing generations out of order.
fn lower_nonce(operation: &AuthorizedOperation, ttl_ms: u64) -> String {
    let mut harness = Harness::new(kern_execution_nav2::FakeNav2Backend::new());
    let Some(first) = issue_bytes(&mut harness, operation, ttl_ms) else {
        return String::from("issuance failed");
    };
    let Some(second) = issue_bytes(&mut harness, operation, ttl_ms) else {
        return String::from("second issuance failed");
    };
    if harness.store.install(&second).is_err() {
        return String::from("newer installation failed");
    }
    verdict(harness.store.install(&first))
}

/// Two different bodies claiming one generation.
///
/// Built with two independent issuers, each with its own nonce counter, so both
/// legitimately produce generation zero for the slot with different lease
/// identifiers. Accepting either would let authority be swapped at a fixed point
/// in the supersession order.
fn conflicting_generation(operation: &AuthorizedOperation, ttl_ms: u64) -> String {
    let mut harness = Harness::new(kern_execution_nav2::FakeNav2Backend::new());
    let Some(first) = issue_bytes(&mut harness, operation, ttl_ms) else {
        return String::from("issuance failed");
    };
    if harness.store.install(&first).is_err() {
        return String::from("first installation failed");
    }

    // A second issuer, whose nonce counter starts where the first one did, but
    // whose lease identifiers do not.
    let mut other = Harness::new(kern_execution_nav2::FakeNav2Backend::new());
    other.issuer = kern_authority::LeaseIssuer::new(
        IssuerId::new(ISSUER),
        kern_authority::Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED),
        kern_core::TestClock::new(kern_core::Timestamp::from_millis(
            crate::runner::ISSUED_AT_MS,
        )),
        kern_authority::CountingNonces::new(),
        kern_authority::SequentialLeaseIds::starting_at(0xF0),
    );
    // The challenge has to come from the enforcer under test, or the lease could
    // never be fresh for it.
    let Some(ticket) = mint(&mut harness, operation) else {
        return String::from("challenge mint failed");
    };
    let Ok(lease) = other
        .issuer
        .issue_v2(operation, Ttl::from_millis(ttl_ms), &ticket)
    else {
        return String::from("second issuance failed");
    };
    let Ok(bytes) = encode_v2(&lease) else {
        return String::from("encoding failed");
    };
    verdict(harness.store.install(&bytes))
}

/// Two leases answering one challenge.
fn consumed_challenge(operation: &AuthorizedOperation, ttl_ms: u64) -> String {
    let mut harness = Harness::new(kern_execution_nav2::FakeNav2Backend::new());
    let Some(ticket) = mint(&mut harness, operation) else {
        return String::from("challenge mint failed");
    };
    let Ok(first) = harness
        .issuer
        .issue_v2(operation, Ttl::from_millis(ttl_ms), &ticket)
    else {
        return String::from("issuance failed");
    };
    let Ok(second) = harness
        .issuer
        .issue_v2(operation, Ttl::from_millis(ttl_ms), &ticket)
    else {
        return String::from("second issuance failed");
    };
    let (Ok(first), Ok(second)) = (encode_v2(&first), encode_v2(&second)) else {
        return String::from("encoding failed");
    };
    if harness.store.install(&first).is_err() {
        return String::from("first installation failed");
    }
    verdict(harness.store.install(&second))
}

/// A challenge whose deadline has passed.
fn expired_challenge(operation: &AuthorizedOperation, ttl_ms: u64) -> String {
    let mut harness = Harness::new(kern_execution_nav2::FakeNav2Backend::new());
    let Some(ticket) = mint(&mut harness, operation) else {
        return String::from("challenge mint failed");
    };
    let Ok(lease) = harness
        .issuer
        .issue_v2(operation, Ttl::from_millis(ttl_ms), &ticket)
    else {
        return String::from("issuance failed");
    };
    let Ok(bytes) = encode_v2(&lease) else {
        return String::from("encoding failed");
    };
    harness.clock.advance(CHALLENGE_TTL_MS + 1);
    verdict(harness.store.install(&bytes))
}

/// Authority bound to a different enforcer boot session.
fn previous_session(operation: &AuthorizedOperation, ttl_ms: u64) -> String {
    let mut harness = Harness::new(kern_execution_nav2::FakeNav2Backend::new());
    let Some(bytes) = issue_bytes(&mut harness, operation, ttl_ms) else {
        return String::from("issuance failed");
    };

    // A different boot session. Volatile session state is what makes a lease
    // from before a reboot unusable after one.
    let signer = kern_authority::Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED);
    let mut trust = TrustStore::new();
    if trust
        .authorize(
            IssuerId::new(ISSUER),
            KeyId::new("dev-1"),
            signer.verifying_key_bytes(),
        )
        .is_err()
    {
        return String::from("trust setup failed");
    }
    let Ok(mut other) = kern_enforcer::EnforcerStore::new(
        EnforcerSessionId::from_bytes([0x22u8; 32]),
        trust,
        harness.clock.clone(),
        crate::runner::SequentialChallenges::starting_at(1),
        MonotonicDuration::from_millis(CHALLENGE_TTL_MS),
        4,
        4,
    ) else {
        return String::from("second enforcer setup failed");
    };
    verdict(other.install(&bytes))
}

/// A V1 lease offered to a V2-only enforcer.
///
/// V1 carries no challenge, so it cannot establish freshness at first
/// installation. The format is not broken; it is simply not one this enforcer
/// installs, and it is refused before any cryptography runs.
fn v1_installation(operation: &AuthorizedOperation, ttl_ms: u64) -> String {
    let mut harness = Harness::new(kern_execution_nav2::FakeNav2Backend::new());
    let Ok(lease) = harness.issuer.issue_v1(
        operation,
        Ttl::from_millis(ttl_ms),
        *harness.store.session(),
    ) else {
        return String::from("v1 issuance failed");
    };
    let Ok(bytes) = encode(&lease) else {
        return String::from("encoding failed");
    };
    verdict(harness.store.install(&bytes))
}

/// A challenge minted for a different authority slot.
///
/// The interesting result here is that the attempt does not reach the enforcer
/// at all: the issuer checks the ticket's bindings against the authorization
/// and refuses to sign, so a lease whose freshness could never match is never
/// created. The record says where it was stopped.
fn challenge_mismatch(operation: &AuthorizedOperation, ttl_ms: u64) -> String {
    let mut harness = Harness::new(kern_execution_nav2::FakeNav2Backend::new());
    let Ok(ticket) = harness.store.mint_challenge(
        &IssuerId::new(ISSUER),
        &kern_core::SubjectId::new("someone_else"),
        operation.proposal().device(),
        operation.proposal().capability(),
    ) else {
        return String::from("challenge mint failed");
    };
    match harness
        .issuer
        .issue_v2(operation, Ttl::from_millis(ttl_ms), &ticket)
    {
        Ok(_) => String::from("issuer signed a mismatched ticket"),
        Err(error) => format!("issuer refused: {error:?}"),
    }
}

/// A lease signed by a key the trust store does not hold.
fn untrusted_key(operation: &AuthorizedOperation, ttl_ms: u64) -> String {
    let mut harness = Harness::new(kern_execution_nav2::FakeNav2Backend::new());
    let Some(ticket) = mint(&mut harness, operation) else {
        return String::from("challenge mint failed");
    };
    let mut rogue = kern_authority::LeaseIssuer::new(
        IssuerId::new(ISSUER),
        kern_authority::Ed25519Signer::from_seed(KeyId::new("dev-1"), [9u8; 32]),
        kern_core::TestClock::new(kern_core::Timestamp::from_millis(
            crate::runner::ISSUED_AT_MS,
        )),
        kern_authority::CountingNonces::new(),
        kern_authority::SequentialLeaseIds::starting_at(1),
    );
    let Ok(lease) = rogue.issue_v2(operation, Ttl::from_millis(ttl_ms), &ticket) else {
        return String::from("rogue issuance failed");
    };
    let Ok(bytes) = encode_v2(&lease) else {
        return String::from("encoding failed");
    };
    verdict(harness.store.install(&bytes))
}

/// Authenticated bytes with one bit flipped.
fn tampered_bytes(operation: &AuthorizedOperation, ttl_ms: u64) -> String {
    let mut harness = Harness::new(kern_execution_nav2::FakeNav2Backend::new());
    let Some(mut bytes) = issue_bytes(&mut harness, operation, ttl_ms) else {
        return String::from("issuance failed");
    };
    // The last byte is inside the signature, which is the cleanest way to show
    // the signature is checked over the transmitted bytes.
    if let Some(last) = bytes.last_mut() {
        *last ^= 0x01;
    }
    verdict(harness.store.install(&bytes))
}

fn mint(
    harness: &mut Harness,
    operation: &AuthorizedOperation,
) -> Option<kern_core::ChallengeTicket> {
    harness
        .store
        .mint_challenge(
            &IssuerId::new(ISSUER),
            operation.proposal().actor(),
            operation.proposal().device(),
            operation.proposal().capability(),
        )
        .ok()
}

fn issue_bytes(
    harness: &mut Harness,
    operation: &AuthorizedOperation,
    ttl_ms: u64,
) -> Option<Vec<u8>> {
    let ticket = mint(harness, operation)?;
    let lease = harness
        .issuer
        .issue_v2(operation, Ttl::from_millis(ttl_ms), &ticket)
        .ok()?;
    encode_v2(&lease).ok()
}

/// Unused-import anchor for the uptime type the clock helpers return.
pub fn _uptime_anchor(_: Uptime) {}
