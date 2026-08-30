//! Installed authority, and the hot path that exercises it.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::Cell;

use kern_core::{
    AuthorityArtifactId, CapabilityName, ChallengeTicket, DeviceId, EnforcerSessionId, IssuerId,
    LeaseBodyV2, LeaseId, MonotonicClock, MonotonicDuration, NormalizedActionProposal, SubjectId,
    Uptime,
};

use crate::challenge::{ChallengeRecord, ChallengeSource, ChallengeState};
use crate::error::{ConfigError, EnforcementError, InstallError, MintError};
use crate::trust::TrustStore;
use crate::verify::verify_bytes;

/// The four components that identify an authority slot within one session.
///
/// The session is not a member: the whole store belongs to one boot session, so
/// carrying it in every key would be duplicated state that could disagree with
/// itself.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SlotKey {
    /// The issuing authority.
    pub issuer: IssuerId,
    /// The subject the authority is granted to.
    pub subject: SubjectId,
    /// The target device.
    pub device: DeviceId,
    /// The authorized capability.
    pub capability: CapabilityName,
}

/// Authority the store has installed.
///
/// # What possession proves
///
/// That every installation check succeeded **at the install commit**:
/// authenticated under a trusted issuer and key, canonically encoded, session
/// matched, freshness accepted, generation accepted, and a monotonic deadline
/// established.
///
/// # What it does not prove
///
/// That it is *still* the current authority for its slot — a later lease may
/// have superseded it. That its deadline has not passed. That no revocation
/// exists. And nothing whatsoever about physical safety: correct authority is
/// not safe motion.
///
/// Current authority is established by the store at the moment authority is
/// exercised, never by possession of a value. That is why this type is neither
/// `Clone` nor constructible outside this module, and is only ever reachable as
/// a borrow from the store.
#[derive(Debug)]
pub struct InstalledLease {
    body: LeaseBodyV2,
    artifact: AuthorityArtifactId,
    deadline: Uptime,
}

impl InstalledLease {
    /// The authenticated body.
    pub fn body(&self) -> &LeaseBodyV2 {
        &self.body
    }

    /// The identity of the authenticated authority artifact.
    pub fn artifact(&self) -> &AuthorityArtifactId {
        &self.artifact
    }

    /// When this authority ends, in enforcer uptime.
    pub fn deadline(&self) -> Uptime {
        self.deadline
    }
}

/// A receipt naming installed authority. **Not** authority by possession.
///
/// Freely copyable and proves nothing on its own. Exercising authority means
/// handing it back to the store, which re-resolves the slot and revalidates.
///
/// The slot-table index is deliberately absent: storage position is not
/// identity. A handle names a semantic [`SlotKey`], a [`LeaseId`], and an
/// artifact digest, so a handle whose lease was superseded — or whose storage
/// was reclaimed for unrelated authority — fails to resolve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseHandle {
    slot: SlotKey,
    lease_id: LeaseId,
    artifact: AuthorityArtifactId,
}

impl LeaseHandle {
    /// The slot this receipt names.
    pub fn slot(&self) -> &SlotKey {
        &self.slot
    }

    /// The lease this receipt names.
    pub fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    /// The artifact this receipt names.
    pub fn artifact(&self) -> &AuthorityArtifactId {
        &self.artifact
    }
}

/// The outcome of a successful installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Installed {
    /// Newly installed. A challenge was consumed.
    Fresh(LeaseHandle),
    /// This exact authority was already installed.
    ///
    /// A delivery retry, not an attack. No challenge is required, and the
    /// original deadline stands: a retry must never refresh authority lifetime.
    Already(LeaseHandle),
}

impl Installed {
    /// The receipt, whichever way installation resolved.
    pub fn handle(&self) -> &LeaseHandle {
        match self {
            Self::Fresh(handle) | Self::Already(handle) => handle,
        }
    }
}

struct SlotEntry {
    key: SlotKey,
    lease: InstalledLease,
}

/// One boot session's authority state.
///
/// # Concurrency
///
/// Single-threaded and structurally `!Sync` — it holds a [`Cell`], so no promise
/// in a comment is load-bearing. `install` takes `&mut self` and is the only
/// mutation of authority state; `enforce` takes `&self`. The borrow checker
/// therefore rules out observing a partial commit. Interrupt-context or
/// concurrent enforcement is **not** supported and would need its own design.
///
/// ```compile_fail
/// # use kern_core::{Challenge, TestMonotonicClock};
/// # use kern_enforcer::{ChallengeSource, EnforcerStore, EntropyError};
/// // A caller-supplied entropy source; the crate ships none.
/// struct Entropy;
/// impl ChallengeSource for Entropy {
///     fn next_challenge(&mut self) -> Result<Challenge, EntropyError> { unimplemented!() }
/// }
///
/// fn requires_sync<T: Sync>(_: &T) {}
/// let store: EnforcerStore<TestMonotonicClock, Entropy> = unimplemented!();
/// requires_sync(&store);
/// ```
///
/// # Atomicity
///
/// A normal in-process install call exposes no intermediate authority state: all
/// fallible work — authentication, every check, locating both table indices, and
/// building the entry — completes before two writes into pre-allocated storage.
/// That is *not* hardware atomicity, crash atomicity, or power-loss safety.
/// Session, challenge, and slot state are volatile and disappear together on
/// reboot, so there is nothing for a torn write to corrupt across a boot.
///
/// The tables are fixed-capacity arrays rather than maps for exactly this
/// reason: a map insert allocates, and could therefore fail *after* every check
/// has passed.
pub struct EnforcerStore<M: MonotonicClock, R: ChallengeSource> {
    session: EnforcerSessionId,
    trust: TrustStore,
    clock: M,
    challenges: R,
    challenge_ttl: MonotonicDuration,
    last_uptime: Cell<Uptime>,
    challenge_table: Box<[Option<ChallengeRecord>]>,
    slot_table: Box<[Option<SlotEntry>]>,
}

impl<M: MonotonicClock, R: ChallengeSource> EnforcerStore<M, R> {
    /// Builds a store for one boot session.
    ///
    /// The session identifier must come from a CSPRNG and must be obtained
    /// before any lease is accepted. Entropy failure is fatal: there is no
    /// degraded mode, because a predictable session is a replayable one.
    pub fn new(
        session: EnforcerSessionId,
        trust: TrustStore,
        clock: M,
        challenges: R,
        challenge_ttl: MonotonicDuration,
        challenge_capacity: usize,
        slot_capacity: usize,
    ) -> Result<Self, ConfigError> {
        if challenge_ttl.is_zero() {
            return Err(ConfigError::ZeroChallengeTtl);
        }
        if challenge_capacity == 0 || slot_capacity == 0 {
            return Err(ConfigError::ZeroCapacity);
        }

        let start = clock.uptime();
        Ok(Self {
            session,
            trust,
            clock,
            challenges,
            challenge_ttl,
            last_uptime: Cell::new(start),
            challenge_table: (0..challenge_capacity)
                .map(|_| None)
                .collect::<Vec<_>>()
                .into(),
            slot_table: (0..slot_capacity).map(|_| None).collect::<Vec<_>>().into(),
        })
    }

    /// This enforcer's boot session.
    pub fn session(&self) -> &EnforcerSessionId {
        &self.session
    }

    /// The trust store.
    pub fn trust(&self) -> &TrustStore {
        &self.trust
    }

    /// Reads the monotonic clock, refusing if it moved backwards.
    ///
    /// Checked on every path including the hot one: a backwards clock would make
    /// leases live *longer*, which is the dangerous direction.
    fn now(&self) -> Option<Uptime> {
        let now = self.clock.uptime();
        if now < self.last_uptime.get() {
            return None;
        }
        self.last_uptime.set(now);
        Some(now)
    }

    /// Mints a challenge for one authority slot.
    ///
    /// Capacity is resolved before entropy is drawn, and the record is written
    /// before the ticket is returned, so a full table never burns a challenge
    /// and no ticket ever escapes without its record.
    pub fn mint_challenge(
        &mut self,
        issuer: &IssuerId,
        subject: &SubjectId,
        device: &DeviceId,
        capability: &CapabilityName,
    ) -> Result<ChallengeTicket, MintError> {
        let now = self.now().ok_or(MintError::ClockWentBackwards)?;
        let deadline = now
            .checked_add(self.challenge_ttl)
            .ok_or(MintError::DeadlineOverflow)?;

        for slot in self.challenge_table.iter_mut() {
            let reclaimable = matches!(
                slot,
                Some(record)
                    if record.state == ChallengeState::Consumed || record.deadline < now
            );
            if reclaimable {
                *slot = None;
            }
        }

        let index = self
            .challenge_table
            .iter()
            .position(Option::is_none)
            .ok_or(MintError::CapacityExhausted)?;

        let challenge = self.challenges.next_challenge()?;

        self.challenge_table[index] = Some(ChallengeRecord {
            issuer: issuer.clone(),
            session: self.session,
            challenge,
            subject: subject.clone(),
            device: device.clone(),
            capability: capability.clone(),
            issued_at: now,
            deadline,
            state: ChallengeState::Outstanding,
        });

        Ok(ChallengeTicket {
            issuer: issuer.clone(),
            session: self.session,
            challenge,
            subject: subject.clone(),
            device: device.clone(),
            capability: capability.clone(),
        })
    }

    /// Authenticates and installs a lease.
    ///
    /// See the type documentation for the atomicity claim. Every fallible step
    /// precedes the commit, and a rejected lease mutates nothing — a nonce
    /// comparison is a comparison, never a consumption.
    pub fn install(&mut self, bytes: &[u8]) -> Result<Installed, InstallError> {
        let now = self.now().ok_or(InstallError::ClockWentBackwards)?;

        let verified = verify_bytes(bytes, &self.trust)?;
        let (body, artifact) = verified.into_parts();

        if body.core.enforcer_session != self.session {
            return Err(InstallError::SessionMismatch);
        }

        let key = SlotKey {
            issuer: body.core.issuer.clone(),
            subject: body.core.subject.clone(),
            device: body.core.device.clone(),
            capability: body.core.capability.clone(),
        };

        let existing = self
            .slot_table
            .iter()
            .position(|slot| matches!(slot, Some(entry) if entry.key == key));

        // Supersession, before freshness: an exact re-presentation of installed
        // authority is a delivery retry and must succeed without a still-live
        // challenge, and without recomputing the deadline it was installed with.
        if let Some(index) = existing {
            let entry = self.slot_table[index]
                .as_ref()
                .expect("index came from a match");
            let installed = &entry.lease.body.core;

            if body.core.nonce == installed.nonce {
                return if body.core.id == installed.id && artifact == entry.lease.artifact {
                    Ok(Installed::Already(LeaseHandle {
                        slot: key,
                        lease_id: installed.id,
                        artifact: entry.lease.artifact,
                    }))
                } else {
                    Err(InstallError::ConflictingGeneration)
                };
            }
            if body.core.nonce < installed.nonce {
                return Err(InstallError::SupersededNonce);
            }
        }

        let challenge_index = self.validate_challenge(&body, &key, now)?;
        let deadline = self.authority_deadline(&body, challenge_index, now)?;

        let slot_index = match existing {
            Some(index) => index,
            None => self
                .slot_table
                .iter()
                .position(Option::is_none)
                .ok_or(InstallError::CapacityExhausted)?,
        };

        let handle = LeaseHandle {
            slot: key.clone(),
            lease_id: body.core.id,
            artifact,
        };
        let entry = SlotEntry {
            key,
            lease: InstalledLease {
                body,
                artifact,
                deadline,
            },
        };

        // ==== commit: two writes into pre-allocated storage, no failure path ====
        self.slot_table[slot_index] = Some(entry);
        self.challenge_table[challenge_index]
            .as_mut()
            .expect("index came from a match")
            .state = ChallengeState::Consumed;

        Ok(Installed::Fresh(handle))
    }

    /// Locates the outstanding challenge this lease answers.
    fn validate_challenge(
        &self,
        body: &LeaseBodyV2,
        key: &SlotKey,
        now: Uptime,
    ) -> Result<usize, InstallError> {
        let index = self
            .challenge_table
            .iter()
            .position(|slot| matches!(slot, Some(record) if record.challenge == body.challenge))
            .ok_or(InstallError::ChallengeUnknown)?;

        let record = self.challenge_table[index]
            .as_ref()
            .expect("index came from a match");

        if record.state == ChallengeState::Consumed {
            return Err(InstallError::ChallengeConsumed);
        }
        if record.deadline < now {
            return Err(InstallError::ChallengeExpired);
        }
        if record.session != self.session {
            return Err(InstallError::SessionMismatch);
        }
        // The complete slot binding: a challenge establishes freshness for
        // exactly one authority slot, never for a neighbouring one.
        if record.issuer != key.issuer
            || record.subject != key.subject
            || record.device != key.device
            || record.capability != key.capability
        {
            return Err(InstallError::ChallengeMismatch);
        }

        Ok(index)
    }

    /// Computes when installed authority ends.
    ///
    /// Anchored at **challenge issuance**, not arrival, so delivery delay is
    /// charged against the lease's own lifetime instead of being forgiven.
    ///
    /// The challenge deadline gates first installation only. It does not
    /// truncate authority that was already freshly installed: a 500 ms challenge
    /// answered at 400 ms with a 10 s signed window yields authority for the
    /// full 10 s.
    fn authority_deadline(
        &self,
        body: &LeaseBodyV2,
        challenge_index: usize,
        now: Uptime,
    ) -> Result<Uptime, InstallError> {
        let issued_at = body.core.issued_at.as_millis();
        let expires_at = body.core.expires_at.as_millis();
        let window = expires_at
            .checked_sub(issued_at)
            .filter(|window| *window > 0)
            .ok_or(InstallError::ExpiresBeforeIssued)?;

        let anchor = self.challenge_table[challenge_index]
            .as_ref()
            .expect("index came from a match")
            .issued_at;

        let deadline = anchor
            .checked_add(MonotonicDuration::from_millis(window))
            .ok_or(InstallError::DeadlineOverflow)?;

        if now >= deadline {
            return Err(InstallError::AlreadyExpired);
        }
        Ok(deadline)
    }

    /// Resolves a receipt to the authority it names, if that is still installed.
    pub fn installed(&self, handle: &LeaseHandle) -> Option<&InstalledLease> {
        self.slot_table.iter().flatten().find_map(|entry| {
            (entry.key == handle.slot
                && entry.lease.body.core.id == handle.lease_id
                && entry.lease.artifact == handle.artifact)
                .then_some(&entry.lease)
        })
    }

    /// Decides whether an operation is authorized under installed authority.
    ///
    /// Comparisons only — no signature verification, no decoding, no allocation.
    /// One expensive verification happens per lease at installation; this runs
    /// per physical command.
    pub fn enforce(
        &self,
        handle: &LeaseHandle,
        operation: &NormalizedActionProposal,
    ) -> Result<(), EnforcementError> {
        let now = self.now().ok_or(EnforcementError::ClockWentBackwards)?;

        let entry = self
            .slot_table
            .iter()
            .flatten()
            .find(|entry| entry.key == handle.slot)
            .ok_or(EnforcementError::NoAuthority)?;

        // Storage position is not identity. A superseded lease, or a slot
        // reclaimed for unrelated authority, fails here.
        if entry.lease.body.core.id != handle.lease_id || entry.lease.artifact != handle.artifact {
            return Err(EnforcementError::Superseded);
        }

        if now >= entry.lease.deadline {
            return Err(EnforcementError::DeadlineExpired);
        }

        let body = &entry.lease.body.core;
        if &body.subject != operation.actor() {
            return Err(EnforcementError::SubjectMismatch);
        }
        if &body.device != operation.device() {
            return Err(EnforcementError::DeviceMismatch);
        }
        if &body.capability != operation.capability() {
            return Err(EnforcementError::CapabilityMismatch);
        }
        if !body.constraints.permits(operation.params()) {
            return Err(EnforcementError::ConstraintViolation);
        }

        Ok(())
    }
}
