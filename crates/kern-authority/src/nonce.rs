//! Supersession ordering.

use alloc::collections::BTreeMap;
use core::fmt;

use kern_core::{CapabilityName, DeviceId, EnforcerSessionId, IssuerId, Nonce, SubjectId};

/// The V1 supersession domain.
///
/// Two leases compete — one able to supersede the other — exactly when they
/// share all five components:
///
/// ```text
/// (issuer, enforcer_session, subject, device, capability)
/// ```
///
/// Each component earns its place. `issuer`, because two issuers keep
/// independent counters and comparing them is meaningless. `enforcer_session`,
/// because leases from a previous session are already dead, so counter state is
/// naturally scoped to one boot. `subject` and `device`, because one subject's
/// authority must never cancel another's. `capability`, because a `speak` lease
/// must not be able to invalidate a concurrent `navigate` lease.
///
/// # V1 limitation
///
/// One active authority generation per slot. Two concurrent, independent
/// authority lineages over the same slot are not representable: the later lease
/// supersedes the earlier one. Disjunction *within* a capability is still
/// expressible in a single lease — an allow-list of destinations is one
/// constraint — but two concurrent missions with genuinely separate bounds are
/// not. Adding a lineage or generation identifier is a protocol-version
/// decision, not a counter detail.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slot {
    /// The issuing authority.
    pub issuer: IssuerId,
    /// The enforcer boot session.
    pub enforcer_session: EnforcerSessionId,
    /// The subject the authority is granted to.
    pub subject: SubjectId,
    /// The target device.
    pub device: DeviceId,
    /// The authorized capability.
    pub capability: CapabilityName,
}

/// A nonce could not be produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NonceError {
    /// The slot's counter cannot advance any further.
    Exhausted,
}

impl fmt::Display for NonceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => f.write_str("nonce space exhausted for this slot"),
        }
    }
}

impl core::error::Error for NonceError {}

/// Supplies strictly increasing nonces per slot.
///
/// # Invariant
///
/// ```text
/// nonces strictly increase within a slot, and NEVER wrap
/// ```
///
/// A wrapped nonce would break the ordering the whole supersession scheme rests
/// on. Arithmetic is checked: reaching `u64::MAX` yields
/// [`NonceError::Exhausted`], never zero. An enforcer that had seen the previous
/// generation would reject the wrapped value anyway, so wrapping buys nothing
/// and costs the invariant.
///
/// Gaps are fine. Only strict increase is required, so a nonce consumed by an
/// issuance that later fails to sign leaves a harmless hole.
///
/// Strict monotonicity within a slot is the only property the protocol requires.
/// How an implementation achieves it is its own business: a counter, a monotonic
/// millisecond clock, or durable storage are all valid, and they differ in how
/// they survive an issuer restart.
///
/// # Unresolved for production
///
/// [`CountingNonces`] keeps state in memory. A restarted issuer re-emits nonces
/// an enforcer has already seen, and those leases are rejected — fail-closed, but
/// unusable. Recovery would need either durable issuer state or an enforcer
/// reboot into a fresh session. Durable nonce and generation state is an open
/// question, and no persistence work happens in this phase.
pub trait NonceSource {
    /// The next nonce for `slot`, strictly greater than every previous one.
    fn next_nonce(&mut self, slot: &Slot) -> Result<Nonce, NonceError>;
}

/// An in-memory counter per slot, starting at 1.
///
/// Deterministic, which suits tests. Not durable, which does not suit
/// production — see [`NonceSource`].
#[derive(Clone, Debug, Default)]
pub struct CountingNonces {
    counters: BTreeMap<Slot, u64>,
}

impl CountingNonces {
    /// A source with no slots yet seen.
    pub fn new() -> Self {
        Self::default()
    }

    /// The last nonce issued for `slot`, if any.
    pub fn last_issued(&self, slot: &Slot) -> Option<Nonce> {
        self.counters.get(slot).copied().map(Nonce::new)
    }

    /// Restores the last nonce known to have been issued for `slot`.
    ///
    /// The seam a durable implementation would use to pick up where a previous
    /// issuer process left off. Durable nonce state itself is unresolved, and
    /// nothing in this phase persists anything.
    pub fn resume(&mut self, slot: Slot, last_issued: Nonce) {
        self.counters.insert(slot, last_issued.value());
    }
}

impl NonceSource for CountingNonces {
    fn next_nonce(&mut self, slot: &Slot) -> Result<Nonce, NonceError> {
        let counter = self.counters.entry(slot.clone()).or_insert(0);
        let next = counter.checked_add(1).ok_or(NonceError::Exhausted)?;
        *counter = next;
        Ok(Nonce::new(next))
    }
}
