//! Lease vocabulary: the semantic shape of temporary physical authority.
//!
//! Data types only. No cryptography lives here, and no signing key ever does.
//! The canonical wire encoding is in [`crate::wire`]; keeping the two apart lets
//! the authority algebra evolve without dragging serialization behind it.

use alloc::string::String;
use core::fmt;

use crate::challenge::Challenge;
use crate::clock::Timestamp;
use crate::constraint_set::ConstraintSet;
use crate::ids::{CapabilityName, DeviceId, SubjectId};

/// Identifies one issued lease.
///
/// Identity and provenance only. It is **not** the replay primitive — that is
/// [`Nonce`]. Uniqueness is a responsibility of whatever source mints these; a
/// `LeaseId` value proves nothing about global uniqueness on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeaseId([u8; 16]);

impl LeaseId {
    /// Wraps 16 bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The underlying bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Identifies the authority that issued a lease.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IssuerId(String);

impl IssuerId {
    /// Wraps an issuer identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrows the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IssuerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Names which key signed a lease.
///
/// A lookup hint for selecting a verification key, and nothing more. Finding a
/// key for a claimed identifier is not authorization: the signature must still
/// verify against a trust-store entry accepted for the claimed issuer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// Wraps a key identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrows the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Orders leases that supersede one another.
///
/// # Supersession domain
///
/// A nonce is meaningful only within one *slot*:
///
/// ```text
/// (issuer, enforcer_session, subject, device, capability)
/// ```
///
/// Within a slot, nonces strictly increase, and an enforcer rejects any lease
/// whose nonce is at or below the highest it has installed for that slot. Across
/// slots there is no ordering and no interaction, so a `speak` lease can never
/// invalidate a concurrent `navigate` lease.
///
/// # What this actually prevents
///
/// Not presenting a live lease twice — a lease is *meant* to be presented
/// repeatedly inside its validity window; that is the point of a lease.
///
/// What it prevents is re-installing a **superseded** lease: an attacker who
/// captured a permissive lease cannot install it again after a narrower one took
/// effect, even though every field of it would still verify.
///
/// # V1 limitation
///
/// One active authority generation per slot. Independent concurrent authority
/// lineages for the same issuer, session, subject, device, and capability are
/// not representable. Adding a lineage or generation identifier would be a
/// protocol-version decision, not a counter detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nonce(u64);

impl Nonce {
    /// Wraps a counter value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The underlying counter value.
    pub const fn value(&self) -> u64 {
        self.0
    }
}

/// Identifies one enforcer boot session.
///
/// Regenerated on every enforcer boot, so leases bound to a previous session are
/// rejected wholesale after a reboot (AGENT.md section 6). This bounds
/// cross-reboot replay. It does **not** bound how long delivery may be delayed
/// within a single session — freshness at installation remains unresolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnforcerSessionId([u8; 32]);

impl EnforcerSessionId {
    /// Wraps 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The underlying bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A detached Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Wraps 64 bytes.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The underlying bytes.
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({} bytes)", self.0.len())
    }
}

/// The authenticated content of a lease.
///
/// Every field here is covered by the signature. Nothing outside this struct is
/// signed, and nothing outside it may be trusted.
///
/// The authority this grants is exactly `subject`, `device`, `capability`, and
/// `constraints`. There is no separate scope field, and no authority-invariant
/// field — see AGENT.md section 4.4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseBody {
    /// Identity and provenance.
    pub id: LeaseId,
    /// Which authority issued this.
    pub issuer: IssuerId,
    /// Which key signed it. A lookup hint, not authorization.
    pub key_id: KeyId,
    /// Who the authority is granted to.
    pub subject: SubjectId,
    /// Which device it applies to.
    pub device: DeviceId,
    /// Which semantic capability it authorizes.
    pub capability: CapabilityName,
    /// The bounds the operation must satisfy.
    pub constraints: ConstraintSet,
    /// When the issuer minted this.
    pub issued_at: Timestamp,
    /// When the authority ends.
    ///
    /// Absolute timestamps are signed audit data. They do **not** by themselves
    /// solve freshness at installation: an enforcer must not convert
    /// `expires_at - issued_at` into a fresh full lifetime measured from an
    /// arbitrarily delayed arrival (AGENT.md section 7).
    pub expires_at: Timestamp,
    /// Position in this slot's supersession order. See [`Nonce`].
    pub nonce: Nonce,
    /// The enforcer boot session this lease is bound to.
    pub enforcer_session: EnforcerSessionId,
}

/// Which wire schema and domain separator a lease uses.
///
/// Serialized explicitly as a fixed-width prefix and authenticated by the
/// signature, so it can be read before any schema is chosen and cannot be
/// tampered with afterwards. An unsupported version fails closed before the body
/// is decoded at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolVersion {
    /// Signed authority without a freshness binding.
    ///
    /// A complete, frozen, signable format. It simply cannot offer
    /// freshness at first installation, because it carries no per-request
    /// challenge.
    V1,
    /// Signed authority with a per-request challenge binding.
    V2,
}

impl ProtocolVersion {
    /// The numeric version, as it appears on the wire.
    pub const fn as_u16(&self) -> u16 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }

    /// Recognizes a wire version, or `None` for one this build cannot parse.
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::V1),
            2 => Some(Self::V2),
            _ => None,
        }
    }
}

/// The authenticated content of a V2 lease.
///
/// Every V1 field, unchanged, plus the per-request challenge that makes
/// freshness at first installation provable. The V1 body is embedded rather
/// than copied so "V2 retains the V1 fields unchanged" is structurally true
/// rather than true by convention — and because the canonical encoding of a
/// nested struct is exactly its fields in order, V2 bytes are V1 bytes followed
/// by the challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseBodyV2 {
    /// Every V1 field.
    pub core: LeaseBody,
    /// The enforcer challenge this lease answers.
    pub challenge: Challenge,
}

/// A V2 lease body together with the signature over it.
///
/// Constructible data, not authenticated authority — see [`SignedLease`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedLeaseV2 {
    /// The wire schema this lease was signed under. Always [`ProtocolVersion::V2`].
    pub version: ProtocolVersion,
    /// The authenticated content.
    pub body: LeaseBodyV2,
    /// The signature over the canonical signing input.
    pub signature: Signature,
}

/// A lease body together with the signature over it.
///
/// # Constructible data is not authenticated authority
///
/// Anyone can build one of these with arbitrary fields and arbitrary signature
/// bytes, and that mints nothing. A `SignedLease` is a claim. Verification
/// against a trusted key is the boundary where a claim becomes authority, and
/// that boundary lives at the enforcer.
///
/// Contrast [`crate::NormalizedActionProposal`] and `AuthorizedOperation`, whose
/// private constructors *are* the guarantee: possessing one means a validation
/// step ran. Possessing a `SignedLease` means someone assembled a struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedLease {
    /// The wire schema this lease was signed under.
    pub version: ProtocolVersion,
    /// The authenticated content.
    pub body: LeaseBody,
    /// The signature over the canonical signing input.
    pub signature: Signature,
}
