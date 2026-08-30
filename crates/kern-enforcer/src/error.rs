//! Failure vocabulary for the edge.
//!
//! Install-time and steady-state failures are separate enums. They have
//! different consumers, different rates, and different collapsing rules at any
//! future external boundary.

use core::fmt;

use kern_core::wire::DecodeError;

use crate::trust::TrustError;

/// Configuration that cannot produce a working store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// A zero challenge lifetime would reject every lease it ever gated.
    ZeroChallengeTtl,
    /// A table with no capacity can hold nothing.
    ZeroCapacity,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroChallengeTtl => f.write_str("challenge lifetime must be greater than zero"),
            Self::ZeroCapacity => f.write_str("table capacity must be greater than zero"),
        }
    }
}

impl core::error::Error for ConfigError {}

/// The entropy source failed.
///
/// Fatal by design. A challenge or session identifier drawn from a weak source
/// is one an attacker can predict and have answered in advance, so there is no
/// degraded mode to fall back to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntropyError;

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("entropy source unavailable")
    }
}

impl core::error::Error for EntropyError {}

/// A challenge could not be minted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintError {
    /// The monotonic clock moved backwards.
    ClockWentBackwards,
    /// Adding the challenge lifetime to now overflows.
    DeadlineOverflow,
    /// Every challenge record is in use and none could be reclaimed.
    ///
    /// Raised *before* entropy is drawn, so a full table never burns a
    /// challenge, and a ticket is never returned whose record was not written.
    CapacityExhausted,
    /// The entropy source failed.
    Entropy(EntropyError),
}

impl From<EntropyError> for MintError {
    fn from(error: EntropyError) -> Self {
        Self::Entropy(error)
    }
}

impl fmt::Display for MintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClockWentBackwards => f.write_str("monotonic clock moved backwards"),
            Self::DeadlineOverflow => f.write_str("challenge deadline overflows"),
            Self::CapacityExhausted => f.write_str("no challenge record available"),
            Self::Entropy(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for MintError {}

/// A lease could not be installed.
///
/// Granular internally, because tests and provenance need to know *which* check
/// refused. Any externally facing surface should collapse the three
/// authentication failures into one opaque value, and likewise the four
/// challenge failures: distinguishing them tells a prober which issuers and keys
/// are trusted and what challenge state exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallError {
    // -- framing and encoding, before any trust --
    /// The protocol version is not one this enforcer installs.
    ///
    /// This enforcer installs V2 only. V1 carries no challenge and therefore
    /// cannot support freshness at first installation.
    UnsupportedVersion {
        /// The version found on the wire.
        found: u16,
    },
    /// The bytes are not a well-formed envelope or body.
    Malformed,
    /// The body decodes, but not from the one canonical encoding of its value.
    NonCanonicalEncoding,

    // -- authentication; collapse these three externally --
    /// No key is trusted for the claimed issuer.
    UntrustedIssuer,
    /// The claimed issuer is trusted, but not under that key identifier.
    UnknownKey,
    /// The signature does not verify over the transmitted bytes.
    InvalidSignature,

    // -- binding --
    /// The lease is bound to a different enforcer boot session.
    SessionMismatch,

    // -- freshness; collapse these four externally --
    /// No record exists for the lease's challenge.
    ChallengeUnknown,
    /// The challenge record's local deadline has passed.
    ChallengeExpired,
    /// The challenge was already spent on an installation.
    ChallengeConsumed,
    /// The challenge exists but was minted for a different authority slot.
    ChallengeMismatch,

    // -- lifetime --
    /// The lease expires no later than it was issued.
    ExpiresBeforeIssued,
    /// The authority deadline overflows the uptime space.
    DeadlineOverflow,
    /// The authority window had already elapsed by the time of installation.
    AlreadyExpired,
    /// The monotonic clock moved backwards.
    ClockWentBackwards,

    // -- supersession --
    /// A newer generation is already installed in this slot.
    SupersededNonce,
    /// A different authority artifact already holds this generation.
    ///
    /// Two distinct bodies claiming one generation is an issuer fault or an
    /// attack. Accepting either would let authority be swapped at a fixed point
    /// in the supersession order.
    ConflictingGeneration,

    // -- resources --
    /// Every slot is occupied.
    CapacityExhausted,
}

impl From<TrustError> for InstallError {
    fn from(error: TrustError) -> Self {
        match error {
            TrustError::UntrustedIssuer => Self::UntrustedIssuer,
            TrustError::UnknownKey => Self::UnknownKey,
        }
    }
}

impl From<DecodeError> for InstallError {
    fn from(error: DecodeError) -> Self {
        match error {
            DecodeError::UnsupportedVersion { found } => Self::UnsupportedVersion { found },
            DecodeError::NonCanonicalEncoding => Self::NonCanonicalEncoding,
            DecodeError::Truncated
            | DecodeError::TrailingBytes
            | DecodeError::BodyTooLarge
            | DecodeError::Malformed => Self::Malformed,
        }
    }
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found } => write!(f, "unsupported lease version {found}"),
            Self::Malformed => f.write_str("malformed lease"),
            Self::NonCanonicalEncoding => f.write_str("lease is not canonically encoded"),
            Self::UntrustedIssuer => f.write_str("untrusted issuer"),
            Self::UnknownKey => f.write_str("unknown key for issuer"),
            Self::InvalidSignature => f.write_str("signature does not verify"),
            Self::SessionMismatch => f.write_str("lease is bound to a different session"),
            Self::ChallengeUnknown => f.write_str("no such challenge"),
            Self::ChallengeExpired => f.write_str("challenge expired"),
            Self::ChallengeConsumed => f.write_str("challenge already consumed"),
            Self::ChallengeMismatch => f.write_str("challenge was minted for another slot"),
            Self::ExpiresBeforeIssued => f.write_str("lease expires no later than it was issued"),
            Self::DeadlineOverflow => f.write_str("authority deadline overflows"),
            Self::AlreadyExpired => f.write_str("authority window already elapsed"),
            Self::ClockWentBackwards => f.write_str("monotonic clock moved backwards"),
            Self::SupersededNonce => f.write_str("a newer generation is installed"),
            Self::ConflictingGeneration => {
                f.write_str("a different artifact already holds this generation")
            }
            Self::CapacityExhausted => f.write_str("no slot available"),
        }
    }
}

impl core::error::Error for InstallError {}

/// An operation was refused at the hot path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnforcementError {
    /// Nothing is installed for the handle's slot.
    NoAuthority,
    /// The slot holds different authority than the handle names.
    ///
    /// The handle is stale: its lease was superseded, or its storage was
    /// reclaimed for unrelated authority.
    Superseded,
    /// The authority deadline has passed.
    DeadlineExpired,
    /// The monotonic clock moved backwards.
    ClockWentBackwards,
    /// The operation names a different subject than the lease authorizes.
    SubjectMismatch,
    /// The operation names a different device.
    DeviceMismatch,
    /// The operation names a different capability.
    CapabilityMismatch,
    /// The operation's parameters fall outside the lease's bounds.
    ConstraintViolation,
}

impl fmt::Display for EnforcementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAuthority => f.write_str("no authority installed for this slot"),
            Self::Superseded => f.write_str("handle names authority that is no longer installed"),
            Self::DeadlineExpired => f.write_str("authority deadline passed"),
            Self::ClockWentBackwards => f.write_str("monotonic clock moved backwards"),
            Self::SubjectMismatch => f.write_str("operation subject does not match the lease"),
            Self::DeviceMismatch => f.write_str("operation device does not match the lease"),
            Self::CapabilityMismatch => {
                f.write_str("operation capability does not match the lease")
            }
            Self::ConstraintViolation => f.write_str("operation exceeds the lease bounds"),
        }
    }
}

impl core::error::Error for EnforcementError {}
