//! Failure vocabulary for execution governance.

use core::fmt;

use kern_core::wire::EncodeError;
use kern_enforcer::EnforcementError;

use crate::contract::LapseAction;

/// Configuration that cannot produce a working governor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// A table with no capacity can hold nothing.
    ZeroCapacity,
    /// A journal with no capacity would drop every entry it was given.
    ZeroJournalCapacity,
    /// A zero observation budget would never drain a single report.
    ZeroObservationBudget,
    /// The adapter does not declare the configured lapse action.
    ///
    /// Refused at wiring time rather than discovered at lapse time, so an
    /// adapter can never silently turn a configured instruction into a no-op.
    LapseActionUnsupported {
        /// The action the governor was configured with.
        required: LapseAction,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity => f.write_str("execution table capacity must be greater than zero"),
            Self::ZeroJournalCapacity => f.write_str("journal capacity must be greater than zero"),
            Self::ZeroObservationBudget => {
                f.write_str("observation budget must be greater than zero")
            }
            Self::LapseActionUnsupported { .. } => {
                f.write_str("the executor does not declare the configured lapse action")
            }
        }
    }
}

impl core::error::Error for ConfigError {}

/// An execution could not be prepared.
///
/// # The invariant this type carries
///
/// `Err(GovernError)` means the executor was never invoked and no command was
/// sent. Every variant is a failure that happens before any adapter call, and
/// the type is producible only by
/// [`ExecutionGovernor::prepare`](crate::ExecutionGovernor::prepare) — the
/// submitting method returns no `Result` at all.
///
/// Authority lost between preparation and submission is therefore **not** a
/// `GovernError`: a record already exists, and that is a different provenance
/// fact. It arrives as
/// [`NotStartedReason::AuthorityLost`](crate::NotStartedReason::AuthorityLost).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GovernError {
    /// The operation is not authorized by the named authority.
    Authorization(EnforcementError),
    /// Every execution record is in use and none could be reclaimed.
    CapacityExhausted,
    /// The execution identifier source is exhausted.
    IdentifierExhausted,
    /// The store belongs to a different enforcer session than this governor.
    SessionMismatch,
    /// The operation could not be canonically encoded, so it cannot be named.
    CommandEncoding(EncodeError),
}

impl From<EnforcementError> for GovernError {
    fn from(error: EnforcementError) -> Self {
        Self::Authorization(error)
    }
}

impl From<EncodeError> for GovernError {
    fn from(error: EncodeError) -> Self {
        Self::CommandEncoding(error)
    }
}

impl fmt::Display for GovernError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(error) => write!(f, "{error}"),
            Self::CapacityExhausted => f.write_str("no execution record available"),
            Self::IdentifierExhausted => f.write_str("execution identifier space exhausted"),
            Self::SessionMismatch => f.write_str("store belongs to a different enforcer session"),
            Self::CommandEncoding(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for GovernError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Authorization(error) => Some(error),
            Self::CommandEncoding(error) => Some(error),
            Self::CapacityExhausted | Self::IdentifierExhausted | Self::SessionMismatch => None,
        }
    }
}

/// A dispute could not be resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveDisputeError {
    /// No record exists for that execution.
    NoSuchExecution,
    /// The execution is not disputed.
    ///
    /// Resolution exists to settle contradictory evidence. It is not a way to
    /// overwrite a terminal result Kern actually observed.
    NotDisputed,
}

impl fmt::Display for ResolveDisputeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchExecution => f.write_str("no such execution"),
            Self::NotDisputed => f.write_str("execution is not disputed"),
        }
    }
}

impl core::error::Error for ResolveDisputeError {}
