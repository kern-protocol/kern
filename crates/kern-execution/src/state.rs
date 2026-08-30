//! The three orthogonal dimensions of what Kern knows about an execution.
//!
//! ```text
//! AuthorityState      Kern's authority position        always decidable locally
//! ExecutionState      Kern's belief about progress     external, sometimes unknown
//! CancellationState   Kern's cancellation position     Kern's request + adapter reply
//! ```
//!
//! They are separate because they move on different inputs. Fusing them into one
//! enum would need the product of the three, and — worse — would make
//! "authority lapsed" read as "execution stopped". It does not. The honest
//! sentence this module exists to express is:
//!
//! ```text
//! execution: Running, authority: Lapsed(LeaseExpired), cancellation: Requested
//! ```
//!
//! A running machine, no authority, a cancellation asked for and not yet
//! confirmed. A single enum cannot say that without lying about one dimension.

use core::fmt;

use kern_core::Uptime;
use kern_enforcer::AuthorityStatusError;

/// Why Kern stopped granting authority to an execution.
///
/// A closed set. Every variant corresponds to something the authority substrate
/// actually reports; there is deliberately no variant for a condition only a
/// governor flag would know about.
///
/// Absent on purpose: revocation (out of scope), policy mutation (no policy
/// re-evaluation exists), and anything named for an emergency stop — hardware
/// E-stop lives below Kern and is not an authority concept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityLapseReason {
    /// The lease deadline passed.
    LeaseExpired,
    /// A different authority generation now occupies the slot.
    Superseded,
    /// Nothing is installed for the slot any more, or the enforcer session is
    /// not the one that authorized the execution.
    AuthorityMissing,
    /// The monotonic clock moved backwards, so lifetime accounting can no longer
    /// be trusted. Fails closed, in the same direction as the hot path.
    ClockUntrusted,
}

impl From<AuthorityStatusError> for AuthorityLapseReason {
    fn from(error: AuthorityStatusError) -> Self {
        match error {
            AuthorityStatusError::AuthorityMissing => Self::AuthorityMissing,
            AuthorityStatusError::Superseded => Self::Superseded,
            AuthorityStatusError::DeadlineExpired => Self::LeaseExpired,
            AuthorityStatusError::ClockWentBackwards => Self::ClockUntrusted,
        }
    }
}

impl fmt::Display for AuthorityLapseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LeaseExpired => "lease expired",
            Self::Superseded => "authority superseded",
            Self::AuthorityMissing => "no authority installed",
            Self::ClockUntrusted => "monotonic clock untrustworthy",
        })
    }
}

/// Kern's authority position on one execution.
///
/// Monotonic: once lapsed, never current again. A newer lease does not adopt an
/// execution prepared under an older one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityState {
    /// The authority that permitted this execution was still current at the last
    /// check.
    Current,
    /// Kern has stopped granting authority to this execution.
    ///
    /// Says nothing about the machine. A physical operation may still be running
    /// after this, and Kern never claims otherwise.
    Lapsed {
        /// Why authority ended.
        reason: AuthorityLapseReason,
        /// When Kern marked the lapse, in local uptime.
        at: Uptime,
    },
}

impl AuthorityState {
    /// True when authority has lapsed.
    pub fn is_lapsed(&self) -> bool {
        matches!(self, Self::Lapsed { .. })
    }

    /// The lapse reason, if authority has lapsed.
    pub fn lapse_reason(&self) -> Option<AuthorityLapseReason> {
        match self {
            Self::Lapsed { reason, .. } => Some(*reason),
            Self::Current => None,
        }
    }

    /// When Kern marked the lapse, if it has.
    pub fn lapsed_at(&self) -> Option<Uptime> {
        match self {
            Self::Lapsed { at, .. } => Some(*at),
            Self::Current => None,
        }
    }
}

/// How a machine operation ended, as reported by an executor.
///
/// Evidence about an attempted operation. Never used for an attempt that never
/// reached the executor — that is [`ExecutionState::NotStarted`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureClass {
    /// The executor reported the operation could not achieve its effect.
    OperationFailed,
    /// The executor reported the operation was aborted by something outside
    /// Kern's request.
    AbortedByExecutor,
}

/// A terminal result an executor can report about an operation it ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalOutcome {
    /// The executor reported completion.
    Completed,
    /// The executor reported failure.
    Failed(FailureClass),
    /// The executor reported the operation was cancelled.
    Cancelled,
}

/// Why an execution never started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotStartedReason {
    /// The submit-time liveness check refused. The executor was never invoked.
    AuthorityLost(AuthorityLapseReason),
    /// The executor was invoked and proved the command did not start.
    Rejected(RejectionReason),
    /// The preparation was dropped without being submitted. The executor was
    /// never invoked.
    Abandoned,
}

/// An adapter's reason for proving a command did not start.
///
/// Only ever reported when the adapter *knows* nothing reached the executor.
/// Doubt is [`SubmitOutcome::Unknown`](crate::SubmitOutcome::Unknown), not a
/// rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionReason {
    /// The executor was not reachable, and nothing was sent.
    Unavailable,
    /// The executor does not implement this capability.
    Unsupported,
    /// The executor refused the command as malformed for its own interface.
    InvalidCommand,
    /// The executor declined to accept another operation right now.
    Busy,
    /// The executor refused for a reason of its own.
    Refused,
}

/// Which phase of an execution Kern lost knowledge in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownPhase {
    /// The submission acknowledgement was lost. Kern holds no operation
    /// identity, so it cannot query, cancel, or instruct — only reconciliation
    /// with an echoed execution identifier can recover this.
    Submission,
    /// The operation was accepted, and Kern later lost sight of its result.
    Result,
}

/// What Kern last knew before knowledge was lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LastKnown {
    /// Recorded, not yet acknowledged by the executor.
    Prepared,
    /// Accepted by the executor.
    Submitted,
    /// Observed running.
    Running,
}

/// Kern's belief about an execution's progress.
///
/// Terminal states are absorbing: `Completed`, `Failed`, `Cancelled`,
/// `NotStarted`, and `Disputed`. `Unknown` is *not* terminal — it is quiescent,
/// and is left only by evidence, never by elapsed time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionState {
    /// A record exists and nothing has been sent.
    Prepared,
    /// Nothing was sent and nothing ever will be under this attempt.
    NotStarted(NotStartedReason),
    /// The executor accepted the command and has not been observed running it.
    Submitted,
    /// The executor has been observed running the operation.
    Running,
    /// The executor reported completion.
    Completed,
    /// The executor reported failure of an attempted operation.
    Failed(FailureClass),
    /// The executor reported the operation was cancelled.
    Cancelled,
    /// Executors reported two different terminal results.
    ///
    /// Kern holds contradictory evidence and refuses to choose which physical
    /// result is true. Nothing automatic leaves this state; only an explicit,
    /// attributed resolution does.
    Disputed {
        /// The first terminal result observed.
        first: TerminalOutcome,
        /// The contradicting result observed afterwards.
        conflicting: TerminalOutcome,
    },
    /// Kern does not know what the machine is doing.
    ///
    /// A claim about Kern, not about the machine. Converting this to `Failed`
    /// would assert a physical fact Kern has no evidence for.
    Unknown {
        /// Where knowledge was lost.
        phase: UnknownPhase,
        /// What Kern last knew.
        last_known: LastKnown,
    },
}

impl ExecutionState {
    /// True for a state no automatic transition may leave.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::NotStarted(_)
                | Self::Completed
                | Self::Failed(_)
                | Self::Cancelled
                | Self::Disputed { .. }
        )
    }

    /// True when Kern has lost knowledge of this execution.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown { .. })
    }

    /// The terminal result, when the executor reported one.
    ///
    /// `NotStarted` has none: no operation ran, so there is no machine result to
    /// report.
    pub fn terminal_outcome(&self) -> Option<TerminalOutcome> {
        match self {
            Self::Completed => Some(TerminalOutcome::Completed),
            Self::Failed(class) => Some(TerminalOutcome::Failed(*class)),
            Self::Cancelled => Some(TerminalOutcome::Cancelled),
            _ => None,
        }
    }

    /// The state a terminal result puts an execution into.
    pub(crate) fn from_terminal(outcome: TerminalOutcome) -> Self {
        match outcome {
            TerminalOutcome::Completed => Self::Completed,
            TerminalOutcome::Failed(class) => Self::Failed(class),
            TerminalOutcome::Cancelled => Self::Cancelled,
        }
    }

    /// What Kern would remember of this state if knowledge were lost now.
    pub(crate) fn as_last_known(&self) -> Option<LastKnown> {
        match self {
            Self::Prepared => Some(LastKnown::Prepared),
            Self::Submitted => Some(LastKnown::Submitted),
            Self::Running => Some(LastKnown::Running),
            Self::Unknown { last_known, .. } => Some(*last_known),
            _ => None,
        }
    }
}

/// Why a cancellation request did not take effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelRefusal {
    /// The executor refused the request.
    Rejected,
    /// The executor does not support the requested lapse action.
    Unsupported,
    /// The executor reported the operation had already ended.
    AlreadyTerminal,
}

/// Kern's cancellation position on one execution.
///
/// Three facts that must never be collapsed:
///
/// ```text
/// Requested        Kern told the adapter continued execution is unauthorized
/// RequestAccepted  the adapter took the request
/// Confirmed        the executor reported the operation cancelled
/// ```
///
/// A fourth is deliberately absent, because Kern can never establish it: that
/// the machine physically stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancellationState {
    /// Nothing has been asked of the executor.
    NotRequested,
    /// Kern issued the request.
    Requested {
        /// When Kern issued it, in local uptime.
        at: Uptime,
    },
    /// The adapter took the request. **Received, not cancelled.**
    RequestAccepted {
        /// When the adapter took it, in local uptime.
        at: Uptime,
    },
    /// The executor reported the operation cancelled.
    Confirmed {
        /// When Kern observed the confirmation, in local uptime.
        at: Uptime,
    },
    /// The request did not take.
    Refused(CancelRefusal),
    /// The request may or may not have reached the executor.
    RequestUnknown,
    /// The operation reached a different terminal result first.
    Moot,
}

impl CancellationState {
    /// True while a request is outstanding and unconfirmed.
    pub(crate) fn is_outstanding(&self) -> bool {
        matches!(
            self,
            Self::Requested { .. } | Self::RequestAccepted { .. } | Self::RequestUnknown
        )
    }
}
