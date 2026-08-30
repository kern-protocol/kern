//! Provenance emission, as returned data rather than callbacks.
//!
//! # Why not an observer trait
//!
//! A sink invoked from inside a transition can panic, and a panic between
//! marking a lapse and issuing the lapse instruction would leave authority state
//! and executor state disagreeing. So no host code runs inside a transition at
//! all: the governor commits every state change and performs every executor
//! call, appending entries as it goes, and the host reads the journal afterwards.
//!
//! # Not event sourcing
//!
//! The [`ExecutionRecord`](crate::ExecutionRecord) is authoritative. Journal
//! entries are derived from transitions and are never replayed to rebuild state.
//! With no persistence there would be nothing to rebuild from.
//!
//! # Bounded
//!
//! The journal has a fixed capacity chosen at construction. Overflow drops
//! provenance detail and says so. It can never drop an authority state
//! transition or a lapse instruction, because those happen in the record and at
//! the adapter, not here.

use kern_core::Uptime;

use crate::command::CommandDigest;
use crate::contract::{CancelRequestOutcome, LapseAction};
use crate::id::ExecutionId;
use crate::state::{
    AuthorityLapseReason, LastKnown, NotStartedReason, TerminalOutcome, UnknownPhase,
};

/// What a journal entry is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionSubject {
    /// One execution Kern has a record for.
    Execution(ExecutionId),
    /// The adapter as a whole: link health, reconciliation, operations Kern has
    /// no record for.
    Adapter,
}

/// Why an execution's dispute was resolved the way it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolutionSource {
    /// The executor was reconciled and one result stood.
    ExecutorReconciliation,
    /// A human operator attested to the result.
    OperatorAttested,
}

/// One recorded transition.
///
/// Fixed size and `Copy`: no parameters, no handle, no allocation. The full
/// operation is the host's to keep; see the crate documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transition {
    /// What this entry is about.
    pub subject: TransitionSubject,
    /// When Kern recorded it, in local uptime.
    pub at: Uptime,
    /// What happened.
    pub kind: TransitionKind,
}

/// What a transition recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionKind {
    /// A record was written. Nothing has been sent.
    Prepared {
        /// Names the operation the execution was prepared for.
        digest: CommandDigest,
    },
    /// The executor accepted the command.
    SubmissionAccepted,
    /// The executor was invoked and the command may or may not have landed.
    SubmissionUnknown,
    /// The execution ended without a machine operation ever starting.
    NotStarted(NotStartedReason),
    /// The executor was observed running the operation.
    ObservedRunning,
    /// Kern stopped granting authority.
    AuthorityLapsed(AuthorityLapseReason),
    /// Kern issued a lapse instruction.
    CancellationRequested(LapseAction),
    /// What the adapter said about the instruction.
    CancellationRequestOutcome(CancelRequestOutcome),
    /// The executor reported the operation cancelled.
    CancellationConfirmed,
    /// A cancellation request was overtaken by a different terminal result.
    CancellationMoot,
    /// Authority lapsed but Kern holds no operation identity to instruct with.
    LapseNotRequestedNoOperation,
    /// A terminal result was applied.
    Terminal(TerminalOutcome),
    /// Kern lost knowledge of an execution.
    BecameUnknown {
        /// Where knowledge was lost.
        phase: UnknownPhase,
        /// What Kern last knew.
        last_known: LastKnown,
    },
    /// A second, different terminal result arrived.
    DisputeOpened {
        /// The first result observed.
        first: TerminalOutcome,
        /// The contradicting result.
        conflicting: TerminalOutcome,
    },
    /// A disputed execution received yet another report. Nothing changed.
    DisputeObservedAgain,
    /// A dispute was resolved by explicit attribution.
    DisputeResolved {
        /// The result the host attested to.
        outcome: TerminalOutcome,
        /// Where that attestation came from.
        source: ResolutionSource,
    },
    /// An observation older than what Kern already applied was dropped.
    StaleObservationDropped,
    /// An observation named an operation Kern has no record for.
    UnmatchedObservation,
    /// The adapter reported it cannot observe the executor.
    LinkDisconnected,
    /// The adapter is reporting again. Resolves nothing on its own.
    LinkRestored,
    /// A lost submission was rebound to an operation by an echoed identifier.
    UnknownResolvedByReconcile,
    /// The adapter enumerated its active operations.
    ReconciliationDiscovered {
        /// Operations matched to an existing record.
        attributed: u32,
        /// Operations Kern cannot attribute to any record.
        unattributed: u32,
        /// Whether the enumeration was exhaustive.
        complete: bool,
    },
    /// The adapter cannot enumerate its active operations.
    ReconciliationUnsupported,
    /// A lapse instruction was issued for an operation Kern has no record for.
    LapseRequestedForUnattributed,
    /// A terminal record's storage was reclaimed to make room.
    RecordReclaimed,
}
