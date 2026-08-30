//! The executor boundary.
//!
//! Deliberately free of robotics vocabulary: no goals, poses, frames,
//! trajectories, topics, or actions. A navigation stack, a manipulation planner,
//! a machine controller, and a simulator all fit the same contract.
//!
//! # No error channel
//!
//! No method here returns `Result`. An adapter cannot hand Kern an opaque
//! failure, because an opaque failure says nothing about whether a physical
//! effect may have started — and that is the only question that matters. The
//! adapter must classify its own transport failures into Kern's uncertainty
//! vocabulary, at the one place where the transport is understood.

use alloc::vec::Vec;

use crate::command::SemanticCommand;
use crate::id::ExecutionId;
use crate::state::{FailureClass, RejectionReason};

/// What Kern asks an executor to do when authority lapses.
///
/// The mapping from action to machine behaviour belongs to the adapter. Kern
/// only guarantees that it asked, and records what came back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LapseAction {
    /// Stop the operation.
    Cancel,
    /// Suspend the operation in place.
    Hold,
    /// End the operation by the strongest means the executor offers.
    Terminate,
    /// Accept no further commands for the operation, and otherwise leave it
    /// alone.
    NoFurtherCommands,
}

impl LapseAction {
    fn bit(self) -> u8 {
        match self {
            Self::Cancel => 1,
            Self::Hold => 2,
            Self::Terminate => 4,
            Self::NoFurtherCommands => 8,
        }
    }
}

/// The set of lapse actions an adapter declares it can perform.
///
/// Checked against the governor's configured action at construction, so an
/// adapter can never silently turn a configured `Cancel` into a no-op: the
/// mismatch is a wiring error, raised before any authority exists.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LapseActionSet(u8);

impl LapseActionSet {
    /// The empty set. An adapter declaring this cannot be governed at all.
    pub const fn none() -> Self {
        Self(0)
    }

    /// Adds one action.
    #[must_use]
    pub fn with(self, action: LapseAction) -> Self {
        Self(self.0 | action.bit())
    }

    /// True when the adapter declares support for `action`.
    pub fn supports(self, action: LapseAction) -> bool {
        self.0 & action.bit() != 0
    }

    /// True when the adapter declares nothing.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Whether an adapter's observations carry a usable order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationOrdering {
    /// Observations carry a per-operation sequence number that strictly
    /// increases. Kern drops anything at or below what it has already applied.
    Sequenced,
    /// No ordering is claimed. Kern falls back to the state lattice and
    /// represents whatever uncertainty remains.
    Unordered,
}

/// What an adapter says about itself, once, at wiring time.
///
/// Captured by the governor at construction. An adapter that changes its mind
/// later is not consulted again: a declaration is a contract, not a status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorDeclaration {
    /// Which lapse actions the adapter can actually perform.
    pub supported_lapse_actions: LapseActionSet,
    /// True when acceptance of a command means the operation is already running,
    /// so no separate `Submitted` phase is observable.
    pub accept_implies_running: bool,
    /// True when the adapter can ever report a cancellation as confirmed.
    ///
    /// When false, Kern knows in advance that `Cancelled` is unreachable for
    /// this adapter, and provenance says so rather than waiting for it.
    pub confirms_cancellation: bool,
    /// True when the adapter can report terminal results at all.
    pub reports_terminal_results: bool,
    /// True when the adapter attaches [`SemanticCommand::execution_id`] to the
    /// operations it creates and echoes it back during reconciliation.
    ///
    /// The only mechanism by which a lost submission acknowledgement can ever be
    /// recovered.
    pub echoes_execution_id: bool,
    /// Whether observations carry a usable order.
    pub ordering: ObservationOrdering,
}

/// The result of handing a command to an executor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmitOutcome<O> {
    /// The executor accepted the command, and this identifies the operation.
    Accepted {
        /// The executor's identity for the operation.
        operation: O,
    },
    /// The command provably did not reach the executor.
    ///
    /// **Only** when the adapter knows this. Any doubt — a broken connection, a
    /// timeout, an ambiguous transport error — is [`SubmitOutcome::Unknown`].
    Rejected {
        /// Why it did not start.
        reason: RejectionReason,
    },
    /// The command may or may not have reached the executor.
    ///
    /// Kern will never retry it. A physical operation is not idempotent, and a
    /// lost acknowledgement is not evidence that nothing happened.
    Unknown,
}

/// The result of asking an executor to stop honouring an operation.
///
/// `Accepted` means the adapter *received* the request. It does not mean the
/// operation is cancelled, and it never means the machine stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelRequestOutcome {
    /// The adapter took the request.
    Accepted,
    /// The executor reported the operation had already ended.
    AlreadyTerminal,
    /// The executor refused the request.
    Rejected,
    /// The executor cannot perform the requested action.
    Unsupported,
    /// The request may or may not have arrived.
    Unknown,
}

/// What an executor reports about an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedReport {
    /// The operation is running.
    Running,
    /// The operation completed.
    Completed,
    /// The operation failed.
    Failed(FailureClass),
    /// The operation was cancelled.
    Cancelled,
}

/// One report about one operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionObservation<O> {
    /// The operation the report is about.
    pub operation: O,
    /// What the executor reported.
    pub report: ObservedReport,
    /// A per-operation sequence number, when the adapter declares
    /// [`ObservationOrdering::Sequenced`].
    ///
    /// Deliberately not a timestamp. An executor clock is not known to be
    /// comparable with the enforcer's monotonic clock, and Kern will not
    /// subtract two instants it cannot compare.
    pub sequence: Option<u64>,
}

/// The result of polling an adapter for observations.
///
/// `Idle` and `Disconnected` are different facts: nothing new, versus no longer
/// able to see. Collapsing them would let a dead link look like a quiet one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationPoll<O> {
    /// A report is available.
    Observation(ExecutionObservation<O>),
    /// Connected, nothing new.
    Idle,
    /// The adapter cannot observe the executor. Knowledge is stale from here.
    Disconnected,
}

/// The result of querying one operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryOutcome<O> {
    /// The executor reported this.
    Observed(ExecutionObservation<O>),
    /// The executor could not say.
    Unknown,
    /// The adapter cannot query individual operations.
    Unsupported,
    /// The adapter cannot reach the executor.
    Disconnected,
}

/// What an executor is currently running, as far as its adapter can tell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileReport<O> {
    /// Operations the executor reports as **currently active**.
    ///
    /// The second element is the echoed [`ExecutionId`], present only when the
    /// adapter declares [`ExecutorDeclaration::echoes_execution_id`].
    pub discovered: Vec<(O, Option<ExecutionId>)>,
    /// True when the enumeration was exhaustive.
    ///
    /// When false, absence from `discovered` proves nothing, and Kern resolves
    /// no record by omission.
    pub complete: bool,
}

/// The result of asking an adapter what is still running.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconcileOutcome<O> {
    /// The adapter enumerated what it could.
    Report(ReconcileReport<O>),
    /// The adapter cannot enumerate operations.
    Unsupported,
    /// The adapter cannot reach the executor.
    Disconnected,
}

/// A system that can be asked to perform semantic operations.
///
/// # What an implementation must never do
///
/// Return [`SubmitOutcome::Rejected`] when it is not certain the command failed
/// to reach the executor. Kern's entire non-idempotency story rests on that one
/// clause, and Kern cannot verify it. Any doubt is [`SubmitOutcome::Unknown`].
pub trait Executor {
    /// The executor's identity for one operation.
    type OperationId: Clone + Eq;

    /// What this adapter can do. Read once, at governor construction.
    fn declaration(&self) -> ExecutorDeclaration;

    /// Hands one authorized command to the executor.
    ///
    /// Called at most once per [`ExecutionId`], ever. Kern does not retry.
    fn submit(&mut self, command: &SemanticCommand<'_>) -> SubmitOutcome<Self::OperationId>;

    /// Instructs the executor that continued execution is no longer authorized.
    ///
    /// This is a request, not a stop. Kern records that it asked and what came
    /// back, and claims nothing about the machine.
    fn on_authority_lapse(
        &mut self,
        operation: &Self::OperationId,
        action: LapseAction,
        reason: crate::state::AuthorityLapseReason,
    ) -> CancelRequestOutcome;
}

/// An executor whose adapter can report progress.
///
/// Optional. An adapter without it can still submit and be instructed on lapse;
/// its executions simply stay unknown after submission, which is the truth.
pub trait ExecutorObservations: Executor {
    /// Takes the next pending report, if any.
    fn poll_observation(&mut self) -> ObservationPoll<Self::OperationId>;
}

/// An executor whose adapter can be asked about one operation.
///
/// A recovery path, not a hot path. It is useless for a lost submission
/// acknowledgement, because in that case Kern holds no operation identity to ask
/// about.
pub trait ExecutorQuery: Executor {
    /// Asks about one operation.
    fn query(&mut self, operation: &Self::OperationId) -> QueryOutcome<Self::OperationId>;
}

/// An executor whose adapter can enumerate what is still running.
///
/// The only mechanism that can recover a lost submission acknowledgement, and
/// only when the adapter also echoes the execution identifier.
pub trait ExecutorReconcile: Executor {
    /// Enumerates the operations the executor currently has active.
    fn reconcile_active_operations(&mut self) -> ReconcileOutcome<Self::OperationId>;
}
