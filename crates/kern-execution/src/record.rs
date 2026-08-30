//! What Kern retains about one governed attempt at a physical effect.

use kern_core::Uptime;
use kern_enforcer::LeaseHandle;

use crate::command::CommandDigest;
use crate::id::ExecutionId;
use crate::state::{
    AuthorityLapseReason, AuthorityState, CancellationState, ExecutionState, LastKnown,
    NotStartedReason, TerminalOutcome, UnknownPhase,
};

/// One execution's record.
///
/// # Authority identity lives in one place
///
/// The [`LeaseHandle`] *is* the provenance triple — slot, lease identifier,
/// artifact digest — and it is the argument
/// [`check_authority`](kern_enforcer::EnforcerStore::check_authority) takes.
/// Storing the handle rather than copies of its parts means the submit-time
/// check and the tick-time check re-check the same value, so they cannot drift.
///
/// # Parameters are not here
///
/// Only [`CommandDigest`]. The record is fixed size except for the handle's
/// identifiers, so a fixed-capacity table on a constrained target cannot be
/// grown by a large parameter payload. The host keeps the payload and can prove
/// it is the authorized one by recomputing the digest.
///
/// # Every instant is a Kern-local observation time
///
/// No field is a physical event time. `terminal_observed_at` is when Kern
/// observed a report, not when a machine did anything, and no API subtracts one
/// of these from another to order physical events.
#[derive(Clone, Debug)]
pub struct ExecutionRecord<O> {
    execution_id: ExecutionId,
    handle: LeaseHandle,
    command_digest: CommandDigest,
    authority: AuthorityState,
    execution: ExecutionState,
    cancellation: CancellationState,
    operation: Option<O>,
    last_sequence: Option<u64>,
    lapse_handled: bool,
    prepared_at: Uptime,
    submitted_at: Option<Uptime>,
    last_observation_at: Option<Uptime>,
    terminal_observed_at: Option<Uptime>,
}

impl<O> ExecutionRecord<O> {
    pub(crate) fn new(
        execution_id: ExecutionId,
        handle: LeaseHandle,
        command_digest: CommandDigest,
        prepared_at: Uptime,
    ) -> Self {
        Self {
            execution_id,
            handle,
            command_digest,
            authority: AuthorityState::Current,
            execution: ExecutionState::Prepared,
            cancellation: CancellationState::NotRequested,
            operation: None,
            last_sequence: None,
            lapse_handled: false,
            prepared_at,
            submitted_at: None,
            last_observation_at: None,
            terminal_observed_at: None,
        }
    }

    /// This execution's identifier.
    pub fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// The authority that permitted preparation: slot, lease, artifact.
    pub fn handle(&self) -> &LeaseHandle {
        &self.handle
    }

    /// Names the exact operation this execution was prepared for.
    pub fn command_digest(&self) -> &CommandDigest {
        &self.command_digest
    }

    /// Kern's authority position.
    pub fn authority(&self) -> AuthorityState {
        self.authority
    }

    /// Kern's belief about progress.
    pub fn execution(&self) -> ExecutionState {
        self.execution
    }

    /// Kern's cancellation position.
    pub fn cancellation(&self) -> CancellationState {
        self.cancellation
    }

    /// The executor's identity for the operation, once it accepted one.
    pub fn operation(&self) -> Option<&O> {
        self.operation.as_ref()
    }

    /// When the record was written, in local uptime.
    pub fn prepared_at(&self) -> Uptime {
        self.prepared_at
    }

    /// When Kern invoked the adapter — not when the executor received anything.
    pub fn submitted_at(&self) -> Option<Uptime> {
        self.submitted_at
    }

    /// When Kern last applied an observation.
    pub fn last_observation_at(&self) -> Option<Uptime> {
        self.last_observation_at
    }

    /// When Kern observed a terminal report.
    ///
    /// Not the instant the machine finished. Kern has no way to establish that,
    /// and does not pretend otherwise.
    pub fn terminal_observed_at(&self) -> Option<Uptime> {
        self.terminal_observed_at
    }

    /// True once the lapse pass has dealt with this execution, whether or not an
    /// instruction could be issued. Ensures at most one instruction per
    /// execution.
    pub(crate) fn lapse_handled(&self) -> bool {
        self.lapse_handled
    }

    pub(crate) fn mark_lapse_handled(&mut self) {
        self.lapse_handled = true;
    }

    pub(crate) fn mark_lapsed(&mut self, reason: AuthorityLapseReason, at: Uptime) {
        // Monotonic: the first lapse stands, and authority never returns.
        if self.authority == AuthorityState::Current {
            self.authority = AuthorityState::Lapsed { reason, at };
        }
    }

    pub(crate) fn set_cancellation(&mut self, state: CancellationState) {
        self.cancellation = state;
    }

    pub(crate) fn set_submitted_at(&mut self, at: Uptime) {
        self.submitted_at = Some(at);
    }

    pub(crate) fn set_not_started(&mut self, reason: NotStartedReason) {
        self.execution = ExecutionState::NotStarted(reason);
    }

    pub(crate) fn accept_operation(&mut self, operation: O, running: bool) {
        self.operation = Some(operation);
        self.execution = if running {
            ExecutionState::Running
        } else {
            ExecutionState::Submitted
        };
    }

    pub(crate) fn set_running(&mut self) {
        self.execution = ExecutionState::Running;
    }

    pub(crate) fn set_unknown(&mut self, phase: UnknownPhase, last_known: LastKnown) {
        self.execution = ExecutionState::Unknown { phase, last_known };
    }

    pub(crate) fn set_terminal(&mut self, outcome: TerminalOutcome, at: Uptime) {
        self.execution = ExecutionState::from_terminal(outcome);
        self.terminal_observed_at = Some(at);
    }

    pub(crate) fn set_disputed(&mut self, first: TerminalOutcome, conflicting: TerminalOutcome) {
        self.execution = ExecutionState::Disputed { first, conflicting };
    }

    pub(crate) fn observed_at(&mut self, at: Uptime) {
        self.last_observation_at = Some(at);
    }

    pub(crate) fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }

    pub(crate) fn set_last_sequence(&mut self, sequence: Option<u64>) {
        if sequence.is_some() {
            self.last_sequence = sequence;
        }
    }

    pub(crate) fn bind_operation(&mut self, operation: O) {
        self.operation = Some(operation);
    }
}
