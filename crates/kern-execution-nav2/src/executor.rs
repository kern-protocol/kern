//! `NavigateToPose` as a Kern executor.
//!
//! The adapter knows execution. It does not know authorization: no lease, no
//! artifact, no constraint set, and no policy reaches it. It receives commands
//! the governor already authorized, reports what Nav2 did, and answers a lapse
//! instruction by asking Nav2 to cancel.

use std::string::String;
use std::vec::Vec;

use kern_execution::{
    CancelRequestOutcome, ExecutionId, ExecutionObservation, Executor, ExecutorDeclaration,
    ExecutorObservations, FailureClass, LapseAction, LapseActionSet, ObservationOrdering,
    ObservationPoll, ObservedReport, RejectionReason, SemanticCommand, SubmitOutcome,
};

use crate::backend::{
    BackendEvent, BackendPoll, CancelSend, Nav2Backend, Nav2Goal, Nav2OperationId, SendGoal,
    SpeedControl, SpeedLimitOutcome,
};
use crate::capability::NavigateRequest;
use crate::units::{mdeg_to_rad, mm_s_to_m_s, mm_to_m, yaw_quaternion};

/// An adapter could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterError {
    /// The backend cannot bound speed.
    ///
    /// Fails closed at construction. A `navigate` capability that carries
    /// `max_speed_mm_s` must not be served by transport that cannot apply it:
    /// silently ignoring an authorized bound is the one outcome this phase
    /// forbids outright.
    SpeedControlUnavailable,
    /// A tracking table with no capacity can hold no operation.
    ZeroCapacity,
    /// The configured frame is empty.
    EmptyFrame,
}

impl core::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SpeedControlUnavailable => {
                f.write_str("the backend cannot enforce max_speed_mm_s")
            }
            Self::ZeroCapacity => f.write_str("tracking capacity must be greater than zero"),
            Self::EmptyFrame => f.write_str("frame_id must not be empty"),
        }
    }
}

impl std::error::Error for AdapterError {}

/// Adapter configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nav2Config {
    /// The frame goals are expressed in, typically `map`.
    pub frame_id: String,
    /// How many operations the adapter tracks at once.
    pub tracking_capacity: usize,
}

impl Default for Nav2Config {
    fn default() -> Self {
        Self {
            frame_id: String::from("map"),
            tracking_capacity: 8,
        }
    }
}

/// What the adapter knows about one goal. Execution only — never authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdapterState {
    /// Accepted by the action server, no feedback yet.
    Accepted,
    /// Feedback observed.
    Running,
    /// A terminal result was reported.
    Terminal,
}

#[derive(Clone, Copy, Debug)]
struct Tracked {
    operation: Nav2OperationId,
    execution: ExecutionId,
    state: AdapterState,
    cancel_requested: bool,
    sequence: u64,
}

/// A `NavigateToPose` executor.
///
/// # Concurrency
///
/// One operation at a time. Nav2's `NavigateToPose` replaces a running goal
/// rather than running two, and the speed limit this adapter applies is a
/// controller-wide setting that cannot be scoped to two goals at once. A second
/// concurrent submission is therefore refused as `Busy`, with nothing sent.
pub struct Nav2Executor<B: Nav2Backend> {
    backend: B,
    config: Nav2Config,
    declaration: ExecutorDeclaration,
    tracked: Vec<Tracked>,
    speed_limit_applied: bool,
    report_loss: bool,
}

impl<B: Nav2Backend> Nav2Executor<B> {
    /// Builds an adapter, refusing a backend that cannot enforce the speed bound.
    pub fn new(backend: B, config: Nav2Config) -> Result<Self, AdapterError> {
        let declared = backend.declaration();
        if declared.speed_control == SpeedControl::None {
            return Err(AdapterError::SpeedControlUnavailable);
        }
        if config.tracking_capacity == 0 {
            return Err(AdapterError::ZeroCapacity);
        }
        if config.frame_id.is_empty() {
            return Err(AdapterError::EmptyFrame);
        }

        let declaration = ExecutorDeclaration {
            // Only what is implemented. Hold and Terminate are not.
            supported_lapse_actions: LapseActionSet::none().with(LapseAction::Cancel),
            // Nav2 accepting an action goal is not evidence the robot moved.
            accept_implies_running: false,
            confirms_cancellation: declared.confirms_cancellation,
            reports_terminal_results: declared.reports_terminal_results,
            // Nav2 generates goal UUIDs; there is no field to carry a Kern
            // identifier back, so reconciliation cannot be supported honestly.
            echoes_execution_id: false,
            // The adapter numbers its own observations per operation. The
            // ordering is adapter-local and owes nothing to ROS or simulation
            // time.
            ordering: ObservationOrdering::Sequenced,
        };

        Ok(Self {
            backend,
            config,
            declaration,
            tracked: Vec::new(),
            speed_limit_applied: false,
            report_loss: false,
        })
    }

    /// The transport, for wiring and tests.
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// The transport.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// The adapter's Kern identity for a goal, if it is still tracked.
    pub fn execution_of(&self, operation: &Nav2OperationId) -> Option<ExecutionId> {
        self.find(operation).map(|tracked| tracked.execution)
    }

    /// Releases transport resources and restores the controller's speed.
    pub fn shutdown(&mut self) {
        if self.speed_limit_applied {
            let _ = self.backend.clear_speed_limit();
            self.speed_limit_applied = false;
        }
        self.backend.shutdown();
    }

    fn find(&self, operation: &Nav2OperationId) -> Option<&Tracked> {
        self.tracked
            .iter()
            .find(|tracked| &tracked.operation == operation)
    }

    fn find_mut(&mut self, operation: &Nav2OperationId) -> Option<&mut Tracked> {
        self.tracked
            .iter_mut()
            .find(|tracked| &tracked.operation == operation)
    }

    fn has_live_operation(&self) -> bool {
        self.tracked
            .iter()
            .any(|tracked| tracked.state != AdapterState::Terminal)
    }

    fn make_room(&mut self) -> bool {
        if self.tracked.len() < self.config.tracking_capacity {
            return true;
        }
        // Only finished goals are forgotten.
        self.tracked
            .retain(|tracked| tracked.state != AdapterState::Terminal);
        self.tracked.len() < self.config.tracking_capacity
    }

    fn goal_from(&self, request: NavigateRequest, execution: ExecutionId) -> Nav2Goal {
        let yaw_rad = mdeg_to_rad(request.yaw_mdeg);
        let (qz, qw) = yaw_quaternion(yaw_rad);
        Nav2Goal {
            frame_id: self.config.frame_id.clone(),
            x_m: mm_to_m(request.destination_x_mm),
            y_m: mm_to_m(request.destination_y_mm),
            yaw_rad,
            qz,
            qw,
            max_speed_m_s: mm_s_to_m_s(request.max_speed_mm_s),
            execution,
        }
    }

    /// Restores the controller's speed once no goal can still be running under
    /// the limit.
    fn clear_speed_limit_if_idle(&mut self) {
        if self.speed_limit_applied && !self.has_live_operation() {
            let _ = self.backend.clear_speed_limit();
            self.speed_limit_applied = false;
        }
    }

    fn observation(&mut self, event: BackendEvent) -> ExecutionObservation<Nav2OperationId> {
        let operation = event.operation();
        let report = match event {
            BackendEvent::Feedback { .. } => ObservedReport::Running,
            BackendEvent::Succeeded { .. } => ObservedReport::Completed,
            // Nav2 aborting is evidence about an attempted machine operation.
            BackendEvent::Aborted { .. } => ObservedReport::Failed(FailureClass::OperationFailed),
            BackendEvent::Canceled { .. } => ObservedReport::Cancelled,
        };

        let terminal = !matches!(report, ObservedReport::Running);
        let sequence = match self.find_mut(&operation) {
            Some(tracked) => {
                tracked.sequence += 1;
                tracked.state = if terminal {
                    AdapterState::Terminal
                } else if tracked.state == AdapterState::Accepted {
                    AdapterState::Running
                } else {
                    tracked.state
                };
                Some(tracked.sequence)
            }
            None => None,
        };

        if terminal {
            self.clear_speed_limit_if_idle();
        }

        ExecutionObservation {
            operation,
            report,
            sequence,
        }
    }
}

impl<B: Nav2Backend> Executor for Nav2Executor<B> {
    type OperationId = Nav2OperationId;

    fn declaration(&self) -> ExecutorDeclaration {
        self.declaration
    }

    fn submit(&mut self, command: &SemanticCommand<'_>) -> SubmitOutcome<Nav2OperationId> {
        // Nothing below this point may run on a command the adapter does not
        // fully understand.
        let request = match NavigateRequest::from_command(command) {
            Ok(request) => request,
            Err(_) => {
                return SubmitOutcome::Rejected {
                    reason: RejectionReason::InvalidCommand,
                }
            }
        };

        if self.has_live_operation() || !self.make_room() {
            return SubmitOutcome::Rejected {
                reason: RejectionReason::Busy,
            };
        }

        // The bound is applied before the goal exists, so no goal can run
        // unbounded even briefly.
        match self
            .backend
            .apply_speed_limit(mm_s_to_m_s(request.max_speed_mm_s))
        {
            SpeedLimitOutcome::Applied => self.speed_limit_applied = true,
            SpeedLimitOutcome::NotDelivered | SpeedLimitOutcome::Unknown => {
                // No goal was sent, so nothing can be running: the rejection is
                // provable even though the limit's fate is not.
                let _ = self.backend.clear_speed_limit();
                self.speed_limit_applied = false;
                return SubmitOutcome::Rejected {
                    reason: RejectionReason::Unavailable,
                };
            }
        }

        let goal = self.goal_from(request, command.execution_id());
        match self.backend.send_goal(&goal) {
            SendGoal::Accepted { operation } => {
                self.tracked.push(Tracked {
                    operation,
                    execution: command.execution_id(),
                    state: AdapterState::Accepted,
                    cancel_requested: false,
                    sequence: 0,
                });
                SubmitOutcome::Accepted { operation }
            }
            SendGoal::Rejected { reason } => {
                let _ = self.backend.clear_speed_limit();
                self.speed_limit_applied = false;
                SubmitOutcome::Rejected { reason }
            }
            // The limit stays applied: a goal may be running under it, and
            // removing a bound from a possibly-live operation is the one
            // direction that must never be taken on uncertainty.
            SendGoal::Unknown => SubmitOutcome::Unknown,
        }
    }

    fn on_authority_lapse(
        &mut self,
        operation: &Nav2OperationId,
        action: LapseAction,
        _reason: kern_execution::AuthorityLapseReason,
    ) -> CancelRequestOutcome {
        if action != LapseAction::Cancel {
            return CancelRequestOutcome::Unsupported;
        }

        match self.find(operation).map(|tracked| tracked.state) {
            Some(AdapterState::Terminal) => CancelRequestOutcome::AlreadyTerminal,
            Some(_) => {
                if let Some(tracked) = self.find_mut(operation) {
                    tracked.cancel_requested = true;
                }
                match self.backend.cancel_goal(operation) {
                    CancelSend::Accepted => CancelRequestOutcome::Accepted,
                    CancelSend::AlreadyTerminal => CancelRequestOutcome::AlreadyTerminal,
                    CancelSend::Rejected => CancelRequestOutcome::Rejected,
                    // Unreachable transport is uncertainty, not refusal.
                    CancelSend::Unknown | CancelSend::Disconnected => CancelRequestOutcome::Unknown,
                }
            }
            // A goal the adapter never tracked. Claiming it already ended would
            // be a claim about a machine the adapter cannot see.
            None => CancelRequestOutcome::Unknown,
        }
    }
}

impl<B: Nav2Backend> ExecutorObservations for Nav2Executor<B> {
    fn poll_observation(&mut self) -> ObservationPoll<Nav2OperationId> {
        if std::mem::take(&mut self.report_loss) {
            return ObservationPoll::Disconnected;
        }

        match self.backend.poll_event() {
            BackendPoll::Event(event) => ObservationPoll::Observation(self.observation(event)),
            BackendPoll::Idle => ObservationPoll::Idle,
            BackendPoll::Disconnected => ObservationPoll::Disconnected,
            // Dropped events mean Kern's picture is incomplete. Reported as loss
            // of observation, which turns live executions unknown — never into a
            // claim that anything failed.
            BackendPoll::EventsLost => ObservationPoll::Disconnected,
        }
    }
}
