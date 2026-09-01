//! `pick_and_place` as a Kern executor.
//!
//! The adapter knows execution. It does not know authorization: no lease, no
//! artifact, no constraint set, and no policy reaches it. It receives commands
//! the governor already authorized, translates the two zone names into the two
//! poses the host configured, reports what the arm did, and answers a lapse
//! instruction by asking the arm to stop.
//!
//! Translating a zone into a pose is the *only* place joint angles appear at
//! all, and the poses come from trusted configuration rather than from anything
//! a proposal carried.

use std::string::String;
use std::vec::Vec;

use kern_core::Symbol;
use kern_execution::{
    CancelRequestOutcome, ExecutionId, ExecutionObservation, Executor, ExecutorDeclaration,
    ExecutorObservations, FailureClass, LapseAction, LapseActionSet, ObservationOrdering,
    ObservationPoll, ObservedReport, RejectionReason, SemanticCommand, SubmitOutcome,
};

use crate::backend::{
    ArmBackend, ArmMotion, ArmOperationId, ArmPose, BackendEvent, BackendPoll, StartMotion,
    StopSend, WorkspaceControl,
};
use crate::capability::PickAndPlaceRequest;

/// An adapter could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterError {
    /// The backend would move the arm outside the configured poses.
    WorkspaceControlUnavailable,
    /// A tracking table with no capacity can hold no operation.
    ZeroCapacity,
    /// No zone was configured, so no motion could ever be served.
    NoZones,
    /// Two zones share a name.
    DuplicateZone(String),
}

impl core::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkspaceControlUnavailable => {
                f.write_str("the backend does not confine the arm to configured poses")
            }
            Self::ZeroCapacity => f.write_str("tracking capacity must be greater than zero"),
            Self::NoZones => f.write_str("at least one zone must be configured"),
            Self::DuplicateZone(name) => write!(f, "duplicate zone `{name}`"),
        }
    }
}

impl std::error::Error for AdapterError {}

/// Where a named zone is, in joint space.
///
/// Trusted adapter configuration. A zone a deployment did not configure has no
/// pose, and the adapter refuses to invent one — which is why a model naming
/// `maintenance_bay` cannot become arm motion even if a policy somewhere
/// permitted the symbol.
#[derive(Clone, Debug, PartialEq)]
pub struct Zone {
    /// The name policy and proposals use.
    pub name: String,
    /// The pose the arm adopts for it.
    pub pose: ArmPose,
}

/// Adapter configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct ArmConfig {
    /// The zones this arm can reach.
    pub zones: Vec<Zone>,
    /// How many operations the adapter tracks at once.
    pub tracking_capacity: usize,
}

impl Default for ArmConfig {
    fn default() -> Self {
        Self {
            zones: Vec::new(),
            tracking_capacity: 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdapterState {
    Accepted,
    Running,
    Terminal,
}

#[derive(Clone, Copy, Debug)]
struct Tracked {
    operation: ArmOperationId,
    execution: ExecutionId,
    state: AdapterState,
    stop_requested: bool,
    sequence: u64,
}

/// A `pick_and_place` executor.
///
/// # Concurrency
///
/// One motion at a time. An arm has one set of joints; two concurrent motions
/// would be two authorities commanding one actuator, and the second is refused
/// as `Busy` with nothing sent.
pub struct ArmExecutor<B: ArmBackend> {
    backend: B,
    config: ArmConfig,
    declaration: ExecutorDeclaration,
    tracked: Vec<Tracked>,
    report_loss: bool,
}

impl<B: ArmBackend> ArmExecutor<B> {
    /// Builds an adapter, refusing a backend that would leave the workspace.
    pub fn new(backend: B, config: ArmConfig) -> Result<Self, AdapterError> {
        let declared = backend.declaration();
        if declared.workspace_control == WorkspaceControl::Unbounded {
            return Err(AdapterError::WorkspaceControlUnavailable);
        }
        if config.tracking_capacity == 0 {
            return Err(AdapterError::ZeroCapacity);
        }
        if config.zones.is_empty() {
            return Err(AdapterError::NoZones);
        }
        for (index, zone) in config.zones.iter().enumerate() {
            if config.zones[..index]
                .iter()
                .any(|earlier| earlier.name == zone.name)
            {
                return Err(AdapterError::DuplicateZone(zone.name.clone()));
            }
        }

        let declaration = ExecutorDeclaration {
            supported_lapse_actions: LapseActionSet::none().with(LapseAction::Cancel),
            // Taking a motion command is not evidence the arm moved.
            accept_implies_running: false,
            confirms_cancellation: declared.confirms_cancellation,
            reports_terminal_results: declared.reports_terminal_results,
            echoes_execution_id: false,
            ordering: ObservationOrdering::Sequenced,
        };

        Ok(Self {
            backend,
            config,
            declaration,
            tracked: Vec::new(),
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

    /// The configured zones.
    pub fn zones(&self) -> &[Zone] {
        &self.config.zones
    }

    /// The adapter's Kern identity for a motion, if it is still tracked.
    pub fn execution_of(&self, operation: &ArmOperationId) -> Option<ExecutionId> {
        self.find(operation).map(|tracked| tracked.execution)
    }

    /// Releases transport resources.
    pub fn shutdown(&mut self) {
        self.backend.shutdown();
    }

    fn zone(&self, name: &Symbol) -> Option<&Zone> {
        self.config
            .zones
            .iter()
            .find(|zone| zone.name == name.as_str())
    }

    fn find(&self, operation: &ArmOperationId) -> Option<&Tracked> {
        self.tracked
            .iter()
            .find(|tracked| &tracked.operation == operation)
    }

    fn find_mut(&mut self, operation: &ArmOperationId) -> Option<&mut Tracked> {
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
        self.tracked
            .retain(|tracked| tracked.state != AdapterState::Terminal);
        self.tracked.len() < self.config.tracking_capacity
    }

    fn observation(&mut self, event: BackendEvent) -> ExecutionObservation<ArmOperationId> {
        let operation = event.operation();
        let report = match event {
            BackendEvent::Moving { .. } => ObservedReport::Running,
            BackendEvent::Placed { .. } => ObservedReport::Completed,
            BackendEvent::Faulted { .. } => ObservedReport::Failed(FailureClass::OperationFailed),
            BackendEvent::Stopped { .. } => ObservedReport::Cancelled,
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

        ExecutionObservation {
            operation,
            report,
            sequence,
        }
    }
}

impl<B: ArmBackend> Executor for ArmExecutor<B> {
    type OperationId = ArmOperationId;

    fn declaration(&self) -> ExecutorDeclaration {
        self.declaration
    }

    fn submit(&mut self, command: &SemanticCommand<'_>) -> SubmitOutcome<ArmOperationId> {
        // Nothing below this point may run on a command the adapter does not
        // fully understand.
        let Ok(request) = PickAndPlaceRequest::from_command(command) else {
            return SubmitOutcome::Rejected {
                reason: RejectionReason::InvalidCommand,
            };
        };
        let (Some(source), Some(destination)) = (
            self.zone(&request.source_zone).map(|zone| zone.pose),
            self.zone(&request.destination_zone).map(|zone| zone.pose),
        ) else {
            return SubmitOutcome::Rejected {
                reason: RejectionReason::InvalidCommand,
            };
        };
        let motion = ArmMotion {
            source,
            destination,
            execution: command.execution_id(),
        };

        if self.has_live_operation() || !self.make_room() {
            return SubmitOutcome::Rejected {
                reason: RejectionReason::Busy,
            };
        }

        match self.backend.start_motion(&motion) {
            StartMotion::Accepted { operation } => {
                self.tracked.push(Tracked {
                    operation,
                    execution: command.execution_id(),
                    state: AdapterState::Accepted,
                    stop_requested: false,
                    sequence: 0,
                });
                SubmitOutcome::Accepted { operation }
            }
            StartMotion::Rejected { reason } => SubmitOutcome::Rejected { reason },
            StartMotion::Unknown => SubmitOutcome::Unknown,
        }
    }

    fn on_authority_lapse(
        &mut self,
        operation: &ArmOperationId,
        action: LapseAction,
        _reason: kern_execution::AuthorityLapseReason,
    ) -> CancelRequestOutcome {
        if action != LapseAction::Cancel {
            return CancelRequestOutcome::Unsupported;
        }
        if let Some(tracked) = self.find_mut(operation) {
            tracked.stop_requested = true;
        }
        match self.backend.stop(*operation) {
            StopSend::Accepted => CancelRequestOutcome::Accepted,
            StopSend::AlreadyTerminal => CancelRequestOutcome::AlreadyTerminal,
            StopSend::Rejected => CancelRequestOutcome::Rejected,
            // A request Kern cannot confirm arrived is not a request Kern may
            // report as taken.
            StopSend::Unknown | StopSend::Disconnected => CancelRequestOutcome::Unknown,
        }
    }
}

impl<B: ArmBackend> ExecutorObservations for ArmExecutor<B> {
    fn poll_observation(&mut self) -> ObservationPoll<ArmOperationId> {
        if self.report_loss {
            self.report_loss = false;
            return ObservationPoll::Disconnected;
        }
        match self.backend.poll() {
            BackendPoll::Event(event) => ObservationPoll::Observation(self.observation(event)),
            BackendPoll::Idle => ObservationPoll::Idle,
            BackendPoll::Disconnected => ObservationPoll::Disconnected,
        }
    }
}
