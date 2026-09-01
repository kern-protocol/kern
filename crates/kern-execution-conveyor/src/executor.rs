//! `transfer_item` as a Kern executor.
//!
//! The adapter knows execution. It does not know authorization: no lease, no
//! artifact, no constraint set, and no policy reaches it. It receives commands
//! the governor already authorized, reports what the belt did, and answers a
//! lapse instruction by asking the belt to stop.

use std::string::String;
use std::vec::Vec;

use kern_core::Symbol;
use kern_execution::{
    CancelRequestOutcome, ExecutionId, ExecutionObservation, Executor, ExecutorDeclaration,
    ExecutorObservations, FailureClass, LapseAction, LapseActionSet, ObservationOrdering,
    ObservationPoll, ObservedReport, RejectionReason, SemanticCommand, SubmitOutcome,
};

use crate::backend::{
    BackendEvent, BackendPoll, ConveyorBackend, ConveyorMove, ConveyorOperationId, SpeedControl,
    StartTransfer, StopSend,
};
use crate::capability::TransferRequest;
use crate::units::{mm_s_to_m_s, mm_to_m};

/// An adapter could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterError {
    /// The backend cannot bound belt speed.
    SpeedControlUnavailable,
    /// A tracking table with no capacity can hold no operation.
    ZeroCapacity,
    /// No station was configured, so no transfer could ever be served.
    NoStations,
    /// Two stations share a name.
    DuplicateStation(String),
}

impl core::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SpeedControlUnavailable => {
                f.write_str("the backend cannot enforce max_speed_mm_s")
            }
            Self::ZeroCapacity => f.write_str("tracking capacity must be greater than zero"),
            Self::NoStations => f.write_str("at least one station must be configured"),
            Self::DuplicateStation(name) => write!(f, "duplicate station `{name}`"),
        }
    }
}

impl std::error::Error for AdapterError {}

/// Where a named station is, along the belt.
///
/// Trusted adapter configuration. A station a deployment did not configure has
/// no position, and the adapter refuses to invent one — which is why a model
/// naming `station_c` cannot become a belt movement even if a policy somewhere
/// permitted the symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Station {
    /// The name policy and proposals use.
    pub name: String,
    /// Where it is, millimetres along the belt.
    pub position_mm: i64,
}

/// Adapter configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConveyorConfig {
    /// The stations this belt has.
    pub stations: Vec<Station>,
    /// How many operations the adapter tracks at once.
    pub tracking_capacity: usize,
}

impl Default for ConveyorConfig {
    fn default() -> Self {
        Self {
            stations: Vec::new(),
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
    operation: ConveyorOperationId,
    execution: ExecutionId,
    state: AdapterState,
    stop_requested: bool,
    sequence: u64,
}

/// A `transfer_item` executor.
///
/// # Concurrency
///
/// One transfer at a time. A belt has one position and one speed; two
/// concurrent transfers would be two authorities commanding one actuator, and
/// the second is refused as `Busy` with nothing sent.
pub struct ConveyorExecutor<B: ConveyorBackend> {
    backend: B,
    config: ConveyorConfig,
    declaration: ExecutorDeclaration,
    tracked: Vec<Tracked>,
    report_loss: bool,
}

impl<B: ConveyorBackend> ConveyorExecutor<B> {
    /// Builds an adapter, refusing a backend that cannot enforce the speed bound.
    pub fn new(backend: B, config: ConveyorConfig) -> Result<Self, AdapterError> {
        let declared = backend.declaration();
        if declared.speed_control == SpeedControl::None {
            return Err(AdapterError::SpeedControlUnavailable);
        }
        if config.tracking_capacity == 0 {
            return Err(AdapterError::ZeroCapacity);
        }
        if config.stations.is_empty() {
            return Err(AdapterError::NoStations);
        }
        for (index, station) in config.stations.iter().enumerate() {
            if config.stations[..index]
                .iter()
                .any(|earlier| earlier.name == station.name)
            {
                return Err(AdapterError::DuplicateStation(station.name.clone()));
            }
        }

        let declaration = ExecutorDeclaration {
            supported_lapse_actions: LapseActionSet::none().with(LapseAction::Cancel),
            // Taking a transfer command is not evidence the belt moved.
            accept_implies_running: false,
            confirms_cancellation: declared.confirms_cancellation,
            reports_terminal_results: declared.reports_terminal_results,
            // The controller numbers its own transfers; there is no field to
            // carry a Kern identifier back.
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

    /// The configured stations.
    pub fn stations(&self) -> &[Station] {
        &self.config.stations
    }

    /// The adapter's Kern identity for a transfer, if it is still tracked.
    pub fn execution_of(&self, operation: &ConveyorOperationId) -> Option<ExecutionId> {
        self.find(operation).map(|tracked| tracked.execution)
    }

    /// Releases transport resources.
    pub fn shutdown(&mut self) {
        self.backend.shutdown();
    }

    fn station(&self, name: &Symbol) -> Option<&Station> {
        self.config
            .stations
            .iter()
            .find(|station| station.name == name.as_str())
    }

    fn find(&self, operation: &ConveyorOperationId) -> Option<&Tracked> {
        self.tracked
            .iter()
            .find(|tracked| &tracked.operation == operation)
    }

    fn find_mut(&mut self, operation: &ConveyorOperationId) -> Option<&mut Tracked> {
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

    fn observation(&mut self, event: BackendEvent) -> ExecutionObservation<ConveyorOperationId> {
        let operation = event.operation();
        let report = match event {
            BackendEvent::Moving { .. } => ObservedReport::Running,
            BackendEvent::Arrived { .. } => ObservedReport::Completed,
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

impl<B: ConveyorBackend> Executor for ConveyorExecutor<B> {
    type OperationId = ConveyorOperationId;

    fn declaration(&self) -> ExecutorDeclaration {
        self.declaration
    }

    fn submit(&mut self, command: &SemanticCommand<'_>) -> SubmitOutcome<ConveyorOperationId> {
        // Nothing below this point may run on a command the adapter does not
        // fully understand.
        let Ok(request) = TransferRequest::from_command(command) else {
            return SubmitOutcome::Rejected {
                reason: RejectionReason::InvalidCommand,
            };
        };
        let Some(position_mm) = self
            .station(&request.destination_station)
            .map(|station| station.position_mm)
        else {
            return SubmitOutcome::Rejected {
                reason: RejectionReason::InvalidCommand,
            };
        };
        if self.has_live_operation() || !self.make_room() {
            return SubmitOutcome::Rejected {
                reason: RejectionReason::Busy,
            };
        }

        let movement = ConveyorMove {
            target_m: mm_to_m(position_mm),
            max_speed_m_s: mm_s_to_m_s(request.max_speed_mm_s),
            execution: command.execution_id(),
        };

        match self.backend.start_transfer(&movement) {
            StartTransfer::Accepted { operation } => {
                self.tracked.push(Tracked {
                    operation,
                    execution: command.execution_id(),
                    state: AdapterState::Accepted,
                    stop_requested: false,
                    sequence: 0,
                });
                SubmitOutcome::Accepted { operation }
            }
            StartTransfer::Rejected { reason } => SubmitOutcome::Rejected { reason },
            StartTransfer::Unknown => SubmitOutcome::Unknown,
        }
    }

    fn on_authority_lapse(
        &mut self,
        operation: &ConveyorOperationId,
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

impl<B: ConveyorBackend> ExecutorObservations for ConveyorExecutor<B> {
    fn poll_observation(&mut self) -> ObservationPoll<ConveyorOperationId> {
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
