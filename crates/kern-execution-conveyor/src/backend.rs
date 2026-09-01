//! The transport seam.
//!
//! Everything above this trait is ROS-free and testable without a machine.
//! Everything below it is somebody's belt.

use kern_execution::RejectionReason;

/// The adapter's identity for one transfer.
///
/// Adapter-local and monotonic. It is not a Kern identifier and confers
/// nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConveyorOperationId(u64);

impl ConveyorOperationId {
    /// Wraps a raw value.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// The raw value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for ConveyorOperationId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "conveyor-{}", self.0)
    }
}

/// Whether a backend can hold the belt to an authorized speed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpeedControl {
    /// The backend commands the belt at a bounded rate.
    RateLimited,
    /// The backend cannot bound speed.
    ///
    /// An executor refuses to be built on such a backend. Accepting a
    /// `max_speed_mm_s` that nothing enforces would make the authority bound a
    /// decoration.
    None,
}

/// What a backend says about itself, once, at construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendDeclaration {
    /// How the backend bounds belt speed.
    pub speed_control: SpeedControl,
    /// True when the backend can ever report a cancellation as confirmed.
    pub confirms_cancellation: bool,
    /// True when the backend can report terminal results at all.
    pub reports_terminal_results: bool,
}

/// One transfer, in machine units.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ConveyorMove {
    /// Where the item is going, metres along the belt.
    pub target_m: f64,
    /// The authorized belt speed, metres per second.
    pub max_speed_m_s: f64,
    /// The Kern execution this belongs to, for the adapter's own logging.
    pub execution: kern_execution::ExecutionId,
}

/// The result of trying to start a transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartTransfer {
    /// The belt took the command, and this identifies the operation.
    Accepted {
        /// The backend's identity for it.
        operation: ConveyorOperationId,
    },
    /// The transfer **provably** did not start.
    ///
    /// Only when the backend knows this: no controller was reachable and
    /// nothing was transmitted, or the controller explicitly refused.
    Rejected {
        /// Why it did not start.
        reason: RejectionReason,
    },
    /// It may or may not have started.
    Unknown,
}

/// The result of handing a stop request to the belt controller.
///
/// `Accepted` means the request was taken at the transport boundary. It does
/// not mean the belt stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopSend {
    /// The request was taken.
    Accepted,
    /// The transfer had already ended.
    AlreadyTerminal,
    /// The controller refused.
    Rejected,
    /// The request may or may not have arrived.
    Unknown,
    /// The backend cannot reach the controller.
    Disconnected,
}

/// Something the belt controller reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendEvent {
    /// The belt is moving the item.
    Moving {
        /// The transfer it concerns.
        operation: ConveyorOperationId,
    },
    /// The item reached the station.
    Arrived {
        /// The transfer it concerns.
        operation: ConveyorOperationId,
    },
    /// The transfer failed.
    Faulted {
        /// The transfer it concerns.
        operation: ConveyorOperationId,
    },
    /// The transfer was stopped before arriving.
    Stopped {
        /// The transfer it concerns.
        operation: ConveyorOperationId,
    },
}

impl BackendEvent {
    /// The transfer an event concerns.
    pub fn operation(&self) -> ConveyorOperationId {
        match self {
            Self::Moving { operation }
            | Self::Arrived { operation }
            | Self::Faulted { operation }
            | Self::Stopped { operation } => *operation,
        }
    }
}

/// The result of asking a backend what it has seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendPoll {
    /// One event.
    Event(BackendEvent),
    /// Connected to the controller, nothing new.
    Idle,
    /// Cannot see the controller. Knowledge is stale from here.
    Disconnected,
}

/// The transport a conveyor executor drives.
pub trait ConveyorBackend {
    /// What this backend can do. Read once, at construction.
    fn declaration(&self) -> BackendDeclaration;

    /// Commands one transfer.
    fn start_transfer(&mut self, request: &ConveyorMove) -> StartTransfer;

    /// Asks the belt to stop a transfer.
    fn stop(&mut self, operation: ConveyorOperationId) -> StopSend;

    /// Takes the next report, if any.
    fn poll(&mut self) -> BackendPoll;

    /// Releases transport resources.
    fn shutdown(&mut self);
}
