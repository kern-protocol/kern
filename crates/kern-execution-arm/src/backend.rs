//! The transport seam.
//!
//! Everything above this trait is ROS-free and testable without an arm.
//! Everything below it is somebody's joints.

use kern_execution::RejectionReason;

/// The adapter's identity for one motion.
///
/// Adapter-local and monotonic. It is not a Kern identifier and confers
/// nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArmOperationId(u64);

impl ArmOperationId {
    /// Wraps a raw value.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// The raw value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for ArmOperationId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "arm-{}", self.0)
    }
}

/// Whether a backend will move only to poses the host configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceControl {
    /// The backend commands only the poses it is handed, and nothing else.
    ConfiguredPosesOnly,
    /// The backend may move the arm anywhere.
    ///
    /// An executor refuses to be built on such a backend. An authorized zone
    /// set that nothing confines the arm to would make the authority bound a
    /// decoration, in exactly the way an unenforced speed limit would.
    Unbounded,
}

/// What a backend says about itself, once, at construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendDeclaration {
    /// Whether the backend confines the arm to configured poses.
    pub workspace_control: WorkspaceControl,
    /// True when the backend can ever report a cancellation as confirmed.
    pub confirms_cancellation: bool,
    /// True when the backend can report terminal results at all.
    pub reports_terminal_results: bool,
}

/// One arm pose, in joint space.
///
/// Two joints is what the demonstration arm has. The pose is trusted host
/// configuration keyed by zone name; nothing above this crate ever names a
/// joint angle.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ArmPose {
    /// Shoulder angle, radians.
    pub shoulder_rad: f64,
    /// Elbow angle, radians.
    pub elbow_rad: f64,
}

/// One pick-and-place, in machine units.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ArmMotion {
    /// Where to pick from.
    pub source: ArmPose,
    /// Where to place.
    pub destination: ArmPose,
    /// The Kern execution this belongs to, for the adapter's own logging.
    pub execution: kern_execution::ExecutionId,
}

/// The result of trying to start a motion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartMotion {
    /// The controller took the command, and this identifies the motion.
    Accepted {
        /// The backend's identity for it.
        operation: ArmOperationId,
    },
    /// The motion **provably** did not start.
    Rejected {
        /// Why it did not start.
        reason: RejectionReason,
    },
    /// It may or may not have started.
    Unknown,
}

/// The result of handing a stop request to the arm controller.
///
/// `Accepted` means the request was taken at the transport boundary. It does
/// not mean the arm stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopSend {
    /// The request was taken.
    Accepted,
    /// The motion had already ended.
    AlreadyTerminal,
    /// The controller refused.
    Rejected,
    /// The request may or may not have arrived.
    Unknown,
    /// The backend cannot reach the controller.
    Disconnected,
}

/// Something the arm controller reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendEvent {
    /// The arm is moving.
    Moving {
        /// The motion it concerns.
        operation: ArmOperationId,
    },
    /// The motion finished.
    Placed {
        /// The motion it concerns.
        operation: ArmOperationId,
    },
    /// The motion failed.
    Faulted {
        /// The motion it concerns.
        operation: ArmOperationId,
    },
    /// The motion was stopped before finishing.
    Stopped {
        /// The motion it concerns.
        operation: ArmOperationId,
    },
}

impl BackendEvent {
    /// The motion an event concerns.
    pub fn operation(&self) -> ArmOperationId {
        match self {
            Self::Moving { operation }
            | Self::Placed { operation }
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

/// The transport an arm executor drives.
pub trait ArmBackend {
    /// What this backend can do. Read once, at construction.
    fn declaration(&self) -> BackendDeclaration;

    /// Commands one pick-and-place.
    fn start_motion(&mut self, motion: &ArmMotion) -> StartMotion;

    /// Asks the arm to stop a motion.
    fn stop(&mut self, operation: ArmOperationId) -> StopSend;

    /// Takes the next report, if any.
    fn poll(&mut self) -> BackendPoll;

    /// Releases transport resources.
    fn shutdown(&mut self);
}
