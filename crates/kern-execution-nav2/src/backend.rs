//! The seam between Kern's synchronous execution contract and ROS.
//!
//! A backend does transport. It decides nothing about authority, keeps no
//! authority state, and is never told which lease permitted anything — it
//! receives a converted goal and reports what the action server did.
//!
//! Every method is synchronous and must not block: the ROS bridge owns a spin
//! thread and a bounded queue, and answers these calls from what that thread has
//! already collected.
//!
//! # Uncertainty is the backend's to classify
//!
//! No method returns `Result`. A transport failure means nothing on its own —
//! what matters is whether a goal may have reached Nav2 — and only the backend
//! knows that. `Rejected` is a claim the backend must be able to prove; anything
//! else is `Unknown`.

use std::string::String;

use kern_execution::{ExecutionId, RejectionReason};

/// Nav2's identity for one navigation goal.
///
/// The action goal UUID, wrapped. Deliberately **not** derived from
/// [`ExecutionId`]: Kern identity is provenance, ROS identity is transport, and
/// an encoding that made one readable from the other would invite code that
/// treats a goal UUID as authority.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nav2OperationId {
    goal_uuid: [u8; 16],
}

impl Nav2OperationId {
    /// Wraps an action goal UUID.
    pub const fn from_uuid(goal_uuid: [u8; 16]) -> Self {
        Self { goal_uuid }
    }

    /// The underlying goal UUID.
    pub const fn uuid(&self) -> &[u8; 16] {
        &self.goal_uuid
    }
}

impl core::fmt::Debug for Nav2OperationId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Nav2OperationId({:02x}{:02x}{:02x}{:02x}..)",
            self.goal_uuid[0], self.goal_uuid[1], self.goal_uuid[2], self.goal_uuid[3]
        )
    }
}

/// A converted navigation goal, ready for `nav2_msgs/action/NavigateToPose`.
///
/// Below the integer boundary. Nothing here is authority; the goal exists only
/// because a Kern authority decision already permitted it.
#[derive(Clone, Debug, PartialEq)]
pub struct Nav2Goal {
    /// The frame the pose is expressed in, typically `map`.
    pub frame_id: String,
    /// Target X, metres.
    pub x_m: f64,
    /// Target Y, metres.
    pub y_m: f64,
    /// Target heading, radians.
    pub yaw_rad: f64,
    /// Quaternion `z` for the heading.
    pub qz: f64,
    /// Quaternion `w` for the heading.
    pub qw: f64,
    /// The speed bound this goal is authorized under, metres per second.
    pub max_speed_m_s: f64,
    /// Correlation only. Never sent as authority, never trusted on return.
    pub execution: ExecutionId,
}

/// How, if at all, a backend can bound the speed of an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpeedControl {
    /// The backend can apply an absolute controller speed limit before a goal is
    /// sent, and clear it when the operation ends.
    ControllerSpeedLimit,
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
    /// How the backend bounds speed.
    pub speed_control: SpeedControl,
    /// True when the backend can ever report a `CANCELED` result.
    pub confirms_cancellation: bool,
    /// True when the backend can report terminal results at all.
    pub reports_terminal_results: bool,
}

/// The result of trying to apply or clear a speed limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpeedLimitOutcome {
    /// The limit was handed to the controller interface.
    Applied,
    /// The limit provably did not reach the controller interface.
    NotDelivered,
    /// It may or may not have arrived.
    Unknown,
}

/// The result of trying to send a goal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendGoal {
    /// The action server accepted the goal and returned this identity.
    Accepted {
        /// Nav2's goal identity.
        operation: Nav2OperationId,
    },
    /// The goal **provably** did not start.
    ///
    /// Only when the backend knows this: no action server was present and
    /// nothing was transmitted, or the server explicitly rejected the goal.
    Rejected {
        /// Why it did not start.
        reason: RejectionReason,
    },
    /// The goal may or may not have been accepted.
    Unknown,
}

/// The result of handing a cancellation request to the action interface.
///
/// `Accepted` means the request was taken at the transport boundary. It does not
/// mean the goal is cancelled, and it never means the robot stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelSend {
    /// The request was taken.
    Accepted,
    /// The goal had already reached a terminal state.
    AlreadyTerminal,
    /// The action server refused the request.
    Rejected,
    /// The request may or may not have arrived.
    Unknown,
    /// The backend cannot reach the action server.
    Disconnected,
}

/// Something the action interface reported about a goal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendEvent {
    /// Credible progress: action feedback for this goal.
    Feedback {
        /// The goal it concerns.
        operation: Nav2OperationId,
    },
    /// Result `SUCCEEDED`.
    Succeeded {
        /// The goal it concerns.
        operation: Nav2OperationId,
    },
    /// Result `ABORTED`.
    Aborted {
        /// The goal it concerns.
        operation: Nav2OperationId,
    },
    /// Result `CANCELED`.
    Canceled {
        /// The goal it concerns.
        operation: Nav2OperationId,
    },
}

impl BackendEvent {
    /// The goal an event concerns.
    pub fn operation(&self) -> Nav2OperationId {
        match self {
            Self::Feedback { operation }
            | Self::Succeeded { operation }
            | Self::Aborted { operation }
            | Self::Canceled { operation } => *operation,
        }
    }
}

/// The result of asking a backend what it has seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendPoll {
    /// One event.
    Event(BackendEvent),
    /// Connected to the action interface, nothing new.
    Idle,
    /// Cannot see the action interface.
    Disconnected,
    /// Events were dropped: the bounded queue overflowed, or the worker died.
    ///
    /// Distinct from `Disconnected` at the backend boundary because the causes
    /// differ, and both are reported honestly rather than smoothed over. The
    /// executor treats both as loss of knowledge.
    EventsLost,
}

/// A transport to a `nav2_msgs/action/NavigateToPose` action server.
pub trait Nav2Backend {
    /// What this backend can do. Read once, at executor construction.
    fn declaration(&self) -> BackendDeclaration;

    /// Applies an absolute speed limit for the operation about to be sent.
    fn apply_speed_limit(&mut self, limit_m_s: f64) -> SpeedLimitOutcome;

    /// Restores the controller's configured speed.
    fn clear_speed_limit(&mut self) -> SpeedLimitOutcome;

    /// Sends one navigation goal. Called at most once per [`ExecutionId`].
    fn send_goal(&mut self, goal: &Nav2Goal) -> SendGoal;

    /// Requests cancellation of one goal.
    fn cancel_goal(&mut self, operation: &Nav2OperationId) -> CancelSend;

    /// Takes the next event the backend has collected.
    fn poll_event(&mut self) -> BackendPoll;

    /// Releases transport resources. Idempotent.
    fn shutdown(&mut self);
}
