//! A `nav2_msgs/action/NavigateToPose` executor for Kern.
//!
//! ```text
//! kern-execution (ROS-free, no_std)
//!     Executor + ExecutorObservations
//!         ^
//!         |  implemented here, still ROS-free
//! kern-execution-nav2
//!     Nav2Executor<B: Nav2Backend>
//!         ^
//!         |  Nav2Backend, the transport seam
//! adapters/nav2-bridge   (outside the cargo workspace)
//!     r2r action client + spin thread + bounded queue
//!         ^
//!         |
//! ROS 2 Jazzy / Nav2 / Gazebo Harmonic
//! ```
//!
//! This crate has no ROS dependency and never will. Everything that links
//! against ROS lives behind [`Nav2Backend`](backend::Nav2Backend), in a crate
//! excluded from the workspace, so the whole mapping and the whole state
//! machine are testable — and gated — on a machine with no robot.
//!
//! # Where the integer boundary is
//!
//! Kern's semantics are integer: millimetres, millidegrees, millimetres per
//! second. Conversion to metres and radians happens in [`units`], below every
//! authority decision. No `f64` is ever an input to policy, a lease, or an
//! enforcement check.
//!
//! # Where the speed bound is enforced
//!
//! [`Nav2Executor::submit`](executor::Nav2Executor) applies an absolute
//! controller speed limit through the backend **before** the goal is sent, and
//! clears it once no goal can still be running under it. A backend that declares
//! [`SpeedControl::None`](backend::SpeedControl::None) is refused at
//! construction: an authorized `max_speed_mm_s` that nothing applies is worse
//! than no bound at all, because it reads like one.
//!
//! The bound is a *commanded* limit at the Nav2 controller. It is not a
//! guarantee about wheel speed, and this crate never describes it as one.
//!
//! # Failure mapping
//!
//! | ROS / Nav2 condition | Kern |
//! |---|---|
//! | action server absent, nothing transmitted | `SubmitOutcome::Rejected(Unavailable)` |
//! | speed limit could not be applied | `SubmitOutcome::Rejected(Unavailable)` — no goal was sent |
//! | goal explicitly rejected by the server | `SubmitOutcome::Rejected(Refused)` |
//! | command the adapter cannot serve | `SubmitOutcome::Rejected(InvalidCommand)` |
//! | another goal already active | `SubmitOutcome::Rejected(Busy)` |
//! | goal accepted, UUID obtained | `SubmitOutcome::Accepted { operation }` |
//! | send timed out / transport ambiguous | `SubmitOutcome::Unknown` |
//! | first credible action feedback | `ObservedReport::Running` |
//! | result `SUCCEEDED` | `ObservedReport::Completed` |
//! | result `ABORTED` | `ObservedReport::Failed(OperationFailed)` |
//! | result `CANCELED` | `ObservedReport::Cancelled` |
//! | no event, link healthy | `ObservationPoll::Idle` |
//! | action server or node unreachable | `ObservationPoll::Disconnected` |
//! | bounded queue overflowed | `ObservationPoll::Disconnected` (knowledge incomplete) |
//! | spin thread died | `ObservationPoll::Disconnected` |
//! | cancel request taken by the interface | `CancelRequestOutcome::Accepted` |
//! | goal already terminal | `CancelRequestOutcome::AlreadyTerminal` |
//! | cancel explicitly rejected | `CancelRequestOutcome::Rejected` |
//! | cancel while disconnected / ambiguous | `CancelRequestOutcome::Unknown` |
//! | lapse action other than `Cancel` | `CancelRequestOutcome::Unsupported` |
//!
//! There is no "error means failed" row. `Failed` is evidence about an attempted
//! machine operation; a transport problem is evidence about the adapter.
//!
//! # What reconciliation this adapter does *not* claim
//!
//! [`ExecutorReconcile`](kern_execution::ExecutorReconcile) and
//! [`ExecutorQuery`](kern_execution::ExecutorQuery) are **not** implemented. A
//! ROS action client generates goal UUIDs itself and offers no field to carry a
//! Kern identifier back, and there is no supported way to enumerate a Nav2
//! server's active goals from outside after an adapter restart. Inferring
//! operations from topic traffic or timing would be a guess dressed as a record.
//! `echoes_execution_id` is therefore `false`, and a submission whose
//! acknowledgement was lost stays unknown.
//!
//! # Physical safety boundary
//!
//! Kern controls the authority to *request* execution. It does not provide
//! certified collision avoidance, motor power removal, braking guarantees,
//! emergency-stop guarantees, SIL or PL compliance, or safe torque off. Nav2,
//! the controller, and the hardware remain responsible for what the machine
//! physically does. A successful Gazebo run does not make Kern a
//! functional-safety system.

#![forbid(unsafe_code)]

pub mod backend;
pub mod capability;
pub mod executor;
pub mod queue;
pub mod units;
pub mod view;

#[cfg(feature = "fake-backend")]
pub mod fake;

pub use backend::{
    BackendDeclaration, BackendEvent, BackendPoll, CancelSend, Nav2Backend, Nav2Goal,
    Nav2OperationId, SendGoal, SpeedControl, SpeedLimitOutcome,
};
pub use capability::{
    navigate_schema, CommandError, NavigateRequest, DESTINATION_X_MM, DESTINATION_Y_MM,
    MAX_SPEED_MM_S, NAVIGATE, YAW_MDEG,
};
pub use executor::{AdapterError, Nav2Config, Nav2Executor};
pub use queue::EventQueue;
pub use view::{navigate_label, render_execution, transition_label};

#[cfg(feature = "fake-backend")]
pub use fake::FakeNav2Backend;
