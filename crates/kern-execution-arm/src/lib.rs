//! A robotic arm as a Kern executor.
//!
//! ```text
//! kern-execution (ROS-free, no_std)
//!     Executor + ExecutorObservations
//!         ^
//!         |  implemented here, still ROS-free
//! kern-execution-arm
//!     ArmExecutor<B: ArmBackend>
//!         ^
//!         |  ArmBackend, the transport seam
//! an arm controller
//! ```
//!
//! # What is deliberately not exposed
//!
//! The capability is `pick_and_place(source_zone, destination_zone)`. Not a
//! joint angle, not a trajectory, not a torque, not a controller topic. An arm
//! is a stack of joints; Kern governs the *task*, because a task is the thing a
//! policy can bound and a joint command is not.
//!
//! Both parameters are symbols, so the authorized set of zones *is* the
//! authorized workspace, expressed with the constraint algebra that already
//! exists.
//!
//! # Where the workspace bound is enforced
//!
//! Zone names become poses only through trusted adapter configuration, and a
//! backend declaring
//! [`WorkspaceControl::Unbounded`](backend::WorkspaceControl::Unbounded) is
//! refused at construction: an authorized zone set that nothing confines the
//! arm to would make the authority bound a decoration.
//!
//! The bound is a *commanded* set of poses. It is not a guarantee about where
//! the arm physically ends up, and this crate never describes it as one.

#![forbid(unsafe_code)]

pub mod backend;
pub mod capability;
pub mod executor;

#[cfg(feature = "fake-backend")]
pub mod fake;

pub use backend::{
    ArmBackend, ArmMotion, ArmOperationId, ArmPose, BackendDeclaration, BackendEvent, BackendPoll,
    StartMotion, StopSend, WorkspaceControl,
};
pub use capability::{
    pick_and_place_schema, CommandError, PickAndPlaceRequest, DESTINATION_ZONE, PICK_AND_PLACE,
    SOURCE_ZONE,
};
pub use executor::{AdapterError, ArmConfig, ArmExecutor, Zone};

#[cfg(feature = "fake-backend")]
pub use fake::FakeArmBackend;
