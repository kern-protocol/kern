//! A conveyor workstation as a Kern executor.
//!
//! ```text
//! kern-execution (ROS-free, no_std)
//!     Executor + ExecutorObservations
//!         ^
//!         |  implemented here, still ROS-free
//! kern-execution-conveyor
//!     ConveyorExecutor<B: ConveyorBackend>
//!         ^
//!         |  ConveyorBackend, the transport seam
//! a belt controller
//! ```
//!
//! # What is deliberately not exposed
//!
//! The capability is `transfer_item(destination_station, max_speed_mm_s)`. Not a
//! velocity setpoint, not a direction and a duration, not a PWM value, not a
//! topic name. A belt is a motor; Kern governs the *transfer*, because a
//! transfer is the thing a policy can bound and a motor command is not.
//!
//! # Where the speed bound is enforced
//!
//! [`ConveyorExecutor::submit`](executor::ConveyorExecutor) passes the
//! authorized bound to the backend, and a backend declaring
//! [`SpeedControl::None`](backend::SpeedControl::None) is refused at
//! construction: an authorized `max_speed_mm_s` that nothing applies is worse
//! than no bound at all, because it reads like one.
//!
//! The bound is a *commanded* limit. It is not a guarantee about belt surface
//! speed, and this crate never describes it as one.
//!
//! # Where the integer boundary is
//!
//! Kern's semantics are integer and symbolic: millimetres per second, and a
//! station by name. Conversion to metres happens in [`units`], below every
//! authority decision.

#![forbid(unsafe_code)]

pub mod backend;
pub mod capability;
pub mod executor;
pub mod units;

#[cfg(feature = "fake-backend")]
pub mod fake;

pub use backend::{
    BackendDeclaration, BackendEvent, BackendPoll, ConveyorBackend, ConveyorMove,
    ConveyorOperationId, SpeedControl, StartTransfer, StopSend,
};
pub use capability::{
    transfer_item_schema, CommandError, TransferRequest, DESTINATION_STATION, MAX_SPEED_MM_S,
    TRANSFER_ITEM,
};
pub use executor::{AdapterError, ConveyorConfig, ConveyorExecutor, Station};

#[cfg(feature = "fake-backend")]
pub use fake::FakeConveyorBackend;
