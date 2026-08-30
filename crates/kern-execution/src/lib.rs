//! Execution governance: what current authority permits, and what happens when
//! that authority disappears while an operation is already running.
//!
//! ```text
//! LeaseHandle + NormalizedActionProposal
//!   -> enforce            authorization, at preparation time
//!   -> ExecutionId        identity for provenance
//!   -> Prepared record    written before anything is sent
//!   -> check_authority    liveness, immediately before the adapter is invoked
//!   -> executor.submit    once, ever
//!   -> observations       running, completed, failed, cancelled, or unknown
//! ```
//!
//! # Authority and execution are separate
//!
//! ```text
//! authorization                  != execution
//! accepted by an executor        != physical effect completed
//! authority lapsed               != machine stopped
//! cancellation requested         != cancellation confirmed
//! cancellation confirmed         != physical stop
//! ```
//!
//! Each line is a distinct fact with its own representation here, and the last
//! one has no representation at all, because Kern can never establish it.
//!
//! # Physical safety boundary
//!
//! Kern can stop granting authority, stop forwarding commands, request
//! cancellation, hold, or termination from an executor, observe what comes back,
//! and record provenance.
//!
//! Kern cannot, by itself, guarantee motor power removal, collision avoidance,
//! braking distance, a certified emergency stop, SIL or PL compliance, safe
//! torque off, or any physical safe-state transition. Those belong to
//! lower-level controllers and functional-safety systems. Nothing here is named
//! `Safe`, and correct authority is not safe motion.
//!
//! # Limits of this phase
//!
//! No persistence. If this process restarts while an executor is still running a
//! command, every execution record is lost, the new enforcer session invalidates
//! every prior lease, and Kern cannot attribute a discovered operation to any
//! subject or lease. [`ExecutionGovernor::reconcile`] can surface such
//! operations as unattributed; it cannot restore their provenance.
//!
//! No async runtime, no networking, no adapters for any particular robotics or
//! automation stack. Every pass is a synchronous call the host drives.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod command;
pub mod contract;
pub mod error;
pub mod governor;
pub mod id;
pub mod journal;
pub mod record;
pub mod state;

pub use command::{CommandDigest, SemanticCommand, COMMAND_DOMAIN_V1};
pub use contract::{
    CancelRequestOutcome, ExecutionObservation, Executor, ExecutorDeclaration,
    ExecutorObservations, ExecutorQuery, ExecutorReconcile, LapseAction, LapseActionSet,
    ObservationOrdering, ObservationPoll, ObservedReport, QueryOutcome, ReconcileOutcome,
    ReconcileReport, SubmitOutcome,
};
pub use error::{ConfigError, GovernError, ResolveDisputeError};
pub use governor::{
    ExecutionGovernor, GovernorConfig, LinkState, PreparedExecution, ReconcileSummary,
    StartupPolicy, SubmitReceipt, TickReport,
};
pub use id::{ExecutionId, ExecutionIdError, ExecutionIdSource, SequentialExecutionIds};
pub use journal::{ResolutionSource, Transition, TransitionKind, TransitionSubject};
pub use record::ExecutionRecord;
pub use state::{
    AuthorityLapseReason, AuthorityState, CancelRefusal, CancellationState, ExecutionState,
    FailureClass, LastKnown, NotStartedReason, RejectionReason, TerminalOutcome, UnknownPhase,
};
