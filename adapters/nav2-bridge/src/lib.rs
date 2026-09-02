//! A `Nav2Backend` over ROS 2 Jazzy and Nav2's `NavigateToPose` action.
//!
//! # What this crate is allowed to know
//!
//! Transport. It never sees a lease, an artifact, a constraint set, or a policy,
//! and it holds no authority state. It converts a goal that Kern already
//! authorized into a ROS action goal, reports what the action server did, and
//! asks the server to cancel when Kern says authority has lapsed.
//!
//! # Threading
//!
//! ```text
//! Kern thread                      worker thread
//!   Nav2Backend method  --cmd-->   bounded SyncSender (capacity 1)
//!                       <-reply--  bounded reply channel, with timeout
//!   poll_event()        <--------  Mutex<EventQueue>, bounded, drops newest
//!                                  r2r node spin + action futures
//! ```
//!
//! Kern's side stays synchronous and never blocks indefinitely: every command
//! carries a deadline, and a deadline that elapses becomes `Unknown` rather than
//! a claim about the robot. The worker owns all ROS state; nothing `!Send`
//! crosses the boundary. No Tokio: the worker drives futures with
//! `futures::executor::block_on` between `spin_once` calls.
//!
//! A panic in the worker is caught at the thread boundary and turns into
//! `BackendPoll::EventsLost`, which Kern reads as loss of knowledge — never as a
//! machine result.
//!
//! # Where the speed bound is applied
//!
//! Before every goal, on `/speed_limit`
//! (`nav2_msgs/msg/SpeedLimit`, `percentage: false`), which
//! `nav2_controller` consumes and passes to the controller plugin's
//! `setSpeedLimit`. Cleared with `speed_limit: 0.0`, Nav2's "no limit" value,
//! once no goal can still be running under it. This is a *commanded* limit at
//! the controller. It is not a guarantee about wheel speed, and nothing here
//! describes it as one.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use kern_execution::RejectionReason;
use kern_execution_nav2::backend::{
    BackendDeclaration, BackendEvent, BackendPoll, CancelSend, Nav2Backend, Nav2Goal,
    Nav2OperationId, SendGoal, SpeedControl, SpeedLimitOutcome,
};
use kern_execution_nav2::EventQueue;

pub mod pose;
pub mod ros;
pub mod workstation;

/// How long a Kern-thread call waits for the worker before calling the result
/// unknown.
pub const COMMAND_TIMEOUT: Duration = Duration::from_millis(2_000);

/// The topic `nav2_controller` reads speed limits from.
pub const SPEED_LIMIT_TOPIC: &str = "/speed_limit";

/// Nav2's "no restriction" speed-limit value.
pub const NO_SPEED_LIMIT: f64 = 0.0;

/// A command from the Kern thread to the ROS worker.
#[derive(Debug)]
pub enum Command {
    /// Publish an absolute speed limit, metres per second.
    SpeedLimit {
        /// The limit, or [`NO_SPEED_LIMIT`] to clear.
        limit_m_s: f64,
        /// Where the answer goes.
        reply: SyncSender<SpeedLimitOutcome>,
    },
    /// Send one `NavigateToPose` goal.
    SendGoal {
        /// The converted goal.
        goal: Box<Nav2Goal>,
        /// Where the answer goes.
        reply: SyncSender<SendGoal>,
    },
    /// Ask the server to cancel one goal.
    Cancel {
        /// The goal to cancel.
        operation: Nav2OperationId,
        /// Where the answer goes.
        reply: SyncSender<CancelSend>,
    },
    /// Stop the worker.
    Shutdown,
}

/// State shared between the Kern thread and the ROS worker.
#[derive(Debug)]
pub struct Shared {
    /// Bounded. Overflow drops the newest event and records the loss.
    pub events: Mutex<EventQueue>,
    /// False when the action server is not reachable.
    pub connected: AtomicBool,
    /// False once the worker has stopped, whether cleanly or by panic.
    pub worker_alive: AtomicBool,
    /// True when the worker died unexpectedly.
    pub worker_failed: AtomicBool,
}

impl Shared {
    /// Shared state with a bounded event queue.
    pub fn new(queue_capacity: usize) -> Self {
        Self {
            events: Mutex::new(EventQueue::with_capacity(queue_capacity)),
            connected: AtomicBool::new(false),
            worker_alive: AtomicBool::new(true),
            worker_failed: AtomicBool::new(false),
        }
    }

    /// Records one event, dropping it if the queue is full.
    pub fn push(&self, event: BackendEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}

/// The Kern-side handle on a running ROS worker.
pub struct RosNav2Backend {
    commands: SyncSender<Command>,
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
    declaration: BackendDeclaration,
}

impl RosNav2Backend {
    /// Starts a worker thread owning a ROS node and a `NavigateToPose` client.
    ///
    /// # Errors
    ///
    /// When the ROS context or node cannot be created. A backend that cannot
    /// publish a speed limit is never returned: the adapter would refuse it at
    /// construction anyway, and failing here says why.
    pub fn start(config: ros::BridgeConfig) -> Result<Self, ros::BridgeError> {
        let shared = Arc::new(Shared::new(config.queue_capacity));
        // Capacity 1: the Kern thread issues one command at a time and waits for
        // its reply, so a deeper queue would only hide a stalled worker.
        let (commands, inbox) = sync_channel(1);
        let worker = ros::spawn_worker(config, Arc::clone(&shared), inbox)?;

        Ok(Self {
            commands,
            shared,
            worker: Some(worker),
            declaration: BackendDeclaration {
                speed_control: SpeedControl::ControllerSpeedLimit,
                // Nav2 reports CANCELED as an action result.
                confirms_cancellation: true,
                reports_terminal_results: true,
            },
        })
    }

    fn worker_is_gone(&self) -> bool {
        !self.shared.worker_alive.load(Ordering::SeqCst)
    }

    /// Sends a command and waits for its reply, or gives up.
    ///
    /// `on_timeout` decides what a silent worker means for this particular
    /// command — which is never the same answer twice: a lost goal send is
    /// `Unknown`, a lost cancel is `Unknown`, a lost speed limit is `Unknown`.
    fn call<T>(&self, make: impl FnOnce(SyncSender<T>) -> Command, on_timeout: T) -> T {
        if self.worker_is_gone() {
            return on_timeout;
        }
        let (reply, answers): (SyncSender<T>, Receiver<T>) = sync_channel(1);
        if self.commands.try_send(make(reply)).is_err() {
            return on_timeout;
        }
        match answers.recv_timeout(COMMAND_TIMEOUT) {
            Ok(outcome) => outcome,
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => on_timeout,
        }
    }
}

impl Nav2Backend for RosNav2Backend {
    fn declaration(&self) -> BackendDeclaration {
        self.declaration
    }

    fn apply_speed_limit(&mut self, limit_m_s: f64) -> SpeedLimitOutcome {
        self.call(
            |reply| Command::SpeedLimit { limit_m_s, reply },
            SpeedLimitOutcome::Unknown,
        )
    }

    fn clear_speed_limit(&mut self) -> SpeedLimitOutcome {
        self.call(
            |reply| Command::SpeedLimit {
                limit_m_s: NO_SPEED_LIMIT,
                reply,
            },
            SpeedLimitOutcome::Unknown,
        )
    }

    fn send_goal(&mut self, goal: &Nav2Goal) -> SendGoal {
        // A silent worker is ambiguity, never a rejection: the goal may have
        // reached Nav2. Rejected is reserved for the worker proving otherwise.
        let goal = Box::new(goal.clone());
        self.call(
            move |reply| Command::SendGoal { goal, reply },
            SendGoal::Unknown,
        )
    }

    fn cancel_goal(&mut self, operation: &Nav2OperationId) -> CancelSend {
        let operation = *operation;
        self.call(
            move |reply| Command::Cancel { operation, reply },
            CancelSend::Unknown,
        )
    }

    fn poll_event(&mut self) -> BackendPoll {
        if self.shared.worker_failed.load(Ordering::SeqCst) {
            return BackendPoll::EventsLost;
        }

        let mut events = match self.shared.events.lock() {
            Ok(events) => events,
            // A poisoned lock means a panic happened while holding it: what is
            // in the queue is no longer the whole picture.
            Err(_) => return BackendPoll::EventsLost,
        };
        if events.take_lost() {
            return BackendPoll::EventsLost;
        }
        if let Some(event) = events.pop() {
            return BackendPoll::Event(event);
        }
        drop(events);

        if self.worker_is_gone() || !self.shared.connected.load(Ordering::SeqCst) {
            return BackendPoll::Disconnected;
        }
        BackendPoll::Idle
    }

    fn shutdown(&mut self) {
        let _ = self.commands.try_send(Command::Shutdown);
        if let Some(worker) = self.worker.take() {
            // A worker that panicked is already accounted for by worker_failed;
            // joining it must not propagate the panic into Kern.
            let _ = worker.join();
        }
        self.shared.worker_alive.store(false, Ordering::SeqCst);
    }
}

impl Drop for RosNav2Backend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Nav2 result codes, mapped without a catch-all.
///
/// Kept as a function so the mapping is one readable place rather than scattered
/// through the worker. `ABORTED` is evidence about an attempted machine
/// operation; a transport problem is not, and never lands here.
pub fn event_for_status(
    operation: Nav2OperationId,
    status: ros::ResultStatus,
) -> Option<BackendEvent> {
    match status {
        ros::ResultStatus::Succeeded => Some(BackendEvent::Succeeded { operation }),
        ros::ResultStatus::Aborted => Some(BackendEvent::Aborted { operation }),
        ros::ResultStatus::Canceled => Some(BackendEvent::Canceled { operation }),
        // Still running, or a status this adapter does not read as terminal.
        ros::ResultStatus::Unknown => None,
    }
}

/// Why a goal was refused, when the worker can prove it never started.
pub fn rejection_for(kind: ros::RejectionKind) -> RejectionReason {
    match kind {
        ros::RejectionKind::ServerAbsent => RejectionReason::Unavailable,
        ros::RejectionKind::GoalRejected => RejectionReason::Refused,
    }
}

/// Goals the worker is following, by UUID.
pub type GoalTable = HashMap<[u8; 16], ()>;
