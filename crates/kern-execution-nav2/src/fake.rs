//! A deterministic backend that speaks no ROS.
//!
//! Layer 2 of the test plan: every fault the contract admits — rejection, lost
//! acknowledgement, disconnection, dropped events, worker death, refused
//! cancellation — is scripted rather than provoked. It is also what the demo
//! example runs on, so the demo needs no robot.

use std::collections::VecDeque;
use std::vec::Vec;

use crate::backend::{
    BackendDeclaration, BackendEvent, BackendPoll, CancelSend, Nav2Backend, Nav2Goal,
    Nav2OperationId, SendGoal, SpeedControl, SpeedLimitOutcome,
};
use crate::queue::EventQueue;

/// A scriptable, ROS-free [`Nav2Backend`].
#[derive(Debug)]
pub struct FakeNav2Backend {
    declaration: BackendDeclaration,
    next_uuid: u8,
    send_script: VecDeque<SendGoal>,
    cancel_script: VecDeque<CancelSend>,
    speed_script: VecDeque<SpeedLimitOutcome>,
    events: EventQueue,
    connected: bool,
    worker_failed: bool,
    /// Sent goals, in order.
    pub sent: Vec<Nav2Goal>,
    /// Cancellation requests, in order.
    pub cancelled: Vec<Nav2OperationId>,
    /// Speed limits applied, metres per second, in order. `None` is a clear.
    pub speed_limits: Vec<Option<f64>>,
    /// How many times shutdown was called.
    pub shutdowns: u32,
    /// A simulation clock, advanced by tests.
    ///
    /// Deliberately inert: nothing in Kern reads it. Simulation time may pause,
    /// jump, or reset, and authority lifetime is measured against the enforcer's
    /// monotonic clock alone.
    pub sim_time_ms: u64,
}

impl Default for FakeNav2Backend {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeNav2Backend {
    /// A connected backend that accepts goals and confirms cancellations.
    pub fn new() -> Self {
        Self {
            declaration: BackendDeclaration {
                speed_control: SpeedControl::ControllerSpeedLimit,
                confirms_cancellation: true,
                reports_terminal_results: true,
            },
            next_uuid: 1,
            send_script: VecDeque::new(),
            cancel_script: VecDeque::new(),
            speed_script: VecDeque::new(),
            events: EventQueue::with_capacity(16),
            connected: true,
            worker_failed: false,
            sent: Vec::new(),
            cancelled: Vec::new(),
            speed_limits: Vec::new(),
            shutdowns: 0,
            sim_time_ms: 0,
        }
    }

    /// Replaces the declaration, for construction tests.
    pub fn with_declaration(mut self, declaration: BackendDeclaration) -> Self {
        self.declaration = declaration;
        self
    }

    /// Sets the event queue bound.
    pub fn with_queue_capacity(mut self, capacity: usize) -> Self {
        self.events = EventQueue::with_capacity(capacity);
        self
    }

    /// Scripts one goal-send outcome.
    pub fn script_send(mut self, outcome: SendGoal) -> Self {
        self.send_script.push_back(outcome);
        self
    }

    /// Scripts one cancellation outcome.
    pub fn script_cancel(mut self, outcome: CancelSend) -> Self {
        self.cancel_script.push_back(outcome);
        self
    }

    /// Scripts one speed-limit outcome.
    pub fn script_speed_limit(mut self, outcome: SpeedLimitOutcome) -> Self {
        self.speed_script.push_back(outcome);
        self
    }

    /// Queues an event the action interface will report.
    pub fn emit(&mut self, event: BackendEvent) {
        self.events.push(event);
    }

    /// Breaks the link to the action interface.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Restores the link. Resolves nothing on its own.
    pub fn reconnect(&mut self) {
        self.connected = true;
    }

    /// Kills the worker, as a panic caught at the thread boundary would.
    pub fn fail_worker(&mut self) {
        self.worker_failed = true;
    }

    /// How many events were dropped by the bounded queue.
    pub fn dropped_events(&self) -> u64 {
        self.events.dropped()
    }

    /// The identity the next accepted goal will get.
    fn next_operation(&mut self) -> Nav2OperationId {
        let mut uuid = [0u8; 16];
        uuid[0] = self.next_uuid;
        self.next_uuid = self.next_uuid.wrapping_add(1);
        Nav2OperationId::from_uuid(uuid)
    }
}

impl Nav2Backend for FakeNav2Backend {
    fn declaration(&self) -> BackendDeclaration {
        self.declaration
    }

    fn apply_speed_limit(&mut self, limit_m_s: f64) -> SpeedLimitOutcome {
        let outcome = self
            .speed_script
            .pop_front()
            .unwrap_or(SpeedLimitOutcome::Applied);
        if outcome == SpeedLimitOutcome::Applied {
            self.speed_limits.push(Some(limit_m_s));
        }
        outcome
    }

    fn clear_speed_limit(&mut self) -> SpeedLimitOutcome {
        self.speed_limits.push(None);
        SpeedLimitOutcome::Applied
    }

    fn send_goal(&mut self, goal: &Nav2Goal) -> SendGoal {
        self.sent.push(goal.clone());
        match self.send_script.pop_front() {
            Some(outcome) => outcome,
            None => SendGoal::Accepted {
                operation: self.next_operation(),
            },
        }
    }

    fn cancel_goal(&mut self, operation: &Nav2OperationId) -> CancelSend {
        self.cancelled.push(*operation);
        if !self.connected || self.worker_failed {
            return CancelSend::Disconnected;
        }
        self.cancel_script
            .pop_front()
            .unwrap_or(CancelSend::Accepted)
    }

    fn poll_event(&mut self) -> BackendPoll {
        // A dead worker is reported before anything queued: what is in the queue
        // is no longer the whole picture.
        if self.worker_failed {
            return BackendPoll::EventsLost;
        }
        if self.events.take_lost() {
            return BackendPoll::EventsLost;
        }
        if let Some(event) = self.events.pop() {
            return BackendPoll::Event(event);
        }
        if !self.connected {
            return BackendPoll::Disconnected;
        }
        BackendPoll::Idle
    }

    fn shutdown(&mut self) {
        self.shutdowns += 1;
        self.connected = false;
    }
}
