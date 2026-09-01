//! A deterministic backend that drives no arm.
//!
//! Every fault the contract admits — rejection, a lost acknowledgement,
//! disconnection, a refused stop — is scripted rather than provoked, so the
//! whole adapter and the whole state machine are testable on a machine with no
//! arm.

use std::collections::VecDeque;
use std::vec::Vec;

use crate::backend::{
    ArmBackend, ArmMotion, ArmOperationId, BackendDeclaration, BackendEvent, BackendPoll,
    StartMotion, StopSend, WorkspaceControl,
};

/// A scriptable, ROS-free [`ArmBackend`].
#[derive(Debug)]
pub struct FakeArmBackend {
    declaration: BackendDeclaration,
    next_id: u64,
    start_script: VecDeque<StartMotion>,
    stop_script: VecDeque<StopSend>,
    events: VecDeque<BackendEvent>,
    connected: bool,
    /// Motions commanded, in order.
    pub started: Vec<ArmMotion>,
    /// Stop requests, in order.
    pub stopped: Vec<ArmOperationId>,
    /// How many times shutdown was called.
    pub shutdowns: u32,
}

impl Default for FakeArmBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeArmBackend {
    /// A connected backend that accepts motions and confirms stops.
    pub fn new() -> Self {
        Self {
            declaration: BackendDeclaration {
                workspace_control: WorkspaceControl::ConfiguredPosesOnly,
                confirms_cancellation: true,
                reports_terminal_results: true,
            },
            next_id: 1,
            start_script: VecDeque::new(),
            stop_script: VecDeque::new(),
            events: VecDeque::new(),
            connected: true,
            started: Vec::new(),
            stopped: Vec::new(),
            shutdowns: 0,
        }
    }

    /// Replaces the declaration, for construction tests.
    #[must_use]
    pub fn with_declaration(mut self, declaration: BackendDeclaration) -> Self {
        self.declaration = declaration;
        self
    }

    /// Scripts one start outcome.
    #[must_use]
    pub fn script_start(mut self, outcome: StartMotion) -> Self {
        self.start_script.push_back(outcome);
        self
    }

    /// Scripts one stop outcome.
    #[must_use]
    pub fn script_stop(mut self, outcome: StopSend) -> Self {
        self.stop_script.push_back(outcome);
        self
    }

    /// Queues an event the controller will report.
    pub fn emit(&mut self, event: BackendEvent) {
        self.events.push_back(event);
    }

    /// Breaks the link to the controller.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Restores the link. Resolves nothing on its own.
    pub fn reconnect(&mut self) {
        self.connected = true;
    }

    /// The identity the next accepted motion will get.
    fn next_operation(&mut self) -> ArmOperationId {
        let id = ArmOperationId::from_u64(self.next_id);
        self.next_id += 1;
        id
    }
}

impl ArmBackend for FakeArmBackend {
    fn declaration(&self) -> BackendDeclaration {
        self.declaration
    }

    fn start_motion(&mut self, motion: &ArmMotion) -> StartMotion {
        if let Some(scripted) = self.start_script.pop_front() {
            if let StartMotion::Accepted { .. } | StartMotion::Unknown = scripted {
                self.started.push(*motion);
            }
            return scripted;
        }
        if !self.connected {
            return StartMotion::Rejected {
                reason: kern_execution::RejectionReason::Unavailable,
            };
        }
        self.started.push(*motion);
        StartMotion::Accepted {
            operation: self.next_operation(),
        }
    }

    fn stop(&mut self, operation: ArmOperationId) -> StopSend {
        self.stopped.push(operation);
        if let Some(scripted) = self.stop_script.pop_front() {
            return scripted;
        }
        if !self.connected {
            return StopSend::Disconnected;
        }
        StopSend::Accepted
    }

    fn poll(&mut self) -> BackendPoll {
        if !self.connected {
            return BackendPoll::Disconnected;
        }
        match self.events.pop_front() {
            Some(event) => BackendPoll::Event(event),
            None => BackendPoll::Idle,
        }
    }

    fn shutdown(&mut self) {
        self.shutdowns += 1;
    }
}
