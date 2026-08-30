//! A bounded event queue, shared by the fake backend and the ROS bridge.
//!
//! Unbounded queues are forbidden: a stalled consumer must not be able to grow
//! adapter memory without limit while a robot is moving. Overflow therefore
//! drops events and *says so*, which the executor turns into loss of knowledge
//! rather than into a claim about a machine.

use std::collections::VecDeque;

use crate::backend::BackendEvent;

/// A fixed-capacity queue of backend events.
#[derive(Debug)]
pub struct EventQueue {
    capacity: usize,
    events: VecDeque<BackendEvent>,
    lost: bool,
    dropped: u64,
}

impl EventQueue {
    /// A queue holding at most `capacity` events. A zero capacity is raised to
    /// one, because a queue that can hold nothing loses everything.
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            events: VecDeque::with_capacity(capacity),
            lost: false,
            dropped: 0,
        }
    }

    /// Appends an event, or records that one was lost.
    ///
    /// The **new** event is dropped rather than the oldest: a queue that evicts
    /// its front can silently discard the acceptance that explains everything
    /// after it.
    pub fn push(&mut self, event: BackendEvent) {
        if self.events.len() >= self.capacity {
            self.lost = true;
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.events.push_back(event);
    }

    /// Takes the oldest event.
    pub fn pop(&mut self) -> Option<BackendEvent> {
        self.events.pop_front()
    }

    /// True once anything has been dropped and not yet reported.
    pub fn lost(&self) -> bool {
        self.lost
    }

    /// Reports the loss once, then clears the flag.
    ///
    /// Cleared so that a single overflow produces a single loss report; the
    /// executions running at that moment become unknown, and later credible
    /// events can still resolve them.
    pub fn take_lost(&mut self) -> bool {
        core::mem::take(&mut self.lost)
    }

    /// How many events have been dropped over this queue's life.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// How many events are waiting.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// True when nothing is waiting.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The configured bound.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}
