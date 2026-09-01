//! ROS 2 transports for the conveyor and the arm.
//!
//! Both machines are position-controlled joints, so both backends are the same
//! machine underneath: publish a setpoint, watch a joint state, decide when the
//! commanded motion is done. That shared part is [`JointMachine`]; the two
//! public types differ only in how many joints they drive and what a "motion"
//! means to them.
//!
//! # What these backends may do, and may not
//!
//! They publish to exactly the joint-command topics the world declares, and
//! nothing else. There is no generic publisher, no topic name that comes from a
//! proposal, and no path by which a model's bytes could name a topic: the
//! adapters above them hand over poses and positions drawn from trusted
//! configuration, and these backends turn those into the one message type each
//! joint accepts.
//!
//! # What "arrived" means here
//!
//! Both machines report a terminal result when the commanded setpoint has
//! reached its target **and** the observed joint has settled within tolerance
//! of it. The second half is what makes it evidence rather than an assertion:
//! without the joint-state subscription this would only say the adapter
//! finished publishing, which is a claim about the adapter.
//!
//! It is still a claim about a *joint*, not about a package or a cup. Kern
//! observes what the simulator reports and says no more than that.

use std::pin::Pin;
use std::time::{Duration, Instant};

use futures::future::FutureExt;
use futures::stream::{Stream, StreamExt};
use r2r::sensor_msgs::msg::JointState;
use r2r::std_msgs::msg::Float64;
use r2r::{Context, Node, QosProfile};

use kern_execution_arm::backend::{
    ArmBackend, ArmMotion, ArmOperationId, BackendDeclaration as ArmDeclaration,
    BackendEvent as ArmEvent, BackendPoll as ArmPoll, StartMotion, StopSend as ArmStop,
    WorkspaceControl,
};
use kern_execution_conveyor::backend::{
    BackendDeclaration as ConveyorDeclaration, BackendEvent as ConveyorEvent,
    BackendPoll as ConveyorPoll, ConveyorBackend, ConveyorMove, ConveyorOperationId, SpeedControl,
    StartTransfer, StopSend as ConveyorStop,
};

/// One spin slice.
const SPIN_SLICE: Duration = Duration::from_millis(5);
/// How long a poll may spin looking for a joint-state message.
const POLL_BUDGET: Duration = Duration::from_millis(20);
/// How close the belt must be to its target to count as settled, in metres.
///
/// Tight, because a prismatic joint under a position controller holds its
/// setpoint almost exactly.
const BELT_SETTLE_TOLERANCE_M: f64 = 0.02;
/// How close each arm joint must be to its target to count as settled, radians.
///
/// About 3.4 degrees. Wider than the belt's because a revolute joint holding a
/// pose against gravity sits at a steady-state error the position controller
/// does not remove — measured at roughly 0.03 rad on this arm. A tolerance
/// tighter than the controller's own error would mean the arm never settles at
/// all, and every motion would end as a fault, which would be a claim about the
/// tolerance rather than about the machine.
const ARM_SETTLE_TOLERANCE_RAD: f64 = 0.06;
/// How long the observed joint must stay inside the tolerance.
const SETTLE_HOLD: Duration = Duration::from_millis(400);
/// How long a commanded motion may run before the backend gives up on ever
/// seeing it settle, and reports a fault rather than waiting forever.
const MOTION_DEADLINE: Duration = Duration::from_secs(60);

/// A joint being driven towards a target at a bounded rate.
struct Ramp {
    /// Which joint, by name, in the machine's joint-state message.
    name: String,
    /// Where the setpoint is now.
    setpoint: f64,
    /// Where it is going.
    target: f64,
    /// How fast the setpoint may move, per second.
    rate: f64,
}

impl Ramp {
    fn advance(&mut self, dt: f64) {
        let step = self.rate * dt;
        let remaining = self.target - self.setpoint;
        if remaining.abs() <= step {
            self.setpoint = self.target;
        } else {
            self.setpoint += step.copysign(remaining);
        }
    }

    fn commanded_to_target(&self) -> bool {
        (self.target - self.setpoint).abs() < 1e-9
    }
}

/// What the machine is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Nothing commanded.
    Idle,
    /// A motion is under way, at this waypoint index.
    Running(usize),
    /// The motion ended.
    Done,
}

/// The shared position-controlled-joint transport.
///
/// Owns one ROS node, one publisher per joint, and one joint-state
/// subscription. It drives a list of waypoints — each a full set of joint
/// targets — in order, at a bounded rate.
struct JointMachine {
    node: Node,
    publishers: Vec<r2r::Publisher<Float64>>,
    joint_state: Pin<Box<dyn Stream<Item = JointState> + Send>>,
    ramps: Vec<Ramp>,
    waypoints: Vec<Vec<f64>>,
    phase: Phase,
    observed: Vec<Option<f64>>,
    settled_since: Option<Instant>,
    started_at: Option<Instant>,
    last_tick: Instant,
    stop_requested: bool,
    announced_moving: bool,
    settle_tolerance: f64,
}

impl JointMachine {
    /// Builds the node, the publishers, and the subscription.
    fn new(
        node_name: &str,
        namespace: &str,
        joints: &[(&str, &str, f64)],
        joint_state_topic: &str,
        settle_tolerance: f64,
    ) -> Result<Self, r2r::Error> {
        let context = Context::create()?;
        let mut node = Node::create(context, node_name, namespace)?;

        let mut publishers = Vec::new();
        let mut ramps = Vec::new();
        for (joint, topic, rate) in joints {
            publishers.push(node.create_publisher::<Float64>(topic, QosProfile::default())?);
            ramps.push(Ramp {
                name: (*joint).to_string(),
                setpoint: 0.0,
                target: 0.0,
                rate: *rate,
            });
        }
        let joint_state =
            Box::pin(node.subscribe::<JointState>(joint_state_topic, QosProfile::default())?);

        let observed = vec![None; ramps.len()];
        Ok(Self {
            node,
            publishers,
            joint_state,
            ramps,
            waypoints: Vec::new(),
            phase: Phase::Idle,
            observed,
            settled_since: None,
            started_at: None,
            last_tick: Instant::now(),
            stop_requested: false,
            announced_moving: false,
            settle_tolerance,
        })
    }

    /// True while a commanded motion is under way.
    fn busy(&self) -> bool {
        matches!(self.phase, Phase::Running(_))
    }

    /// Starts a motion through `waypoints`, each a full set of joint targets.
    ///
    /// The rate limit is per joint and is applied here, to the setpoint, which
    /// is the only place a bound can be applied to a position controller.
    fn start(&mut self, waypoints: Vec<Vec<f64>>, rates: &[f64]) -> bool {
        if waypoints.is_empty()
            || waypoints
                .iter()
                .any(|point| point.len() != self.ramps.len())
        {
            return false;
        }
        for (ramp, rate) in self.ramps.iter_mut().zip(rates) {
            ramp.rate = *rate;
        }
        for (ramp, target) in self.ramps.iter_mut().zip(&waypoints[0]) {
            ramp.target = *target;
        }
        self.waypoints = waypoints;
        self.phase = Phase::Running(0);
        self.settled_since = None;
        self.started_at = Some(Instant::now());
        self.last_tick = Instant::now();
        self.stop_requested = false;
        self.announced_moving = false;
        self.publish()
    }

    /// Stops where it is: the current setpoint becomes the target.
    ///
    /// A position controller cannot be told "stop"; it can only be told to hold
    /// where it already is. That is what this does, and it is why the adapter
    /// reports a *request* rather than a stop.
    fn hold(&mut self) -> bool {
        for ramp in &mut self.ramps {
            ramp.target = ramp.setpoint;
        }
        self.stop_requested = true;
        self.publish()
    }

    fn publish(&mut self) -> bool {
        for (publisher, ramp) in self.publishers.iter().zip(&self.ramps) {
            if publisher
                .publish(&Float64 {
                    data: ramp.setpoint,
                })
                .is_err()
            {
                return false;
            }
        }
        true
    }

    /// Reads whatever joint states have arrived.
    fn drain_joint_state(&mut self) {
        let deadline = Instant::now() + POLL_BUDGET;
        loop {
            let next = self.joint_state.next();
            match next.now_or_never() {
                Some(Some(message)) => {
                    for (index, ramp) in self.ramps.iter().enumerate() {
                        if let Some(position) = message
                            .name
                            .iter()
                            .position(|name| name == &ramp.name)
                            .and_then(|at| message.position.get(at).copied())
                        {
                            self.observed[index] = Some(position);
                        }
                    }
                }
                Some(None) => return,
                None => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    self.node.spin_once(SPIN_SLICE);
                }
            }
        }
    }

    /// True when every joint has been observed within tolerance of its target.
    ///
    /// `false` when a joint has not been observed at all: absence of evidence
    /// is not settlement.
    fn observed_settled(&self) -> bool {
        self.ramps
            .iter()
            .zip(&self.observed)
            .all(|(ramp, observed)| match observed {
                Some(position) => (position - ramp.target).abs() < self.settle_tolerance,
                None => false,
            })
    }

    /// One step. Returns a terminal outcome when the motion ends.
    fn tick(&mut self) -> Step {
        self.drain_joint_state();

        let Phase::Running(index) = self.phase else {
            return Step::Idle;
        };

        let now = Instant::now();
        let dt = now.duration_since(self.last_tick).as_secs_f64().min(0.25);
        self.last_tick = now;

        for ramp in &mut self.ramps {
            ramp.advance(dt);
        }
        if !self.publish() {
            self.phase = Phase::Done;
            return Step::Faulted;
        }

        if !self.announced_moving {
            self.announced_moving = true;
            return Step::Moving;
        }

        if self
            .started_at
            .is_some_and(|start| now.duration_since(start) > MOTION_DEADLINE)
        {
            self.phase = Phase::Done;
            return Step::Faulted;
        }

        let commanded = self.ramps.iter().all(Ramp::commanded_to_target);
        if !commanded {
            self.settled_since = None;
            return Step::Idle;
        }

        if self.observed_settled() {
            match self.settled_since {
                Some(since) if now.duration_since(since) >= SETTLE_HOLD => {
                    if self.stop_requested {
                        self.phase = Phase::Done;
                        return Step::Stopped;
                    }
                    let next = index + 1;
                    if next < self.waypoints.len() {
                        for (ramp, target) in self.ramps.iter_mut().zip(&self.waypoints[next]) {
                            ramp.target = *target;
                        }
                        self.phase = Phase::Running(next);
                        self.settled_since = None;
                        return Step::Idle;
                    }
                    self.phase = Phase::Done;
                    return Step::Arrived;
                }
                Some(_) => {}
                None => self.settled_since = Some(now),
            }
        } else {
            self.settled_since = None;
        }
        Step::Idle
    }

    /// The observed joint positions, for the demo's own reporting.
    fn observed_positions(&self) -> Vec<Option<f64>> {
        self.observed.clone()
    }
}

/// What one step of a machine produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Idle,
    Moving,
    Arrived,
    Stopped,
    Faulted,
}

/// The conveyor's ROS transport.
pub struct ConveyorRosBackend {
    machine: JointMachine,
    next_id: u64,
    live: Option<ConveyorOperationId>,
    shutdown: bool,
}

impl ConveyorRosBackend {
    /// Starts the transport for the world's `conveyor_01` model.
    pub fn start() -> Result<Self, r2r::Error> {
        Ok(Self {
            machine: JointMachine::new(
                "kern_conveyor_bridge",
                "",
                &[("belt", "/conveyor_01/belt_cmd", 0.2)],
                "/conveyor_01/joint_state",
                BELT_SETTLE_TOLERANCE_M,
            )?,
            next_id: 1,
            live: None,
            shutdown: false,
        })
    }

    /// The observed belt position, metres, when one has been seen.
    pub fn observed_position_m(&self) -> Option<f64> {
        self.machine.observed_positions().first().copied().flatten()
    }
}

impl ConveyorBackend for ConveyorRosBackend {
    fn declaration(&self) -> ConveyorDeclaration {
        ConveyorDeclaration {
            // The rate limit is applied to the setpoint, which is the only
            // place a position controller can be bounded.
            speed_control: SpeedControl::RateLimited,
            confirms_cancellation: true,
            reports_terminal_results: true,
        }
    }

    fn start_transfer(&mut self, request: &ConveyorMove) -> StartTransfer {
        if self.shutdown || self.machine.busy() {
            return StartTransfer::Rejected {
                reason: kern_execution::RejectionReason::Busy,
            };
        }
        if !self
            .machine
            .start(vec![vec![request.target_m]], &[request.max_speed_m_s])
        {
            // Publishing failed outright: nothing reached the controller.
            return StartTransfer::Rejected {
                reason: kern_execution::RejectionReason::Unavailable,
            };
        }
        let operation = ConveyorOperationId::from_u64(self.next_id);
        self.next_id += 1;
        self.live = Some(operation);
        StartTransfer::Accepted { operation }
    }

    fn stop(&mut self, operation: ConveyorOperationId) -> ConveyorStop {
        if self.live != Some(operation) {
            return ConveyorStop::AlreadyTerminal;
        }
        if self.machine.hold() {
            ConveyorStop::Accepted
        } else {
            ConveyorStop::Unknown
        }
    }

    fn poll(&mut self) -> ConveyorPoll {
        let Some(operation) = self.live else {
            return ConveyorPoll::Idle;
        };
        match self.machine.tick() {
            Step::Idle => ConveyorPoll::Idle,
            Step::Moving => ConveyorPoll::Event(ConveyorEvent::Moving { operation }),
            Step::Arrived => {
                self.live = None;
                ConveyorPoll::Event(ConveyorEvent::Arrived { operation })
            }
            Step::Stopped => {
                self.live = None;
                ConveyorPoll::Event(ConveyorEvent::Stopped { operation })
            }
            Step::Faulted => {
                self.live = None;
                ConveyorPoll::Event(ConveyorEvent::Faulted { operation })
            }
        }
    }

    fn shutdown(&mut self) {
        self.shutdown = true;
    }
}

/// The arm's ROS transport.
pub struct ArmRosBackend {
    machine: JointMachine,
    next_id: u64,
    live: Option<ArmOperationId>,
    shutdown: bool,
    joint_rate: f64,
}

impl ArmRosBackend {
    /// Starts the transport for the world's `robotic_arm_01` model.
    pub fn start() -> Result<Self, r2r::Error> {
        Ok(Self {
            machine: JointMachine::new(
                "kern_arm_bridge",
                "",
                &[
                    ("shoulder", "/robotic_arm_01/shoulder_cmd", 0.35),
                    ("elbow", "/robotic_arm_01/elbow_cmd", 0.35),
                ],
                "/robotic_arm_01/joint_state",
                ARM_SETTLE_TOLERANCE_RAD,
            )?,
            next_id: 1,
            live: None,
            shutdown: false,
            joint_rate: 0.35,
        })
    }

    /// The observed joint angles, radians, when they have been seen.
    pub fn observed_joints(&self) -> Vec<Option<f64>> {
        self.machine.observed_positions()
    }
}

impl ArmBackend for ArmRosBackend {
    fn declaration(&self) -> ArmDeclaration {
        ArmDeclaration {
            // The backend commands exactly the two poses it is handed and
            // nothing between them but the ramp between the two.
            workspace_control: WorkspaceControl::ConfiguredPosesOnly,
            confirms_cancellation: true,
            reports_terminal_results: true,
        }
    }

    fn start_motion(&mut self, motion: &ArmMotion) -> StartMotion {
        if self.shutdown || self.machine.busy() {
            return StartMotion::Rejected {
                reason: kern_execution::RejectionReason::Busy,
            };
        }
        // Pick, then place: two waypoints, both from trusted configuration.
        let waypoints = vec![
            vec![motion.source.shoulder_rad, motion.source.elbow_rad],
            vec![
                motion.destination.shoulder_rad,
                motion.destination.elbow_rad,
            ],
        ];
        if !self
            .machine
            .start(waypoints, &[self.joint_rate, self.joint_rate])
        {
            return StartMotion::Rejected {
                reason: kern_execution::RejectionReason::Unavailable,
            };
        }
        let operation = ArmOperationId::from_u64(self.next_id);
        self.next_id += 1;
        self.live = Some(operation);
        StartMotion::Accepted { operation }
    }

    fn stop(&mut self, operation: ArmOperationId) -> ArmStop {
        if self.live != Some(operation) {
            return ArmStop::AlreadyTerminal;
        }
        if self.machine.hold() {
            ArmStop::Accepted
        } else {
            ArmStop::Unknown
        }
    }

    fn poll(&mut self) -> ArmPoll {
        let Some(operation) = self.live else {
            return ArmPoll::Idle;
        };
        match self.machine.tick() {
            Step::Idle => ArmPoll::Idle,
            Step::Moving => ArmPoll::Event(ArmEvent::Moving { operation }),
            Step::Arrived => {
                self.live = None;
                ArmPoll::Event(ArmEvent::Placed { operation })
            }
            Step::Stopped => {
                self.live = None;
                ArmPoll::Event(ArmEvent::Stopped { operation })
            }
            Step::Faulted => {
                self.live = None;
                ArmPoll::Event(ArmEvent::Faulted { operation })
            }
        }
    }

    fn shutdown(&mut self) {
        self.shutdown = true;
    }
}
