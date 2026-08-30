//! Everything that touches `r2r`, and nothing that does not.
//!
//! The worker owns the ROS node, the `NavigateToPose` action client, and the
//! speed-limit publisher. It answers commands with a deadline and never blocks
//! forever: a deadline that elapses is reported as ambiguity, because a goal
//! whose fate is unknown may be a goal that is running.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use futures::future::FutureExt;
use futures::stream::StreamExt;
use r2r::nav2_msgs::action::NavigateToPose;
use r2r::nav2_msgs::msg::SpeedLimit;
use r2r::{Context, Node, QosProfile};

use kern_execution_nav2::backend::{
    BackendEvent, CancelSend, Nav2Goal, Nav2OperationId, SendGoal, SpeedLimitOutcome,
};

use crate::{event_for_status, rejection_for, Command, Shared, NO_SPEED_LIMIT};

/// How long to wait for the action server before declaring it absent.
const SERVER_WAIT: Duration = Duration::from_millis(1_500);
/// How long to wait for a goal response before calling the send ambiguous.
const GOAL_RESPONSE_TIMEOUT: Duration = Duration::from_millis(1_500);
/// One spin slice.
const SPIN_SLICE: Duration = Duration::from_millis(10);
/// How long to wait for a speed-limit subscriber before declaring the bound
/// undeliverable.
const SUBSCRIBER_WAIT: Duration = Duration::from_millis(1_000);
/// How often the worker re-checks that the action server is still there.
const AVAILABILITY_INTERVAL: Duration = Duration::from_millis(500);
/// How long one availability check may spin before it counts as a miss.
const AVAILABILITY_BUDGET: Duration = Duration::from_millis(200);
/// Consecutive misses before the link is called lost.
///
/// One slow check is not a dead server. On a loaded machine a single poll can
/// exceed its budget while Nav2 is perfectly healthy, and reporting that as a
/// disconnect turns every hiccup into an execution Kern says it can no longer
/// see. Debouncing is a transport judgement and belongs here, not in Kern.
const AVAILABILITY_MISSES: u32 = 3;

/// Worker configuration.
#[derive(Clone, Debug)]
pub struct BridgeConfig {
    /// ROS node name.
    pub node_name: String,
    /// ROS namespace.
    pub namespace: String,
    /// The `NavigateToPose` action name.
    pub action_name: String,
    /// The topic `nav2_controller` reads speed limits from.
    pub speed_limit_topic: String,
    /// Bound on the event queue.
    pub queue_capacity: usize,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            node_name: String::from("kern_nav2_bridge"),
            namespace: String::new(),
            action_name: String::from("/navigate_to_pose"),
            speed_limit_topic: String::from(crate::SPEED_LIMIT_TOPIC),
            queue_capacity: 64,
        }
    }
}

/// The bridge could not be started.
#[derive(Debug)]
pub enum BridgeError {
    /// The ROS context or node could not be created.
    Ros(r2r::Error),
    /// The worker thread could not be spawned.
    Spawn(std::io::Error),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ros(error) => write!(f, "ROS: {error}"),
            Self::Spawn(error) => write!(f, "worker thread: {error}"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// The terminal action statuses this adapter reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultStatus {
    /// `SUCCEEDED`.
    Succeeded,
    /// `ABORTED`.
    Aborted,
    /// `CANCELED`.
    Canceled,
    /// Anything else: not terminal as far as this adapter is concerned.
    Unknown,
}

impl From<r2r::GoalStatus> for ResultStatus {
    fn from(status: r2r::GoalStatus) -> Self {
        match status {
            r2r::GoalStatus::Succeeded => Self::Succeeded,
            r2r::GoalStatus::Aborted => Self::Aborted,
            r2r::GoalStatus::Canceled => Self::Canceled,
            _ => Self::Unknown,
        }
    }
}

/// Why a goal provably did not start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionKind {
    /// No action server was there, so nothing was transmitted.
    ServerAbsent,
    /// The server received the goal and refused it.
    GoalRejected,
}

/// The action result future, which resolves once Nav2 reports a terminal status.
type ResultFuture =
    Pin<Box<dyn Future<Output = r2r::Result<(r2r::GoalStatus, NavigateToPose::Result)>>>>;
/// The action feedback stream.
type FeedbackStream = Pin<Box<dyn futures::Stream<Item = NavigateToPose::Feedback>>>;

/// One goal the worker is following.
struct Tracked {
    operation: Nav2OperationId,
    handle: r2r::ActionClientGoal<NavigateToPose::Action>,
    result: ResultFuture,
    feedback: FeedbackStream,
    reported_feedback: bool,
}

/// Starts the worker thread.
///
/// A panic anywhere inside is caught here and turned into
/// `worker_failed`, which the Kern side reads as lost events. A panic must never
/// cross into Kern, and a dead worker must never look like a machine result.
pub fn spawn_worker(
    config: BridgeConfig,
    shared: Arc<Shared>,
    inbox: Receiver<Command>,
) -> Result<JoinHandle<()>, BridgeError> {
    std::thread::Builder::new()
        .name(String::from("kern-nav2-worker"))
        .spawn(move || {
            let guard = Arc::clone(&shared);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run(config, Arc::clone(&shared), inbox);
            }));
            if outcome.is_err() {
                guard.worker_failed.store(true, Ordering::SeqCst);
            }
            guard.worker_alive.store(false, Ordering::SeqCst);
            guard.connected.store(false, Ordering::SeqCst);
        })
        .map_err(BridgeError::Spawn)
}

fn run(config: BridgeConfig, shared: Arc<Shared>, inbox: Receiver<Command>) {
    let context = match Context::create() {
        Ok(context) => context,
        Err(_) => return,
    };
    let mut node = match Node::create(context, &config.node_name, &config.namespace) {
        Ok(node) => node,
        Err(_) => return,
    };
    let client = match node.create_action_client::<NavigateToPose::Action>(&config.action_name) {
        Ok(client) => client,
        Err(_) => return,
    };
    let speed_limit = match node
        .create_publisher::<SpeedLimit>(&config.speed_limit_topic, QosProfile::default())
    {
        Ok(publisher) => publisher,
        Err(_) => return,
    };

    let mut tracked: Vec<Tracked> = Vec::new();
    let mut last_check = Instant::now() - AVAILABILITY_INTERVAL;
    let mut misses: u32 = 0;

    loop {
        match inbox.recv_timeout(SPIN_SLICE) {
            Ok(Command::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(Command::SpeedLimit { limit_m_s, reply }) => {
                let outcome = publish_speed_limit(&mut node, &speed_limit, limit_m_s);
                let _ = reply.try_send(outcome);
            }
            Ok(Command::SendGoal { goal, reply }) => {
                let outcome = send_goal(&mut node, &client, &goal, &mut tracked);
                let _ = reply.try_send(outcome);
            }
            Ok(Command::Cancel { operation, reply }) => {
                let outcome = cancel(&mut node, &tracked, operation);
                let _ = reply.try_send(outcome);
            }
            Err(RecvTimeoutError::Timeout) => {}
        }

        node.spin_once(SPIN_SLICE);
        drain(&shared, &mut tracked);

        if last_check.elapsed() >= AVAILABILITY_INTERVAL {
            if server_is_available(&mut node, &client) {
                misses = 0;
            } else {
                misses = misses.saturating_add(1);
            }
            shared
                .connected
                .store(misses < AVAILABILITY_MISSES, Ordering::SeqCst);
            last_check = Instant::now();
        }
    }

    // Leave the controller as it was found.
    let _ = publish_speed_limit(&mut node, &speed_limit, NO_SPEED_LIMIT);
}

/// Whether the action server is reachable right now.
///
/// The future from `is_available` resolves only once a server is there, so a
/// budget that elapses means absent. Creating the future proves nothing on its
/// own — an earlier version of this file checked exactly that and reported a
/// killed server as healthy, which is a false claim that Kern can still see an
/// operation.
fn server_is_available(
    node: &mut Node,
    client: &r2r::ActionClient<NavigateToPose::Action>,
) -> bool {
    let Ok(waiting) = Node::is_available(client) else {
        return false;
    };
    let mut waiting = Box::pin(waiting);
    matches!(
        await_with_spin(node, &mut waiting, AVAILABILITY_BUDGET),
        Some(Ok(()))
    )
}

/// Publishes a speed limit, refusing to call it applied when nothing is
/// listening.
///
/// # Why the subscriber check exists
///
/// A ROS publisher accepts a message whether or not any subscriber has been
/// discovered yet, and an unmatched publish is silently dropped. Reporting that
/// as `Applied` would let a goal run with an authorized bound that never reached
/// the controller — the one failure this phase forbids outright. A run of the
/// integration harness caught exactly that, which is why this check is here.
///
/// # What it proves, and what it does not
///
/// That *a* subscriber to the configured topic exists and that the message was
/// handed to a reliable publisher. Not that the subscriber is
/// `controller_server`, and not that any wheel turned more slowly: the topic
/// name is configuration, and the bound is a command to a controller.
fn publish_speed_limit(
    node: &mut Node,
    publisher: &r2r::Publisher<SpeedLimit>,
    limit_m_s: f64,
) -> SpeedLimitOutcome {
    match publisher.get_inter_process_subscription_count() {
        Ok(0) => {
            let Ok(waiting) = publisher.wait_for_inter_process_subscribers() else {
                return SpeedLimitOutcome::Unknown;
            };
            let mut waiting = Box::pin(waiting);
            if await_with_spin(node, &mut waiting, SUBSCRIBER_WAIT).is_none() {
                // Nobody is listening, so the bound cannot be enforced.
                return SpeedLimitOutcome::NotDelivered;
            }
        }
        Ok(_) => {}
        Err(_) => return SpeedLimitOutcome::Unknown,
    }

    let message = SpeedLimit {
        header: r2r::std_msgs::msg::Header::default(),
        // Absolute, not a percentage: Kern's bound is in m/s, and a percentage
        // of an unknown maximum is not a bound.
        percentage: false,
        speed_limit: limit_m_s,
    };
    match publisher.publish(&message) {
        Ok(()) => SpeedLimitOutcome::Applied,
        Err(_) => SpeedLimitOutcome::NotDelivered,
    }
}

fn send_goal(
    node: &mut Node,
    client: &r2r::ActionClient<NavigateToPose::Action>,
    goal: &Nav2Goal,
    tracked: &mut Vec<Tracked>,
) -> SendGoal {
    // Absence is provable: no server, nothing transmitted.
    match Node::is_available(client) {
        Ok(available) => {
            let mut available = Box::pin(available);
            if await_with_spin(node, &mut available, SERVER_WAIT).is_none() {
                return SendGoal::Rejected {
                    reason: rejection_for(RejectionKind::ServerAbsent),
                };
            }
        }
        Err(_) => {
            return SendGoal::Rejected {
                reason: rejection_for(RejectionKind::ServerAbsent),
            }
        }
    }

    let request = NavigateToPose::Goal {
        pose: pose_stamped(goal),
        behavior_tree: String::new(),
    };

    let pending = match client.send_goal_request(request) {
        Ok(pending) => pending,
        // The request never left: a rejection this adapter can prove.
        Err(_) => {
            return SendGoal::Rejected {
                reason: rejection_for(RejectionKind::GoalRejected),
            }
        }
    };

    let mut pending = Box::pin(pending);
    match await_with_spin(node, &mut pending, GOAL_RESPONSE_TIMEOUT) {
        Some(Ok((handle, result, feedback))) => {
            let operation = Nav2OperationId::from_uuid(*handle.uuid.as_bytes());
            tracked.push(Tracked {
                operation,
                handle,
                result: Box::pin(result),
                feedback: Box::pin(feedback),
                reported_feedback: false,
            });
            SendGoal::Accepted { operation }
        }
        // The server answered, and its answer was no.
        Some(Err(_)) => SendGoal::Rejected {
            reason: rejection_for(RejectionKind::GoalRejected),
        },
        // No answer inside the deadline. The goal may be running.
        None => SendGoal::Unknown,
    }
}

fn cancel(node: &mut Node, tracked: &[Tracked], operation: Nav2OperationId) -> CancelSend {
    let Some(entry) = tracked.iter().find(|entry| entry.operation == operation) else {
        // The worker never followed this goal, so it cannot say what became of
        // it.
        return CancelSend::Unknown;
    };

    match entry.handle.cancel() {
        Ok(pending) => {
            let mut pending = Box::pin(pending);
            match await_with_spin(node, &mut pending, GOAL_RESPONSE_TIMEOUT) {
                // Received at the action interface. Not a stopped robot.
                Some(Ok(())) => CancelSend::Accepted,
                Some(Err(_)) => CancelSend::Rejected,
                None => CancelSend::Unknown,
            }
        }
        Err(_) => CancelSend::Unknown,
    }
}

/// Moves finished work into the shared queue.
fn drain(shared: &Arc<Shared>, tracked: &mut Vec<Tracked>) {
    let mut finished = Vec::new();

    for (index, entry) in tracked.iter_mut().enumerate() {
        // First credible feedback is the only thing this adapter reads as
        // "running". Goal acceptance is not.
        if !entry.reported_feedback && entry.feedback.next().now_or_never().flatten().is_some() {
            entry.reported_feedback = true;
            shared.push(BackendEvent::Feedback {
                operation: entry.operation,
            });
        }

        if let Some(Ok((status, _result))) = entry.result.as_mut().now_or_never() {
            if let Some(event) = event_for_status(entry.operation, ResultStatus::from(status)) {
                shared.push(event);
            }
            finished.push(index);
        }
    }

    for index in finished.into_iter().rev() {
        tracked.remove(index);
    }
}

/// Polls one future while keeping the node spinning, up to a deadline.
fn await_with_spin<F: std::future::Future + Unpin>(
    node: &mut Node,
    future: &mut F,
    budget: Duration,
) -> Option<F::Output> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(output) = future.now_or_never() {
            return Some(output);
        }
        if Instant::now() >= deadline {
            return None;
        }
        node.spin_once(SPIN_SLICE);
    }
}

/// The one place a Kern goal becomes a ROS message.
pub fn pose_stamped(goal: &Nav2Goal) -> r2r::geometry_msgs::msg::PoseStamped {
    r2r::geometry_msgs::msg::PoseStamped {
        header: r2r::std_msgs::msg::Header {
            frame_id: goal.frame_id.clone(),
            ..Default::default()
        },
        pose: r2r::geometry_msgs::msg::Pose {
            position: r2r::geometry_msgs::msg::Point {
                x: goal.x_m,
                y: goal.y_m,
                z: 0.0,
            },
            orientation: r2r::geometry_msgs::msg::Quaternion {
                x: 0.0,
                y: 0.0,
                z: goal.qz,
                w: goal.qw,
            },
        },
    }
}
