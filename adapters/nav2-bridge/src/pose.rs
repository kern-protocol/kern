//! Reading where the robot actually is, so the planner does not have to guess.
//!
//! # Why this is a node of its own
//!
//! The obvious place for this subscription is the Nav2 worker, which already
//! owns a long-lived node. It cannot go there, because of *when* the worker
//! exists. `kern-ai-demo` deliberately creates no action client and no
//! publisher until policy has authorized something — that ordering is what lets
//! a denied run say "nothing was sent" as a fact about the process rather than
//! as a claim about a check. An observation is needed strictly earlier, before
//! inference, so it needs a node that exists earlier.
//!
//! So this is a second node, and a deliberately impoverished one: **one
//! subscription and nothing else**. No action client, no publisher, no service,
//! no parameter. It can read a topic and it can do nothing else, which keeps the
//! denied-path property intact in precise terms — a refused proposal still
//! cannot publish a speed limit or send a goal, because at the moment of refusal
//! there is still no publisher and no action client anywhere in the process.
//!
//! It is started once and retained for the life of the process. It is not
//! created per inference.
//!
//! # What it produces
//!
//! A [`WorldObservation`], which is planning context and never authority. The
//! conversion from ROS floats to Kern integers happens here, at the boundary,
//! using the checked conversions in `kern_ai::observation` — so a NaN from a
//! diverged localizer becomes an explicit "position unknown" rather than a
//! number.
//!
//! # What it does not claim
//!
//! That the robot is where this says. It is a localization estimate, with
//! localization error, sensor error, and latency, and the robot may have moved
//! since. The age accompanies every reading for exactly that reason.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use futures::future::FutureExt;
use futures::stream::StreamExt;
use r2r::geometry_msgs::msg::PoseWithCovarianceStamped;
use r2r::{Context, Node, QosProfile};

use kern_ai::observation::{
    meters_to_millimeters, quaternion_yaw_radians, radians_to_millidegrees, resolve,
    ConversionError, ObservationSnapshot, PoseObservation, WorldObservation,
};
use kern_core::DeviceId;

/// One spin slice for the observer thread.
const SPIN_SLICE: Duration = Duration::from_millis(20);

/// How often to ask the graph whether anyone publishes the topic.
const GRAPH_CHECK_INTERVAL: Duration = Duration::from_millis(250);

/// The default localization topic.
///
/// AMCL's estimate, in the `map` frame — which is the frame the demo's named
/// places are given in. `/odom` is the alternative and is deliberately not the
/// default: it is smooth and never stale, but it drifts without bound and is in
/// a different frame, so an odometry reading compared against a map-frame
/// destination is a comparison of two different things.
pub const DEFAULT_POSE_TOPIC: &str = "/amcl_pose";

/// How old a reading may be before the host declines to plan on it.
///
/// Generous on purpose. AMCL publishes on update rather than on a timer, so a
/// stationary, well-localized robot can legitimately go seconds without a new
/// message. Too tight a bound here would report a perfectly good pose as stale
/// precisely when the robot is sitting still waiting for an instruction, which
/// is the most common moment to ask.
pub const DEFAULT_MAX_AGE_MS: u64 = 5_000;

/// How long `start` waits for the observer thread to report that its node and
/// subscription exist.
const STARTUP_TIMEOUT: Duration = Duration::from_millis(5_000);

/// The observer could not be started.
///
/// Its own type rather than a new variant on
/// [`BridgeError`](crate::ros::BridgeError): the Nav2 worker's failure modes are
/// frozen and describe a different subsystem, and widening a public enum that
/// callers match on is a change this feature has no reason to make.
#[derive(Debug)]
pub enum PoseObserverError {
    /// The thread could not be spawned.
    Spawn(std::io::Error),
    /// The ROS context, node, or subscription could not be created.
    ///
    /// Carries the error's rendering rather than the error, because it is
    /// produced on the observer thread and `r2r::Error` does not cross it.
    Ros(String),
    /// The thread did not report readiness inside [`STARTUP_TIMEOUT`].
    Timeout,
}

impl std::fmt::Display for PoseObserverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(error) => write!(f, "observer thread: {error}"),
            Self::Ros(detail) => write!(f, "ROS: {detail}"),
            Self::Timeout => f.write_str("the observer did not start in time"),
        }
    }
}

impl std::error::Error for PoseObserverError {}

/// Observer configuration.
#[derive(Clone, Debug)]
pub struct PoseObserverConfig {
    /// ROS node name.
    pub node_name: String,
    /// ROS namespace.
    pub namespace: String,
    /// The topic carrying the localization estimate.
    pub topic: String,
    /// The oldest reading the host will plan on.
    pub max_age_ms: u64,
}

impl Default for PoseObserverConfig {
    fn default() -> Self {
        Self {
            node_name: String::from("kern_pose_observer"),
            namespace: String::new(),
            topic: String::from(DEFAULT_POSE_TOPIC),
            max_age_ms: DEFAULT_MAX_AGE_MS,
        }
    }
}

/// The newest reading, and when this host received it.
///
/// The receipt instant is taken from the host's own monotonic clock rather than
/// from the message header. A header stamp is written by whichever machine
/// published it, against a clock this process does not control and may not
/// share; using it would make freshness depend on clock synchronisation that
/// nothing here establishes. What the host can honestly say is how long ago the
/// bytes arrived, so that is what it says.
#[derive(Clone, Copy, Debug)]
struct Reading {
    pose: PoseObservation,
    received: Instant,
}

/// State shared between the observer thread and its readers.
#[derive(Debug)]
struct Shared {
    /// The newest usable reading, if any has ever arrived.
    latest: Mutex<Option<Reading>>,
    /// The most recent conversion failure, if the newest message was unusable.
    ///
    /// Kept separately from `latest` so an unusable message does not erase a
    /// good earlier one: the honest report is then "here is a reading, and it
    /// is this old", and staleness handles the rest.
    last_error: Mutex<Option<ConversionError>>,
    /// False once the observer thread has stopped, for any reason.
    alive: AtomicBool,
    /// True once any publisher for the topic has been seen on the graph.
    ///
    /// Latching rather than instantaneous: a publisher that appeared and went
    /// away is still evidence that the topic exists and is worth waiting for,
    /// and it distinguishes "the localizer is silent" from "the localizer is
    /// not running", which send an operator to different places.
    publisher_seen: AtomicBool,
}

/// A read-only view of where the robot is.
pub struct PoseObserver {
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    max_age_ms: u64,
}

impl PoseObserver {
    /// Starts the observer thread and its single-subscription node.
    ///
    /// # Why the node is created on the worker thread
    ///
    /// `r2r`'s node and subscription stream are not `Send`, so neither can be
    /// created here and moved into the thread — the Nav2 worker in `ros.rs`
    /// creates its node inside `run` for exactly this reason. The consequence is
    /// that a creation failure happens somewhere the caller cannot see it, so
    /// the thread reports readiness back over a channel and this function waits
    /// for that report. A host that cannot observe learns so here, rather than
    /// discovering it as a silent absence of readings later.
    ///
    /// # Errors
    ///
    /// When the thread cannot be spawned, the ROS context, node, or
    /// subscription cannot be created, or the thread does not report readiness
    /// in time. A host that cannot observe reports that it cannot observe; it
    /// does not proceed with an assumed position.
    pub fn start(config: PoseObserverConfig) -> Result<Self, PoseObserverError> {
        let shared = Arc::new(Shared {
            latest: Mutex::new(None),
            last_error: Mutex::new(None),
            alive: AtomicBool::new(true),
            publisher_seen: AtomicBool::new(false),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let max_age_ms = config.max_age_ms;

        let (ready_tx, ready_rx) = sync_channel::<Result<(), String>>(1);
        let thread_shared = Arc::clone(&shared);
        let thread_stop = Arc::clone(&stop);

        let worker = std::thread::Builder::new()
            .name(String::from("kern-pose-observer"))
            .spawn(move || {
                let guard = Arc::clone(&thread_shared);
                // A panic here must never cross into Kern, and must never leave
                // a stale reading looking live: the thread is marked dead and
                // every later observation says the source is unavailable.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let (mut node, latched, live) = match Context::create()
                        .and_then(|context| {
                            Node::create(context, &config.node_name, &config.namespace)
                        })
                        .and_then(|mut node| {
                            // Two subscriptions to one topic, because a single
                            // durability setting cannot match both kinds of
                            // publisher, and getting it wrong fails silently.
                            //
                            // TRANSIENT_LOCAL is what receives a *latched*
                            // sample. AMCL publishes `amcl_pose` on update
                            // rather than on a timer, so a stationary robot's
                            // only pose may have been published long ago and
                            // retained by the publisher. A VOLATILE subscriber
                            // matches such a publisher perfectly well and is
                            // simply never given the retained sample: it waits
                            // forever for a message that already happened.
                            // That is the defect this pair fixes.
                            //
                            // The volatile subscription stays because the
                            // reverse mismatch is worse: a TRANSIENT_LOCAL
                            // subscriber is *incompatible* with a VOLATILE
                            // publisher and matches nothing at all, so a
                            // deployment whose localizer publishes volatile
                            // would go blind if this were the only one.
                            //
                            // Neither can produce a wrong pose. The worst a
                            // redundant delivery does is hand over the same
                            // reading twice, and the newest wins.
                            let latched = node.subscribe::<PoseWithCovarianceStamped>(
                                &config.topic,
                                QosProfile::default().transient_local(),
                            )?;
                            let live = node.subscribe::<PoseWithCovarianceStamped>(
                                &config.topic,
                                QosProfile::default(),
                            )?;
                            Ok((node, latched, live))
                        }) {
                        Ok(parts) => {
                            let _ = ready_tx.send(Ok(()));
                            parts
                        }
                        Err(error) => {
                            let _ = ready_tx.send(Err(error.to_string()));
                            return;
                        }
                    };
                    run(
                        &mut node,
                        Box::pin(latched),
                        Box::pin(live),
                        &config.topic,
                        &thread_shared,
                        &thread_stop,
                    );
                }));
                guard.alive.store(false, Ordering::SeqCst);
            })
            .map_err(PoseObserverError::Spawn)?;

        match ready_rx.recv_timeout(STARTUP_TIMEOUT) {
            Ok(Ok(())) => Ok(Self {
                shared,
                stop,
                worker: Some(worker),
                max_age_ms,
            }),
            Ok(Err(detail)) => {
                let _ = worker.join();
                Err(PoseObserverError::Ros(detail))
            }
            Err(_) => {
                stop.store(true, Ordering::SeqCst);
                let _ = worker.join();
                Err(PoseObserverError::Timeout)
            }
        }
    }

    /// What the host currently knows about `device`'s position.
    ///
    /// Never blocks on ROS and never waits for a message. It reports what has
    /// already arrived, or says explicitly why nothing usable has.
    pub fn observe(&self, device: &DeviceId) -> WorldObservation {
        resolve(device.clone(), self.snapshot(), self.max_age_ms)
    }

    /// Everything known right now, in the form the shared resolver takes.
    ///
    /// The age is computed here, against the host's own monotonic clock, at the
    /// moment of asking — a reading does not carry an age, it acquires one when
    /// somebody wants to know.
    fn snapshot(&self) -> ObservationSnapshot {
        let reading = self.shared.latest.lock().ok().and_then(|guard| *guard);
        let pose = reading.map(|reading| {
            // Saturating: a monotonic clock cannot run backwards, but a wrong
            // answer here must not be a panic on a planning path.
            let age_ms = reading.received.elapsed().as_millis().min(u64::MAX as u128) as u64;
            PoseObservation::new(
                reading.pose.x_mm(),
                reading.pose.y_mm(),
                reading.pose.yaw_mdeg(),
                age_ms,
            )
        });
        ObservationSnapshot {
            pose,
            last_error: self.shared.last_error.lock().ok().and_then(|guard| *guard),
            publisher_seen: self.shared.publisher_seen.load(Ordering::SeqCst),
            source_alive: self.shared.alive.load(Ordering::SeqCst),
        }
    }

    /// The freshness bound this observer applies.
    pub fn max_age_ms(&self) -> u64 {
        self.max_age_ms
    }

    /// Whether a publisher for the topic has been discovered.
    pub fn publisher_seen(&self) -> bool {
        self.shared.publisher_seen.load(Ordering::SeqCst)
    }

    /// Waits, bounded, for a reading this host would actually plan on.
    ///
    /// Returns as soon as one is usable rather than sleeping out the whole
    /// deadline, and returns early when waiting has become pointless — a dead
    /// source will not start producing.
    ///
    /// A reading that arrives already too old does **not** end the wait. That
    /// is the case where a latched sample is delivered on subscription match
    /// and is older than the freshness bound: the honest thing is to keep
    /// listening for a live one until the deadline, and only then report the
    /// staleness.
    pub fn await_first(&self, deadline: Duration) -> ObservationReadiness {
        let until = Instant::now() + deadline;
        loop {
            let snapshot = self.snapshot();
            if !snapshot.source_alive {
                return ObservationReadiness::SourceStopped;
            }
            if snapshot
                .pose
                .is_some_and(|pose| pose.is_fresh_within(self.max_age_ms))
            {
                return ObservationReadiness::Observed;
            }
            if Instant::now() >= until {
                return if snapshot.pose.is_some() {
                    ObservationReadiness::OnlyStale
                } else if snapshot.last_error.is_some() {
                    ObservationReadiness::OnlyUnusable
                } else if snapshot.publisher_seen {
                    ObservationReadiness::PublisherSilent
                } else {
                    ObservationReadiness::NoPublisher
                };
            }
            std::thread::sleep(SPIN_SLICE);
        }
    }
}

/// How a bounded wait for a first reading ended.
///
/// Reported so a demo transcript records what the host was actually up against,
/// rather than only that it ended up with nothing. Every variant other than
/// [`Observed`](Self::Observed) leaves the observation explicitly unavailable;
/// none of them causes a position to be assumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationReadiness {
    /// A reading arrived and is within the freshness bound.
    Observed,
    /// No publisher for the topic was ever discovered.
    NoPublisher,
    /// A publisher exists, but sent nothing inside the deadline.
    PublisherSilent,
    /// Readings arrived and none could be represented in Kern's units.
    OnlyUnusable,
    /// A reading arrived but is older than the freshness bound.
    OnlyStale,
    /// The observer stopped while waiting.
    SourceStopped,
}

impl std::fmt::Display for ObservationReadiness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Observed => "a pose observation arrived",
            Self::NoPublisher => "no publisher for the pose topic was discovered",
            Self::PublisherSilent => "a publisher exists but sent no pose in time",
            Self::OnlyUnusable => "every pose received was unusable",
            Self::OnlyStale => "the only pose available is older than the freshness bound",
            Self::SourceStopped => "the observer stopped",
        })
    }
}

impl Drop for PoseObserver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// The observer loop: spin, take whatever arrived, convert it, store it.
fn run(
    node: &mut Node,
    mut latched: Pin<Box<impl futures::Stream<Item = PoseWithCovarianceStamped> + ?Sized>>,
    mut live: Pin<Box<impl futures::Stream<Item = PoseWithCovarianceStamped> + ?Sized>>,
    topic: &str,
    shared: &Arc<Shared>,
    stop: &Arc<AtomicBool>,
) {
    let mut last_graph_check = Instant::now() - GRAPH_CHECK_INTERVAL;
    while !stop.load(Ordering::SeqCst) {
        node.spin_once(SPIN_SLICE);

        // Whether anyone publishes this topic at all. Asked on the observer
        // thread because that is where the node lives, and periodically rather
        // than every slice because it is a graph query, not a message read.
        if last_graph_check.elapsed() >= GRAPH_CHECK_INTERVAL
            && !shared.publisher_seen.load(Ordering::SeqCst)
        {
            if let Ok(publishers) = node.get_publishers_info_by_topic(topic, false) {
                if !publishers.is_empty() {
                    shared.publisher_seen.store(true, Ordering::SeqCst);
                }
            }
            last_graph_check = Instant::now();
        }

        // Drain both, keeping only the newest: a planner wants the current
        // position, not a history. One stream ending means its subscription is
        // gone; the other may still deliver, so it is not fatal on its own.
        let latched_open = drain(&mut latched, shared);
        let live_open = drain(&mut live, shared);
        if !latched_open && !live_open {
            return;
        }
    }
}

/// Reads whatever is queued on one subscription. Returns false once it ends.
fn drain(
    subscription: &mut Pin<Box<impl futures::Stream<Item = PoseWithCovarianceStamped> + ?Sized>>,
    shared: &Arc<Shared>,
) -> bool {
    loop {
        match subscription.next().now_or_never() {
            Some(Some(message)) => {
                // A delivered message is itself proof that a publisher exists,
                // and it arrives before the periodic graph query would notice.
                shared.publisher_seen.store(true, Ordering::SeqCst);
                apply(shared, &message);
            }
            Some(None) => return false,
            None => return true,
        }
    }
}

/// Converts one message and records the outcome.
fn apply(shared: &Arc<Shared>, message: &PoseWithCovarianceStamped) {
    match convert(message) {
        Ok(pose) => {
            if let Ok(mut latest) = shared.latest.lock() {
                *latest = Some(Reading {
                    pose,
                    received: Instant::now(),
                });
            }
            if let Ok(mut error) = shared.last_error.lock() {
                *error = None;
            }
        }
        Err(error) => {
            // The bad reading is discarded, not repaired and not blended with
            // the previous one. An earlier good reading stays exactly as old as
            // it actually is.
            if let Ok(mut last) = shared.last_error.lock() {
                *last = Some(error);
            }
        }
    }
}

/// One ROS pose, in Kern's integer units, or the reason it is not usable.
///
/// Every float leaves the pipeline here. Nothing downstream of this function
/// sees an `f64`, which is what makes NaN and infinity a boundary problem with
/// one place to solve it rather than a class of bug that reappears wherever a
/// coordinate is touched.
fn convert(message: &PoseWithCovarianceStamped) -> Result<PoseObservation, ConversionError> {
    let position = &message.pose.pose.position;
    let orientation = &message.pose.pose.orientation;

    let x_mm = meters_to_millimeters(position.x)?;
    let y_mm = meters_to_millimeters(position.y)?;
    let yaw = quaternion_yaw_radians(orientation.x, orientation.y, orientation.z, orientation.w)
        .ok_or(ConversionError::NotANumber)?;
    let yaw_mdeg = radians_to_millidegrees(yaw)?;

    // Age is filled in by `observe`, against the receipt instant. A reading
    // has no age at the moment it is read.
    Ok(PoseObservation::new(x_mm, y_mm, yaw_mdeg, 0))
}
