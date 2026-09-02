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
    meters_to_millimeters, quaternion_yaw_radians, radians_to_millidegrees, ConversionError,
    ObservationUnavailable, PoseObservation, WorldObservation,
};
use kern_core::DeviceId;

/// One spin slice for the observer thread.
const SPIN_SLICE: Duration = Duration::from_millis(20);

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
                    let (mut node, subscription) = match Context::create()
                        .and_then(|context| {
                            Node::create(context, &config.node_name, &config.namespace)
                        })
                        .and_then(|mut node| {
                            let subscription = node.subscribe::<PoseWithCovarianceStamped>(
                                &config.topic,
                                QosProfile::default(),
                            )?;
                            Ok((node, subscription))
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
                        Box::pin(subscription),
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
    /// already arrived, or says explicitly that nothing usable has.
    pub fn observe(&self, device: &DeviceId) -> WorldObservation {
        if !self.shared.alive.load(Ordering::SeqCst) {
            return WorldObservation::unavailable(
                device.clone(),
                ObservationUnavailable::SourceUnavailable,
            );
        }

        let latest = self.shared.latest.lock().ok().and_then(|guard| *guard);

        let Some(reading) = latest else {
            // Never a reading. If the last message was unusable, say which
            // failure it was rather than the less informative "nothing yet".
            let reason = self
                .shared
                .last_error
                .lock()
                .ok()
                .and_then(|guard| *guard)
                .map_or(ObservationUnavailable::NotYetReceived, |error| {
                    ObservationUnavailable::Unrepresentable(error)
                });
            return WorldObservation::unavailable(device.clone(), reason);
        };

        // Saturating, because a monotonic clock cannot run backwards but a
        // wrong answer here must not be a panic in a planning path.
        let age_ms = reading.received.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let aged = PoseObservation::new(
            reading.pose.x_mm(),
            reading.pose.y_mm(),
            reading.pose.yaw_mdeg(),
            age_ms,
        );
        WorldObservation::fresh_within(device.clone(), aged, self.max_age_ms)
    }

    /// The freshness bound this observer applies.
    pub fn max_age_ms(&self) -> u64 {
        self.max_age_ms
    }

    /// Waits until a usable reading exists, or the deadline passes.
    ///
    /// Returns whether one arrived. A caller that does not wait is not wrong —
    /// `observe` reports the absence honestly — but a demo that has just
    /// started usually wants to give AMCL a moment rather than print "no
    /// reading yet" on every first run.
    pub fn wait_for_first(&self, deadline: Duration) -> bool {
        let until = Instant::now() + deadline;
        while Instant::now() < until {
            if self
                .shared
                .latest
                .lock()
                .ok()
                .and_then(|guard| *guard)
                .is_some()
            {
                return true;
            }
            if !self.shared.alive.load(Ordering::SeqCst) {
                return false;
            }
            std::thread::sleep(SPIN_SLICE);
        }
        false
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
    mut subscription: Pin<Box<impl futures::Stream<Item = PoseWithCovarianceStamped> + ?Sized>>,
    shared: &Arc<Shared>,
    stop: &Arc<AtomicBool>,
) {
    while !stop.load(Ordering::SeqCst) {
        node.spin_once(SPIN_SLICE);
        // Drain everything queued, keeping only the newest: a planner wants the
        // current position, not a history.
        loop {
            match subscription.next().now_or_never() {
                Some(Some(message)) => apply(shared, &message),
                // The stream ended: the subscription is gone and will not
                // resume, so the source is no longer observable.
                Some(None) => return,
                None => break,
            }
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
