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
//! So this is a second node, and a deliberately impoverished one: two
//! subscriptions and one service client. No publisher, no action client, no
//! parameter server.
//!
//! The service client is `/request_nomotion_update`, and it is worth being exact
//! about rather than glossing. AMCL publishes on filter update, so a stationary
//! robot produces no pose at all, and an observer that only listens waits out
//! its deadline and reports the retained sample as stale — honest, and useless.
//! The service asks the localizer to run an update over data it already holds.
//! It carries `std_srvs/srv/Empty` in both directions, reaches no action server,
//! no velocity topic and no controller, and cannot move the machine.
//!
//! It is therefore **not** true that this node can only read, and this module no
//! longer says so. What remains true is the property the claim was protecting: a
//! refused proposal still cannot publish a speed limit or send a goal, because
//! at the moment of refusal there is no publisher and no action client anywhere
//! in the process.
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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::future::FutureExt;
use futures::stream::StreamExt;
use r2r::geometry_msgs::msg::PoseWithCovarianceStamped;
use r2r::rosgraph_msgs::msg::Clock as ClockMsg;
use r2r::std_srvs::srv::Empty;
use r2r::{Context, Node, QosProfile};

use kern_ai::observation::{
    meters_to_millimeters, observation_age_ms, quaternion_yaw_radians, radians_to_millidegrees,
    resolve, Admission, ConversionError, ObservationSnapshot, PoseLedger, PoseObservation,
    SourceAgeError, SourceClock, SourceTime, WorldObservation,
};
use kern_core::DeviceId;

/// One spin slice for the observer thread.
const SPIN_SLICE: Duration = Duration::from_millis(20);

/// The topic simulated time arrives on.
pub const DEFAULT_CLOCK_TOPIC: &str = "/clock";

/// How stale a `/clock` sample may be, in host time, before the simulated clock
/// is treated as unavailable.
///
/// A running simulator publishes `/clock` continuously. One that has been
/// paused stops, and after this long the host can no longer say what the
/// simulated time is — which is the honest position, and the reason a paused
/// simulator produces `UNKNOWN` rather than a confidently-aged observation.
const CLOCK_SAMPLE_MAX_AGE: Duration = Duration::from_millis(2_000);

/// How far a stamp may sit from wall-clock time and still be treated as
/// wall-clock.
///
/// Used only when nothing has ever published `/clock`, which means the stack is
/// not on simulated time. A simulated stamp is billions of seconds away from
/// wall time, so this separates the two domains with an enormous margin rather
/// than a fine judgement.
const WALL_CLOCK_TOLERANCE: Duration = Duration::from_secs(60 * 60 * 24 * 30);

/// The AMCL service that asks for a localization update with no motion.
///
/// `std_srvs/srv/Empty`: it carries no data in either direction.
pub const DEFAULT_NOMOTION_SERVICE: &str = "/request_nomotion_update";

/// How long to wait for the service to appear before giving up on it.
const SERVICE_WAIT: Duration = Duration::from_millis(1_000);

/// How long one service call may take before it is abandoned.
const SERVICE_BUDGET: Duration = Duration::from_millis(1_000);

/// How often to ask AMCL to recompute while there is no usable pose.
const NOMOTION_INTERVAL: Duration = Duration::from_millis(1_500);

/// How many times to ask before concluding it is not going to help.
///
/// Bounded because this is a request to another node, and an observer that
/// cannot get a pose must become quiet rather than hammer the graph for the
/// life of the process.
const NOMOTION_MAX_ATTEMPTS: u32 = 8;

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
    /// The thread stopped before it finished starting up.
    Died,
}

impl std::fmt::Display for PoseObserverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(error) => write!(f, "observer thread: {error}"),
            Self::Ros(detail) => write!(f, "ROS: {detail}"),
            Self::Timeout => f.write_str("the observer did not start in time"),
            Self::Died => f.write_str("the observer stopped while starting up"),
        }
    }
}

impl std::error::Error for PoseObserverError {}

/// Which durability the pose subscription requests.
///
/// # Why this is a choice and not both
///
/// It was both. Two subscriptions were opened on one node — transient-local to
/// receive a publisher's retained sample, volatile to stay compatible with a
/// publisher that offers none — and on the live stack the observer then froze on
/// a single 57-second-old reading while an independent subscriber on the same
/// machine received fresh ones continuously. Two readers for one topic on one
/// node is not a construct this adapter can justify from first principles, and
/// it is not one whose delivery behaviour can be verified without a robot
/// attached. It is gone.
///
/// One subscription is enough, because the asymmetry runs the useful way: a
/// **transient-local subscriber matched to a transient-local publisher receives
/// the retained sample *and* every live one afterwards**. It is only against a
/// publisher offering volatile durability that it fails to match at all, and
/// that case is a configuration this host can be told about.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PoseDurability {
    /// Request `TRANSIENT_LOCAL`: retained sample plus everything live.
    ///
    /// The default, and correct for Nav2's AMCL, which advertises
    /// `RELIABLE`/`TRANSIENT_LOCAL`.
    #[default]
    TransientLocal,
    /// Request `VOLATILE`: live samples only.
    ///
    /// For a publisher that offers volatile durability, which a transient-local
    /// subscriber cannot match at all. The cost is that a stationary machine
    /// whose last pose was published before this process started is not seen
    /// until it publishes again — reported honestly as no reading yet, never
    /// guessed at.
    Volatile,
}

impl core::str::FromStr for PoseDurability {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "transient_local" | "transient-local" | "latched" => Ok(Self::TransientLocal),
            "volatile" | "live" => Ok(Self::Volatile),
            _ => Err(()),
        }
    }
}

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
    /// The topic carrying simulated time, when the stack uses it.
    pub clock_topic: String,
    /// Which durability the pose subscription requests.
    pub durability: PoseDurability,
    /// The AMCL no-motion update service, or `None` to never call it.
    pub nomotion_service: Option<String>,
}

impl Default for PoseObserverConfig {
    fn default() -> Self {
        Self {
            node_name: String::from("kern_pose_observer"),
            namespace: String::new(),
            topic: String::from(DEFAULT_POSE_TOPIC),
            max_age_ms: DEFAULT_MAX_AGE_MS,
            clock_topic: String::from(DEFAULT_CLOCK_TOPIC),
            durability: PoseDurability::TransientLocal,
            nomotion_service: Some(String::from(DEFAULT_NOMOTION_SERVICE)),
        }
    }
}

/// State shared between the observer thread and its readers.
#[derive(Debug)]
struct Shared {
    /// The newest usable reading, and what became of every delivery.
    ///
    /// Counting is not decoration. When an observer reports a stale pose while
    /// the topic is demonstrably live, "nothing arrived" and "something arrived
    /// and was rejected" are different faults with different fixes, and from
    /// outside the process they look identical. These counters separate them in
    /// one line of output.
    ledger: Mutex<PoseLedger>,
    /// When the observer started, so a receipt instant can be plain millis.
    started: Instant,
    /// The pose topic, for graph queries and diagnostics.
    topic: String,
    /// The oldest reading this host will plan on.
    max_age_ms: u64,
    /// The most recent conversion failure, if the newest message was unusable.
    ///
    /// Kept apart from the ledger so an unusable message does not erase a good
    /// earlier one: the honest report is then "here is a reading, and it is this
    /// old", and staleness handles the rest.
    last_error: Mutex<Option<ConversionError>>,
    /// False once the observer thread has stopped, for any reason.
    alive: AtomicBool,
    /// The newest `/clock` sample, and when this host received it.
    ///
    /// The only way to obtain a time in the same domain as a message stamp
    /// under simulated time. Deliberately not extrapolated: a paused simulator
    /// stops publishing, and inventing elapsed simulated time from host elapsed
    /// time would be exactly the cross-domain arithmetic this whole mechanism
    /// exists to avoid.
    ros_clock: Mutex<Option<(SourceTime, Instant)>>,
    /// Why the newest reading's age could not be established, if it could not.
    age_error: Mutex<Option<SourceAgeError>>,
    /// How many no-motion updates were requested, and how many were answered.
    nomotion_requested: AtomicU32,
    nomotion_answered: AtomicU32,
    /// True once the no-motion service has been found on the graph.
    nomotion_available: AtomicBool,
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
            ledger: Mutex::new(PoseLedger::new()),
            started: Instant::now(),
            topic: config.topic.clone(),
            max_age_ms: config.max_age_ms,
            last_error: Mutex::new(None),
            ros_clock: Mutex::new(None),
            age_error: Mutex::new(None),
            nomotion_requested: AtomicU32::new(0),
            nomotion_answered: AtomicU32::new(0),
            nomotion_available: AtomicBool::new(false),
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
                    let (mut node, poses, clock, nomotion) = match Context::create()
                        .and_then(|context| {
                            Node::create(context, &config.node_name, &config.namespace)
                        })
                        .and_then(|mut node| {
                            // One subscription, not two. A transient-local
                            // subscriber matched to a transient-local publisher
                            // receives the retained sample *and* every live one
                            // after it, so the retained case needs no second
                            // reader — and a second reader on the same topic and
                            // node is a construct whose delivery behaviour this
                            // adapter could not justify or verify, and which
                            // coincided with the observer freezing on one stale
                            // sample while the topic was demonstrably live.
                            let poses = node.subscribe::<PoseWithCovarianceStamped>(
                                &config.topic,
                                match config.durability {
                                    PoseDurability::TransientLocal => {
                                        QosProfile::default().transient_local()
                                    }
                                    PoseDurability::Volatile => QosProfile::default(),
                                },
                            )?;
                            // The only source of a time in the same domain as
                            // the pose stamps. Under `use_sim_time` every node
                            // in the graph reads its clock from here, so this is
                            // the domain by definition rather than by
                            // assumption. When nothing publishes it, the stack
                            // is on wall-clock time and the fallback in
                            // `source_clock` applies.
                            let clock = node.subscribe::<ClockMsg>(
                                &config.clock_topic,
                                QosProfile::default(),
                            )?;
                            // The one thing this node can do besides listen.
                            // See `request_nomotion_update` for what it is and
                            // why it does not make the observer an actuator.
                            let nomotion = match &config.nomotion_service {
                                Some(name) => Some(node.create_client::<Empty::Service>(
                                    name,
                                    QosProfile::services_default(),
                                )?),
                                None => None,
                            };
                            Ok((node, poses, clock, nomotion))
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
                        Box::pin(poses),
                        Box::pin(clock),
                        nomotion.as_ref(),
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
            // The sender was dropped without a report, which means the
            // observer thread unwound before it finished setting up. Reporting
            // that as a timeout would send a reader looking for a slow network
            // when the thread is already dead.
            Err(RecvTimeoutError::Disconnected) => {
                let _ = worker.join();
                Err(PoseObserverError::Died)
            }
            Err(RecvTimeoutError::Timeout) => {
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
        let held = self
            .shared
            .ledger
            .lock()
            .ok()
            .and_then(|guard| guard.held());
        let clock = source_clock(&self.shared, held.map(|(_, stamp, _)| stamp));
        let now_ms = self
            .shared
            .started
            .elapsed()
            .as_millis()
            .min(u64::MAX as u128) as u64;

        let mut age_error = None;
        let pose = held.and_then(|(pose, stamp, received_ms)| {
            // Receipt age: host monotonic, always available, and a lower bound
            // on staleness. It is measured from the *first* delivery of this
            // source stamp, so a redelivery cannot make it younger.
            let receipt_age_ms = now_ms.saturating_sub(received_ms);
            match observation_age_ms(stamp, clock, receipt_age_ms) {
                Ok(age_ms) => Some(PoseObservation::new(
                    pose.x_mm(),
                    pose.y_mm(),
                    pose.yaw_mdeg(),
                    age_ms,
                )),
                Err(error) => {
                    // A reading whose age cannot be established is not a fresh
                    // reading and is not offered as one. Its coordinates go
                    // with it.
                    age_error = Some(error);
                    None
                }
            }
        });

        ObservationSnapshot {
            pose,
            last_error: self.shared.last_error.lock().ok().and_then(|guard| *guard),
            age_error: age_error
                .or_else(|| self.shared.age_error.lock().ok().and_then(|guard| *guard)),
            publisher_seen: self.shared.publisher_seen.load(Ordering::SeqCst),
            source_alive: self.shared.alive.load(Ordering::SeqCst),
        }
    }

    /// No-motion updates requested, and how many the service answered.
    ///
    /// Diagnostic only. An answered request is not a pose and is never treated
    /// as one; it only says the localizer was asked to publish.
    pub fn nomotion_counts(&self) -> (u32, u32) {
        (
            self.shared.nomotion_requested.load(Ordering::SeqCst),
            self.shared.nomotion_answered.load(Ordering::SeqCst),
        )
    }

    /// What the ledger has seen: deliveries, accepted, duplicates, superseded.
    ///
    /// For the demo banner and for a bug report. A transcript that says "stale
    /// pose" and nothing else cannot distinguish a silent topic from a rejected
    /// stream; one that also says `deliveries=0` or `superseded=412` can.
    pub fn delivery_counts(&self) -> (u64, u64, u64, u64) {
        self.shared
            .ledger
            .lock()
            .map(|ledger| {
                (
                    ledger.deliveries(),
                    ledger.accepted(),
                    ledger.duplicates(),
                    ledger.superseded(),
                )
            })
            .unwrap_or((0, 0, 0, 0))
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
                } else if snapshot.age_error.is_some() {
                    ObservationReadiness::OnlyUndatable
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
    /// Readings arrived and none could be dated, so none can be called fresh.
    OnlyUndatable,
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
            Self::OnlyUndatable => "a pose was received but its age could not be established",
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
    mut poses: Pin<Box<impl futures::Stream<Item = PoseWithCovarianceStamped> + ?Sized>>,
    mut clock: Pin<Box<impl futures::Stream<Item = ClockMsg> + ?Sized>>,
    nomotion: Option<&r2r::Client<Empty::Service>>,
    shared: &Arc<Shared>,
    stop: &Arc<AtomicBool>,
) {
    let mut last_graph_check = Instant::now() - GRAPH_CHECK_INTERVAL;
    // Nudge promptly on startup rather than after a first idle interval.
    let mut last_nomotion = Instant::now() - NOMOTION_INTERVAL;
    while !stop.load(Ordering::SeqCst) {
        node.spin_once(SPIN_SLICE);

        // Whether anyone publishes this topic at all. Asked on the observer
        // thread because that is where the node lives, and periodically rather
        // than every slice because it is a graph query, not a message read.
        if last_graph_check.elapsed() >= GRAPH_CHECK_INTERVAL
            && !shared.publisher_seen.load(Ordering::SeqCst)
        {
            if let Ok(publishers) = node.get_publishers_info_by_topic(&shared.topic, false) {
                if !publishers.is_empty() {
                    shared.publisher_seen.store(true, Ordering::SeqCst);
                }
            }
            last_graph_check = Instant::now();
        }

        // Simulated time first, so a pose read in the same slice is aged
        // against the freshest clock sample available.
        drain_clock(&mut clock, shared);

        // Then every pose queued. The ledger keeps the newest by source stamp,
        // so a retained backlog delivered oldest-first settles on its newest
        // member, and a live sample that follows supersedes it.
        if !drain(&mut poses, shared) {
            return;
        }

        // AMCL publishes on filter update. A stationary robot produces no
        // update, so a host that only listens waits out its deadline and
        // correctly reports the retained sample as stale — honest, and useless.
        // Asking for a no-motion update makes the source produce a current
        // estimate. Only while there is nothing usable, rate-limited, bounded.
        if let Some(client) = nomotion {
            if last_nomotion.elapsed() >= NOMOTION_INTERVAL
                && shared.nomotion_requested.load(Ordering::SeqCst) < NOMOTION_MAX_ATTEMPTS
                && needs_refresh(shared)
            {
                request_nomotion_update(node, client, shared);
                last_nomotion = Instant::now();
            }
        }
    }
}

/// A current time in the same domain `stamp` was written in, if one exists.
///
/// Two domains are recognised, and never mixed:
///
/// - **Simulated.** Something publishes `/clock`. That value *is* the
///   domain every node in the graph stamps in, so it is used directly and
///   never extrapolated with host elapsed time. A sample older than
///   [`CLOCK_SAMPLE_MAX_AGE`] means the simulator stopped publishing —
///   paused, most likely — and the simulated present is then unknown.
/// - **Wall clock.** Nothing has ever published `/clock`, so the stack runs
///   on real time and message stamps are epoch-based. The host's own wall
///   clock is then the same domain, subject to a sanity check that the
///   stamp is anywhere near it.
///
/// Anything else is [`SourceClock::Unavailable`], which costs an
/// observation and never produces a wrong age.
fn source_clock(shared: &Arc<Shared>, stamp: Option<SourceTime>) -> SourceClock {
    let sample = shared.ros_clock.lock().ok().and_then(|guard| *guard);
    if let Some((simulated, received)) = sample {
        return if received.elapsed() <= CLOCK_SAMPLE_MAX_AGE {
            SourceClock::Established(simulated)
        } else {
            SourceClock::Unavailable
        };
    }

    // Nothing has ever published `/clock`. Wall-clock domain, if the stamp
    // is plausibly in it.
    let Some(stamp) = stamp else {
        return SourceClock::Unavailable;
    };
    let Ok(epoch) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return SourceClock::Unavailable;
    };
    let wall = SourceTime::from_nanos(epoch.as_nanos() as i128);
    let distance = (wall.nanos() - stamp.nanos()).unsigned_abs();
    if distance <= WALL_CLOCK_TOLERANCE.as_nanos() {
        SourceClock::Established(wall)
    } else {
        SourceClock::Unavailable
    }
}

/// Whether the host currently lacks a pose it would plan on.
///
/// The same rule the planner is shown, asked on the observer thread: no reading,
/// a reading too old, or a reading whose age cannot be established. Anything
/// else, and there is nothing to ask AMCL for.
fn needs_refresh(shared: &Arc<Shared>) -> bool {
    let Some((_, stamp, received_ms)) = shared.ledger.lock().ok().and_then(|guard| guard.held())
    else {
        return true;
    };
    let now_ms = shared.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let clock = source_clock(shared, Some(stamp));
    match observation_age_ms(stamp, clock, now_ms.saturating_sub(received_ms)) {
        Ok(age_ms) => age_ms > shared.max_age_ms,
        Err(_) => true,
    }
}

/// Asks AMCL to recompute its estimate without the robot having moved.
///
/// # Advisory, and not pose data
///
/// The request is `std_srvs/srv/Empty`: no data out, none back. Nothing in the
/// response is read and nothing about it is trusted. A reply is not evidence
/// that a pose exists — it is a hint to another node that now would be a good
/// time to publish one. The only thing this host ever treats as an observation
/// is an `/amcl_pose` message arriving afterwards, which survives the same
/// source-stamp, clock-domain, and freshness rules as any other message.
///
/// If the service is absent, the call fails, or nothing is published in
/// response, the observation stays `UNKNOWN`. The time of the request is never
/// used as the time of a pose, and no timestamp is ever rewritten.
///
/// # Why this does not make the observer an actuator
///
/// One client, one named service, an empty message, whose documented effect is
/// that a localization filter runs an update over data it already holds. It
/// reaches no action server, no velocity topic, and no controller, and it
/// cannot move the machine. That is a much weaker capability than publishing,
/// but it is not nothing — which is why the module documentation no longer says
/// this node can only read.
fn request_nomotion_update(
    node: &mut Node,
    client: &r2r::Client<Empty::Service>,
    shared: &Arc<Shared>,
) {
    if !shared.nomotion_available.load(Ordering::SeqCst) {
        let Ok(waiting) = Node::is_available(client) else {
            return;
        };
        let mut waiting = Box::pin(waiting);
        if !matches!(
            await_with_spin(node, &mut waiting, SERVICE_WAIT),
            Some(Ok(()))
        ) {
            // Not there. Counted as an attempt, so a missing service cannot
            // keep this loop retrying for the life of the process.
            shared.nomotion_requested.fetch_add(1, Ordering::SeqCst);
            return;
        }
        shared.nomotion_available.store(true, Ordering::SeqCst);
    }

    shared.nomotion_requested.fetch_add(1, Ordering::SeqCst);
    let Ok(pending) = client.request(&Empty::Request {}) else {
        return;
    };
    let mut pending = Box::pin(pending);
    if await_with_spin(node, &mut pending, SERVICE_BUDGET).is_some() {
        // The service answered. That is all it means: no pose has been observed
        // yet, and one may never arrive.
        shared.nomotion_answered.fetch_add(1, Ordering::SeqCst);
    }
}

/// Polls a future while spinning the node, up to a budget.
fn await_with_spin<F: core::future::Future + Unpin>(
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

/// Reads whatever simulated-time samples have arrived.
fn drain_clock(
    subscription: &mut Pin<Box<impl futures::Stream<Item = ClockMsg> + ?Sized>>,
    shared: &Arc<Shared>,
) {
    loop {
        match subscription.next().now_or_never() {
            Some(Some(message)) => apply_clock(shared, &message),
            Some(None) | None => return,
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
    let stamp = SourceTime::from_ros(message.header.stamp.sec, message.header.stamp.nanosec);
    match convert(message) {
        Ok(pose) => {
            let received_ms = shared.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            if let Ok(mut ledger) = shared.ledger.lock() {
                // The ordering and duplicate rules live in the ledger, where
                // they can be tested without a robot.
                let _: Admission = ledger.record(pose, stamp, received_ms);
            }
            if let Ok(mut error) = shared.last_error.lock() {
                *error = None;
            }
            if let Ok(mut error) = shared.age_error.lock() {
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

/// Records the newest simulated-time sample.
fn apply_clock(shared: &Arc<Shared>, message: &ClockMsg) {
    let now = SourceTime::from_ros(message.clock.sec, message.clock.nanosec);
    if let Ok(mut clock) = shared.ros_clock.lock() {
        // Monotonic in the simulated domain: a simulator that restarts jumps
        // backwards, and the newest sample is then the correct one to hold, so
        // this deliberately takes whatever arrived last rather than the maximum.
        *clock = Some((now, Instant::now()));
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
