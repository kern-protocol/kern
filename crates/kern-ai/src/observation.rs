//! What the host may tell a planner about where the robot actually is.
//!
//! # The problem this solves
//!
//! Before this module existed, the demo told the model the robot's position in
//! a hand-written sentence: *"The robot is currently at the origin, idle."* That
//! sentence was true when it was written and false every moment after the robot
//! moved. Asked to return to the origin from six metres away, a model reading it
//! answered `no_action` and gave the only reason available to it — the robot is
//! already there. The model was not hallucinating. It was believing the host.
//!
//! A [`WorldObservation`] replaces that sentence with a reading taken from the
//! machine, carrying the one thing a sentence could not: how old it is.
//!
//! # What this is not
//!
//! It is not authority, and there is no path by which it could become authority.
//! An observation is an *input to the prompt*. It is not consulted by the
//! evaluator, it is not part of an [`ActionProposal`](kern_core::ActionProposal),
//! it cannot relax a constraint, and a proposal is evaluated identically whether
//! one was attached or not. A robot observed at `x = 6000` gets exactly the same
//! answer to `x = 40000, speed = 5000` as a robot observed nowhere: refused.
//!
//! It is also not ground truth, and nothing here should be read as claiming so.
//! It is what a localization system reported, some milliseconds ago. It carries
//! the ordinary limits of the thing that produced it — localization error,
//! sensor error, latency, and the possibility that the robot has moved since.
//! The `age_ms` field exists because that last one is not hypothetical.
//!
//! # Why absence is a variant and not an `Option`
//!
//! [`PoseKnowledge`] has no "empty" case that reads as a position. A missing
//! pose is [`PoseKnowledge::Unavailable`] carrying *why*, and the prompt renders
//! it as an explicit statement that the position is unknown. The failure this
//! shape forbids is the obvious one:
//!
//! ```text
//! missing pose  !=  (0, 0, 0)
//! ```
//!
//! An `Option<PoseObservation>` defaulted to `Default::default()` anywhere in
//! the call chain would silently reintroduce exactly the bug this module was
//! written to fix, one origin at a time.

use alloc::format;
use alloc::string::String;
use core::fmt;

use kern_core::DeviceId;

/// A physical quantity could not be represented in Kern's integer units.
///
/// Every variant is a refusal. None of them carries a repaired value, because
/// the honest answer to "the localizer reported NaN" is that the position is
/// unknown — not that it is somewhere convenient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversionError {
    /// The value was NaN.
    NotANumber,
    /// The value was an infinity, of either sign.
    Infinite,
    /// The value is finite but outside the range Kern's integer units can hold.
    OutOfRange,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotANumber => "value is NaN",
            Self::Infinite => "value is infinite",
            Self::OutOfRange => "value is outside the representable integer range",
        })
    }
}

impl core::error::Error for ConversionError {}

/// The largest magnitude a converted physical quantity may take.
///
/// One thousand kilometres in millimetres. Nothing about a café robot comes
/// within six orders of magnitude of this, so a reading that exceeds it is not a
/// position that needs representing — it is a localizer that has failed, and it
/// is refused rather than truncated. The bound is well inside `i64`, so every
/// downstream arithmetic on a converted value stays far from overflow.
pub const MAX_MAGNITUDE_MM: i64 = 1_000_000_000;

/// The largest magnitude a converted angle may take, in millidegrees.
///
/// A full turn is 360_000. This admits a little over a thousand turns, which is
/// far more than any sane yaw and still refuses a diverged value.
pub const MAX_MAGNITUDE_MDEG: i64 = 400_000_000;

/// Converts metres to millimetres, refusing anything it cannot represent.
///
/// # Why this lives in `kern-ai` rather than in the ROS adapter
///
/// Because it must be tested on a machine with no ROS installed. The unit
/// boundary is the place a physical reading stops being a float and becomes a
/// Kern integer, and it is exactly the kind of code that is wrong in ways only a
/// test finds — NaN, infinity, a sign, a rounding mode, an overflow. Putting it
/// behind `r2r` would mean it is only ever exercised on a machine that also has
/// Gazebo, which is to say almost never. It takes an `f64` and knows nothing
/// about where the `f64` came from.
///
/// Rounds half away from zero, which keeps `-0.0015 m` and `0.0015 m`
/// symmetric — a rounding rule that treats the sign asymmetrically puts a
/// systematic bias into a coordinate.
#[cfg(feature = "std")]
pub fn meters_to_millimeters(meters: f64) -> Result<i64, ConversionError> {
    scale_checked(meters, 1_000.0, MAX_MAGNITUDE_MM)
}

/// Converts radians to millidegrees, refusing anything it cannot represent.
///
/// No normalization into `[-180, 180]` happens here. Normalizing is a semantic
/// decision about what an angle means, and this function's whole job is to
/// change units without changing meaning; see [`normalize_mdeg`] for the
/// separate, explicit step.
#[cfg(feature = "std")]
pub fn radians_to_millidegrees(radians: f64) -> Result<i64, ConversionError> {
    scale_checked(
        radians,
        180_000.0 / core::f64::consts::PI,
        MAX_MAGNITUDE_MDEG,
    )
}

/// The yaw of a unit quaternion, in radians.
///
/// The standard ROS convention: rotation about `z`, extracted from the
/// quaternion the localizer publishes. Returns `None` when any component is not
/// finite, rather than propagating a NaN into a conversion that would then have
/// to detect it.
#[cfg(feature = "std")]
pub fn quaternion_yaw_radians(x: f64, y: f64, z: f64, w: f64) -> Option<f64> {
    if !(x.is_finite() && y.is_finite() && z.is_finite() && w.is_finite()) {
        return None;
    }
    let siny_cosp = 2.0 * (w * z + x * y);
    let cosy_cosp = 1.0 - 2.0 * (y * y + z * z);
    // atan2 is defined at (0, 0) and returns 0, so a degenerate quaternion
    // yields a yaw of zero rather than a NaN. That is a real reading of a
    // degenerate input, and the caller sees it as an ordinary angle; the
    // components being finite is the property that matters here.
    let yaw = libm_atan2(siny_cosp, cosy_cosp);
    yaw.is_finite().then_some(yaw)
}

#[cfg(feature = "std")]
fn libm_atan2(y: f64, x: f64) -> f64 {
    y.atan2(x)
}

/// Scales a float into an integer, checking every way that can go wrong.
#[cfg(feature = "std")]
fn scale_checked(value: f64, factor: f64, limit: i64) -> Result<i64, ConversionError> {
    if value.is_nan() {
        return Err(ConversionError::NotANumber);
    }
    if value.is_infinite() {
        return Err(ConversionError::Infinite);
    }
    let scaled = value * factor;
    // The product of two finite floats can still be infinite.
    if !scaled.is_finite() {
        return Err(ConversionError::OutOfRange);
    }
    // Round half away from zero, then bound. `as i64` saturates rather than
    // wrapping in Rust, but the explicit comparison is what the bound is for:
    // saturation would silently turn a diverged reading into `i64::MAX`.
    let rounded = if scaled >= 0.0 {
        (scaled + 0.5).floor()
    } else {
        (scaled - 0.5).ceil()
    };
    if !(-(limit as f64)..=(limit as f64)).contains(&rounded) {
        return Err(ConversionError::OutOfRange);
    }
    Ok(rounded as i64)
}

/// Folds an angle into `[-180_000, 180_000)` millidegrees.
///
/// Separate from the unit conversion on purpose, and never applied implicitly:
/// a caller that wants a normalized angle asks for one.
pub const fn normalize_mdeg(mdeg: i64) -> i64 {
    const TURN: i64 = 360_000;
    let wrapped = mdeg % TURN;
    if wrapped >= TURN / 2 {
        wrapped - TURN
    } else if wrapped < -TURN / 2 {
        wrapped + TURN
    } else {
        wrapped
    }
}

/// A timestamp as the observation source wrote it.
///
/// Nanoseconds, in whatever clock domain the publisher was using. Held as
/// `i128` so the arithmetic against another timestamp cannot overflow and so a
/// negative difference stays negative instead of wrapping into an enormous
/// positive age.
///
/// # This carries no domain
///
/// A `SourceTime` is a number. Whether it means simulated time, wall-clock
/// time, or something else is a property of the publisher, not of this value,
/// and is why [`SourceClock`] must be established separately rather than
/// assumed. Two timestamps may only be subtracted when both come from the same
/// domain, and nothing in this type can tell you that they do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceTime {
    nanos: i128,
}

impl SourceTime {
    /// From a ROS `builtin_interfaces/Time`.
    pub const fn from_ros(sec: i32, nanosec: u32) -> Self {
        Self {
            nanos: (sec as i128) * 1_000_000_000 + (nanosec as i128),
        }
    }

    /// From raw nanoseconds.
    pub const fn from_nanos(nanos: i128) -> Self {
        Self { nanos }
    }

    /// The raw nanoseconds.
    pub const fn nanos(self) -> i128 {
        self.nanos
    }

    /// Whether this is the all-zero stamp ROS uses for "not set".
    ///
    /// A publisher that never filled in the header leaves `sec = 0,
    /// nanosec = 0`. Under simulated time that is also a legitimate instant —
    /// the very start of the run — which is precisely why it is refused rather
    /// than interpreted: the two cases are indistinguishable from here, and one
    /// of them would make an arbitrarily old observation look new.
    pub const fn is_unset(self) -> bool {
        self.nanos == 0
    }
}

/// The current time in the same clock domain as a [`SourceTime`].
///
/// # Why this is not just "now"
///
/// The host's monotonic clock and a ROS message stamp are different domains,
/// and under simulated time they are not even close: a Gazebo stack a few
/// seconds into a run stamps messages at `0.1 s` while the host's wall clock
/// reads some 1.7 billion seconds. Subtracting one from the other produces a
/// number, and that number is meaningless.
///
/// So the domain is established explicitly, or it is not established and the
/// age is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceClock {
    /// A current reading from the same domain the stamp was written in.
    Established(SourceTime),
    /// No clock in the stamp's domain could be established.
    ///
    /// Simulated time with no `/clock` arriving, a paused simulator, or a
    /// publisher whose domain does not match anything the host can read.
    Unavailable,
}

/// The age of an observation could not be established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceAgeError {
    /// The stamp was the all-zero "not set" value.
    Unset,
    /// No clock in the stamp's domain was available.
    ClockUnavailable,
    /// The stamp is ahead of the source clock by more than the tolerance.
    Future {
        /// By how much, in milliseconds.
        by_ms: u64,
    },
}

impl fmt::Display for SourceAgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unset => f.write_str("the source timestamp is unset"),
            Self::ClockUnavailable => {
                f.write_str("no clock in the source's time domain is available")
            }
            Self::Future { by_ms } => {
                write!(f, "the source timestamp is {by_ms} ms in the future")
            }
        }
    }
}

/// How far ahead of the source clock a stamp may be before it is refused.
///
/// Publishers and clock samples race, so a stamp a little ahead of the newest
/// clock reading is ordinary. A stamp far ahead is a clock that reset, a
/// simulation that restarted, or a domain mismatch, and none of those may be
/// read as a very fresh observation.
pub const FUTURE_STAMP_TOLERANCE_MS: u64 = 500;

/// How old an observation is, conservatively, in milliseconds.
///
/// # The two ages, and why the larger one wins
///
/// `receipt_age_ms` is how long *this process* has held the message. It is
/// measured on the host's monotonic clock and it is always trustworthy, but it
/// answers the wrong question: a retained sample published an hour ago and
/// delivered to a new subscriber a moment ago has a receipt age of a few
/// milliseconds and a real age of an hour. That gap is the defect this function
/// exists to close.
///
/// The source age answers the right question but only when a clock in the
/// stamp's own domain is available.
///
/// Both are lower bounds on how stale the reading actually is, so the larger is
/// the honest answer. This is not a heuristic blend: it is the maximum of two
/// quantities each computed inside one domain, and neither is ever subtracted
/// from the other.
pub fn observation_age_ms(
    stamp: SourceTime,
    clock: SourceClock,
    receipt_age_ms: u64,
) -> Result<u64, SourceAgeError> {
    if stamp.is_unset() {
        return Err(SourceAgeError::Unset);
    }
    let SourceClock::Established(now) = clock else {
        return Err(SourceAgeError::ClockUnavailable);
    };

    let delta_ns = now.nanos() - stamp.nanos();
    if delta_ns < 0 {
        let ahead_ms = ((-delta_ns) / 1_000_000) as u64;
        if ahead_ms > FUTURE_STAMP_TOLERANCE_MS {
            return Err(SourceAgeError::Future { by_ms: ahead_ms });
        }
        // Inside the tolerance: an ordinary race between a publisher and a
        // clock sample. Treated as zero source age, never as negative.
        return Ok(receipt_age_ms);
    }

    let source_age_ms = (delta_ns / 1_000_000).min(u64::MAX as i128) as u64;
    Ok(source_age_ms.max(receipt_age_ms))
}

/// Where the robot was, and how long ago it was there.
///
/// Every field is an integer in Kern's units. No float reaches this type, which
/// is the point: the conversion happens once, at the adapter boundary, where it
/// is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoseObservation {
    x_mm: i64,
    y_mm: i64,
    yaw_mdeg: i64,
    age_ms: u64,
}

impl PoseObservation {
    /// Records one pose reading and how old it is.
    ///
    /// `age_ms` is the time between the reading arriving at the host and the
    /// planning request being assembled. It is measured by the host, against
    /// the host's own clock, and it is never taken from a message: a timestamp
    /// inside a ROS message comes from another machine's clock and answers a
    /// different question.
    pub fn new(x_mm: i64, y_mm: i64, yaw_mdeg: i64, age_ms: u64) -> Self {
        Self {
            x_mm,
            y_mm,
            yaw_mdeg,
            age_ms,
        }
    }

    /// Millimetres along x, in the frame the named places are given in.
    pub fn x_mm(&self) -> i64 {
        self.x_mm
    }

    /// Millimetres along y.
    pub fn y_mm(&self) -> i64 {
        self.y_mm
    }

    /// Heading in millidegrees.
    pub fn yaw_mdeg(&self) -> i64 {
        self.yaw_mdeg
    }

    /// How long ago this reading arrived, in milliseconds.
    pub fn age_ms(&self) -> u64 {
        self.age_ms
    }

    /// Whether this reading is no older than `max_age_ms`.
    pub fn is_fresh_within(&self, max_age_ms: u64) -> bool {
        self.age_ms <= max_age_ms
    }
}

/// Why there is no pose to report.
///
/// Each variant is a distinct fact about the host's knowledge, and the prompt
/// renders each differently. Collapsing them into one "unknown" would lose the
/// difference between a localizer that has not started and one that has stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationUnavailable {
    /// The topic was discovered and has a publisher, but no reading has
    /// arrived yet.
    NotYetReceived,
    /// No publisher for the topic was discovered at all.
    ///
    /// A different fact from [`NotYetReceived`](Self::NotYetReceived), and a
    /// far more actionable one: the localizer is not running, or is publishing
    /// somewhere else, or a QoS setting means the two never matched. "Nothing
    /// has arrived" and "there is nobody to hear" send an operator to
    /// different places.
    SourceUndiscovered,
    /// A reading arrived, but it is older than the host is willing to plan on.
    ///
    /// The age is carried so the prompt can say how stale, and so a reader of a
    /// transcript can tell a slightly-late reading from a dead one.
    Stale {
        /// How old the newest reading is.
        age_ms: u64,
        /// The oldest the host was willing to accept.
        max_age_ms: u64,
    },
    /// The observation source itself is not reachable.
    SourceUnavailable,
    /// A reading arrived and could not be represented in Kern's units.
    ///
    /// NaN, an infinity, or a magnitude outside the representable range. The
    /// reading is discarded rather than repaired.
    Unrepresentable(ConversionError),
    /// A reading arrived but its age could not be established.
    ///
    /// Refused rather than reported with the only age the host could compute,
    /// because that age would be the time since delivery — which for a retained
    /// sample is not the age of the observation.
    SourceTimeUnusable(SourceAgeError),
    /// The host chose not to observe.
    ///
    /// A deployment that supplies no observation at all is a supported
    /// configuration, and it is the one every phase before this behaved as.
    NotObserved,
}

impl fmt::Display for ObservationUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotYetReceived => {
                f.write_str("a publisher is present but no reading has arrived yet")
            }
            Self::SourceUndiscovered => {
                f.write_str("no publisher for the observation topic was discovered")
            }
            Self::Stale { age_ms, max_age_ms } => write!(
                f,
                "the newest reading is {age_ms} ms old, over the {max_age_ms} ms limit"
            ),
            Self::SourceUnavailable => f.write_str("the observation source is unreachable"),
            Self::Unrepresentable(error) => write!(f, "the reading was unusable: {error}"),
            Self::SourceTimeUnusable(error) => {
                write!(f, "the reading's age could not be established: {error}")
            }
            Self::NotObserved => f.write_str("this host supplies no position observation"),
        }
    }
}

/// What the host knows about the robot's position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoseKnowledge {
    /// A usable reading.
    Known(PoseObservation),
    /// No usable reading, and why.
    Unavailable(ObservationUnavailable),
}

impl PoseKnowledge {
    /// The pose, when there is one.
    pub fn pose(&self) -> Option<&PoseObservation> {
        match self {
            Self::Known(pose) => Some(pose),
            Self::Unavailable(_) => None,
        }
    }

    /// Why there is no pose, when there is not.
    pub fn unavailable(&self) -> Option<ObservationUnavailable> {
        match self {
            Self::Known(_) => None,
            Self::Unavailable(reason) => Some(*reason),
        }
    }

    /// True when a usable reading is present.
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known(_))
    }
}

/// Everything the host knows at the instant an observation is resolved.
///
/// # Why this type exists
///
/// So the decision it feeds can be tested without ROS, without threads, and
/// without sleeping. The rule for turning "what has arrived so far" into a
/// [`WorldObservation`] is ordinary logic with several branches and a
/// precedence order, and it is exactly the kind of code that is wrong in a way
/// only a test finds. Behind a subscription it would only ever run on a machine
/// with a robot attached, and the failure would show up as a demo that says
/// `UNKNOWN` for reasons nobody can reproduce — which is precisely what
/// happened.
///
/// The adapter's job is reduced to filling these four fields in honestly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservationSnapshot {
    /// The newest usable reading, with its age already computed.
    pub pose: Option<PoseObservation>,
    /// The failure from the most recent message, when it could not be used.
    pub last_error: Option<ConversionError>,
    /// Why the most recent reading's age could not be established, if it could
    /// not be.
    ///
    /// Distinct from `last_error`: the message decoded perfectly well, and it
    /// is only how old it is that is unknown. That is still disqualifying — an
    /// observation of unknown age is not a fresh observation — but it sends a
    /// reader somewhere different.
    pub age_error: Option<SourceAgeError>,
    /// Whether any publisher for the topic has been discovered.
    pub publisher_seen: bool,
    /// Whether the observation source is still running.
    pub source_alive: bool,
}

impl ObservationSnapshot {
    /// The snapshot of a host that has just started and heard nothing.
    pub fn pending() -> Self {
        Self {
            pose: None,
            last_error: None,
            age_error: None,
            publisher_seen: false,
            source_alive: true,
        }
    }
}

/// Turns what the host knows into what the planner is told.
///
/// The precedence is deliberate and is the whole content of this function:
///
/// ```text
/// source stopped            -> SourceUnavailable
/// a reading, within bound   -> Known
/// a reading, too old        -> Stale
/// no reading, last was bad  -> Unrepresentable
/// no reading, age unknown   -> SourceTimeUnusable
/// no reading, no publisher  -> SourceUndiscovered
/// no reading, publisher up  -> NotYetReceived
/// ```
///
/// A dead source outranks a reading because a reading from a source that has
/// since stopped is a reading of unknown age from an unknown past. A conversion
/// failure outranks "nothing yet" because it is the more specific and more
/// useful statement about the same absence.
///
/// No branch produces a position that was not measured.
pub fn resolve(
    device: DeviceId,
    snapshot: ObservationSnapshot,
    max_age_ms: u64,
) -> WorldObservation {
    if !snapshot.source_alive {
        return WorldObservation::unavailable(device, ObservationUnavailable::SourceUnavailable);
    }
    if let Some(pose) = snapshot.pose {
        return WorldObservation::fresh_within(device, pose, max_age_ms);
    }
    if let Some(error) = snapshot.last_error {
        return WorldObservation::unavailable(
            device,
            ObservationUnavailable::Unrepresentable(error),
        );
    }
    if let Some(error) = snapshot.age_error {
        return WorldObservation::unavailable(
            device,
            ObservationUnavailable::SourceTimeUnusable(error),
        );
    }
    let reason = if snapshot.publisher_seen {
        ObservationUnavailable::NotYetReceived
    } else {
        ObservationUnavailable::SourceUndiscovered
    };
    WorldObservation::unavailable(device, reason)
}

/// One machine's observed physical state, as planning context.
///
/// Fixed-size by construction: a device identifier and at most four integers.
/// There is deliberately no map, no list, no free-text field, and no way to
/// attach a sensor payload — the resource bound is the shape of the type rather
/// than a length check, because a shape cannot be argued with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorldObservation {
    device: DeviceId,
    pose: PoseKnowledge,
}

impl WorldObservation {
    /// A usable reading for one device.
    pub fn known(device: DeviceId, pose: PoseObservation) -> Self {
        Self {
            device,
            pose: PoseKnowledge::Known(pose),
        }
    }

    /// An explicit statement that no usable reading exists, and why.
    pub fn unavailable(device: DeviceId, reason: ObservationUnavailable) -> Self {
        Self {
            device,
            pose: PoseKnowledge::Unavailable(reason),
        }
    }

    /// A reading, demoted to [`ObservationUnavailable::Stale`] when too old.
    ///
    /// The freshness decision is made here, once, rather than left to each
    /// caller to remember. A caller that wants the reading regardless uses
    /// [`known`](Self::known) and takes responsibility for saying so.
    pub fn fresh_within(device: DeviceId, pose: PoseObservation, max_age_ms: u64) -> Self {
        if pose.is_fresh_within(max_age_ms) {
            Self::known(device, pose)
        } else {
            Self::unavailable(
                device,
                ObservationUnavailable::Stale {
                    age_ms: pose.age_ms(),
                    max_age_ms,
                },
            )
        }
    }

    /// The machine this describes.
    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    /// What is known about its position.
    pub fn pose(&self) -> &PoseKnowledge {
        &self.pose
    }

    /// The observation as the block the model is shown.
    ///
    /// Rendered from typed fields only. There is no path by which caller text
    /// reaches this string, which is what makes the block unspoofable from the
    /// instruction side: an instruction that contains these exact words is
    /// still only ever rendered into the *user* message, and this block is only
    /// ever rendered into the *system* message.
    pub fn to_block(&self) -> String {
        let mut out = format!("device: {}\n", self.device);
        match &self.pose {
            PoseKnowledge::Known(pose) => {
                out.push_str(&format!(
                    "position: x = {} mm, y = {} mm, yaw = {} mdeg\n\
                     reading age: {} ms\n",
                    pose.x_mm(),
                    pose.y_mm(),
                    pose.yaw_mdeg(),
                    pose.age_ms()
                ));
            }
            PoseKnowledge::Unavailable(reason) => {
                out.push_str(&format!(
                    "position: UNKNOWN ({reason})\n\
                     Do not assume a position. Do not assume the robot is at the origin.\n"
                ));
            }
        }
        out
    }
}
