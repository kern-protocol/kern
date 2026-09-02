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
    /// The host is subscribed but no reading has arrived yet.
    NotYetReceived,
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
    /// The host chose not to observe.
    ///
    /// A deployment that supplies no observation at all is a supported
    /// configuration, and it is the one every phase before this behaved as.
    NotObserved,
}

impl fmt::Display for ObservationUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotYetReceived => f.write_str("no reading has arrived yet"),
            Self::Stale { age_ms, max_age_ms } => write!(
                f,
                "the newest reading is {age_ms} ms old, over the {max_age_ms} ms limit"
            ),
            Self::SourceUnavailable => f.write_str("the observation source is unreachable"),
            Self::Unrepresentable(error) => write!(f, "the reading was unusable: {error}"),
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
