//! Injected time.
//!
//! Domain logic never calls a wall-clock API directly, so tests can advance
//! time deterministically (AGENT.md section 13).
//!
//! Only the issuer-side [`Clock`] exists so far. The enforcer's monotonic clock
//! belongs to the phase that has an enforcer to use it.

/// Milliseconds since the Unix epoch.
///
/// Used by the issuer and by the trace. An enforcer must not treat a timestamp
/// as trustworthy local time — see AGENT.md section 7.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Wraps a millisecond count.
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// The underlying millisecond count.
    pub const fn as_millis(&self) -> u64 {
        self.0
    }

    /// Adds a duration, returning `None` on overflow.
    ///
    /// Deliberately checked. Saturating an expiry would silently produce a lease
    /// that outlives every reasonable bound.
    pub fn checked_add(&self, ttl: Ttl) -> Option<Self> {
        self.0.checked_add(ttl.as_millis()).map(Self)
    }
}

/// A duration could not be expressed as a protocol TTL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TtlError {
    /// Positive, but shorter than the protocol's one-millisecond resolution.
    ///
    /// The dangerous case. Truncating `Duration::from_nanos(1)` to zero
    /// milliseconds would turn a positive lifetime into one that authorizes
    /// nothing, silently.
    SubMillisecond,
    /// Positive and at least a millisecond, but with a sub-millisecond
    /// remainder.
    ///
    /// Rejected rather than rounded. Rounding down shortens authority and
    /// rounding up extends it; neither is a decision this layer should make on
    /// the caller's behalf.
    NotWholeMilliseconds,
    /// Longer than the millisecond space can represent.
    NotRepresentable,
}

impl core::fmt::Display for TtlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SubMillisecond => f.write_str("duration is shorter than one millisecond"),
            Self::NotWholeMilliseconds => {
                f.write_str("duration is not a whole number of milliseconds")
            }
            Self::NotRepresentable => f.write_str("duration exceeds the representable range"),
        }
    }
}

impl core::error::Error for TtlError {}

/// A span of milliseconds.
///
/// Milliseconds are the protocol's resolution, and Phase 3 adds nothing finer.
/// Converting from a [`core::time::Duration`] is therefore fallible — see
/// [`Ttl::try_from_duration`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ttl(u64);

impl Ttl {
    /// Wraps a millisecond span.
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// The underlying millisecond span.
    pub const fn as_millis(&self) -> u64 {
        self.0
    }

    /// True for a zero-length span, which cannot authorize anything.
    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Converts a [`core::time::Duration`], rejecting anything the protocol
    /// cannot represent exactly.
    ///
    /// A positive duration must never become a zero-millisecond TTL. That would
    /// turn a caller's intent to grant authority into a lease that authorizes
    /// nothing, and it would do so without a single error anywhere.
    ///
    /// `Duration::ZERO` converts successfully to a zero TTL. Zero is refused
    /// once, at issuance, so exactly one place owns the rule that a zero-length
    /// lease authorizes nothing.
    pub fn try_from_duration(duration: core::time::Duration) -> Result<Self, TtlError> {
        let millis = duration.as_millis();
        if millis == 0 {
            return if duration.is_zero() {
                Ok(Self(0))
            } else {
                Err(TtlError::SubMillisecond)
            };
        }
        if duration.subsec_nanos() % 1_000_000 != 0 {
            return Err(TtlError::NotWholeMilliseconds);
        }
        u64::try_from(millis)
            .map(Self)
            .map_err(|_| TtlError::NotRepresentable)
    }
}

/// Milliseconds of enforcer uptime.
///
/// Non-wrapping by contract. `u64` milliseconds spans roughly 584 million
/// years, so the *representation* cannot wrap within any supported uptime — but
/// the hardware counter underneath very well might. A 32-bit tick at 1 kHz wraps
/// in about 49.7 days, so extending it is the implementor's job, not this type's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uptime(u64);

impl Uptime {
    /// The instant an enforcer started.
    pub const ZERO: Uptime = Uptime(0);

    /// Wraps a millisecond count.
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// The underlying millisecond count.
    pub const fn as_millis(&self) -> u64 {
        self.0
    }

    /// Adds a span, returning `None` on overflow.
    pub fn checked_add(&self, span: MonotonicDuration) -> Option<Self> {
        self.0.checked_add(span.as_millis()).map(Self)
    }
}

/// A span of enforcer uptime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicDuration(u64);

impl MonotonicDuration {
    /// Wraps a millisecond span.
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// The underlying millisecond span.
    pub const fn as_millis(&self) -> u64 {
        self.0
    }

    /// True for a zero-length span.
    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

/// A source of monotonic uptime.
///
/// # Contract
///
/// `uptime` must be non-decreasing and must not wrap. An implementation over a
/// narrow hardware counter must extend it. An implementation that cannot uphold
/// this must not return a wrapped value — callers detect backwards movement and
/// fail closed, but they cannot detect a full wrap that lands ahead.
pub trait MonotonicClock {
    /// Milliseconds since this enforcer started.
    fn uptime(&self) -> Uptime;
}

/// A monotonic clock driven by tests.
///
/// Clones share the underlying instant, for the same reason [`TestClock`] does.
/// It can be moved backwards on purpose, so that the backwards-movement guard
/// can be exercised.
#[derive(Clone, Debug)]
pub struct TestMonotonicClock {
    uptime: alloc::rc::Rc<core::cell::Cell<u64>>,
}

impl TestMonotonicClock {
    /// A clock reading `start`.
    pub fn new(start: Uptime) -> Self {
        Self {
            uptime: alloc::rc::Rc::new(core::cell::Cell::new(start.as_millis())),
        }
    }

    /// Moves the clock forward.
    pub fn advance(&self, millis: u64) {
        self.uptime.set(self.uptime.get().saturating_add(millis));
    }

    /// Moves the clock to an absolute uptime, forwards or backwards.
    pub fn set(&self, uptime: Uptime) {
        self.uptime.set(uptime.as_millis());
    }
}

impl MonotonicClock for TestMonotonicClock {
    fn uptime(&self) -> Uptime {
        Uptime::from_millis(self.uptime.get())
    }
}

/// A source of wall-clock time.
pub trait Clock {
    /// The current time.
    fn now(&self) -> Timestamp;
}

/// A clock fixed at a chosen instant, advanceable by tests.
///
/// Cloning shares the underlying instant rather than copying it, so a handle
/// kept by a test advances the very clock it handed to the code under test. A
/// clone that silently detached would make time appear frozen for reasons no
/// reader could see.
///
/// # A test utility, and nothing more
///
/// Not a synchronization primitive: it is single-threaded, `Rc`-backed, and not
/// `Send` or `Sync`. Not a monotonic clock: [`TestClock::set`] moves it
/// backwards on request. Not a freshness mechanism: freshness at installation
/// is an unresolved protocol question, and no clock in this crate answers it.
#[derive(Clone, Debug)]
pub struct TestClock {
    now: alloc::rc::Rc<core::cell::Cell<u64>>,
}

impl TestClock {
    /// A clock reading `start`.
    pub fn new(start: Timestamp) -> Self {
        Self {
            now: alloc::rc::Rc::new(core::cell::Cell::new(start.as_millis())),
        }
    }

    /// Moves the clock forward.
    pub fn advance(&self, millis: u64) {
        self.now.set(self.now.get().saturating_add(millis));
    }

    /// Moves the clock to an absolute instant.
    pub fn set(&self, now: Timestamp) {
        self.now.set(now.as_millis());
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_millis(self.now.get())
    }
}

/// The host's wall clock.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

#[cfg(feature = "std")]
impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Timestamp::from_millis(millis)
    }
}
