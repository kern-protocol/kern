//! The constraint primitives the authority algebra is built from.
//!
//! There are three, and there should stay three until a real capability domain
//! proves one is missing. This is not an expression language, and it must not
//! grow into one: every primitive added here is a primitive that every future
//! enforcer has to evaluate correctly on a constrained target.
//!
//! Each primitive answers the same two questions:
//!
//! - `permits`: does this constraint admit a given argument?
//! - `is_subset_of`: does this constraint admit no more than another?
//!
//! `meet` returns `None` when the two constraints share no permitted value.
//! The caller turns that into [`crate::ConstraintSet::no_authority`]. Emptiness
//! is never represented inside a primitive.

use alloc::collections::BTreeSet;

use crate::ids::Symbol;
use crate::proposal::ParamValue;

/// A closed integer interval `[lower, upper]`, never empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    lower: i64,
    upper: i64,
}

impl Interval {
    /// The interval admitting every `i64`.
    pub const UNBOUNDED: Interval = Interval {
        lower: i64::MIN,
        upper: i64::MAX,
    };

    /// Builds `[lower, upper]`, or `None` if the bounds are inverted.
    ///
    /// Inverted bounds are a contradiction, not an interval. Returning `None`
    /// keeps an empty interval unrepresentable.
    pub fn between(lower: i64, upper: i64) -> Option<Self> {
        if lower > upper {
            None
        } else {
            Some(Self { lower, upper })
        }
    }

    /// Builds `value <= upper`.
    pub fn at_most(upper: i64) -> Self {
        Self {
            lower: i64::MIN,
            upper,
        }
    }

    /// Builds `value >= lower`.
    pub fn at_least(lower: i64) -> Self {
        Self {
            lower,
            upper: i64::MAX,
        }
    }

    /// The inclusive lower bound.
    pub fn lower(&self) -> i64 {
        self.lower
    }

    /// The inclusive upper bound.
    pub fn upper(&self) -> i64 {
        self.upper
    }

    /// True when this interval restricts nothing.
    pub fn is_unbounded(&self) -> bool {
        *self == Self::UNBOUNDED
    }

    /// True when `value` falls inside the interval.
    pub fn permits(&self, value: i64) -> bool {
        self.lower <= value && value <= self.upper
    }

    /// True when every value this interval admits is admitted by `other`.
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.lower >= other.lower && self.upper <= other.upper
    }

    /// Intersects two intervals, or `None` if they do not overlap.
    pub fn meet(&self, other: &Self) -> Option<Self> {
        Self::between(self.lower.max(other.lower), self.upper.min(other.upper))
    }
}

/// A restriction over symbolic values.
///
/// The two forms compose in opposite directions, and getting that backwards is
/// the single most dangerous mistake in this file:
///
/// ```text
/// Allowed  meets by intersection   (fewer symbols permitted)
/// Denied   meets by union          (more symbols forbidden)
/// ```
///
/// Implementing `Denied` with intersection fails open, which expands physical
/// authority rather than merely reducing availability.
///
/// There is no `Allowed`/`Denied` asymmetry problem when the two mix: a
/// permitted set minus a forbidden set is again a permitted set, so the meet
/// stays closed over these two variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SymbolSet {
    /// Only these symbols are permitted.
    Allowed(BTreeSet<Symbol>),
    /// Every symbol except these is permitted.
    Denied(BTreeSet<Symbol>),
}

impl SymbolSet {
    /// Builds an allow-list, or `None` if it is empty.
    ///
    /// An empty allow-list permits nothing, which is BOTTOM rather than a
    /// constraint. The caller turns `None` into no authority.
    pub fn allowed<I: IntoIterator<Item = Symbol>>(symbols: I) -> Option<Self> {
        let set: BTreeSet<Symbol> = symbols.into_iter().collect();
        if set.is_empty() {
            None
        } else {
            Some(Self::Allowed(set))
        }
    }

    /// Builds a deny-list. An empty deny-list restricts nothing.
    pub fn denied<I: IntoIterator<Item = Symbol>>(symbols: I) -> Self {
        Self::Denied(symbols.into_iter().collect())
    }

    /// True when this restricts nothing.
    pub fn is_trivial(&self) -> bool {
        matches!(self, Self::Denied(d) if d.is_empty())
    }

    /// True when `symbol` is permitted.
    pub fn permits(&self, symbol: &Symbol) -> bool {
        match self {
            Self::Allowed(a) => a.contains(symbol),
            Self::Denied(d) => !d.contains(symbol),
        }
    }

    /// True when every symbol this admits is admitted by `other`.
    ///
    /// `Denied` is never a subset of `Allowed`: the universe of symbols is open,
    /// so a deny-list always admits symbols no finite allow-list names.
    pub fn is_subset_of(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Allowed(a), Self::Allowed(b)) => a.is_subset(b),
            (Self::Denied(a), Self::Denied(b)) => b.is_subset(a),
            (Self::Allowed(a), Self::Denied(d)) => a.is_disjoint(d),
            (Self::Denied(_), Self::Allowed(_)) => false,
        }
    }

    /// Combines two restrictions, or `None` if nothing remains permitted.
    pub fn meet(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Allowed(a), Self::Allowed(b)) => Self::allowed(a.intersection(b).cloned()),
            (Self::Denied(a), Self::Denied(b)) => Some(Self::denied(a.union(b).cloned())),
            (Self::Allowed(a), Self::Denied(d)) | (Self::Denied(d), Self::Allowed(a)) => {
                Self::allowed(a.difference(d).cloned())
            }
        }
    }
}

/// A restriction on one capability parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamConstraint {
    /// The argument must be a scalar inside this interval.
    Numeric(Interval),
    /// The argument must be a symbol this set admits.
    Symbolic(SymbolSet),
}

impl ParamConstraint {
    /// Convenience constructor for `value <= upper`.
    pub fn at_most(upper: i64) -> Self {
        Self::Numeric(Interval::at_most(upper))
    }

    /// Convenience constructor for `value >= lower`.
    pub fn at_least(lower: i64) -> Self {
        Self::Numeric(Interval::at_least(lower))
    }

    /// True when this restricts nothing, and so can be dropped from a
    /// [`crate::ConstraintSet`] without changing what it permits.
    pub fn is_trivial(&self) -> bool {
        match self {
            Self::Numeric(i) => i.is_unbounded(),
            Self::Symbolic(s) => s.is_trivial(),
        }
    }

    /// True when `value` is permitted.
    ///
    /// A numeric constraint admits only scalars, and a symbolic constraint only
    /// symbols. A mismatched argument is refused rather than ignored.
    pub fn permits(&self, value: &ParamValue) -> bool {
        match (self, value) {
            (Self::Numeric(i), ParamValue::Scalar(v)) => i.permits(*v),
            (Self::Symbolic(s), ParamValue::Symbol(v)) => s.permits(v),
            (Self::Numeric(_), ParamValue::Symbol(_))
            | (Self::Symbolic(_), ParamValue::Scalar(_)) => false,
        }
    }

    /// True when every argument this admits is admitted by `other`.
    ///
    /// Constraints over different value domains admit disjoint argument sets,
    /// so neither contains the other.
    pub fn is_subset_of(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Numeric(a), Self::Numeric(b)) => a.is_subset_of(b),
            (Self::Symbolic(a), Self::Symbolic(b)) => a.is_subset_of(b),
            (Self::Numeric(_), Self::Symbolic(_)) | (Self::Symbolic(_), Self::Numeric(_)) => false,
        }
    }

    /// Combines two constraints on the same parameter, or `None` if nothing
    /// remains permitted.
    ///
    /// Mixing value domains yields `None`. This is not a special case: a numeric
    /// constraint permits only scalar arguments and a symbolic one only symbolic
    /// arguments, so their intersection is genuinely empty.
    pub fn meet(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Numeric(a), Self::Numeric(b)) => a.meet(b).map(Self::Numeric),
            (Self::Symbolic(a), Self::Symbolic(b)) => a.meet(b).map(Self::Symbolic),
            (Self::Numeric(_), Self::Symbolic(_)) | (Self::Symbolic(_), Self::Numeric(_)) => None,
        }
    }
}
