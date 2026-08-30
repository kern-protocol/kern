//! Property tests for the authority algebra.
//!
//! These are part of the implementation, not cleanup after it. `ConstraintSet`
//! is only useful if composing policies provably cannot widen authority, and
//! "provably" here means the meet-semilattice laws hold for generated inputs
//! rather than for the three cases someone thought to write down.
//!
//! Note what is sampled and what is not: the laws over `meet` and `<=` are
//! checked structurally, while the two properties linking `<=` and `meet` back
//! to `permits` are checked against generated arguments. Those are evidence,
//! not proof.

use std::collections::BTreeMap;

use kern_core::{
    ConstraintSet, Interval, ParamConstraint, ParamName, ParamValue, Symbol, SymbolSet,
};
use proptest::prelude::*;

const NUMERIC_PARAMS: [&str; 2] = ["max_speed", "max_force"];
const SYMBOLIC_PARAMS: [&str; 2] = ["destination", "zone"];
const SYMBOLS: [&str; 5] = ["lobby", "cafe", "storage", "staff_only", "table_7"];

fn symbol() -> impl Strategy<Value = Symbol> {
    prop::sample::select(SYMBOLS.to_vec()).prop_map(Symbol::new)
}

fn interval() -> impl Strategy<Value = Interval> {
    prop_oneof![
        (-20i64..20).prop_map(Interval::at_least),
        (-20i64..20).prop_map(Interval::at_most),
        (-20i64..20, 0i64..20)
            .prop_map(|(low, width)| Interval::between(low, low + width).expect("low <= low+width")),
    ]
}

fn symbol_set() -> impl Strategy<Value = SymbolSet> {
    prop_oneof![
        prop::collection::btree_set(symbol(), 1..=4)
            .prop_map(|set| SymbolSet::allowed(set).expect("non-empty allow-list")),
        prop::collection::btree_set(symbol(), 0..=3).prop_map(SymbolSet::denied),
    ]
}

/// Parameter names are bound to a value domain, so generated sets are mostly
/// meaningful rather than mostly domain contradictions. Cross-domain conflicts
/// get their own dedicated property below.
fn entry() -> impl Strategy<Value = (ParamName, ParamConstraint)> {
    prop_oneof![
        (prop::sample::select(NUMERIC_PARAMS.to_vec()), interval())
            .prop_map(|(name, bound)| (ParamName::new(name), ParamConstraint::Numeric(bound))),
        (prop::sample::select(SYMBOLIC_PARAMS.to_vec()), symbol_set())
            .prop_map(|(name, set)| (ParamName::new(name), ParamConstraint::Symbolic(set))),
    ]
}

fn constraint_set() -> impl Strategy<Value = ConstraintSet> {
    prop_oneof![
        1 => Just(ConstraintSet::unconstrained()),
        1 => Just(ConstraintSet::no_authority()),
        8 => prop::collection::vec(entry(), 0..=4).prop_map(ConstraintSet::from_constraints),
    ]
}

fn params() -> impl Strategy<Value = BTreeMap<ParamName, ParamValue>> {
    prop::collection::vec(
        prop_oneof![
            (prop::sample::select(NUMERIC_PARAMS.to_vec()), -25i64..25)
                .prop_map(|(name, value)| (ParamName::new(name), ParamValue::Scalar(value))),
            (prop::sample::select(SYMBOLIC_PARAMS.to_vec()), symbol())
                .prop_map(|(name, value)| (ParamName::new(name), ParamValue::Symbol(value))),
        ],
        0..=4,
    )
    .prop_map(|entries| entries.into_iter().collect())
}

/// Two disjoint, non-empty allow-lists over the shared symbol pool.
fn disjoint_allow_lists() -> impl Strategy<Value = (SymbolSet, SymbolSet)> {
    prop::collection::vec(0u8..3, SYMBOLS.len())
        .prop_filter("both sides non-empty", |tags| {
            tags.contains(&0) && tags.contains(&1)
        })
        .prop_map(|tags| {
            let pick = |wanted: u8| {
                let chosen = SYMBOLS
                    .iter()
                    .zip(&tags)
                    .filter(|(_, tag)| **tag == wanted)
                    .map(|(name, _)| Symbol::new(*name));
                SymbolSet::allowed(chosen).expect("filtered to be non-empty")
            };
            (pick(0), pick(1))
        })
}

proptest! {
    #[test]
    fn meet_is_commutative(a in constraint_set(), b in constraint_set()) {
        prop_assert_eq!(a.meet(&b), b.meet(&a));
    }

    #[test]
    fn meet_is_associative(
        a in constraint_set(),
        b in constraint_set(),
        c in constraint_set(),
    ) {
        prop_assert_eq!(a.meet(&b).meet(&c), a.meet(&b.meet(&c)));
    }

    #[test]
    fn meet_is_idempotent(a in constraint_set()) {
        prop_assert_eq!(a.meet(&a), a.clone());
    }

    #[test]
    fn top_is_the_identity(a in constraint_set()) {
        prop_assert_eq!(ConstraintSet::unconstrained().meet(&a), a.clone());
        prop_assert_eq!(a.meet(&ConstraintSet::unconstrained()), a.clone());
    }

    #[test]
    fn bottom_absorbs(a in constraint_set()) {
        prop_assert!(ConstraintSet::no_authority().meet(&a).is_no_authority());
        prop_assert!(a.meet(&ConstraintSet::no_authority()).is_no_authority());
    }

    /// The restriction law, asserted against each operand independently rather
    /// than derived from commutativity.
    #[test]
    fn meet_restricts_the_left_operand(a in constraint_set(), b in constraint_set()) {
        prop_assert!(a.meet(&b) <= a);
    }

    #[test]
    fn meet_restricts_the_right_operand(a in constraint_set(), b in constraint_set()) {
        prop_assert!(a.meet(&b) <= b);
    }

    #[test]
    fn ordering_is_reflexive(a in constraint_set()) {
        prop_assert!(a <= a);
    }

    /// Structural ordering agrees with the operational definition: if `a <= b`
    /// then anything `a` permits, `b` permits.
    #[test]
    fn ordering_matches_permitted_operations(
        a in constraint_set(),
        b in constraint_set(),
        args in params(),
    ) {
        if a <= b {
            prop_assert!(!a.permits(&args) || b.permits(&args));
        }
    }

    /// `meet` computes exactly the intersection of permitted operations. This
    /// is the property that makes policy composition safe: no operation becomes
    /// permitted by adding a policy.
    #[test]
    fn meet_permits_exactly_the_intersection(
        a in constraint_set(),
        b in constraint_set(),
        args in params(),
    ) {
        prop_assert_eq!(
            a.meet(&b).permits(&args),
            a.permits(&args) && b.permits(&args)
        );
    }

    /// Order of composition cannot change the resulting authority.
    #[test]
    fn composition_is_order_independent(sets in prop::collection::vec(constraint_set(), 0..=4)) {
        let forward = ConstraintSet::meet_all(sets.clone());
        let reversed = ConstraintSet::meet_all(sets.iter().rev().cloned());
        prop_assert_eq!(forward, reversed);
    }

    /// Adding a policy to a composition can only preserve or reduce authority.
    #[test]
    fn adding_a_policy_never_expands_authority(
        sets in prop::collection::vec(constraint_set(), 0..=3),
        extra in constraint_set(),
    ) {
        let before = ConstraintSet::meet_all(sets.clone());
        let after = before.meet(&extra);
        prop_assert!(after <= before);
    }

    /// Disjoint numeric bounds on one parameter contradict.
    #[test]
    fn disjoint_numeric_bounds_collapse_to_bottom(
        name in prop::sample::select(NUMERIC_PARAMS.to_vec()),
        floor in -1000i64..1000,
        gap in 1i64..1000,
    ) {
        let above = ConstraintSet::from_constraints([(
            ParamName::new(name),
            ParamConstraint::at_least(floor + gap),
        )]);
        let below = ConstraintSet::from_constraints([(
            ParamName::new(name),
            ParamConstraint::at_most(floor),
        )]);
        prop_assert!(above.meet(&below).is_no_authority());
    }

    /// Disjoint allow-lists on one parameter contradict.
    #[test]
    fn disjoint_allow_lists_collapse_to_bottom(
        name in prop::sample::select(SYMBOLIC_PARAMS.to_vec()),
        (left, right) in disjoint_allow_lists(),
    ) {
        let a = ConstraintSet::from_constraints([(
            ParamName::new(name),
            ParamConstraint::Symbolic(left),
        )]);
        let b = ConstraintSet::from_constraints([(
            ParamName::new(name),
            ParamConstraint::Symbolic(right),
        )]);
        prop_assert!(a.meet(&b).is_no_authority());
    }

    /// One parameter constrained under two value domains contradicts.
    #[test]
    fn mixed_value_domains_collapse_to_bottom(
        name in prop::sample::select(NUMERIC_PARAMS.to_vec()),
        bound in interval(),
        set in symbol_set(),
    ) {
        prop_assume!(!bound.is_unbounded() && !set.is_trivial());

        let numeric = ConstraintSet::from_constraints([(
            ParamName::new(name),
            ParamConstraint::Numeric(bound),
        )]);
        let symbolic = ConstraintSet::from_constraints([(
            ParamName::new(name),
            ParamConstraint::Symbolic(set),
        )]);
        prop_assert!(numeric.meet(&symbolic).is_no_authority());
    }

    /// Canonical form survives `meet`: a contradiction is BOTTOM itself rather
    /// than a bounded set that happens to permit nothing, and no surviving
    /// constraint is one that restricts nothing.
    #[test]
    fn meet_preserves_canonical_form(a in constraint_set(), b in constraint_set()) {
        let merged = a.meet(&b);
        prop_assert!(merged.iter().all(|(_, constraint)| !constraint.is_trivial()));

        let bounded = !merged.is_no_authority() && !merged.is_unconstrained();
        prop_assert_eq!(bounded, merged.iter().count() > 0);
    }
}
