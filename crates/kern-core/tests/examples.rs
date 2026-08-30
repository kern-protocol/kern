//! Readable examples of the authority algebra.
//!
//! The property tests in `algebra.rs` establish that the algebra is correct.
//! These establish that it is the algebra we meant. A reviewer should be able
//! to read these without reconstructing the lattice in their head.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use kern_core::{
    ActionProposal, CapabilityName, CapabilitySchema, ConstraintSet, DeviceId, Interval,
    NormalizedActionProposal, ParamConstraint, ParamDomain, ParamName, ParamSpec, ParamValue,
    PolicyDecision, SubjectId, Symbol, SymbolSet,
};

fn param(name: &str) -> ParamName {
    ParamName::new(name)
}

fn sym(name: &str) -> Symbol {
    Symbol::new(name)
}

fn numeric(name: &str, constraint: ParamConstraint) -> ConstraintSet {
    ConstraintSet::from_constraints([(param(name), constraint)])
}

fn allowed(name: &str, symbols: &[&str]) -> ConstraintSet {
    let set = SymbolSet::allowed(symbols.iter().map(|s| sym(s))).expect("non-empty allow-list");
    ConstraintSet::from_constraints([(param(name), ParamConstraint::Symbolic(set))])
}

fn denied(name: &str, symbols: &[&str]) -> ConstraintSet {
    let set = SymbolSet::denied(symbols.iter().map(|s| sym(s)));
    ConstraintSet::from_constraints([(param(name), ParamConstraint::Symbolic(set))])
}

/// speed <= 1.0  meet  speed <= 0.5   =>   speed <= 0.5
///
/// Speeds are millimetres per second, so the algebra stays in integers.
#[test]
fn tighter_upper_bound_wins() {
    let loose = numeric("max_speed", ParamConstraint::at_most(1000));
    let tight = numeric("max_speed", ParamConstraint::at_most(500));

    assert_eq!(loose.meet(&tight), tight);

    // The order is partial, so state the direction rather than negating `<=`:
    // the tighter bound grants strictly less authority.
    assert_eq!(tight.partial_cmp(&loose), Some(Ordering::Less));
}

/// allowed = {lobby, cafe}  meet  allowed = {cafe, storage}   =>   {cafe}
#[test]
fn allow_lists_intersect() {
    let left = allowed("destination", &["lobby", "cafe"]);
    let right = allowed("destination", &["cafe", "storage"]);

    assert_eq!(left.meet(&right), allowed("destination", &["cafe"]));
}

/// x >= 10  meet  x <= 5   =>   BOTTOM
#[test]
fn inverted_bounds_collapse_to_bottom() {
    let floor = numeric("x", ParamConstraint::at_least(10));
    let ceiling = numeric("x", ParamConstraint::at_most(5));

    assert!(floor.meet(&ceiling).is_no_authority());
}

/// Deny-lists accumulate. Meeting two denials forbids the union, not the
/// intersection: forbidding fewer things on composition would fail open.
#[test]
fn deny_lists_union() {
    let left = denied("zone", &["staff_only"]);
    let right = denied("zone", &["storage"]);

    assert_eq!(
        left.meet(&right),
        denied("zone", &["staff_only", "storage"])
    );
}

/// An allow-list met with a deny-list is the allow-list minus the denials.
#[test]
fn denial_removes_from_allow_list() {
    let allow = allowed("destination", &["lobby", "cafe", "storage"]);
    let deny = denied("destination", &["storage"]);

    assert_eq!(
        allow.meet(&deny),
        allowed("destination", &["lobby", "cafe"])
    );
}

/// Denying everything an allow-list offered leaves no authority.
#[test]
fn denying_every_allowed_symbol_collapses_to_bottom() {
    let allow = allowed("destination", &["cafe"]);
    let deny = denied("destination", &["cafe"]);

    assert!(allow.meet(&deny).is_no_authority());
}

/// The same parameter constrained under two different value domains permits
/// nothing: a numeric bound admits only scalars, a symbol set only symbols.
#[test]
fn mixed_value_domains_collapse_to_bottom() {
    let numeric_bound = numeric("target", ParamConstraint::at_most(5));
    let symbolic_bound = allowed("target", &["cafe"]);

    assert!(numeric_bound.meet(&symbolic_bound).is_no_authority());
}

/// TOP is the identity, BOTTOM absorbs.
#[test]
fn top_and_bottom_behave() {
    let policy = numeric("max_speed", ParamConstraint::at_most(500));

    assert_eq!(ConstraintSet::unconstrained().meet(&policy), policy);
    assert!(ConstraintSet::no_authority()
        .meet(&policy)
        .is_no_authority());
    assert_eq!(ConstraintSet::meet_all([]), ConstraintSet::unconstrained());
}

/// A constraint that restricts nothing is dropped, so it cannot be mistaken for
/// evidence that a parameter is governed.
#[test]
fn trivial_constraints_normalize_to_top() {
    let unbounded = ConstraintSet::from_constraints([(
        param("max_speed"),
        ParamConstraint::Numeric(Interval::UNBOUNDED),
    )]);
    let empty_denial = denied("zone", &[]);

    assert!(unbounded.is_unconstrained());
    assert!(empty_denial.is_unconstrained());
}

/// Composing policies never widens authority, whichever order they arrive in.
#[test]
fn composition_only_restricts() {
    let speed = numeric("max_speed", ParamConstraint::at_most(500));
    let zones = allowed("destination", &["lobby", "cafe"]);
    let force = numeric("max_force", ParamConstraint::at_most(15));

    let effective = ConstraintSet::meet_all([speed.clone(), zones.clone(), force.clone()]);
    let reordered = ConstraintSet::meet_all([force.clone(), speed.clone(), zones.clone()]);

    assert_eq!(effective, reordered);
    assert!(effective <= speed);
    assert!(effective <= zones);
    assert!(effective <= force);
}

/// A parameter the caller did not supply has not satisfied its bound. Kern
/// fails closed rather than treating a missing argument as unconstrained.
#[test]
fn missing_parameter_is_refused() {
    let policy = numeric("max_speed", ParamConstraint::at_most(500));

    assert!(!policy.permits(&BTreeMap::new()));
}

fn navigate_schema() -> CapabilitySchema {
    CapabilitySchema::new(
        CapabilityName::new("navigate").expect("valid capability name"),
        [
            (param("max_speed"), ParamSpec::required(ParamDomain::Scalar)),
            (
                param("destination"),
                ParamSpec::required(ParamDomain::Symbol),
            ),
        ],
    )
    .expect("well-formed schema")
}

/// Authority evaluation accepts only schema-validated proposals, so the
/// examples below go through normalization exactly as the policy layer does.
fn proposal(speed: i64, destination: &str) -> NormalizedActionProposal {
    let raw = ActionProposal::new(
        SubjectId::new("planner_a"),
        DeviceId::new("cafe_bot_01"),
        CapabilityName::new("navigate").expect("valid capability name"),
    )
    .with_param(param("max_speed"), ParamValue::Scalar(speed))
    .with_param(param("destination"), ParamValue::Symbol(sym(destination)));

    navigate_schema().normalize(&raw).expect("valid proposal")
}

/// The three decision outcomes, on one policy.
#[test]
fn evaluate_distinguishes_three_outcomes() {
    let policy = ConstraintSet::meet_all([
        numeric("max_speed", ParamConstraint::at_most(500)),
        allowed("destination", &["lobby", "cafe"]),
    ]);

    assert!(policy.evaluate(&proposal(400, "cafe")).is_authorized());

    // Over the speed bound: the grantable bounds come back, the proposal is not
    // silently rewritten to 500.
    match policy.evaluate(&proposal(900, "cafe")) {
        PolicyDecision::NotAuthorizedAsProposed { grantable } => assert_eq!(grantable, policy),
        other => panic!("expected NotAuthorizedAsProposed, got {other:?}"),
    }

    assert_eq!(
        ConstraintSet::no_authority().evaluate(&proposal(400, "cafe")),
        PolicyDecision::Denied
    );
}

/// A destination outside the allow-list is refused even at a legal speed.
#[test]
fn out_of_scope_destination_is_not_authorized() {
    let policy = allowed("destination", &["lobby", "cafe"]);

    assert!(!policy.evaluate(&proposal(400, "storage")).is_authorized());
}

/// Sets that restrict unrelated parameters are incomparable, not equal.
#[test]
fn unrelated_policies_are_incomparable() {
    let speed = numeric("max_speed", ParamConstraint::at_most(500));
    let force = numeric("max_force", ParamConstraint::at_most(15));

    assert_eq!(speed.partial_cmp(&force), None);
}

// -- Symbolic ordering under an open symbol universe --------------------------
//
// Kern never enumerates the set of symbols a device might accept, so a
// deny-list always admits symbols no finite allow-list names. That single fact
// decides every comparison below.

/// A smaller allow-list grants strictly less.
#[test]
fn smaller_allow_list_grants_less() {
    let narrow = allowed("destination", &["lobby"]);
    let wide = allowed("destination", &["lobby", "cafe"]);

    assert_eq!(narrow.partial_cmp(&wide), Some(Ordering::Less));
}

/// A larger deny-list grants strictly less: forbidding more permits less.
#[test]
fn larger_deny_list_grants_less() {
    let forbids_more = denied("zone", &["staff_only", "storage"]);
    let forbids_less = denied("zone", &["staff_only"]);

    assert_eq!(
        forbids_more.partial_cmp(&forbids_less),
        Some(Ordering::Less)
    );
}

/// An allow-list disjoint from a deny-list grants strictly less: every symbol
/// it names survives the denial, and the denial still admits everything else.
#[test]
fn allow_list_disjoint_from_denial_grants_less() {
    let allow = allowed("destination", &["lobby", "cafe"]);
    let deny = denied("destination", &["storage"]);

    assert_eq!(allow.partial_cmp(&deny), Some(Ordering::Less));
}

/// An allow-list overlapping a deny-list is incomparable: it permits a symbol
/// the denial forbids, and the denial permits symbols it does not name.
#[test]
fn overlapping_allow_and_denial_are_incomparable() {
    let allow = allowed("destination", &["cafe"]);
    let deny = denied("destination", &["cafe"]);

    assert_eq!(allow.partial_cmp(&deny), None);
}

/// A deny-list is never *below* an allow-list, whatever the overlap. Concluding
/// otherwise would require knowing the symbol universe is closed, and it is not.
///
/// Disjoint, the denial is strictly above: it admits every symbol the allow-list
/// names, plus every symbol nobody named. Overlapping, the two are incomparable.
#[test]
fn denial_is_never_below_an_allow_list() {
    let deny = denied("destination", &["storage"]);

    let disjoint = allowed("destination", &["lobby", "cafe", "table_7"]);
    assert_eq!(deny.partial_cmp(&disjoint), Some(Ordering::Greater));

    let overlapping = allowed("destination", &["lobby", "storage"]);
    assert_eq!(deny.partial_cmp(&overlapping), None);
}
