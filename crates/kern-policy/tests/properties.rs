//! Property tests for evaluation.
//!
//! The load-bearing property is monotonicity of *authority*, not of the
//! decision enum: composing one more applicable policy can only preserve or
//! reduce what is permitted. The decision-level consequences are derived from
//! it, and one of them needs a precondition — see
//! `adding_a_policy_cannot_authorize_a_refused_proposal`.

use std::collections::BTreeMap;

use kern_core::{
    ActionProposal, CapabilityName, CapabilitySchema, ConstraintSet, DeviceId,
    NormalizedActionProposal, ParamConstraint, ParamDomain, ParamName, ParamSpec, ParamValue,
    PolicyDecision, SubjectId, Symbol, SymbolSet,
};
use kern_policy::{Authority, CapabilityRegistry, Policy, PolicyId, PolicySet, Selector};
use proptest::prelude::*;

const SUBJECTS: [&str; 3] = ["planner_a", "planner_b", "planner_c"];
const DEVICES: [&str; 2] = ["cafe_bot_01", "cafe_bot_02"];
const DESTINATIONS: [&str; 3] = ["lobby", "cafe", "storage"];

fn param(name: &str) -> ParamName {
    ParamName::new(name)
}

fn navigate_schema() -> CapabilitySchema {
    CapabilitySchema::new(
        CapabilityName::new("navigate").expect("valid capability name"),
        [
            (
                param("destination"),
                ParamSpec::required(ParamDomain::Symbol),
            ),
            (param("max_speed"), ParamSpec::required(ParamDomain::Scalar)),
        ],
    )
    .expect("well-formed schema")
}

fn registry() -> CapabilityRegistry {
    let mut registry = CapabilityRegistry::new();
    for device in DEVICES {
        registry
            .register(DeviceId::new(device), navigate_schema())
            .expect("distinct devices");
    }
    registry
}

/// The authority a policy set grants for one proposal, straight from the
/// algebra. This is `meet_all` with no empty-set handling, which is exactly why
/// the evaluator must special-case emptiness itself: here, no applicable policy
/// yields TOP.
fn effective(policies: &PolicySet, proposal: &NormalizedActionProposal) -> ConstraintSet {
    ConstraintSet::meet_all(
        policies
            .applicable(proposal)
            .into_iter()
            .map(|policy| policy.constraints().clone()),
    )
}

fn set_of(policies: &[Policy]) -> PolicySet {
    PolicySet::from_policies(policies.iter().cloned()).expect("ids are index-derived")
}

fn decide(policies: &[Policy], proposal: &NormalizedActionProposal) -> PolicyDecision {
    let (_, decision, _) = Authority::new(registry(), set_of(policies))
        .decide(proposal.clone())
        .into_parts();
    decision
}

// -- strategies ---------------------------------------------------------------

fn selector<T: Ord + Clone + core::fmt::Debug + 'static>(
    values: &'static [&'static str],
    wrap: fn(&'static str) -> T,
) -> impl Strategy<Value = Selector<T>> {
    prop_oneof![
        1 => Just(Selector::Any),
        3 => prop::sample::select(values.to_vec()).prop_map(move |v| Selector::Exactly(wrap(v))),
        2 => prop::collection::vec(prop::sample::select(values.to_vec()), 1..=values.len())
            .prop_map(move |vs| Selector::any_of(vs.into_iter().map(wrap)).expect("non-empty")),
    ]
}

/// Never TOP: `Policy::new` refuses an unconstrained set, so every generated
/// policy carries at least one real bound.
fn constraints() -> impl Strategy<Value = ConstraintSet> {
    let speed =
        (0i64..1000).prop_map(|limit| (param("max_speed"), ParamConstraint::at_most(limit)));
    let destination = prop::collection::btree_set(
        prop::sample::select(DESTINATIONS.to_vec()).prop_map(Symbol::new),
        1..=3,
    )
    .prop_map(|set| {
        (
            param("destination"),
            ParamConstraint::Symbolic(SymbolSet::allowed(set).expect("non-empty")),
        )
    });

    prop_oneof![
        speed
            .clone()
            .prop_map(|s| ConstraintSet::from_constraints([s])),
        destination
            .clone()
            .prop_map(|d| ConstraintSet::from_constraints([d])),
        (speed, destination).prop_map(|(s, d)| ConstraintSet::from_constraints([s, d])),
    ]
}

fn policy(id: PolicyId) -> impl Strategy<Value = Policy> {
    (
        selector(&SUBJECTS, SubjectId::new),
        selector(&DEVICES, DeviceId::new),
        prop_oneof![
            1 => Just(Selector::Any),
            3 => Just(Selector::Exactly(CapabilityName::new("navigate").expect("valid capability name"))),
        ],
        constraints(),
    )
        .prop_map(move |(subject, device, capability, constraints)| {
            Policy::new(id.clone(), subject, device, capability, constraints)
                .expect("constraints are never unconstrained")
        })
}

fn policies(max: usize) -> impl Strategy<Value = Vec<Policy>> {
    prop::collection::vec(0usize..=3, 0..=max).prop_flat_map(move |shape| {
        shape
            .into_iter()
            .enumerate()
            .map(|(index, _)| policy(PolicyId::new(format!("p{index}"))).boxed())
            .collect::<Vec<_>>()
    })
}

fn proposal() -> impl Strategy<Value = NormalizedActionProposal> {
    (
        prop::sample::select(SUBJECTS.to_vec()),
        prop::sample::select(DEVICES.to_vec()),
        prop::sample::select(DESTINATIONS.to_vec()),
        0i64..1200,
    )
        .prop_map(|(actor, device, destination, speed)| {
            let raw = ActionProposal::new(
                SubjectId::new(actor),
                DeviceId::new(device),
                CapabilityName::new("navigate").expect("valid capability name"),
            )
            .with_param(
                param("destination"),
                ParamValue::Symbol(Symbol::new(destination)),
            )
            .with_param(param("max_speed"), ParamValue::Scalar(speed));

            navigate_schema().normalize(&raw).expect("valid proposal")
        })
}

fn params_of(proposal: &NormalizedActionProposal) -> BTreeMap<ParamName, ParamValue> {
    proposal.params().clone()
}

proptest! {
    /// The frozen monotonicity property, stated on authority:
    ///
    /// ```text
    /// effective(A + {p}) <= effective(A)
    /// ```
    #[test]
    fn composing_a_policy_never_widens_authority(
        base in policies(3),
        extra in policy(PolicyId::new("extra")),
        proposal in proposal(),
    ) {
        let mut extended = base.clone();
        extended.push(extra);

        let before = effective(&set_of(&base), &proposal);
        let after = effective(&set_of(&extended), &proposal);

        prop_assert!(after <= before);
    }

    /// The direct consequence for a fixed proposal: what was outside the
    /// effective authority cannot become permitted by composing more policy.
    #[test]
    fn composition_cannot_start_permitting_a_refused_proposal(
        base in policies(3),
        extra in policy(PolicyId::new("extra")),
        proposal in proposal(),
    ) {
        let mut extended = base.clone();
        extended.push(extra);

        let params = params_of(&proposal);
        let before = effective(&set_of(&base), &proposal);
        let after = effective(&set_of(&extended), &proposal);

        if !before.permits(&params) {
            prop_assert!(!after.permits(&params));
        }
    }

    /// The decision-level consequence, and the precondition it needs.
    ///
    /// Without at least one applicable policy already, `Denied` means "nobody
    /// granted anything" rather than "authority refused this", and adding a
    /// policy legitimately turns it into `Authorized`. That is the empty-set
    /// case, not a widening of authority.
    #[test]
    fn adding_a_policy_cannot_authorize_a_refused_proposal(
        base in policies(3),
        extra in policy(PolicyId::new("extra")),
        proposal in proposal(),
    ) {
        let set = set_of(&base);
        prop_assume!(!set.applicable(&proposal).is_empty());

        let mut extended = base.clone();
        extended.push(extra);

        if !decide(&base, &proposal).is_authorized() {
            prop_assert!(!decide(&extended, &proposal).is_authorized());
        }
    }

    /// No applicable policy is always a denial, never an unconstrained grant.
    #[test]
    fn no_applicable_policy_always_denies(
        base in policies(3),
        proposal in proposal(),
    ) {
        let set = set_of(&base);
        prop_assume!(set.applicable(&proposal).is_empty());

        let evaluation = Authority::new(registry(), set).decide(proposal);

        prop_assert_eq!(evaluation.decision(), &PolicyDecision::Denied);
        prop_assert!(evaluation.applied().is_empty());
    }

    /// An empty policy set grants nothing to anyone, for every proposal.
    #[test]
    fn empty_policy_set_denies_everything(proposal in proposal()) {
        let evaluation = Authority::new(registry(), PolicySet::new()).decide(proposal);

        prop_assert_eq!(evaluation.decision(), &PolicyDecision::Denied);
        prop_assert!(evaluation.applied().is_empty());
    }

    /// The result does not depend on the order policies were inserted in.
    #[test]
    fn insertion_order_does_not_change_the_result(
        base in policies(4),
        proposal in proposal(),
    ) {
        let forward = Authority::new(registry(), set_of(&base)).decide(proposal.clone());

        let mut reversed_input = base.clone();
        reversed_input.reverse();
        let reversed = Authority::new(registry(), set_of(&reversed_input)).decide(proposal);

        prop_assert_eq!(forward, reversed);
    }

    /// A policy that does not apply changes nothing at all: not the decision,
    /// not the recorded provenance.
    #[test]
    fn non_applicable_policy_changes_nothing(
        base in policies(3),
        extra in policy(PolicyId::new("extra")),
        proposal in proposal(),
    ) {
        prop_assume!(!extra.applies_to(&proposal));

        let mut extended = base.clone();
        extended.push(extra);

        let before = Authority::new(registry(), set_of(&base)).decide(proposal.clone());
        let after = Authority::new(registry(), set_of(&extended)).decide(proposal);

        prop_assert_eq!(before, after);
    }

    /// `applied` is exactly the applicable policies, in identifier order, and
    /// is empty only when nothing applied.
    #[test]
    fn applied_is_deterministic_and_ordered(
        base in policies(4),
        proposal in proposal(),
    ) {
        let set = set_of(&base);
        let expected: Vec<PolicyId> = set
            .applicable(&proposal)
            .into_iter()
            .map(|policy| policy.id().clone())
            .collect();

        let evaluation = Authority::new(registry(), set).decide(proposal);

        prop_assert_eq!(evaluation.applied(), expected.as_slice());

        let mut sorted = evaluation.applied().to_vec();
        sorted.sort();
        prop_assert_eq!(evaluation.applied(), sorted.as_slice());
    }

    /// Evaluation is pure: same authority, same proposal, same answer.
    #[test]
    fn evaluation_is_deterministic(base in policies(3), proposal in proposal()) {
        let authority = Authority::new(registry(), set_of(&base));

        prop_assert_eq!(
            authority.decide(proposal.clone()),
            authority.decide(proposal)
        );
    }
}
