//! The authority lattice.
//!
//! See the crate docs for the definition of the ordering. Everything here
//! implements that one definition.

use alloc::collections::BTreeMap;
use core::cmp::Ordering;

use crate::constraint::ParamConstraint;
use crate::decision::PolicyDecision;
use crate::ids::ParamName;
use crate::proposal::ParamValue;
use crate::schema::NormalizedActionProposal;

/// The internal shape of a [`ConstraintSet`].
///
/// Private so the canonical-form invariant cannot be broken from outside:
///
/// - `Bounded` is never empty, and never holds a trivial constraint.
/// - No authority is `NoAuthority`, never a `Bounded` map that happens to
///   permit nothing.
///
/// The invariant is what makes derived structural equality coincide with
/// semantic equality, which the `meet(TOP, A) == A` property depends on.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Repr {
    Unconstrained,
    Bounded(BTreeMap<ParamName, ParamConstraint>),
    NoAuthority,
}

/// A set of restrictions, denoting the set of operations it permits.
///
/// Three states, all explicitly distinguishable:
///
/// ```text
/// unconstrained authority   TOP      permits every operation
/// constrained authority              permits operations satisfying its bounds
/// no authority              BOTTOM   permits nothing
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstraintSet(Repr);

impl ConstraintSet {
    /// TOP: unconstrained authority, the identity element for [`Self::meet`].
    pub fn unconstrained() -> Self {
        Self(Repr::Unconstrained)
    }

    /// BOTTOM: no authority, the absorbing element for [`Self::meet`].
    pub fn no_authority() -> Self {
        Self(Repr::NoAuthority)
    }

    /// Builds a constraint set from parameter restrictions.
    ///
    /// Repeated names are combined with [`ParamConstraint::meet`], so the
    /// result never depends on how the caller grouped them. A contradiction
    /// anywhere collapses the whole set to BOTTOM.
    pub fn from_constraints<I>(constraints: I) -> Self
    where
        I: IntoIterator<Item = (ParamName, ParamConstraint)>,
    {
        let mut map: BTreeMap<ParamName, ParamConstraint> = BTreeMap::new();
        for (name, constraint) in constraints {
            let merged = match map.get(&name) {
                Some(existing) => match existing.meet(&constraint) {
                    Some(merged) => merged,
                    None => return Self::no_authority(),
                },
                None => constraint,
            };
            map.insert(name, merged);
        }
        Self::from_map(map)
    }

    /// Normalizes a map into canonical form.
    fn from_map(mut map: BTreeMap<ParamName, ParamConstraint>) -> Self {
        map.retain(|_, constraint| !constraint.is_trivial());
        if map.is_empty() {
            Self::unconstrained()
        } else {
            Self(Repr::Bounded(map))
        }
    }

    /// True for TOP.
    pub fn is_unconstrained(&self) -> bool {
        matches!(self.0, Repr::Unconstrained)
    }

    /// True for BOTTOM.
    pub fn is_no_authority(&self) -> bool {
        matches!(self.0, Repr::NoAuthority)
    }

    /// The restriction on one parameter, if this set constrains it.
    pub fn get(&self, name: &ParamName) -> Option<&ParamConstraint> {
        match &self.0 {
            Repr::Bounded(map) => map.get(name),
            Repr::Unconstrained | Repr::NoAuthority => None,
        }
    }

    /// Iterates the restrictions, in parameter-name order.
    ///
    /// Empty for both TOP and BOTTOM. Use [`Self::is_no_authority`] to tell
    /// those apart; do not infer authority from this being empty.
    pub fn iter(&self) -> impl Iterator<Item = (&ParamName, &ParamConstraint)> {
        let map = match &self.0 {
            Repr::Bounded(map) => Some(map),
            Repr::Unconstrained | Repr::NoAuthority => None,
        };
        map.into_iter().flatten()
    }

    /// The greatest lower bound of two constraint sets.
    ///
    /// The result permits exactly the operations both operands permit. There is
    /// no case in which it permits more than either, which is what makes
    /// composing policies safe.
    pub fn meet(&self, other: &Self) -> Self {
        match (&self.0, &other.0) {
            (Repr::NoAuthority, _) | (_, Repr::NoAuthority) => Self::no_authority(),
            (Repr::Unconstrained, _) => other.clone(),
            (_, Repr::Unconstrained) => self.clone(),
            (Repr::Bounded(a), Repr::Bounded(b)) => {
                let mut merged = a.clone();
                for (name, constraint) in b {
                    match merged.get(name) {
                        None => {
                            merged.insert(name.clone(), constraint.clone());
                        }
                        Some(existing) => match existing.meet(constraint) {
                            None => return Self::no_authority(),
                            Some(value) => {
                                merged.insert(name.clone(), value);
                            }
                        },
                    }
                }
                Self::from_map(merged)
            }
        }
    }

    /// Folds `meet` over many constraint sets, starting from TOP.
    ///
    /// An empty input yields TOP. That is the only defensible answer, and it is
    /// why TOP has to exist as a value rather than as a comment.
    pub fn meet_all<I>(sets: I) -> Self
    where
        I: IntoIterator<Item = Self>,
    {
        sets.into_iter()
            .fold(Self::unconstrained(), |acc, next| acc.meet(&next))
    }

    /// True when this set permits an operation carrying `params`.
    ///
    /// This is the operational definition of the permitted set. Everything else
    /// in this module is a decision procedure for it.
    ///
    /// A constrained parameter that is absent from `params` is refused. Kern
    /// fails closed (AGENT.md section 4.5): a bound the caller did not supply a
    /// value for has not been satisfied, so it cannot be treated as met.
    pub fn permits(&self, params: &BTreeMap<ParamName, ParamValue>) -> bool {
        match &self.0 {
            Repr::NoAuthority => false,
            Repr::Unconstrained => true,
            Repr::Bounded(map) => map.iter().all(|(name, constraint)| {
                params
                    .get(name)
                    .is_some_and(|value| constraint.permits(value))
            }),
        }
    }

    /// True when every operation this set permits is also permitted by `other`.
    fn is_subset_of(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Repr::NoAuthority, _) => true,
            (_, Repr::NoAuthority) => false,
            (_, Repr::Unconstrained) => true,
            (Repr::Unconstrained, Repr::Bounded(_)) => false,
            (Repr::Bounded(a), Repr::Bounded(b)) => b
                .iter()
                .all(|(name, wanted)| a.get(name).is_some_and(|held| held.is_subset_of(wanted))),
        }
    }

    /// Decides a schema-validated proposal against these constraints.
    ///
    /// This is the authority-evaluation primitive, and it accepts only a
    /// [`NormalizedActionProposal`]. There is deliberately no variant taking an
    /// unvalidated [`crate::ActionProposal`]: a second, weaker path into the
    /// same decision is a path someone will eventually take.
    ///
    /// The caller is responsible for selecting the constraints that apply to
    /// the proposal's subject, device, and capability, and for handling the
    /// case where *no* policy applied — see AGENT.md section 5, since an empty
    /// composition is TOP rather than a denial. This method answers only the
    /// parameter-bounds question.
    ///
    /// An over-reaching proposal is never rewritten into something executable.
    /// It comes back as [`PolicyDecision::NotAuthorizedAsProposed`] carrying the
    /// bounds that *would* be granted, and the planner has to decide what to do
    /// with that (AGENT.md section 5).
    pub fn evaluate(&self, proposal: &NormalizedActionProposal) -> PolicyDecision {
        if self.is_no_authority() {
            return PolicyDecision::Denied;
        }
        if self.permits(proposal.params()) {
            PolicyDecision::Authorized {
                constraints: self.clone(),
            }
        } else {
            PolicyDecision::NotAuthorizedAsProposed {
                grantable: self.clone(),
            }
        }
    }
}

/// The authority ordering: `a <= b` means `a` grants no more authority than `b`.
///
/// Partial, not total. Two constraint sets that restrict different parameters,
/// or that overlap without one containing the other, are incomparable and
/// compare as `None`.
impl PartialOrd for ConstraintSet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self.is_subset_of(other), other.is_subset_of(self)) {
            (true, true) => Some(Ordering::Equal),
            (true, false) => Some(Ordering::Less),
            (false, true) => Some(Ordering::Greater),
            (false, false) => None,
        }
    }
}
