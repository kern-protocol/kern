//! Turning a proposal into a decision, deterministically.

use alloc::vec::Vec;
use core::fmt;

use kern_core::{
    ActionProposal, ConstraintSet, NormalizedActionProposal, PolicyDecision, SchemaError,
};

use crate::policy::{PolicyId, PolicySet};
use crate::registry::{CapabilityRegistry, RegistryError};

/// The request does not describe a real operation.
///
/// Distinct from [`PolicyDecision::Denied`], which says the request describes a
/// real operation that this subject may not perform. Collapsing the two would
/// hide configuration bugs inside authority answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvaluationError {
    /// The device or capability could not be resolved.
    Registry(RegistryError),
    /// The proposal is not well-formed for its capability.
    Schema(SchemaError),
}

impl From<RegistryError> for EvaluationError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<SchemaError> for EvaluationError {
    fn from(error: SchemaError) -> Self {
        Self::Schema(error)
    }
}

impl fmt::Display for EvaluationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(error) => write!(f, "{error}"),
            Self::Schema(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for EvaluationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Registry(error) => Some(error),
            Self::Schema(error) => Some(error),
        }
    }
}

/// What an evaluation concluded, and what it consulted to get there.
///
/// # A trusted artifact
///
/// Fields are private and there is no public constructor. [`Authority::decide`]
/// is the only thing that builds one, so possessing an `Evaluation` is evidence
/// that a real registry and a real policy set produced it.
///
/// That matters because downstream layers mint signed authority from an
/// authorized `Evaluation`. If this type were forgeable, safe Rust outside this
/// crate could fabricate `Authorized { constraints: unconstrained() }` and every
/// guarantee built on top would be decoration.
///
/// External safe Rust cannot construct one:
///
/// ```compile_fail
/// use kern_policy::Evaluation;
///
/// let forged = Evaluation {
///     proposal: unimplemented!(),
///     decision: unimplemented!(),
///     applied: unimplemented!(),
/// };
/// ```
///
/// Reading one you were *given* is fine, and is what the accessors are for:
///
/// ```
/// # use kern_core::{ActionProposal, CapabilityName, DeviceId, SubjectId};
/// # use kern_policy::Authority;
/// let authority = Authority::default();
/// let proposal = ActionProposal::new(
///     SubjectId::new("planner_a"),
///     DeviceId::new("cafe_bot_01"),
///     CapabilityName::new("navigate").unwrap(),
/// );
/// // An empty registry cannot resolve the capability, so this is an error
/// // rather than a denial.
/// assert!(authority.evaluate(&proposal).is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    proposal: NormalizedActionProposal,
    decision: PolicyDecision,
    applied: Vec<PolicyId>,
}

impl Evaluation {
    /// The validated proposal the decision was made about, defaults applied.
    pub fn proposal(&self) -> &NormalizedActionProposal {
        &self.proposal
    }

    /// The authority outcome.
    pub fn decision(&self) -> &PolicyDecision {
        &self.decision
    }

    /// The policies that applied, in identifier order.
    ///
    /// Together with the decision this separates the two ways a request is
    /// denied, which a later execution trace will need:
    ///
    /// ```text
    /// Denied + applied empty        no applicable authority grant existed
    /// Denied + applied non-empty    applicable authority composed to BOTTOM
    /// ```
    pub fn applied(&self) -> &[PolicyId] {
        &self.applied
    }

    /// Consumes the evaluation, yielding its parts.
    ///
    /// Safe to expose: the guarantee is about where an `Evaluation` came from,
    /// not about keeping its contents secret. Destructuring one you were handed
    /// cannot manufacture authority that was never granted.
    pub fn into_parts(self) -> (NormalizedActionProposal, PolicyDecision, Vec<PolicyId>) {
        (self.proposal, self.decision, self.applied)
    }
}

/// A capability registry and a policy set, evaluated together.
#[derive(Clone, Debug, Default)]
pub struct Authority {
    registry: CapabilityRegistry,
    policies: PolicySet,
}

impl Authority {
    /// Builds an authority from a registry and a policy set.
    pub fn new(registry: CapabilityRegistry, policies: PolicySet) -> Self {
        Self { registry, policies }
    }

    /// The capability registry.
    pub fn registry(&self) -> &CapabilityRegistry {
        &self.registry
    }

    /// The policy set.
    pub fn policies(&self) -> &PolicySet {
        &self.policies
    }

    /// Resolves, normalizes, and decides.
    ///
    /// The two failure kinds stay separate: an unresolvable or malformed
    /// request is an [`EvaluationError`], never a denial.
    pub fn evaluate(&self, proposal: &ActionProposal) -> Result<Evaluation, EvaluationError> {
        let schema = self
            .registry
            .resolve(&proposal.device, &proposal.capability)?;
        let normalized = schema.normalize(proposal)?;
        Ok(self.decide(normalized))
    }

    /// Decides a schema-validated proposal.
    ///
    /// This is the policy-evaluation primitive, and it consumes only a
    /// [`NormalizedActionProposal`]. There is no variant accepting an
    /// unvalidated proposal after the normalization boundary.
    ///
    /// The order of the steps matters, and step two in particular:
    ///
    /// ```text
    /// 1. collect applicable policies
    /// 2. if none apply                   -> Denied
    /// 3. effective = meet of their constraints
    /// 4. if effective is BOTTOM          -> Denied
    /// 5. if effective permits            -> Authorized { constraints }
    /// 6. otherwise                       -> NotAuthorizedAsProposed { grantable }
    /// ```
    ///
    /// Step 2 is not an optimisation and must not be folded into step 3. The
    /// meet of an empty set is TOP, so composing zero applicable policies would
    /// otherwise yield *unconstrained* authority. Capability existence is not
    /// authority: that a device understands an operation says nothing about who
    /// may request it.
    pub fn decide(&self, proposal: NormalizedActionProposal) -> Evaluation {
        let applicable = self.policies.applicable(&proposal);

        if applicable.is_empty() {
            return Evaluation {
                proposal,
                decision: PolicyDecision::Denied,
                applied: Vec::new(),
            };
        }

        let applied: Vec<PolicyId> = applicable.iter().map(|p| p.id().clone()).collect();
        let effective =
            ConstraintSet::meet_all(applicable.into_iter().map(|p| p.constraints().clone()));
        let decision = effective.evaluate(&proposal);

        Evaluation {
            proposal,
            decision,
            applied,
        }
    }
}
