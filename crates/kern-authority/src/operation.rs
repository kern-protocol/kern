//! The only thing issuance will sign.

use kern_core::{ConstraintSet, NormalizedActionProposal, PolicyDecision};
use kern_policy::Evaluation;

/// An operation that policy actually authorized.
///
/// # Why this type exists
///
/// Issuance must not be able to mint authority that no policy granted. That is a
/// property worth enforcing in the type system rather than in review comments,
/// so this type has private fields and exactly one constructor, and that
/// constructor consumes a whole [`Evaluation`].
///
/// The chain, end to end:
///
/// ```text
/// Evaluation            private fields, built only by Authority::decide
///   -> from_evaluation  takes proposal AND constraints from inside it
///   -> AuthorizedOperation
/// ```
///
/// There is deliberately no `new(proposal, constraints)` and no setter, so
/// combining a legitimate normalized proposal with caller-supplied broader
/// constraints has no API to express it.
///
/// External safe Rust cannot fabricate one:
///
/// ```compile_fail
/// use kern_authority::AuthorizedOperation;
///
/// let forged = AuthorizedOperation {
///     proposal: unimplemented!(),
///     constraints: unimplemented!(),
/// };
/// ```
///
/// Nor can it reach one without an authorization, since `from_evaluation`
/// returns `None` for every other decision:
///
/// ```
/// # use kern_authority::AuthorizedOperation;
/// # use kern_core::{ActionProposal, CapabilityName, DeviceId, SubjectId};
/// # use kern_policy::Authority;
/// # let authority = Authority::default();
/// # let proposal = ActionProposal::new(
/// #     SubjectId::new("planner_a"),
/// #     DeviceId::new("cafe_bot_01"),
/// #     CapabilityName::new("navigate").unwrap(),
/// # );
/// // An empty registry cannot even resolve the capability.
/// assert!(authority.evaluate(&proposal).is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedOperation {
    proposal: NormalizedActionProposal,
    constraints: ConstraintSet,
}

impl AuthorizedOperation {
    /// Extracts the authorized operation from an evaluation, if it authorized
    /// anything.
    ///
    /// Returns `None` for `NotAuthorizedAsProposed` and `Denied`. Advisory
    /// grantable bounds are not authority, and must never be signed.
    pub fn from_evaluation(evaluation: Evaluation) -> Option<Self> {
        let (proposal, decision, _applied) = evaluation.into_parts();
        match decision {
            PolicyDecision::Authorized { constraints } => Some(Self {
                proposal,
                constraints,
            }),
            PolicyDecision::NotAuthorizedAsProposed { .. } | PolicyDecision::Denied => None,
        }
    }

    /// The validated proposal that was authorized.
    pub fn proposal(&self) -> &NormalizedActionProposal {
        &self.proposal
    }

    /// The bounds policy granted. These, and only these, go into a lease.
    pub fn constraints(&self) -> &ConstraintSet {
        &self.constraints
    }
}
