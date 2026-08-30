//! The outcome of evaluating a proposal against constraints.

use crate::constraint_set::ConstraintSet;

/// What policy concluded about a proposal.
///
/// The three outcomes are deliberately distinct. Collapsing the middle one into
/// a denial loses the information a planner needs to replan; collapsing it into
/// an authorization would mean executing something the caller did not propose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The proposal is within the granted bounds.
    Authorized {
        /// The effective constraints the operation is authorized under.
        constraints: ConstraintSet,
    },
    /// The proposal exceeds the grantable bounds.
    ///
    /// Kern does not modify the proposal to fit. It returns the bounds that
    /// would be grantable and requires the planner to resubmit explicitly
    /// (AGENT.md section 5).
    NotAuthorizedAsProposed {
        /// The bounds that could be granted for a resubmitted proposal.
        grantable: ConstraintSet,
    },
    /// No authority exists for this proposal at all.
    Denied,
}

impl PolicyDecision {
    /// True only for [`PolicyDecision::Authorized`].
    pub fn is_authorized(&self) -> bool {
        matches!(self, Self::Authorized { .. })
    }
}
