//! The proposal plane: one instruction in, at most one proposal out.
//!
//! ```text
//! PlanningRequest
//!   -> ProposalModel::propose      one attempt, no retry
//!   -> RawModelResponse            untrusted bytes, digested
//!   -> parse_response              strict, local, fail-closed
//!   -> to_action_proposal          actor and device from the host
//!   -> Proposal { record, action }
//! ```
//!
//! # Where this stops
//!
//! At an [`ActionProposal`](kern_core::ActionProposal). The plane does not
//! resolve capabilities, does not normalize, does not evaluate policy, does not
//! mint challenges, does not issue leases, and does not execute. It holds no
//! registry, no policy set, no issuer, no enforcer, and no governor, so it could
//! not do any of those things even by mistake.
//!
//! That is a deliberate refusal to be convenient. A single
//! `authorize_model_response(...)` helper would be shorter to call and much
//! harder to review: every transition it hid — schema, policy, authorization,
//! freshness, installation, execution — is a transition somebody needs to be
//! able to see happening, in order, at the call site.
//!
//! # One attempt, and at most one replan
//!
//! [`ProposalPlane::propose`] calls the model exactly once. There is no retry on
//! provider failure. [`ProposalPlane::replan`] exists for the single case where
//! policy reported grantable bounds, and it is spent from a
//! [`ReplanBudget`] that cannot exceed [`MAX_REPLANS`](crate::bounds::MAX_REPLANS).
//! There is no loop, and nothing anywhere retries until policy says yes.

use core::fmt;

use kern_core::ActionProposal;

use crate::bounds::MAX_REPLANS;
use crate::model::{ModelOutcome, ProposalModel};
use crate::parse::{parse_response, ParsedModelProposal};
use crate::proposal::to_action_proposal;
use crate::provenance::{InstructionDigest, ProposalIdSource, ProposalOutcome, ProposalRecord};
use crate::request::{ConstraintFeedback, PlanningRequest};

/// One trip through the plane.
///
/// The record always exists — a timed-out provider and a rejected response are
/// both facts worth recording. The proposal exists only when there is something
/// to evaluate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    record: ProposalRecord,
    action: Option<ActionProposal>,
    parsed: Option<ParsedModelProposal>,
}

impl Proposal {
    /// The provenance record. Always present.
    pub fn record(&self) -> &ProposalRecord {
        &self.record
    }

    /// The provenance record, for the host to fill in later stages.
    pub fn record_mut(&mut self) -> &mut ProposalRecord {
        &mut self.record
    }

    /// The proposal to evaluate, if the model produced one.
    ///
    /// `None` for a provider failure, a rejected response, and an explicit
    /// `no_action`. All three mean the same thing downstream: nothing to
    /// evaluate, so nothing to authorize, so nothing to execute.
    pub fn action(&self) -> Option<&ActionProposal> {
        self.action.as_ref()
    }

    /// What the parser made of the response, if it accepted it.
    pub fn parsed(&self) -> Option<&ParsedModelProposal> {
        self.parsed.as_ref()
    }

    /// Consumes the trip, yielding its parts.
    pub fn into_parts(self) -> (ProposalRecord, Option<ActionProposal>) {
        (self.record, self.action)
    }
}

/// How many replans remain.
///
/// Carried by the host rather than held by the plane, so the bound survives a
/// caller that builds a fresh plane per request — which is exactly the shape an
/// accidental unbounded loop would take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplanBudget {
    remaining: u8,
}

impl ReplanBudget {
    /// A budget of `replans`, clamped to [`MAX_REPLANS`](crate::bounds::MAX_REPLANS).
    ///
    /// Clamped rather than refused because the ceiling is the security property
    /// and the request is a preference. A caller asking for ten gets one.
    pub fn new(replans: u8) -> Self {
        Self {
            remaining: replans.min(MAX_REPLANS),
        }
    }

    /// A budget that permits no replan at all.
    pub fn none() -> Self {
        Self { remaining: 0 }
    }

    /// How many replans remain.
    pub fn remaining(&self) -> u8 {
        self.remaining
    }

    /// True when no replan remains.
    pub fn is_exhausted(&self) -> bool {
        self.remaining == 0
    }
}

/// A replan was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplanError {
    /// The budget is spent.
    BudgetExhausted,
    /// There is nothing to replan against.
    ///
    /// Feedback is only meaningful when policy reported grantable bounds. An
    /// outright `Denied` names none, and replanning against silence is how a
    /// bounded retry becomes a guessing loop.
    NoFeedback,
}

impl fmt::Display for ReplanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhausted => f.write_str("the replan budget is spent"),
            Self::NoFeedback => {
                f.write_str("policy reported no grantable bounds to replan against")
            }
        }
    }
}

impl core::error::Error for ReplanError {}

/// Drives one model through the untrusted-proposal pipeline.
///
/// Generic over the model, so a live gateway adapter, a deterministic fixture,
/// and a deliberately malicious backend all travel exactly the same code path.
/// The tests rely on that: if the malicious backend needed a different path to
/// be contained, containment would be a property of the path rather than of
/// Kern.
pub struct ProposalPlane<M, I> {
    model: M,
    ids: I,
}

impl<M, I> ProposalPlane<M, I>
where
    M: ProposalModel,
    I: ProposalIdSource,
{
    /// Builds a plane over one model.
    pub fn new(model: M, ids: I) -> Self {
        Self { model, ids }
    }

    /// The model, for inspection.
    pub fn model(&self) -> &M {
        &self.model
    }

    /// The model, mutably, for a test fixture that needs to be reconfigured.
    pub fn model_mut(&mut self) -> &mut M {
        &mut self.model
    }

    /// Invokes the model once and parses whatever comes back.
    ///
    /// Never fails: a provider failure and a rejected response are outcomes, not
    /// errors, because the caller must handle them identically either way — by
    /// doing nothing physical.
    pub fn propose(&mut self, request: &PlanningRequest) -> Proposal {
        self.invoke(request, None)
    }

    /// Invokes the model a second time, with deterministic constraint feedback.
    ///
    /// The result is a *new* proposal with a *new* identifier, linked to the
    /// previous one for provenance and sharing nothing else with it. Proposal A
    /// is not mutated, its evaluation is not reused, and its identifier is not
    /// reused. The second proposal is evaluated from scratch by the same
    /// evaluator, which is why a model cannot improve its odds by being asked
    /// twice.
    pub fn replan(
        &mut self,
        request: &PlanningRequest,
        previous: &ProposalRecord,
        feedback: &ConstraintFeedback,
        budget: &mut ReplanBudget,
    ) -> Result<Proposal, ReplanError> {
        if budget.is_exhausted() {
            return Err(ReplanError::BudgetExhausted);
        }
        if feedback.is_empty() {
            return Err(ReplanError::NoFeedback);
        }
        budget.remaining -= 1;

        let request = request.clone().with_feedback(feedback.clone());
        Ok(self.invoke(&request, Some(previous.proposal_id())))
    }

    fn invoke(
        &mut self,
        request: &PlanningRequest,
        replan_of: Option<crate::provenance::ProposalId>,
    ) -> Proposal {
        let invocation = self.ids.next_invocation_id();
        let proposal_id = self.ids.next_proposal_id();
        let identity = self.model.identity();
        let instruction = InstructionDigest::compute(request.instruction().as_str());

        let outcome = self.model.propose(request);

        let response = match &outcome {
            ModelOutcome::Response(response) => response,
            ModelOutcome::Failed(failure) => {
                return Proposal {
                    record: ProposalRecord::new(
                        proposal_id,
                        invocation,
                        identity,
                        instruction,
                        None,
                        ProposalOutcome::NoResponse(failure.clone()),
                        replan_of,
                    ),
                    action: None,
                    parsed: None,
                }
            }
        };

        let digest = Some(response.digest());
        let parsed = match parse_response(response) {
            Ok(parsed) => parsed,
            Err(error) => {
                return Proposal {
                    record: ProposalRecord::new(
                        proposal_id,
                        invocation,
                        identity,
                        instruction,
                        digest,
                        ProposalOutcome::ParseRejected(error),
                        replan_of,
                    ),
                    action: None,
                    parsed: None,
                }
            }
        };

        let (outcome, action) = match &parsed {
            ParsedModelProposal::NoAction { reason } => (
                ProposalOutcome::NoAction {
                    reason: reason.clone(),
                },
                None,
            ),
            ParsedModelProposal::Capability {
                capability, reason, ..
            } => {
                // The only failure left is a capability name that is not a
                // well-formed identifier, and the parser already refused the
                // empty one. Treated as a parse rejection rather than silently
                // dropped: a proposal that cannot be represented is a proposal
                // Kern did not understand.
                match to_action_proposal(request, &parsed) {
                    Ok(action) => (
                        ProposalOutcome::Parsed {
                            capability: capability.clone(),
                            reason: reason.clone(),
                        },
                        Some(action),
                    ),
                    // A routing failure is not a malformed response: the bytes
                    // were fine and named a machine this host does not have.
                    // Reported as its own rejection so the record can say which.
                    Err(error) => (
                        ProposalOutcome::ParseRejected(crate::parse::ParseError::WrongType {
                            key: match &error {
                                crate::proposal::ProposalError::UnknownTarget { .. } => {
                                    "target".into()
                                }
                                _ => "capability".into(),
                            },
                            expected: "a name this host routes",
                            found: error_kind(&error),
                        }),
                        None,
                    ),
                }
            }
        };

        Proposal {
            record: ProposalRecord::new(
                proposal_id,
                invocation,
                identity,
                instruction,
                digest,
                outcome,
                replan_of,
            ),
            action,
            parsed: Some(parsed),
        }
    }
}

fn error_kind(error: &crate::proposal::ProposalError) -> &'static str {
    match error {
        crate::proposal::ProposalError::NoAction => "no action",
        crate::proposal::ProposalError::InvalidCapability(_) => "an invalid name",
        crate::proposal::ProposalError::UnknownTarget { .. } => "an unrouted machine",
    }
}
