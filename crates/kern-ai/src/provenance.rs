//! Tracing an instruction to whatever it did or did not become.
//!
//! ```text
//! instruction
//!   -> ModelInvocationId    one call to a provider
//!   -> ResponseDigest       the exact bytes that came back
//!   -> ProposalId           one parsed proposal
//!   -> normalization outcome
//!   -> policy outcome
//!   -> AuthorityArtifactId  only if authorized, and only from the enforcer
//!   -> ExecutionId          only if executed, and only from the governor
//! ```
//!
//! # A ProposalId carries no authority
//!
//! It is a name for something that was said. It is not a `LeaseId`, not an
//! `AuthorityArtifactId`, and not an `ExecutionId`; it is a distinct type from
//! all three precisely so no function can accept one where it meant another.
//! Holding every `ProposalId` ever issued permits nothing.
//!
//! # Stages are recorded, never inferred
//!
//! Each stage has its own recording method, each refuses to run out of order,
//! and none of them can be skipped. A record cannot claim a policy outcome it
//! was never given, and cannot name an execution without an authority artifact
//! before it — which is what makes an absent stage in a printed record
//! meaningful rather than merely unfilled.

use alloc::string::String;
use core::fmt;

use kern_core::{AuthorityArtifactId, PolicyDecision};
use kern_execution::ExecutionId;
use sha2::{Digest, Sha256};

use crate::model::{ModelIdentity, ProviderFailure, ResponseDigest};
use crate::parse::ParseError;

/// Domain separator for the instruction-digest construction.
pub const INSTRUCTION_DIGEST_DOMAIN_V1: &[u8] = b"KERN-AI-INSTRUCTION-V1";

/// Names one proposal.
///
/// Deliberately not convertible to or from any authority identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProposalId(u64);

impl ProposalId {
    /// Wraps a raw value.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// The raw value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ProposalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "P-{}", self.0)
    }
}

/// Names one call to a provider.
///
/// Separate from [`ProposalId`] because they are separate events: an invocation
/// that times out produces no proposal at all, and a bounded replan produces two
/// invocations and two proposals that must never be confused with each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModelInvocationId(u64);

impl ModelInvocationId {
    /// Wraps a raw value.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// The raw value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ModelInvocationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "M-{}", self.0)
    }
}

/// Names one instruction, without retaining it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstructionDigest([u8; 32]);

impl InstructionDigest {
    /// Digests instruction text.
    ///
    /// ```text
    /// SHA-256( b"KERN-AI-INSTRUCTION-V1" || instruction_bytes )
    /// ```
    pub fn compute(instruction: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(INSTRUCTION_DIGEST_DOMAIN_V1);
        hasher.update(instruction.as_bytes());
        Self(hasher.finalize().into())
    }

    /// The underlying digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for InstructionDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InstructionDigest({self})")
    }
}

impl fmt::Display for InstructionDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..")
    }
}

/// What became of one inference attempt, at the parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalOutcome {
    /// The provider produced nothing.
    NoResponse(ProviderFailure),
    /// Bytes arrived and the parser refused them.
    ParseRejected(ParseError),
    /// The model explicitly proposed nothing.
    NoAction {
        /// The model's stated reason.
        reason: String,
    },
    /// A syntactically acceptable proposal was parsed.
    ///
    /// Says nothing about whether it means anything or is permitted.
    Parsed {
        /// The capability the model named.
        capability: String,
        /// The model's stated reason. Free text; never branch on it.
        reason: String,
    },
}

/// What became of the proposal at schema normalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NormalizationOutcome {
    /// The registry and schema accepted it.
    Normalized,
    /// The registry or schema refused it, with this description.
    ///
    /// A string, because the record is a provenance artifact rather than a
    /// control-flow input: nothing branches on this value, so nothing needs to
    /// match on it.
    Rejected(String),
}

/// What policy concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyOutcome {
    /// Policy authorized the proposal as made.
    Authorized,
    /// Policy would grant something, but not this.
    NotAuthorizedAsProposed,
    /// No authority exists for this proposal.
    Denied,
}

impl PolicyOutcome {
    /// Reads the outcome off a decision.
    pub fn from_decision(decision: &PolicyDecision) -> Self {
        match decision {
            PolicyDecision::Authorized { .. } => Self::Authorized,
            PolicyDecision::NotAuthorizedAsProposed { .. } => Self::NotAuthorizedAsProposed,
            PolicyDecision::Denied => Self::Denied,
        }
    }

    /// True only for [`Self::Authorized`].
    pub fn is_authorized(&self) -> bool {
        matches!(self, Self::Authorized)
    }
}

/// A stage was recorded out of order, or twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvenanceError {
    /// The stage before this one has not been recorded.
    OutOfOrder {
        /// The stage that was attempted.
        stage: &'static str,
        /// What it requires first.
        requires: &'static str,
    },
    /// This stage was already recorded.
    AlreadyRecorded {
        /// The stage that was attempted.
        stage: &'static str,
    },
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfOrder { stage, requires } => {
                write!(f, "cannot record {stage} before {requires}")
            }
            Self::AlreadyRecorded { stage } => write!(f, "{stage} was already recorded"),
        }
    }
}

impl core::error::Error for ProvenanceError {}

/// Everything known about one proposal, in the order it became known.
///
/// # This record is evidence, never authority
///
/// A record naming an `AuthorityArtifactId` does not confer that authority, and
/// a record cannot be handed to anything that installs, enforces, or executes.
/// It exists to answer, after the fact, which instruction and which model
/// invocation a physical execution descended from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalRecord {
    proposal_id: ProposalId,
    invocation: ModelInvocationId,
    model: ModelIdentity,
    instruction: InstructionDigest,
    response: Option<ResponseDigest>,
    outcome: ProposalOutcome,
    normalization: Option<NormalizationOutcome>,
    policy: Option<PolicyOutcome>,
    artifact: Option<AuthorityArtifactId>,
    execution: Option<ExecutionId>,
    replan_of: Option<ProposalId>,
}

impl ProposalRecord {
    /// Opens a record for one invocation and its outcome.
    ///
    /// Called by [`ProposalPlane`](crate::ProposalPlane) only. Later stages are
    /// recorded by the host as it walks the authority pipeline, because only the
    /// host holds the evaluator, the enforcer, and the governor — and because a
    /// plane that held them could hide the transitions between them.
    pub(crate) fn new(
        proposal_id: ProposalId,
        invocation: ModelInvocationId,
        model: ModelIdentity,
        instruction: InstructionDigest,
        response: Option<ResponseDigest>,
        outcome: ProposalOutcome,
        replan_of: Option<ProposalId>,
    ) -> Self {
        Self {
            proposal_id,
            invocation,
            model,
            instruction,
            response,
            outcome,
            normalization: None,
            policy: None,
            artifact: None,
            execution: None,
            replan_of,
        }
    }

    /// This proposal's identity.
    pub fn proposal_id(&self) -> ProposalId {
        self.proposal_id
    }

    /// The invocation that produced it.
    pub fn invocation(&self) -> ModelInvocationId {
        self.invocation
    }

    /// Which provider and model answered.
    pub fn model(&self) -> &ModelIdentity {
        &self.model
    }

    /// The instruction that was planned against.
    pub fn instruction(&self) -> InstructionDigest {
        self.instruction
    }

    /// The response bytes that arrived, if any did.
    pub fn response(&self) -> Option<ResponseDigest> {
        self.response
    }

    /// What the parser made of them.
    pub fn outcome(&self) -> &ProposalOutcome {
        &self.outcome
    }

    /// The normalization result, once recorded.
    pub fn normalization(&self) -> Option<&NormalizationOutcome> {
        self.normalization.as_ref()
    }

    /// The policy result, once recorded.
    pub fn policy(&self) -> Option<&PolicyOutcome> {
        self.policy.as_ref()
    }

    /// The authority artifact, if authority was installed for this proposal.
    pub fn artifact(&self) -> Option<&AuthorityArtifactId> {
        self.artifact.as_ref()
    }

    /// The execution, if one was prepared for this proposal.
    pub fn execution(&self) -> Option<ExecutionId> {
        self.execution
    }

    /// The earlier proposal this one replanned, if it is a replan.
    ///
    /// A link, not an inheritance: the earlier proposal's evaluation is not
    /// reused, its identifier is not reused, and it is not mutated.
    pub fn replan_of(&self) -> Option<ProposalId> {
        self.replan_of
    }

    /// Records what schema normalization concluded.
    pub fn record_normalization(
        &mut self,
        outcome: NormalizationOutcome,
    ) -> Result<(), ProvenanceError> {
        if self.normalization.is_some() {
            return Err(ProvenanceError::AlreadyRecorded {
                stage: "normalization",
            });
        }
        self.normalization = Some(outcome);
        Ok(())
    }

    /// Records what policy concluded.
    ///
    /// Refuses to run before normalization: a policy outcome for a proposal that
    /// was never normalized would describe an evaluation that cannot have
    /// happened, since the evaluator consumes only normalized proposals.
    pub fn record_policy(&mut self, outcome: PolicyOutcome) -> Result<(), ProvenanceError> {
        if self.normalization.is_none() {
            return Err(ProvenanceError::OutOfOrder {
                stage: "a policy outcome",
                requires: "normalization",
            });
        }
        if self.policy.is_some() {
            return Err(ProvenanceError::AlreadyRecorded {
                stage: "a policy outcome",
            });
        }
        self.policy = Some(outcome);
        Ok(())
    }

    /// Records the authority artifact installed for this proposal.
    ///
    /// Refuses unless policy authorized it. This is the single place where the
    /// provenance model would otherwise be able to tell a lie the rest of the
    /// system cannot: an artifact recorded against a denied proposal.
    pub fn record_authority(
        &mut self,
        artifact: AuthorityArtifactId,
    ) -> Result<(), ProvenanceError> {
        match self.policy {
            Some(PolicyOutcome::Authorized) => {}
            Some(_) => {
                return Err(ProvenanceError::OutOfOrder {
                    stage: "an authority artifact",
                    requires: "an authorized policy outcome",
                })
            }
            None => {
                return Err(ProvenanceError::OutOfOrder {
                    stage: "an authority artifact",
                    requires: "a policy outcome",
                })
            }
        }
        if self.artifact.is_some() {
            return Err(ProvenanceError::AlreadyRecorded {
                stage: "an authority artifact",
            });
        }
        self.artifact = Some(artifact);
        Ok(())
    }

    /// Records the execution prepared under that authority.
    pub fn record_execution(&mut self, execution: ExecutionId) -> Result<(), ProvenanceError> {
        if self.artifact.is_none() {
            return Err(ProvenanceError::OutOfOrder {
                stage: "an execution",
                requires: "an authority artifact",
            });
        }
        if self.execution.is_some() {
            return Err(ProvenanceError::AlreadyRecorded {
                stage: "an execution",
            });
        }
        self.execution = Some(execution);
        Ok(())
    }
}

/// Where proposal and invocation identifiers come from.
///
/// Injected, so a whole planning session is reproducible in a test.
pub trait ProposalIdSource {
    /// The next proposal identifier.
    fn next_proposal_id(&mut self) -> ProposalId;

    /// The next invocation identifier.
    fn next_invocation_id(&mut self) -> ModelInvocationId;
}

/// Counting identifier sources.
///
/// Wrapping is deliberate and harmless: these identifiers are provenance
/// labels, and nothing in Kern's security argument depends on their uniqueness
/// the way it depends on a nonce's monotonicity.
#[derive(Clone, Debug, Default)]
pub struct SequentialProposalIds {
    proposals: u64,
    invocations: u64,
}

impl SequentialProposalIds {
    /// A source starting from `start` for both counters.
    pub fn starting_at(start: u64) -> Self {
        Self {
            proposals: start,
            invocations: start,
        }
    }

    /// A source starting from zero.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ProposalIdSource for SequentialProposalIds {
    fn next_proposal_id(&mut self) -> ProposalId {
        let id = ProposalId(self.proposals);
        self.proposals = self.proposals.wrapping_add(1);
        id
    }

    fn next_invocation_id(&mut self) -> ModelInvocationId {
        let id = ModelInvocationId(self.invocations);
        self.invocations = self.invocations.wrapping_add(1);
        id
    }
}
