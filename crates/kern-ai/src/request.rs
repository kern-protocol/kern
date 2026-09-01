//! What the plane is willing to tell a model.
//!
//! A [`PlanningRequest`] is the *entire* input surface of the proposal plane.
//! Everything a model is ever told passes through this type, which makes the
//! list of things it does not contain worth reading as carefully as the list of
//! things it does:
//!
//! ```text
//! no signing key          no verifying key        no trust-store contents
//! no challenge            no nonce                no enforcer session
//! no lease, of any kind   no TTL                  no issuer identity
//! no policy object        no constraint set       no execution identity
//! ```
//!
//! None of those is omitted for secrecy alone. They are omitted because a model
//! that cannot see them cannot be argued into a proposal that depends on them,
//! and because the proposal contract has no field that could carry one back.
//!
//! The capability vocabulary is built *from the trusted registry*, so what the
//! model is told a device can do and what Kern will actually normalize come from
//! one source. A model cannot widen the vocabulary by describing a wider one.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use kern_core::{CapabilityName, DeviceId, ParamDomain, ParamName, Requirement, SubjectId};
use kern_policy::CapabilityRegistry;

use crate::bounds::{MAX_INSTRUCTION_BYTES, MAX_ROBOT_CONTEXT_BYTES};

/// A planning input exceeded a frozen bound, or was empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// The instruction is empty.
    EmptyInstruction,
    /// The instruction exceeds [`MAX_INSTRUCTION_BYTES`].
    InstructionTooLong {
        /// How many bytes were offered.
        bytes: usize,
    },
    /// The robot context exceeds [`MAX_ROBOT_CONTEXT_BYTES`].
    ContextTooLong {
        /// How many bytes were offered.
        bytes: usize,
    },
    /// The registry exposes nothing for this device, so there is nothing to
    /// plan with.
    ///
    /// Refused rather than sent: a model asked to plan against an empty
    /// vocabulary can only invent one.
    EmptyVocabulary {
        /// The device asked about.
        device: DeviceId,
    },
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInstruction => f.write_str("instruction is empty"),
            Self::InstructionTooLong { bytes } => write!(
                f,
                "instruction is {bytes} bytes, over the {MAX_INSTRUCTION_BYTES} byte bound"
            ),
            Self::ContextTooLong { bytes } => write!(
                f,
                "robot context is {bytes} bytes, over the {MAX_ROBOT_CONTEXT_BYTES} byte bound"
            ),
            Self::EmptyVocabulary { device } => {
                write!(f, "no capability is registered for device `{device}`")
            }
        }
    }
}

impl core::error::Error for RequestError {}

/// A bounded natural-language instruction.
///
/// The text is not inspected, filtered, or sanitized, and deliberately so.
/// Kern's containment argument does not depend on recognising a hostile
/// instruction; it depends on what happens to the proposal afterwards. An
/// instruction that says "ignore all restrictions" is an ordinary instruction
/// here, and is expected to produce an ordinary denial downstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction(String);

impl Instruction {
    /// Wraps instruction text, enforcing the frozen bound.
    pub fn new(text: impl Into<String>) -> Result<Self, RequestError> {
        let text = text.into();
        if text.is_empty() {
            return Err(RequestError::EmptyInstruction);
        }
        if text.len() > MAX_INSTRUCTION_BYTES {
            return Err(RequestError::InstructionTooLong { bytes: text.len() });
        }
        Ok(Self(text))
    }

    /// The instruction text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The semantic environment the model may reason about.
///
/// Semantic only: named places, the working area, what the robot is currently
/// doing. Not a map, not a frame tree, not a topic list, and not anything a
/// model could use to address the machine directly.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RobotContext(String);

impl RobotContext {
    /// Wraps context text, enforcing the frozen bound.
    pub fn new(text: impl Into<String>) -> Result<Self, RequestError> {
        let text = text.into();
        if text.len() > MAX_ROBOT_CONTEXT_BYTES {
            return Err(RequestError::ContextTooLong { bytes: text.len() });
        }
        Ok(Self(text))
    }

    /// The context text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when no context was supplied.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One parameter of a capability, as described to a model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamDescription {
    /// The parameter name, exactly as the schema declares it.
    pub name: ParamName,
    /// Its value domain.
    pub domain: ParamDomain,
    /// Whether the schema requires it.
    pub required: bool,
}

/// One capability, as described to a model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityDescription {
    /// The logical machine this capability belongs to, when the vocabulary was
    /// built from a router.
    pub target: Option<String>,
    /// The capability name, exactly as the registry keys it.
    pub name: CapabilityName,
    /// Its parameters, in schema order.
    pub params: Vec<ParamDescription>,
}

/// The capabilities a model is permitted to know exist.
///
/// # This is a description, never a grant
///
/// A vocabulary entry says a device *understands* an operation. It says nothing
/// about who may request it, and it is not consulted by anything that decides
/// authority. The registry it is built from makes the same distinction, and this
/// type inherits it: describing `navigate` to a model no more authorizes
/// navigation than printing the word does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityVocabulary {
    device: Option<DeviceId>,
    entries: Vec<CapabilityDescription>,
}

impl CapabilityVocabulary {
    /// Describes everything the trusted registry exposes for one device.
    ///
    /// This is the only constructor. There is no way to assemble a vocabulary
    /// from strings, so a vocabulary can never describe a capability the
    /// registry does not actually resolve — which is what makes the model's
    /// available-capability list and Kern's normalization list the same list.
    pub fn from_registry(
        registry: &CapabilityRegistry,
        device: &DeviceId,
    ) -> Result<Self, RequestError> {
        let entries: Vec<CapabilityDescription> = registry
            .iter()
            .filter(|(registered, _, _)| *registered == device)
            .map(|(_, name, schema)| CapabilityDescription {
                target: None,
                name: name.clone(),
                params: schema
                    .params()
                    .map(|(param, spec)| ParamDescription {
                        name: param.clone(),
                        domain: spec.domain,
                        required: matches!(spec.requirement, Requirement::Required),
                    })
                    .collect(),
            })
            .collect();

        if entries.is_empty() {
            return Err(RequestError::EmptyVocabulary {
                device: device.clone(),
            });
        }

        Ok(Self {
            device: Some(device.clone()),
            entries,
        })
    }

    /// The device this vocabulary describes.
    pub fn device(&self) -> Option<&DeviceId> {
        self.device.as_ref()
    }

    /// Describes what every routed machine exposes.
    ///
    /// The vocabulary and the routing table are built from the same trusted
    /// configuration, so the machines a model is told about and the machines a
    /// target name can resolve to are the same set. A model cannot widen either
    /// by describing a wider one.
    ///
    /// A machine the router names but the registry exposes nothing for is
    /// refused rather than silently described as capability-less: that is a
    /// configuration mistake, and a planner told about a machine it can do
    /// nothing with can only invent something.
    pub fn from_router(
        registry: &CapabilityRegistry,
        router: &crate::proposal::DeviceRouter,
    ) -> Result<Self, RequestError> {
        if router.is_empty() {
            return Err(RequestError::EmptyVocabulary {
                device: DeviceId::new("<no routed machine>"),
            });
        }

        let mut entries: Vec<CapabilityDescription> = Vec::new();
        for (logical, device) in router.routes() {
            let described = Self::from_registry(registry, device)?;
            entries.extend(
                described
                    .entries
                    .into_iter()
                    .map(|entry| CapabilityDescription {
                        target: Some(logical.to_string()),
                        ..entry
                    }),
            );
        }

        Ok(Self {
            device: None,
            entries,
        })
    }

    /// The described capabilities.
    pub fn entries(&self) -> &[CapabilityDescription] {
        &self.entries
    }

    /// True when this vocabulary describes `name`.
    ///
    /// Advisory. The registry decides what normalizes; this only decides what
    /// the model was told about.
    pub fn describes(&self, name: &str) -> bool {
        self.entries.iter().any(|entry| entry.name.as_str() == name)
    }
}

/// One bounded planning request.
///
/// The actor and device are held here rather than left to the model. A model
/// that could name the subject could propose *as somebody else*, and a model
/// that could name the device could propose to a machine nobody asked about;
/// both are authority questions wearing a parameter's clothes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanningRequest {
    actor: SubjectId,
    device: DeviceId,
    instruction: Instruction,
    context: RobotContext,
    vocabulary: CapabilityVocabulary,
    router: crate::proposal::DeviceRouter,
    feedback: ConstraintFeedback,
}

impl PlanningRequest {
    /// Assembles a request.
    pub fn new(
        actor: SubjectId,
        device: DeviceId,
        instruction: Instruction,
        context: RobotContext,
        vocabulary: CapabilityVocabulary,
    ) -> Self {
        Self {
            actor,
            device,
            instruction,
            context,
            vocabulary,
            router: crate::proposal::DeviceRouter::default(),
            feedback: ConstraintFeedback::default(),
        }
    }

    /// Attaches the trusted routing table for logical target names.
    ///
    /// Without one, a proposal naming a target resolves to nothing and is
    /// refused — which is the correct behaviour for a single-machine host that
    /// never expected a target in the first place.
    #[must_use]
    pub fn with_router(mut self, router: crate::proposal::DeviceRouter) -> Self {
        self.router = router;
        self
    }

    /// Attaches deterministic constraint feedback for a bounded replan.
    ///
    /// Only [`ProposalPlane::replan`](crate::ProposalPlane::replan) sets this in
    /// normal use. The feedback is advisory text for the model; it is not a
    /// grant, and the resulting proposal is evaluated from scratch.
    #[must_use]
    pub fn with_feedback(mut self, feedback: ConstraintFeedback) -> Self {
        self.feedback = feedback;
        self
    }

    /// The subject the resulting proposal will be attributed to.
    pub fn actor(&self) -> &SubjectId {
        &self.actor
    }

    /// The device the resulting proposal will target.
    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    /// The natural-language instruction.
    pub fn instruction(&self) -> &Instruction {
        &self.instruction
    }

    /// The semantic environment context.
    pub fn context(&self) -> &RobotContext {
        &self.context
    }

    /// The capabilities the model is told about.
    pub fn vocabulary(&self) -> &CapabilityVocabulary {
        &self.vocabulary
    }

    /// The trusted routing table for logical target names.
    pub fn router(&self) -> &crate::proposal::DeviceRouter {
        &self.router
    }

    /// The advisory constraint feedback, empty unless this is a replan.
    pub fn feedback(&self) -> &ConstraintFeedback {
        &self.feedback
    }
}

/// Deterministic feedback about why a proposal was not authorized.
///
/// # Advisory, and only advisory
///
/// This is rendered from a [`PolicyDecision`](kern_core::PolicyDecision) the
/// evaluator already produced, purely so a replan can be told something more
/// useful than "no". Handing it to a model changes nothing about what the next
/// proposal must survive: the second attempt is evaluated from scratch, by the
/// same evaluator, with the same result for the same proposal.
///
/// It never carries an authority artifact, a bound the model may assume it now
/// holds, or an instruction to retry until something passes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConstraintFeedback {
    lines: Vec<String>,
}

impl ConstraintFeedback {
    /// Renders the grantable bounds of a `NotAuthorizedAsProposed` decision.
    ///
    /// Returns an empty feedback for `Authorized` and for `Denied`: an outright
    /// denial names no grantable bounds, and there is deliberately nothing to
    /// tell a model about authority that does not exist.
    pub fn from_decision(decision: &kern_core::PolicyDecision) -> Self {
        Self::rendered(decision, None)
    }

    /// Renders only the bounds `params` actually violated.
    ///
    /// Same source, same wording, narrower selection: a reader of a denial
    /// wants the one bound that was exceeded, not a recital of every bound that
    /// exists. Nothing is inferred — a parameter is listed only when the
    /// constraint the evaluator already produced refuses the value the proposal
    /// already carried.
    pub fn violations(
        decision: &kern_core::PolicyDecision,
        params: &alloc::collections::BTreeMap<kern_core::ParamName, kern_core::ParamValue>,
    ) -> Self {
        Self::rendered(decision, Some(params))
    }

    fn rendered(
        decision: &kern_core::PolicyDecision,
        params: Option<&alloc::collections::BTreeMap<kern_core::ParamName, kern_core::ParamValue>>,
    ) -> Self {
        use kern_core::{ParamConstraint, PolicyDecision, SymbolSet};

        let grantable = match decision {
            PolicyDecision::NotAuthorizedAsProposed { grantable } => grantable,
            PolicyDecision::Authorized { .. } | PolicyDecision::Denied => return Self::default(),
        };

        let lines = grantable
            .iter()
            .filter(|(name, constraint)| match params {
                None => true,
                Some(params) => params
                    .get(*name)
                    .is_some_and(|value| !constraint.permits(value)),
            })
            .map(|(name, constraint)| match constraint {
                ParamConstraint::Numeric(interval) => {
                    match (interval.lower() == i64::MIN, interval.upper() == i64::MAX) {
                        (true, true) => format!("{name} is unbounded"),
                        (true, false) => format!("{name} must be at most {}", interval.upper()),
                        (false, true) => format!("{name} must be at least {}", interval.lower()),
                        (false, false) => format!(
                            "{name} must be between {} and {}",
                            interval.lower(),
                            interval.upper()
                        ),
                    }
                }
                ParamConstraint::Symbolic(SymbolSet::Allowed(allowed)) => format!(
                    "{name} must be one of: {}",
                    allowed
                        .iter()
                        .map(|symbol| symbol.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                ParamConstraint::Symbolic(SymbolSet::Denied(denied)) => format!(
                    "{name} must not be any of: {}",
                    denied
                        .iter()
                        .map(|symbol| symbol.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            })
            .collect();

        Self { lines }
    }

    /// The rendered lines, in parameter-name order.
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// True when there is nothing useful to say.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// The feedback as one block of text.
    pub fn to_text(&self) -> String {
        self.lines.join("\n")
    }
}
