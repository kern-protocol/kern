//! From a parsed model response to an `ActionProposal`.
//!
//! This is one small, deliberately visible step: it attaches the trusted parts
//! of the request to the untrusted parts of the response, and stops.
//!
//! ```text
//! ParsedModelProposal   what the model said         untrusted
//!   + PlanningRequest   actor and device            trusted
//!   -> ActionProposal   intent, carrying no authority
//! ```
//!
//! # What is deliberately not checked here
//!
//! That the capability exists. That the arguments are parameters of it. That
//! the values are in range. That anybody may request it. A model is free to
//! propose `disable_safety`, and this function will happily build an
//! `ActionProposal` naming it — because an `ActionProposal` is intent, and
//! refusing to *represent* an unauthorized request is not the same as refusing
//! to *perform* one.
//!
//! The refusal happens one step later, at
//! [`CapabilityRegistry::resolve`](kern_policy::CapabilityRegistry::resolve),
//! which is trusted Kern configuration and the only thing that decides which
//! capability names mean anything at all.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use core::fmt;

use kern_core::{
    ActionProposal, CapabilityName, DeviceId, InvalidId, ParamName, ParamValue, Symbol,
};

use crate::parse::{ParsedModelProposal, ProposedValue};
use crate::request::PlanningRequest;

/// Which `DeviceId` a logical target name means.
///
/// # This is the routing boundary
///
/// A model may write `"target": "conveyor_01"`. That string is a *request*. It
/// becomes a `DeviceId` only by being found in a router the host built, and a
/// name that is not in the router resolves to nothing at all — there is no
/// fallback, no fuzzy match, and no construction of a `DeviceId` from model
/// text.
///
/// That distinction is the whole reason this type exists. `DeviceId::new` takes
/// any string, so a proposal path that handed model bytes straight to it would
/// let a model name a machine nobody configured. Here, the set of reachable
/// machines is exactly the set the host enumerated.
///
/// Routing is still not authorization. Resolving `conveyor_01` says which
/// machine the proposal is *about*; whether anybody may operate it is a
/// question for the registry and the policy set, one and two steps later.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceRouter {
    routes: BTreeMap<String, DeviceId>,
}

impl DeviceRouter {
    /// An empty router, which resolves nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one logical name.
    #[must_use]
    pub fn with_route(mut self, logical: impl Into<String>, device: DeviceId) -> Self {
        self.routes.insert(logical.into(), device);
        self
    }

    /// Resolves a logical name, or `None` if the host did not configure it.
    pub fn resolve(&self, logical: &str) -> Option<&DeviceId> {
        self.routes.get(logical)
    }

    /// The logical names, in order, for the prompt vocabulary.
    pub fn logical_names(&self) -> impl Iterator<Item = &str> {
        self.routes.keys().map(String::as_str)
    }

    /// Every route, in order.
    pub fn routes(&self) -> impl Iterator<Item = (&str, &DeviceId)> {
        self.routes
            .iter()
            .map(|(name, device)| (name.as_str(), device))
    }

    /// True when the router configures nothing.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// A parsed proposal could not be expressed as an [`ActionProposal`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalError {
    /// The model proposed no action, so there is nothing to build.
    NoAction,
    /// The capability name is not a well-formed identifier.
    InvalidCapability(InvalidId),
    /// The model named a machine the host did not configure.
    ///
    /// Fails closed, and deliberately does not fall back to a default device: a
    /// proposal addressed to a machine that does not exist is not a proposal
    /// for the machine that happens to be nearest.
    UnknownTarget {
        /// The name it asked for.
        target: String,
    },
}

impl fmt::Display for ProposalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAction => f.write_str("the model proposed no action"),
            Self::InvalidCapability(error) => write!(f, "capability name: {error}"),
            Self::UnknownTarget { target } => {
                write!(f, "no machine is routed for target `{target}`")
            }
        }
    }
}

impl core::error::Error for ProposalError {}

/// Builds the proposal Kern will evaluate.
///
/// The actor always comes from `request`. The device comes from the request's
/// own default unless the model named a logical target, in which case it comes
/// from the request's trusted [`DeviceRouter`] — never from the model's string
/// itself. A model that could contribute the subject could propose as somebody
/// else, and a model that could contribute an arbitrary `DeviceId` could
/// propose to a machine nobody configured.
pub fn to_action_proposal(
    request: &PlanningRequest,
    parsed: &ParsedModelProposal,
) -> Result<ActionProposal, ProposalError> {
    let ParsedModelProposal::Capability {
        target,
        capability,
        arguments,
        ..
    } = parsed
    else {
        return Err(ProposalError::NoAction);
    };

    let device = match target {
        None => request.device().clone(),
        Some(target) => request
            .router()
            .resolve(target)
            .ok_or_else(|| ProposalError::UnknownTarget {
                target: target.to_string(),
            })?
            .clone(),
    };

    let capability =
        CapabilityName::new(capability.as_str()).map_err(ProposalError::InvalidCapability)?;

    let mut proposal = ActionProposal::new(request.actor().clone(), device, capability);
    for argument in arguments {
        let value = match &argument.value {
            ProposedValue::Integer(value) => ParamValue::Scalar(*value),
            ProposedValue::Text(text) => ParamValue::Symbol(Symbol::new(text.as_str())),
        };
        proposal = proposal.with_param(ParamName::new(argument.name.as_str()), value);
    }
    Ok(proposal)
}
