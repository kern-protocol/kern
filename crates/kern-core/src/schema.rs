//! Capability schemas: what a semantic operation means.
//!
//! A schema answers "can this device understand this operation". It never
//! answers "may this subject request it". Keep those separate: schema
//! validation is authority-neutral, and nothing in this module may consult a
//! policy, a subject's authority, runtime state, a clock, the network, or
//! device state.
//!
//! Normalization is pure. The same proposal and schema always produce the same
//! result.

use alloc::collections::BTreeMap;
use core::fmt;

use crate::ids::{CapabilityName, DeviceId, ParamName, SubjectId};
use crate::proposal::{ActionProposal, ParamValue};

/// The value domain a parameter accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParamDomain {
    /// Normalized integer scalars, in the capability's own units.
    Scalar,
    /// Opaque symbols.
    Symbol,
}

impl ParamDomain {
    /// True when `value` belongs to this domain.
    pub fn matches(&self, value: &ParamValue) -> bool {
        matches!(
            (self, value),
            (Self::Scalar, ParamValue::Scalar(_)) | (Self::Symbol, ParamValue::Symbol(_))
        )
    }
}

impl fmt::Display for ParamDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Scalar => "scalar",
            Self::Symbol => "symbol",
        })
    }
}

/// Whether a parameter must be supplied, and what happens when it is not.
///
/// A default is part of what the capability *means*. It is inserted during
/// normalization, before any policy sees the proposal, and it must never depend
/// on the subject, the applicable policies, or any runtime state. A default
/// that varies with who is asking is an authority decision wearing a schema's
/// clothes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Requirement {
    /// The proposal must supply this parameter.
    Required,
    /// The proposal may omit this parameter, and it stays absent.
    ///
    /// Absent is not the same as unconstrained. A policy constraining an
    /// omitted optional parameter still refuses the proposal: schema
    /// optionality and policy authority are separate concepts.
    Optional,
    /// The proposal may omit this parameter, and normalization inserts this
    /// value, which policy then checks exactly as if the caller had supplied it.
    DefaultTo(ParamValue),
}

/// The declaration of one capability parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamSpec {
    /// The value domain this parameter accepts.
    pub domain: ParamDomain,
    /// Whether it must be supplied.
    pub requirement: Requirement,
}

impl ParamSpec {
    /// A parameter the proposal must supply.
    pub fn required(domain: ParamDomain) -> Self {
        Self {
            domain,
            requirement: Requirement::Required,
        }
    }

    /// A parameter the proposal may omit, staying absent when omitted.
    pub fn optional(domain: ParamDomain) -> Self {
        Self {
            domain,
            requirement: Requirement::Optional,
        }
    }

    /// A parameter the proposal may omit, defaulting to `value` when omitted.
    pub fn defaulted(domain: ParamDomain, value: ParamValue) -> Self {
        Self {
            domain,
            requirement: Requirement::DefaultTo(value),
        }
    }
}

/// A schema is malformed and cannot be built.
///
/// These are caught at definition time so an unusable schema can never be
/// registered, let alone consulted while deciding authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaDefinitionError {
    /// The same parameter was declared twice.
    DuplicateParameter {
        /// The repeated parameter.
        param: ParamName,
    },
    /// A default value does not belong to its parameter's declared domain.
    DefaultDomainMismatch {
        /// The offending parameter.
        param: ParamName,
        /// The domain the parameter declares.
        expected: ParamDomain,
    },
}

impl fmt::Display for SchemaDefinitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateParameter { param } => write!(f, "duplicate parameter `{param}`"),
            Self::DefaultDomainMismatch { param, expected } => write!(
                f,
                "default for parameter `{param}` is not a {expected} value"
            ),
        }
    }
}

impl core::error::Error for SchemaDefinitionError {}

/// A proposal does not describe a well-formed operation for its capability.
///
/// This is an invalid request, not an authority answer. It must never be
/// reported as a denial: a schema error says the request does not describe a
/// real operation, while a denial says it describes one the subject may not
/// perform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaError {
    /// The proposal names a different capability than this schema.
    CapabilityMismatch {
        /// The capability this schema describes.
        expected: CapabilityName,
        /// The capability the proposal named.
        found: CapabilityName,
    },
    /// The proposal omits a required parameter.
    MissingRequiredParameter {
        /// The missing parameter.
        param: ParamName,
    },
    /// The proposal supplies a parameter the schema does not declare.
    UnknownParameter {
        /// The undeclared parameter.
        param: ParamName,
    },
    /// The proposal supplies a value from the wrong domain.
    WrongDomain {
        /// The offending parameter.
        param: ParamName,
        /// The domain the schema declares for it.
        expected: ParamDomain,
    },
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityMismatch { expected, found } => {
                write!(f, "schema describes `{expected}`, proposal named `{found}`")
            }
            Self::MissingRequiredParameter { param } => {
                write!(f, "missing required parameter `{param}`")
            }
            Self::UnknownParameter { param } => write!(f, "unknown parameter `{param}`"),
            Self::WrongDomain { param, expected } => {
                write!(f, "parameter `{param}` must be a {expected} value")
            }
        }
    }
}

impl core::error::Error for SchemaError {}

/// What a semantic operation means: its parameters, their domains, and which of
/// them may be omitted.
///
/// A schema carries capability identity only. Device identity is deliberately
/// absent, so one schema stays reusable across every device exposing the
/// capability. The device binding belongs to the registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilitySchema {
    name: CapabilityName,
    params: BTreeMap<ParamName, ParamSpec>,
}

impl CapabilitySchema {
    /// Declares a capability, rejecting a malformed definition.
    pub fn new<I>(name: CapabilityName, params: I) -> Result<Self, SchemaDefinitionError>
    where
        I: IntoIterator<Item = (ParamName, ParamSpec)>,
    {
        let mut declared: BTreeMap<ParamName, ParamSpec> = BTreeMap::new();
        for (param, spec) in params {
            if let Requirement::DefaultTo(value) = &spec.requirement {
                if !spec.domain.matches(value) {
                    return Err(SchemaDefinitionError::DefaultDomainMismatch {
                        param,
                        expected: spec.domain,
                    });
                }
            }
            if declared.insert(param.clone(), spec).is_some() {
                return Err(SchemaDefinitionError::DuplicateParameter { param });
            }
        }

        Ok(Self {
            name,
            params: declared,
        })
    }

    /// The capability this schema describes.
    pub fn name(&self) -> &CapabilityName {
        &self.name
    }

    /// The declared parameters, in name order.
    pub fn params(&self) -> impl Iterator<Item = (&ParamName, &ParamSpec)> {
        self.params.iter()
    }

    /// Validates a proposal and produces the normalized form policy evaluates.
    ///
    /// Checks run in a fixed order over ordered collections, so the same input
    /// always produces the same error:
    ///
    /// 1. capability identity
    /// 2. supplied parameters, in name order: declared, and of the right domain
    /// 3. undeclared-but-required parameters, in name order, and defaults
    pub fn normalize(
        &self,
        proposal: &ActionProposal,
    ) -> Result<NormalizedActionProposal, SchemaError> {
        if proposal.capability != self.name {
            return Err(SchemaError::CapabilityMismatch {
                expected: self.name.clone(),
                found: proposal.capability.clone(),
            });
        }

        let mut params: BTreeMap<ParamName, ParamValue> = BTreeMap::new();
        for (param, value) in &proposal.params {
            let spec = self
                .params
                .get(param)
                .ok_or_else(|| SchemaError::UnknownParameter {
                    param: param.clone(),
                })?;
            if !spec.domain.matches(value) {
                return Err(SchemaError::WrongDomain {
                    param: param.clone(),
                    expected: spec.domain,
                });
            }
            params.insert(param.clone(), value.clone());
        }

        for (param, spec) in &self.params {
            if params.contains_key(param) {
                continue;
            }
            match &spec.requirement {
                Requirement::Required => {
                    return Err(SchemaError::MissingRequiredParameter {
                        param: param.clone(),
                    })
                }
                Requirement::Optional => {}
                Requirement::DefaultTo(value) => {
                    params.insert(param.clone(), value.clone());
                }
            }
        }

        Ok(NormalizedActionProposal {
            actor: proposal.actor.clone(),
            device: proposal.device.clone(),
            capability: proposal.capability.clone(),
            params,
        })
    }
}

/// A proposal that has passed schema validation.
///
/// Fields are private and there is no public constructor:
/// [`CapabilitySchema::normalize`] is the only way to obtain one. Authority
/// evaluation consumes this type rather than [`ActionProposal`], so no caller
/// can evaluate an unvalidated proposal as though it were schema-valid.
///
/// Holding one means the operation is well-formed. It means nothing at all
/// about whether the operation is authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedActionProposal {
    actor: SubjectId,
    device: DeviceId,
    capability: CapabilityName,
    params: BTreeMap<ParamName, ParamValue>,
}

impl NormalizedActionProposal {
    /// Who is asking.
    pub fn actor(&self) -> &SubjectId {
        &self.actor
    }

    /// Which device the operation targets.
    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    /// Which capability was requested.
    pub fn capability(&self) -> &CapabilityName {
        &self.capability
    }

    /// The validated arguments, with schema defaults already applied.
    pub fn params(&self) -> &BTreeMap<ParamName, ParamValue> {
        &self.params
    }
}
