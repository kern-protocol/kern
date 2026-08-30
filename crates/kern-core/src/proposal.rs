//! What an upstream system asks for. Never what it is allowed to do.

use alloc::collections::BTreeMap;

use crate::ids::{CapabilityName, DeviceId, ParamName, SubjectId, Symbol};

/// A concrete argument supplied for a capability parameter.
///
/// The value domain is deliberately small. Numbers are `i64` rather than
/// floating point: `f64` is neither `Ord` nor `Eq`, which would break
/// idempotence, structural equality, and deterministic comparison. Units and
/// scaling belong to the capability schema, not to the authority algebra.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParamValue {
    /// A numeric argument in the capability's own fixed-point units.
    Scalar(i64),
    /// An opaque symbolic argument, such as a destination name.
    Symbol(Symbol),
}

/// An upstream request to perform a semantic operation.
///
/// A proposal carries no authority. It is intent. Nothing here has been
/// checked against policy, and nothing here is signed.
///
/// This type is intentionally boring. Do not add lease-shaped fields to it
/// because a lease will exist later; a proposal that starts to look like a
/// lease invites code that treats it as one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionProposal {
    /// Who is asking.
    pub actor: SubjectId,
    /// Which device the operation targets.
    pub device: DeviceId,
    /// Which semantic capability is requested.
    pub capability: CapabilityName,
    /// The arguments proposed for that capability.
    pub params: BTreeMap<ParamName, ParamValue>,
}

impl ActionProposal {
    /// Builds a proposal with no parameters.
    pub fn new(actor: SubjectId, device: DeviceId, capability: CapabilityName) -> Self {
        Self {
            actor,
            device,
            capability,
            params: BTreeMap::new(),
        }
    }

    /// Adds one parameter, replacing any previous value for that name.
    #[must_use]
    pub fn with_param(mut self, name: ParamName, value: ParamValue) -> Self {
        self.params.insert(name, value);
        self
    }
}
