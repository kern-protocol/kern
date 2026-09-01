//! The one capability this adapter serves.
//!
//! An arm is a stack of joints. Kern does not expose the joints. It exposes the
//! *task*: a thing moves from one named zone to another. There is deliberately
//! no capability for a joint angle, a trajectory, a torque, a PWM value, or a
//! controller topic, because each of those would let an authorized proposal
//! mean something the policy could not bound.
//!
//! Both parameters are symbols, which is what lets policy bound them with a
//! [`SymbolSet`](kern_core::SymbolSet): the authorized set of zones *is* the
//! authorized workspace.

use kern_core::{
    CapabilityName, CapabilitySchema, ParamDomain, ParamName, ParamSpec, ParamValue,
    SchemaDefinitionError, Symbol,
};
use kern_execution::SemanticCommand;

/// The capability name this adapter answers to.
pub const PICK_AND_PLACE: &str = "pick_and_place";

/// `source_zone`: where the item is picked up, by name.
pub const SOURCE_ZONE: &str = "source_zone";
/// `destination_zone`: where the item is placed, by name.
pub const DESTINATION_ZONE: &str = "destination_zone";

/// The schema for `pick_and_place`.
///
/// Both parameters are required, and both are symbols. There is no default
/// source and no default destination: an arm that guesses where something came
/// from is an arm that moves something else.
pub fn pick_and_place_schema() -> Result<CapabilitySchema, SchemaDefinitionError> {
    CapabilitySchema::new(
        CapabilityName::new(PICK_AND_PLACE).expect("a non-empty literal"),
        [
            (
                ParamName::new(SOURCE_ZONE),
                ParamSpec::required(ParamDomain::Symbol),
            ),
            (
                ParamName::new(DESTINATION_ZONE),
                ParamSpec::required(ParamDomain::Symbol),
            ),
        ],
    )
}

/// A `pick_and_place` command the adapter understands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PickAndPlaceRequest {
    /// Where the item is picked up.
    pub source_zone: Symbol,
    /// Where it is placed.
    pub destination_zone: Symbol,
}

/// A semantic command this adapter cannot serve.
///
/// Every variant means the adapter refuses **before** anything reaches the arm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandError {
    /// The command names a capability other than `pick_and_place`.
    WrongCapability,
    /// A required parameter is absent.
    MissingParameter(&'static str),
    /// A parameter is present with the wrong value domain.
    WrongDomain(&'static str),
    /// The source and destination are the same zone.
    ///
    /// Refused rather than performed as a no-op: an arm asked to move something
    /// onto itself is being asked something nobody meant.
    SameZone(Symbol),
    /// The zone is not one this arm has a pose for.
    ///
    /// Policy already decides which zones may be requested. This is the adapter
    /// refusing to invent a pose for a name it does not know.
    UnknownZone(Symbol),
}

impl core::fmt::Display for CommandError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongCapability => f.write_str("not a pick_and_place command"),
            Self::MissingParameter(param) => write!(f, "missing parameter {param}"),
            Self::WrongDomain(param) => write!(f, "parameter {param} has the wrong domain"),
            Self::SameZone(zone) => write!(f, "source and destination are both `{zone}`"),
            Self::UnknownZone(zone) => write!(f, "no zone named `{zone}`"),
        }
    }
}

impl std::error::Error for CommandError {}

impl PickAndPlaceRequest {
    /// Reads a pick-and-place request out of a command the governor authorized.
    pub fn from_command(command: &SemanticCommand<'_>) -> Result<Self, CommandError> {
        if command.capability().as_str() != PICK_AND_PLACE {
            return Err(CommandError::WrongCapability);
        }

        let symbol = |name: &'static str| -> Result<Symbol, CommandError> {
            match command.params().get(&ParamName::new(name)) {
                Some(ParamValue::Symbol(symbol)) => Ok(symbol.clone()),
                Some(ParamValue::Scalar(_)) => Err(CommandError::WrongDomain(name)),
                None => Err(CommandError::MissingParameter(name)),
            }
        };

        let source_zone = symbol(SOURCE_ZONE)?;
        let destination_zone = symbol(DESTINATION_ZONE)?;
        if source_zone == destination_zone {
            return Err(CommandError::SameZone(source_zone));
        }

        Ok(Self {
            source_zone,
            destination_zone,
        })
    }
}
