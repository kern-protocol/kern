//! The one capability this adapter serves.
//!
//! A conveyor is a motor. Kern does not expose the motor. It exposes the
//! *transfer*: an item goes to a named station, under an authorized speed
//! bound. There is deliberately no capability for a direction, a duration, a
//! velocity setpoint, a PWM value, or a raw topic, because each of those would
//! let an authorized proposal mean something the policy could not bound.
//!
//! Kern's semantics stay integer and symbolic. Millimetres per second for the
//! bound; a symbol for the station. No float appears above [`crate::units`].

use kern_core::{
    CapabilityName, CapabilitySchema, ParamDomain, ParamName, ParamSpec, ParamValue,
    SchemaDefinitionError, Symbol,
};
use kern_execution::SemanticCommand;

/// The capability name this adapter answers to.
pub const TRANSFER_ITEM: &str = "transfer_item";

/// `destination_station`: the station the item is transferred to, by name.
pub const DESTINATION_STATION: &str = "destination_station";
/// `max_speed_mm_s`: the belt speed bound this operation is authorized under.
pub const MAX_SPEED_MM_S: &str = "max_speed_mm_s";

/// The schema for `transfer_item`.
///
/// Both parameters are required. Nothing is optional and nothing is defaulted:
/// a missing bound is not a permissive one, and the adapter must never guess a
/// belt speed it was not given.
pub fn transfer_item_schema() -> Result<CapabilitySchema, SchemaDefinitionError> {
    CapabilitySchema::new(
        CapabilityName::new(TRANSFER_ITEM).expect("a non-empty literal"),
        [
            (
                ParamName::new(DESTINATION_STATION),
                ParamSpec::required(ParamDomain::Symbol),
            ),
            (
                ParamName::new(MAX_SPEED_MM_S),
                ParamSpec::required(ParamDomain::Scalar),
            ),
        ],
    )
}

/// A `transfer_item` command the adapter understands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferRequest {
    /// The named destination station.
    pub destination_station: Symbol,
    /// The authorized belt speed bound, millimetres per second.
    pub max_speed_mm_s: i64,
}

/// A semantic command this adapter cannot serve.
///
/// Every variant means the adapter refuses **before** anything reaches the
/// machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandError {
    /// The command names a capability other than `transfer_item`.
    WrongCapability,
    /// A required parameter is absent.
    MissingParameter(&'static str),
    /// A parameter is present with the wrong value domain.
    WrongDomain(&'static str),
    /// The speed bound is not positive.
    ///
    /// Refused rather than treated as "no limit": a zero or negative bound is a
    /// caller mistake, and the permissive reading of it is the dangerous one.
    NonPositiveSpeed,
    /// The station is not one this conveyor has.
    ///
    /// Policy already decides which stations may be requested. This is the
    /// adapter refusing to invent a position for a name it does not know, which
    /// is a different job: an adapter that assumes its inputs is an adapter that
    /// converts garbage into motion.
    UnknownStation(Symbol),
}

impl core::fmt::Display for CommandError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongCapability => f.write_str("not a transfer_item command"),
            Self::MissingParameter(param) => write!(f, "missing parameter {param}"),
            Self::WrongDomain(param) => write!(f, "parameter {param} has the wrong domain"),
            Self::NonPositiveSpeed => f.write_str("max_speed_mm_s must be positive"),
            Self::UnknownStation(station) => write!(f, "no station named `{station}`"),
        }
    }
}

impl std::error::Error for CommandError {}

impl TransferRequest {
    /// Reads a transfer request out of a command the governor authorized.
    ///
    /// Schema validation already happened upstream; this repeats the checks the
    /// adapter itself depends on.
    pub fn from_command(command: &SemanticCommand<'_>) -> Result<Self, CommandError> {
        if command.capability().as_str() != TRANSFER_ITEM {
            return Err(CommandError::WrongCapability);
        }

        let station = match command.params().get(&ParamName::new(DESTINATION_STATION)) {
            Some(ParamValue::Symbol(symbol)) => symbol.clone(),
            Some(ParamValue::Scalar(_)) => {
                return Err(CommandError::WrongDomain(DESTINATION_STATION))
            }
            None => return Err(CommandError::MissingParameter(DESTINATION_STATION)),
        };
        let speed = match command.params().get(&ParamName::new(MAX_SPEED_MM_S)) {
            Some(ParamValue::Scalar(value)) => *value,
            Some(ParamValue::Symbol(_)) => return Err(CommandError::WrongDomain(MAX_SPEED_MM_S)),
            None => return Err(CommandError::MissingParameter(MAX_SPEED_MM_S)),
        };
        if speed <= 0 {
            return Err(CommandError::NonPositiveSpeed);
        }

        Ok(Self {
            destination_station: station,
            max_speed_mm_s: speed,
        })
    }
}
