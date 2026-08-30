//! The one capability this adapter serves.
//!
//! Kern's semantics stay integer. Millimetres, millidegrees, millimetres per
//! second — the same units policy, leases, and constraint sets reason in. No
//! float reaches an authority decision, and no float appears above
//! [`crate::units`].

use kern_core::{
    CapabilityName, CapabilitySchema, ParamDomain, ParamName, ParamSpec, ParamValue,
    SchemaDefinitionError,
};
use kern_execution::SemanticCommand;

/// The capability name this adapter answers to.
pub const NAVIGATE: &str = "navigate";

/// `destination_x_mm`: target X, millimetres, in the configured frame.
pub const DESTINATION_X_MM: &str = "destination_x_mm";
/// `destination_y_mm`: target Y, millimetres, in the configured frame.
pub const DESTINATION_Y_MM: &str = "destination_y_mm";
/// `yaw_mdeg`: target heading, millidegrees.
pub const YAW_MDEG: &str = "yaw_mdeg";
/// `max_speed_mm_s`: the speed bound this operation is authorized under.
pub const MAX_SPEED_MM_S: &str = "max_speed_mm_s";

/// The frozen Phase 6 schema for `navigate`.
///
/// All four parameters are required. Nothing is optional and nothing is
/// defaulted: a missing bound is not a permissive one, and the adapter must
/// never guess a speed limit it was not given.
pub fn navigate_schema() -> Result<CapabilitySchema, SchemaDefinitionError> {
    CapabilitySchema::new(
        CapabilityName::new(NAVIGATE).expect("a non-empty literal"),
        [
            (
                ParamName::new(DESTINATION_X_MM),
                ParamSpec::required(ParamDomain::Scalar),
            ),
            (
                ParamName::new(DESTINATION_Y_MM),
                ParamSpec::required(ParamDomain::Scalar),
            ),
            (
                ParamName::new(YAW_MDEG),
                ParamSpec::required(ParamDomain::Scalar),
            ),
            (
                ParamName::new(MAX_SPEED_MM_S),
                ParamSpec::required(ParamDomain::Scalar),
            ),
        ],
    )
}

/// A `navigate` command the adapter understands, still in Kern's integer units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NavigateRequest {
    /// Target X, millimetres.
    pub destination_x_mm: i64,
    /// Target Y, millimetres.
    pub destination_y_mm: i64,
    /// Target heading, millidegrees.
    pub yaw_mdeg: i64,
    /// The authorized speed bound, millimetres per second.
    pub max_speed_mm_s: i64,
}

/// A semantic command this adapter cannot serve.
///
/// Every variant means the adapter refuses **before** anything reaches ROS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandError {
    /// The command names a capability other than `navigate`.
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
}

impl core::fmt::Display for CommandError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongCapability => f.write_str("not a navigate command"),
            Self::MissingParameter(param) => write!(f, "missing parameter {param}"),
            Self::WrongDomain(param) => write!(f, "parameter {param} has the wrong domain"),
            Self::NonPositiveSpeed => f.write_str("max_speed_mm_s must be positive"),
        }
    }
}

impl std::error::Error for CommandError {}

impl NavigateRequest {
    /// Reads a navigate request out of a command the governor authorized.
    ///
    /// Schema validation already happened upstream; this repeats the checks the
    /// adapter itself depends on, because an adapter that assumes its inputs is
    /// an adapter that converts garbage into motion.
    pub fn from_command(command: &SemanticCommand<'_>) -> Result<Self, CommandError> {
        if command.capability().as_str() != NAVIGATE {
            return Err(CommandError::WrongCapability);
        }

        let scalar = |name: &'static str| -> Result<i64, CommandError> {
            match command.params().get(&ParamName::new(name)) {
                Some(ParamValue::Scalar(value)) => Ok(*value),
                Some(ParamValue::Symbol(_)) => Err(CommandError::WrongDomain(name)),
                None => Err(CommandError::MissingParameter(name)),
            }
        };

        let request = Self {
            destination_x_mm: scalar(DESTINATION_X_MM)?,
            destination_y_mm: scalar(DESTINATION_Y_MM)?,
            yaw_mdeg: scalar(YAW_MDEG)?,
            max_speed_mm_s: scalar(MAX_SPEED_MM_S)?,
        };

        if request.max_speed_mm_s <= 0 {
            return Err(CommandError::NonPositiveSpeed);
        }
        Ok(request)
    }
}
