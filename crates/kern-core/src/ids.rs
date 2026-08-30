//! Identity newtypes.
//!
//! AGENT.md section 22 asks for small domain types rather than raw strings
//! passed everywhere. These are deliberately thin. They carry identity, never
//! authority: holding a `SubjectId` permits nothing.

use alloc::string::String;
use core::fmt;

/// An identifier could not be constructed.
///
/// Kept deliberately narrow. The only rule Kern has a concrete reason for is
/// that a capability name cannot be empty, because it keys the registry. Do not
/// add length, character, or pattern rules without a requirement that needs one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidId {
    /// The identifier is empty.
    Empty,
}

impl fmt::Display for InvalidId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("identifier is empty"),
        }
    }
}

impl core::error::Error for InvalidId {}

/// Identifies the subject that proposes an operation: an agent, a human
/// operator, or a service.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubjectId(String);

impl SubjectId {
    /// Wraps an identifier string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrows the underlying identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Identifies the device an operation targets.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(String);

impl DeviceId {
    /// Wraps an identifier string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrows the underlying identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Names a semantic capability exposed by a device, such as `navigate`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityName(String);

impl CapabilityName {
    /// Wraps a capability name, rejecting an empty one.
    ///
    /// Validation lives here rather than in [`crate::CapabilitySchema`] so an
    /// invalid `CapabilityName` cannot exist at all: nothing downstream has to
    /// re-check it, and nothing can key a registry on the empty name.
    pub fn new(name: impl Into<String>) -> Result<Self, InvalidId> {
        let name = name.into();
        if name.is_empty() {
            return Err(InvalidId::Empty);
        }
        Ok(Self(name))
    }

    /// Borrows the underlying name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapabilityName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Names a parameter of a capability, such as `destination` or `max_speed`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParamName(String);

impl ParamName {
    /// Wraps a parameter name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Borrows the underlying name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ParamName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An opaque symbolic parameter value, such as a location or an object name.
///
/// Kern does not interpret symbols. It only compares them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Symbol(String);

impl Symbol {
    /// Wraps a symbol.
    pub fn new(symbol: impl Into<String>) -> Self {
        Self(symbol.into())
    }

    /// Borrows the underlying symbol.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
