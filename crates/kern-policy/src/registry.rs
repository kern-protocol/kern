//! Resolving `(device, capability)` to the schema that defines its meaning.

use alloc::collections::BTreeMap;
use core::fmt;

use kern_core::{CapabilityName, CapabilitySchema, DeviceId};

/// A registry lookup or registration failed.
///
/// `UnknownDevice` and `UnknownCapability` stay distinct because the
/// distinction is useful in development, diagnostics, and tests. An interface
/// answering untrusted callers may need to collapse both into one opaque error,
/// since distinguishable errors are a device and capability enumeration oracle.
/// That is a boundary concern for whichever layer first faces untrusted input,
/// not a reason to blunt these types (AGENT.md section 14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// Nothing is registered for this device.
    UnknownDevice {
        /// The device asked about.
        device: DeviceId,
    },
    /// The device is known, but does not expose this capability.
    UnknownCapability {
        /// The device asked about.
        device: DeviceId,
        /// The capability asked about.
        capability: CapabilityName,
    },
    /// This device already has a schema for that capability.
    DuplicateRegistration {
        /// The device.
        device: DeviceId,
        /// The capability already registered.
        capability: CapabilityName,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownDevice { device } => write!(f, "unknown device `{device}`"),
            Self::UnknownCapability { device, capability } => {
                write!(f, "device `{device}` has no capability `{capability}`")
            }
            Self::DuplicateRegistration { device, capability } => write!(
                f,
                "device `{device}` already registers capability `{capability}`"
            ),
        }
    }
}

impl core::error::Error for RegistryError {}

/// Which capabilities each device exposes, and what they mean.
///
/// The registry establishes meaning. It decides nothing about authority: that a
/// device understands `navigate` implies nothing about who may request it.
#[derive(Clone, Debug, Default)]
pub struct CapabilityRegistry {
    schemas: BTreeMap<(DeviceId, CapabilityName), CapabilitySchema>,
}

impl CapabilityRegistry {
    /// An empty registry, which resolves nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a schema against a device.
    ///
    /// The capability key comes from the schema itself, so a registry entry
    /// cannot claim `(robot_1, navigate) -> schema(name = pick)`. One source of
    /// truth, enforced by the shape of this signature rather than by a
    /// validation rule someone can forget to call.
    ///
    /// Registering twice is an error. A silent overwrite would let one device's
    /// capability quietly become another operation entirely.
    pub fn register(
        &mut self,
        device: DeviceId,
        schema: CapabilitySchema,
    ) -> Result<(), RegistryError> {
        let key = (device, schema.name().clone());
        if self.schemas.contains_key(&key) {
            return Err(RegistryError::DuplicateRegistration {
                device: key.0,
                capability: key.1,
            });
        }
        self.schemas.insert(key, schema);
        Ok(())
    }

    /// Resolves what a requested operation means, failing closed when unknown.
    pub fn resolve(
        &self,
        device: &DeviceId,
        capability: &CapabilityName,
    ) -> Result<&CapabilitySchema, RegistryError> {
        if let Some(schema) = self.schemas.get(&(device.clone(), capability.clone())) {
            return Ok(schema);
        }
        if self.schemas.keys().any(|(known, _)| known == device) {
            Err(RegistryError::UnknownCapability {
                device: device.clone(),
                capability: capability.clone(),
            })
        } else {
            Err(RegistryError::UnknownDevice {
                device: device.clone(),
            })
        }
    }

    /// Every registered binding, in `(device, capability)` order.
    pub fn iter(&self) -> impl Iterator<Item = (&DeviceId, &CapabilityName, &CapabilitySchema)> {
        self.schemas
            .iter()
            .map(|((device, capability), schema)| (device, capability, schema))
    }
}
