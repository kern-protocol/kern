//! What an executor is handed, and how it is named in provenance.

use core::fmt;

use alloc::collections::BTreeMap;
use kern_core::wire::{encode_operation, EncodeError};
use kern_core::{
    CapabilityName, DeviceId, NormalizedActionProposal, ParamName, ParamValue, SubjectId,
};
use sha2::{Digest, Sha256};

use crate::id::ExecutionId;

/// Domain separator for the command-digest construction.
pub const COMMAND_DOMAIN_V1: &[u8] = b"KERN-EXECUTION-COMMAND-V1";

/// Names the exact operation an execution was prepared for.
///
/// ```text
/// SHA-256( b"KERN-EXECUTION-COMMAND-V1" || canonical_operation_encoding )
/// ```
///
/// # Why a digest rather than the parameters
///
/// An [`ExecutionRecord`](crate::ExecutionRecord) lives in a fixed-capacity
/// table on a constrained target, and parameter payloads are not fixed size.
/// Kern therefore keeps the *binding* and lets the host keep the payload: the
/// host can prove at any time that a stored operation is the one that was
/// authorized by recomputing this digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommandDigest([u8; 32]);

impl CommandDigest {
    /// Digests a normalized operation.
    ///
    /// Fails only when the canonical encoding fails, which for a schema-valid
    /// operation means a pathologically large parameter payload.
    pub fn compute(operation: &NormalizedActionProposal) -> Result<Self, EncodeError> {
        let bytes = encode_operation(operation)?;
        let mut hasher = Sha256::new();
        hasher.update(COMMAND_DOMAIN_V1);
        hasher.update(bytes);
        Ok(Self(hasher.finalize().into()))
    }

    /// Wraps a precomputed digest.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The underlying digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CommandDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CommandDigest({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// An operation a current authority decision permitted, addressed to an
/// executor.
///
/// # Construction is private
///
/// There is no public constructor. The only way to obtain one is to hold a
/// [`PreparedExecution`](crate::PreparedExecution) and submit it, which happens
/// only after [`EnforcerStore::enforce`](kern_enforcer::EnforcerStore::enforce)
/// authorized the operation and
/// [`check_authority`](kern_enforcer::EnforcerStore::check_authority) confirmed
/// that authority is still current. An [`ActionProposal`](kern_core::ActionProposal)
/// therefore cannot reach an executor: there is no API that would accept one.
///
/// External code cannot fabricate one:
///
/// ```compile_fail
/// # use kern_execution::{ExecutionId, SemanticCommand};
/// let command = SemanticCommand::new(ExecutionId::from_u128(1), unimplemented!());
/// ```
///
/// # What an adapter is not told
///
/// No lease identifier, no artifact digest, no handle, no constraints. Authority
/// is not an executor input. An adapter receives execution identity and
/// semantics, and decides nothing about permission.
#[derive(Debug)]
pub struct SemanticCommand<'a> {
    execution_id: ExecutionId,
    subject: &'a SubjectId,
    device: &'a DeviceId,
    capability: &'a CapabilityName,
    params: &'a BTreeMap<ParamName, ParamValue>,
}

impl<'a> SemanticCommand<'a> {
    /// Builds a command. Crate-private on purpose — see the type documentation.
    pub(crate) fn new(execution_id: ExecutionId, operation: &'a NormalizedActionProposal) -> Self {
        Self {
            execution_id,
            subject: operation.actor(),
            device: operation.device(),
            capability: operation.capability(),
            params: operation.params(),
        }
    }

    /// The execution this command belongs to.
    ///
    /// An adapter that can attach this to the operation it creates, and echo it
    /// back during reconciliation, lets Kern recover from a lost submission
    /// acknowledgement. See
    /// [`ExecutorDeclaration::echoes_execution_id`](crate::ExecutorDeclaration).
    pub fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// The subject the governing authority was granted to.
    pub fn subject(&self) -> &SubjectId {
        self.subject
    }

    /// The device the operation targets.
    pub fn device(&self) -> &DeviceId {
        self.device
    }

    /// The semantic capability requested.
    pub fn capability(&self) -> &CapabilityName {
        self.capability
    }

    /// The validated arguments, with schema defaults already applied.
    pub fn params(&self) -> &BTreeMap<ParamName, ParamValue> {
        self.params
    }
}
