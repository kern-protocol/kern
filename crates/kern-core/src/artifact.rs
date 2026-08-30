//! Identity of an authenticated authority artifact.
//!
//! The signature authenticates. The digest identifies. Those are separate jobs,
//! and conflating them would tie semantic identity to one signature scheme and
//! to signer behaviour — awkward the moment a future version changes algorithms
//! or admits several valid signatures over identical authority bytes.

use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};

use crate::lease::ProtocolVersion;

/// Domain separator for the artifact-identity construction.
///
/// The `V1` here versions *this construction*, not the lease protocol. The lease
/// protocol version is a separate, explicit input.
pub const ARTIFACT_DOMAIN_V1: &[u8] = b"KERN-AUTHORITY-ARTIFACT-V1";

/// Identifies one authenticated canonical authority artifact.
///
/// ```text
/// SHA-256( b"KERN-AUTHORITY-ARTIFACT-V1" || u16_le(protocol_version) || signing_input )
/// ```
///
/// Signature bytes are deliberately **not** an input: this names the authority
/// that was authenticated, not the particular signature instance that
/// authenticated it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorityArtifactId([u8; 32]);

impl AuthorityArtifactId {
    /// Computes the identity of the authority described by `signing_input`.
    pub fn compute(version: ProtocolVersion, signing_input: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(ARTIFACT_DOMAIN_V1);
        hasher.update(version.as_u16().to_le_bytes());
        hasher.update(signing_input);
        Self(hasher.finalize().into())
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

impl fmt::Debug for AuthorityArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut hex = Vec::with_capacity(8);
        for byte in &self.0[..4] {
            hex.push(*byte);
        }
        write!(
            f,
            "AuthorityArtifactId({:02x}{:02x}{:02x}{:02x}..)",
            hex[0], hex[1], hex[2], hex[3]
        )
    }
}
