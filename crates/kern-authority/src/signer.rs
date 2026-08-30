//! Signing, behind an interface that a TPM, HSM, or KMS can implement later.

use core::fmt;

use ed25519_dalek::Signer as _;
use ed25519_dalek::SigningKey;
use kern_core::{KeyId, Signature};

/// A signature could not be produced.
///
/// Fallible on purpose. Ed25519 signing in process cannot fail, but the point of
/// this interface is that key material moves to a TPM, secure element, or cloud
/// KMS later (AGENT.md section 15), and those refuse, time out, and disappear.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignError {
    /// The signing backend refused or was unreachable.
    Unavailable,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("signing backend unavailable"),
        }
    }
}

impl core::error::Error for SignError {}

/// Something that can sign lease bytes.
///
/// Deliberately narrow: it signs an opaque message and names the key it used.
/// It knows nothing about leases, so key storage can move without the issuance
/// logic noticing.
pub trait Signer {
    /// Which key this signer uses. Travels in the signed body as a lookup hint.
    fn key_id(&self) -> &KeyId;

    /// Signs an opaque message.
    fn sign(&self, message: &[u8]) -> Result<Signature, SignError>;
}

/// An in-process Ed25519 signer.
///
/// Private key material lives here, never in `kern-core`.
pub struct Ed25519Signer {
    key_id: KeyId,
    key: SigningKey,
}

impl Ed25519Signer {
    /// Builds a signer from a 32-byte seed.
    ///
    /// Deterministic, which is what makes golden signature vectors possible.
    /// Development and test fixtures may use fixed seeds; production key
    /// material must not be hard-coded (AGENT.md section 15).
    pub fn from_seed(key_id: KeyId, seed: [u8; 32]) -> Self {
        Self {
            key_id,
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// The public key bytes.
    ///
    /// Exposed so tests and future trust-store tooling can check a signature.
    /// This crate does no verification itself.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl core::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render key material.
        f.debug_struct("Ed25519Signer")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl Signer for Ed25519Signer {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, SignError> {
        Ok(Signature::from_bytes(self.key.sign(message).to_bytes()))
    }
}
