//! Which keys are authorized for which issuers.

use alloc::collections::BTreeMap;
use core::fmt;

use ed25519_dalek::VerifyingKey;
use kern_core::{IssuerId, KeyId};

/// A trust-store operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustError {
    /// No key at all is trusted for the claimed issuer.
    UntrustedIssuer,
    /// The issuer is trusted, but not under that key identifier.
    UnknownKey,
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UntrustedIssuer => f.write_str("untrusted issuer"),
            Self::UnknownKey => f.write_str("unknown key for issuer"),
        }
    }
}

impl core::error::Error for TrustError {}

/// A key could not be authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizeError {
    /// The bytes are not a valid Ed25519 public key.
    InvalidKey,
    /// That issuer already authorizes a key under this identifier.
    ///
    /// Silently overwriting would let a provisioning mistake replace a trusted
    /// key without anyone noticing.
    DuplicateKey,
}

impl fmt::Display for AuthorizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => f.write_str("not a valid Ed25519 public key"),
            Self::DuplicateKey => f.write_str("issuer already authorizes that key identifier"),
        }
    }
}

impl core::error::Error for AuthorizeError {}

/// The keys this enforcer will accept, and whose leases they may sign.
///
/// # A valid signature is not enough
///
/// Verifying a signature under a key the *lease itself* supplied would prove
/// only that whoever wrote the lease owns a keypair. Authorization is the point:
/// a key must be registered here **for the claimed issuer** before it is ever
/// handed to the verifier.
///
/// # Rotation
///
/// An issuer may authorize several keys at once, so rotation is add-then-remove
/// driven by out-of-band provisioning. There is deliberately **no wall-clock key
/// expiry**: that would need trusted absolute time, which is exactly what an
/// edge enforcer does not have.
#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    keys: BTreeMap<(IssuerId, KeyId), VerifyingKey>,
}

impl TrustStore {
    /// A store that trusts nobody.
    pub fn new() -> Self {
        Self::default()
    }

    /// Authorizes a key for an issuer.
    pub fn authorize(
        &mut self,
        issuer: IssuerId,
        key_id: KeyId,
        key_bytes: [u8; 32],
    ) -> Result<(), AuthorizeError> {
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| AuthorizeError::InvalidKey)?;
        let entry = (issuer, key_id);
        if self.keys.contains_key(&entry) {
            return Err(AuthorizeError::DuplicateKey);
        }
        self.keys.insert(entry, key);
        Ok(())
    }

    /// Removes a key, for rotation.
    pub fn revoke_key(&mut self, issuer: &IssuerId, key_id: &KeyId) -> bool {
        self.keys
            .remove(&(issuer.clone(), key_id.clone()))
            .is_some()
    }

    /// Resolves a candidate verification key.
    ///
    /// Both arguments come from an unauthenticated body and are lookup hints
    /// only. A successful lookup authorizes nothing by itself — the signature
    /// still has to verify.
    pub fn key_for(&self, issuer: &IssuerId, key_id: &KeyId) -> Result<&VerifyingKey, TrustError> {
        if let Some(key) = self.keys.get(&(issuer.clone(), key_id.clone())) {
            return Ok(key);
        }
        if self.keys.keys().any(|(known, _)| known == issuer) {
            Err(TrustError::UnknownKey)
        } else {
            Err(TrustError::UntrustedIssuer)
        }
    }

    /// How many keys are authorized in total.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when nothing is trusted.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}
