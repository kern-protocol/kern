//! Turning transmitted bytes into authenticated authority.

use ed25519_dalek::{Signature as DalekSignature, Verifier};
use kern_core::wire::{encode_body_v2, parse, ParsedLease};
use kern_core::{AuthorityArtifactId, LeaseBodyV2, ProtocolVersion};

use crate::error::InstallError;
use crate::trust::TrustStore;

/// A lease whose signature has verified under an authorized key.
///
/// # What this proves
///
/// - the signature verified over the **exact transmitted bytes**
/// - under a key the trust store authorizes **for the claimed issuer**
/// - the body is canonically encoded V2
///
/// # What it does not prove
///
/// Nothing about session, freshness, supersession, or lifetime. Those are
/// installation's job, and a `VerifiedLease` on its own authorizes no operation
/// whatsoever.
#[derive(Debug)]
pub struct VerifiedLease {
    body: LeaseBodyV2,
    artifact: AuthorityArtifactId,
}

impl VerifiedLease {
    /// The authenticated body.
    pub fn body(&self) -> &LeaseBodyV2 {
        &self.body
    }

    /// The identity of the authenticated authority artifact.
    pub fn artifact(&self) -> &AuthorityArtifactId {
        &self.artifact
    }

    /// Consumes the lease, yielding its parts.
    pub fn into_parts(self) -> (LeaseBodyV2, AuthorityArtifactId) {
        (self.body, self.artifact)
    }
}

/// Authenticates transmitted lease bytes.
///
/// The ordering is deliberate, and each step is either a resource decision or a
/// trust decision:
///
/// ```text
/// 1. frame                        resource: bounded, version-checked first
/// 2. canonical decode             resource: reject garbage before any crypto,
///                                 which costs far less than a verification
/// 3. issuer and key_id            hints only, carrying zero authority
/// 4. trust lookup                 an unauthorized key never reaches the verifier
/// 5. verify over the RAW bytes    trust: the boundary
/// 6. re-encode byte equality      trust: authoritative canonicality gate
/// ```
///
/// Step 5 verifies the bytes that arrived, never a re-encoding of the parsed
/// body, so a decoder bug cannot become a signature bypass. Step 6 is largely
/// redundant given step 2, and deliberately so: it catches encoder/decoder
/// asymmetry, which is precisely the bug class that would let two byte strings
/// represent one authority.
pub fn verify_bytes(bytes: &[u8], trust: &TrustStore) -> Result<VerifiedLease, InstallError> {
    let parsed = parse(bytes)?;
    verify_parsed(&parsed, trust)
}

/// Authenticates an already-framed lease.
pub fn verify_parsed(
    parsed: &ParsedLease<'_>,
    trust: &TrustStore,
) -> Result<VerifiedLease, InstallError> {
    // This enforcer installs V2 only: V1 carries no challenge and so cannot
    // support freshness at first installation. Accepting it silently would offer
    // a weaker guarantee than the one this type claims.
    if parsed.version() != ProtocolVersion::V2 {
        return Err(InstallError::UnsupportedVersion {
            found: parsed.version().as_u16(),
        });
    }

    let body = parsed.decode_untrusted_body_v2()?;

    let key = trust.key_for(&body.core.issuer, &body.core.key_id)?;

    let signing_input = parsed.signing_input();
    let signature = DalekSignature::from_bytes(parsed.signature().as_bytes());
    key.verify(&signing_input, &signature)
        .map_err(|_| InstallError::InvalidSignature)?;

    if encode_body_v2(&body).map_err(|_| InstallError::Malformed)? != parsed.body_bytes() {
        return Err(InstallError::NonCanonicalEncoding);
    }

    let artifact = AuthorityArtifactId::compute(ProtocolVersion::V2, &signing_input);

    Ok(VerifiedLease { body, artifact })
}
