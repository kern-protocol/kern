//! The model boundary.
//!
//! Everything above this module is Kern. Everything below it — a provider
//! adapter, an HTTP client, a hosted model, a fixture, an attacker — is not.
//! The boundary is one synchronous method returning one enum:
//!
//! ```text
//! PlanningRequest  ->  ProposalModel::propose  ->  ModelOutcome
//! ```
//!
//! # Why this is synchronous
//!
//! Inference is networked, and networked work wants an async runtime. Kern's
//! trusted crates do not have one and will not acquire one, because "the
//! authority crates depend on a specific async runtime" is a much larger
//! commitment than it looks. A provider that needs concurrency contains it —
//! in a worker thread, an internal runtime, a blocking client — and hands back
//! the bytes it got. Network concurrency is a provider concern.
//!
//! # Why the success case is bytes
//!
//! [`RawModelResponse`] holds bytes, not a proposal. A model cannot return a
//! parsed proposal because the trait does not let it: the only way from a model
//! to an [`ActionProposal`](kern_core::ActionProposal) runs through
//! [`crate::parse`], which is Kern's code operating on untrusted input.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};

use crate::bounds::MAX_RESPONSE_BYTES;
use crate::request::PlanningRequest;

/// Domain separator for the model-response digest construction.
pub const RESPONSE_DIGEST_DOMAIN_V1: &[u8] = b"KERN-AI-MODEL-RESPONSE-V1";

/// Which provider and model produced a response.
///
/// # Provenance, and nothing else
///
/// No authority decision anywhere in Kern reads this type. Two identical
/// normalized proposals are evaluated identically whether one came from a live
/// hosted model and the other from a fixture written to attack it, and the test
/// suite asserts exactly that. Model identity answers "what happened"; it must
/// never answer "is this allowed".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelIdentity {
    provider: String,
    model: String,
    config_digest: Option<[u8; 32]>,
}

impl ModelIdentity {
    /// Names a provider and model.
    pub fn new(provider: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            config_digest: None,
        }
    }

    /// Attaches a digest of the adapter's non-secret configuration.
    ///
    /// A provider adapter that computes one must digest the *non-secret*
    /// configuration only. An API key is not configuration for this purpose; it
    /// is a host secret, and a digest of it has no place in a provenance record
    /// that may be printed, logged, or shipped.
    #[must_use]
    pub fn with_config_digest(mut self, digest: [u8; 32]) -> Self {
        self.config_digest = Some(digest);
        self
    }

    /// The provider identity, such as `nebius-token-factory`.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// The model identifier the provider was asked for.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The adapter configuration digest, if the adapter supplied one.
    pub fn config_digest(&self) -> Option<&[u8; 32]> {
        self.config_digest.as_ref()
    }
}

impl fmt::Display for ModelIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.provider, self.model)
    }
}

/// The response was too large to look at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseTooLarge {
    /// How many bytes the provider offered.
    pub bytes: usize,
}

impl fmt::Display for ResponseTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "model response is {} bytes, over the {MAX_RESPONSE_BYTES} byte bound",
            self.bytes
        )
    }
}

impl core::error::Error for ResponseTooLarge {}

/// Bytes a model returned. Attacker-controlled, in full.
///
/// # Read this before adding a method here
///
/// Every byte in this type is under the control of whoever controls the model —
/// which, given prompt injection, may be whoever controls the instruction, the
/// environment description, or a document the model read last week. That is
/// true of JSON structure, of numbers, of capability names, of the reason
/// string, and of anything a provider's structured-output feature promises.
///
/// The size bound is enforced at construction, so an oversized response cannot
/// exist as a `RawModelResponse` at all: it is rejected before it is stored,
/// not truncated and then parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawModelResponse {
    bytes: Vec<u8>,
}

impl RawModelResponse {
    /// Accepts provider bytes, enforcing the frozen size bound.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, ResponseTooLarge> {
        let bytes = bytes.into();
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ResponseTooLarge { bytes: bytes.len() });
        }
        Ok(Self { bytes })
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// How many bytes the model returned.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when the model returned nothing at all.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Names these exact bytes.
    ///
    /// ```text
    /// SHA-256( b"KERN-AI-MODEL-RESPONSE-V1" || response_bytes )
    /// ```
    ///
    /// Computed over what arrived, before any unwrapping or parsing, so the
    /// digest in a provenance record names the bytes the provider actually
    /// sent rather than what Kern made of them.
    pub fn digest(&self) -> ResponseDigest {
        let mut hasher = Sha256::new();
        hasher.update(RESPONSE_DIGEST_DOMAIN_V1);
        hasher.update(&self.bytes);
        ResponseDigest(hasher.finalize().into())
    }
}

/// Names one exact model response.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResponseDigest([u8; 32]);

impl ResponseDigest {
    /// Wraps a precomputed digest.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The underlying digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ResponseDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResponseDigest({self})")
    }
}

impl fmt::Display for ResponseDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..")
    }
}

/// Why a provider produced no response.
///
/// # These are not denials
///
/// A provider failure says nothing whatsoever about authority. It is not a
/// `Denied`, it is not an execution failure, and it is certainly not an
/// authorization. The only correct consequence of any variant here is that
/// there is no proposal — and therefore no normalization, no evaluation, no
/// challenge, no lease, and no motion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderFailure {
    /// The provider could not be reached, or reported itself unavailable.
    Unavailable,
    /// The local deadline for the inference call passed.
    ///
    /// Kern gave up waiting. Whether the provider eventually answered is
    /// unknown and does not matter: an answer that arrives after the deadline
    /// is not consumed.
    Timeout,
    /// The transport ended ambiguously.
    ///
    /// Distinct from [`Self::Unavailable`] because "we know it was not there"
    /// and "we do not know what happened" are different facts, and only one of
    /// them is worth retrying by hand.
    TransportUnknown,
    /// The provider definitively refused the request.
    ///
    /// Authentication failure, an unknown model identifier, a malformed
    /// request, a quota refusal. A configuration problem on Kern's side, in
    /// almost every case.
    ProviderRejected {
        /// A short, non-secret description. Must never carry credentials.
        detail: String,
    },
}

impl fmt::Display for ProviderFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("provider unavailable"),
            Self::Timeout => f.write_str("provider timed out"),
            Self::TransportUnknown => f.write_str("provider transport ended ambiguously"),
            Self::ProviderRejected { detail } => {
                write!(f, "provider rejected the request: {detail}")
            }
        }
    }
}

impl core::error::Error for ProviderFailure {}

/// What one inference attempt produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelOutcome {
    /// The provider returned bytes. Nothing is claimed about them.
    Response(RawModelResponse),
    /// The provider produced nothing, for this reason.
    Failed(ProviderFailure),
}

impl ModelOutcome {
    /// The response, if there was one.
    pub fn response(&self) -> Option<&RawModelResponse> {
        match self {
            Self::Response(response) => Some(response),
            Self::Failed(_) => None,
        }
    }

    /// The failure, if there was one.
    pub fn failure(&self) -> Option<&ProviderFailure> {
        match self {
            Self::Failed(failure) => Some(failure),
            Self::Response(_) => None,
        }
    }
}

/// Something that can be asked to propose an action.
///
/// # The trait is the whole privilege
///
/// An implementation may do anything at all: call a hosted model, replay a
/// fixture, return the most hostile bytes it can construct. What it may *not*
/// do is anything else, because this signature is the entire interface. It
/// takes a bounded request and returns bytes or a failure. There is no
/// parameter through which it could receive a signing key, a challenge, a
/// lease, or an enforcer handle, and no return path through which it could hand
/// back a `NormalizedActionProposal`, an `AuthorizedOperation`, a `SignedLease`,
/// a `LeaseHandle`, or a `SemanticCommand`.
///
/// That is deliberate, and it is the reason the malicious-model tests are
/// short: there is nothing for a malicious implementation to reach for.
///
/// # One attempt
///
/// The plane calls this once per invocation and does not retry. A provider
/// implementation must not retry internally either, unless it documents the
/// semantics of doing so.
pub trait ProposalModel {
    /// Asks for at most one proposal.
    ///
    /// Implementations must not panic. A panicking model would be a model that
    /// decides whether Kern keeps running, which is more authority than a model
    /// is allowed to have.
    fn propose(&mut self, request: &PlanningRequest) -> ModelOutcome;

    /// Which provider and model this is, for provenance.
    fn identity(&self) -> ModelIdentity;
}
