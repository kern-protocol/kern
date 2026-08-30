//! The V1 wire protocol: canonical encoding, framing, and signing input.
//!
//! Everything in this module is **protocol-frozen**. Changing a field, a field
//! order, an enum variant order, or an integer representation changes the bytes
//! that get signed, and is therefore a protocol-version decision with new golden
//! vectors — never a refactor.
//!
//! The wire types are deliberately separate from the semantic types. Deriving a
//! serializer straight onto [`ConstraintSet`] would make its private internal
//! representation into a protocol discriminant, and the algebra could then never
//! change shape without silently invalidating every signature in existence.
//!
//! # Canonicality
//!
//! One authority has exactly one valid encoding. Decoding *validates* that
//! rather than assuming it: ordering, duplicates, and emptiness are all checked,
//! and a violation is [`DecodeError::NonCanonicalEncoding`]. Relying on
//! "`BTreeMap` happens to iterate in order" would leave a decoder accepting byte
//! strings the encoder would never produce.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::challenge::Challenge;
use crate::clock::Timestamp;
use crate::constraint::{Interval, ParamConstraint, SymbolSet};
use crate::constraint_set::ConstraintSet;
use crate::ids::{CapabilityName, DeviceId, ParamName, SubjectId, Symbol};
use crate::lease::{
    EnforcerSessionId, IssuerId, KeyId, LeaseBody, LeaseBodyV2, LeaseId, Nonce, ProtocolVersion,
    Signature, SignedLease, SignedLeaseV2,
};

/// Domain separator for version 1 signing input.
pub const LEASE_DOMAIN_V1: &[u8] = b"KERN-LEASE-V1";

/// Domain separator for version 2 signing input.
///
/// A distinct domain per version means a V1 verifier cannot be induced to check
/// a V2 body: the signing inputs differ, so verification fails rather than
/// misinterpreting the schema.
pub const LEASE_DOMAIN_V2: &[u8] = b"KERN-LEASE-V2";

/// The domain separator a version signs under.
pub const fn domain_for(version: ProtocolVersion) -> &'static [u8] {
    match version {
        ProtocolVersion::V1 => LEASE_DOMAIN_V1,
        ProtocolVersion::V2 => LEASE_DOMAIN_V2,
    }
}

const VERSION_BYTES: usize = 2;
const LENGTH_BYTES: usize = 4;
const SIGNATURE_BYTES: usize = 64;

/// Largest lease body the V1 wire format permits.
///
/// Enforced on **both** encoding and parsing, which makes it part of the V1
/// format rather than a local decoder choice: an interoperable V1
/// implementation must reject a body above this size. It stops a malformed
/// length prefix from asking a constrained target for an enormous allocation,
/// and a body anywhere near this size would already be pathological.
///
/// It changes no authority semantics — nothing about who may do what depends on
/// it — but changing the number changes what V1 accepts, so it is a
/// protocol-version decision. There is deliberately no smaller per-capability
/// limit yet.
pub const MAX_BODY_BYTES: u32 = 64 * 1024;

/// A lease could not be encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The serializer failed.
    Serialization,
    /// The encoded body exceeds [`MAX_BODY_BYTES`].
    BodyTooLarge,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization => f.write_str("lease body could not be serialized"),
            Self::BodyTooLarge => f.write_str("lease body exceeds the maximum encoded size"),
        }
    }
}

impl core::error::Error for EncodeError {}

/// A lease could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The protocol version is not one this build understands.
    ///
    /// Checked before the body is parsed at all.
    UnsupportedVersion {
        /// The version found on the wire.
        found: u16,
    },
    /// The input ended earlier than the framing requires.
    Truncated,
    /// Bytes remain after the envelope.
    TrailingBytes,
    /// The declared body length exceeds [`MAX_BODY_BYTES`].
    BodyTooLarge,
    /// The body bytes are not a well-formed encoding.
    Malformed,
    /// The body decodes, but not from the one canonical encoding of its value.
    ///
    /// Unsorted entries, duplicates, an empty `Bounded` set, an empty allow-list,
    /// or a constraint that restricts nothing all land here. Accepting these
    /// would mean one authority had several valid byte representations.
    NonCanonicalEncoding,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found } => {
                write!(f, "unsupported lease protocol version {found}")
            }
            Self::Truncated => f.write_str("lease envelope is truncated"),
            Self::TrailingBytes => f.write_str("trailing bytes after the lease envelope"),
            Self::BodyTooLarge => f.write_str("lease body exceeds the maximum encoded size"),
            Self::Malformed => f.write_str("lease body is malformed"),
            Self::NonCanonicalEncoding => f.write_str("lease body is not canonically encoded"),
        }
    }
}

impl core::error::Error for DecodeError {}

// -- V1 wire schema -----------------------------------------------------------

/// The V1 encoding of a constraint on one parameter. Protocol-frozen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireConstraint {
    /// An inclusive integer interval.
    Numeric {
        /// Inclusive lower bound.
        lower: i64,
        /// Inclusive upper bound.
        upper: i64,
    },
    /// Only these symbols are permitted. Sorted, unique, non-empty.
    Allowed(Vec<String>),
    /// Every symbol except these. Sorted, unique, non-empty.
    Denied(Vec<String>),
}

/// The V1 encoding of a constraint set. Protocol-frozen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireConstraintSet {
    /// TOP.
    Unconstrained,
    /// Bounded authority. Sorted by parameter name, unique, non-empty.
    Bounded(Vec<(String, WireConstraint)>),
    /// BOTTOM.
    NoAuthority,
}

/// The V2 encoding of a lease body. Protocol-frozen.
///
/// The V1 body is nested rather than restated. Postcard writes a nested struct
/// as its fields in order with no tag or length, so these bytes are exactly the
/// V1 bytes followed by the challenge — the V1 encoding is reused, not
/// reimplemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLeaseBodyV2 {
    /// Every V1 field.
    pub core: WireLeaseBodyV1,
    /// The enforcer challenge this lease answers.
    pub challenge: [u8; 32],
}

/// The V1 encoding of a lease body. Protocol-frozen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLeaseBodyV1 {
    /// Lease identity.
    pub id: [u8; 16],
    /// Issuing authority.
    pub issuer: String,
    /// Signing key hint.
    pub key_id: String,
    /// Subject the authority is granted to.
    pub subject: String,
    /// Target device.
    pub device: String,
    /// Authorized capability.
    pub capability: String,
    /// Parameter bounds.
    pub constraints: WireConstraintSet,
    /// Issuance instant, milliseconds since the Unix epoch.
    pub issued_at: u64,
    /// Expiry instant, milliseconds since the Unix epoch.
    pub expires_at: u64,
    /// Supersession position within this lease's slot.
    pub nonce: u64,
    /// Enforcer boot session binding.
    pub enforcer_session: [u8; 32],
}

// -- semantic -> wire ---------------------------------------------------------

impl From<&ConstraintSet> for WireConstraintSet {
    fn from(set: &ConstraintSet) -> Self {
        if set.is_no_authority() {
            return Self::NoAuthority;
        }
        if set.is_unconstrained() {
            return Self::Unconstrained;
        }
        Self::Bounded(
            set.iter()
                .map(|(name, constraint)| (name.as_str().to_string(), constraint.into()))
                .collect(),
        )
    }
}

impl From<&ParamConstraint> for WireConstraint {
    fn from(constraint: &ParamConstraint) -> Self {
        match constraint {
            ParamConstraint::Numeric(interval) => Self::Numeric {
                lower: interval.lower(),
                upper: interval.upper(),
            },
            ParamConstraint::Symbolic(SymbolSet::Allowed(symbols)) => {
                Self::Allowed(symbols.iter().map(|s| s.as_str().to_string()).collect())
            }
            ParamConstraint::Symbolic(SymbolSet::Denied(symbols)) => {
                Self::Denied(symbols.iter().map(|s| s.as_str().to_string()).collect())
            }
        }
    }
}

impl From<&LeaseBodyV2> for WireLeaseBodyV2 {
    fn from(body: &LeaseBodyV2) -> Self {
        Self {
            core: (&body.core).into(),
            challenge: *body.challenge.as_bytes(),
        }
    }
}

impl From<&LeaseBody> for WireLeaseBodyV1 {
    fn from(body: &LeaseBody) -> Self {
        Self {
            id: *body.id.as_bytes(),
            issuer: body.issuer.as_str().to_string(),
            key_id: body.key_id.as_str().to_string(),
            subject: body.subject.as_str().to_string(),
            device: body.device.as_str().to_string(),
            capability: body.capability.as_str().to_string(),
            constraints: (&body.constraints).into(),
            issued_at: body.issued_at.as_millis(),
            expires_at: body.expires_at.as_millis(),
            nonce: body.nonce.value(),
            enforcer_session: *body.enforcer_session.as_bytes(),
        }
    }
}

// -- wire -> semantic, validating canonicality --------------------------------

/// True when `values` is strictly ascending, which implies sorted and unique.
fn strictly_ascending(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

impl TryFrom<WireConstraint> for ParamConstraint {
    type Error = DecodeError;

    fn try_from(constraint: WireConstraint) -> Result<Self, Self::Error> {
        match constraint {
            WireConstraint::Numeric { lower, upper } => {
                let interval = Interval::between(lower, upper).ok_or(DecodeError::Malformed)?;
                // An unbounded interval restricts nothing, so a canonical set
                // would have dropped it rather than encoded it.
                if interval.is_unbounded() {
                    return Err(DecodeError::NonCanonicalEncoding);
                }
                Ok(Self::Numeric(interval))
            }
            WireConstraint::Allowed(symbols) => {
                if symbols.is_empty() || !strictly_ascending(&symbols) {
                    return Err(DecodeError::NonCanonicalEncoding);
                }
                let set = SymbolSet::allowed(symbols.into_iter().map(Symbol::new))
                    .ok_or(DecodeError::NonCanonicalEncoding)?;
                Ok(Self::Symbolic(set))
            }
            WireConstraint::Denied(symbols) => {
                // An empty deny-list restricts nothing, same as above.
                if symbols.is_empty() || !strictly_ascending(&symbols) {
                    return Err(DecodeError::NonCanonicalEncoding);
                }
                Ok(Self::Symbolic(SymbolSet::denied(
                    symbols.into_iter().map(Symbol::new),
                )))
            }
        }
    }
}

impl TryFrom<WireConstraintSet> for ConstraintSet {
    type Error = DecodeError;

    fn try_from(set: WireConstraintSet) -> Result<Self, Self::Error> {
        match set {
            WireConstraintSet::Unconstrained => Ok(Self::unconstrained()),
            WireConstraintSet::NoAuthority => Ok(Self::no_authority()),
            WireConstraintSet::Bounded(entries) => {
                if entries.is_empty() {
                    return Err(DecodeError::NonCanonicalEncoding);
                }
                let names: Vec<String> = entries.iter().map(|(name, _)| name.clone()).collect();
                if !strictly_ascending(&names) {
                    return Err(DecodeError::NonCanonicalEncoding);
                }

                let mut constraints = Vec::with_capacity(entries.len());
                for (name, constraint) in entries {
                    constraints.push((ParamName::new(name), constraint.try_into()?));
                }

                let rebuilt = Self::from_constraints(constraints);
                // Every entry was already checked non-trivial, so normalization
                // cannot have dropped one. If it did, the encoding was not the
                // canonical form of this value.
                if rebuilt.is_unconstrained() || rebuilt.is_no_authority() {
                    return Err(DecodeError::NonCanonicalEncoding);
                }
                Ok(rebuilt)
            }
        }
    }
}

impl TryFrom<WireLeaseBodyV1> for LeaseBody {
    type Error = DecodeError;

    fn try_from(wire: WireLeaseBodyV1) -> Result<Self, Self::Error> {
        Ok(Self {
            id: LeaseId::from_bytes(wire.id),
            issuer: IssuerId::new(wire.issuer),
            key_id: KeyId::new(wire.key_id),
            subject: SubjectId::new(wire.subject),
            device: DeviceId::new(wire.device),
            capability: CapabilityName::new(wire.capability)
                .map_err(|_| DecodeError::NonCanonicalEncoding)?,
            constraints: wire.constraints.try_into()?,
            issued_at: Timestamp::from_millis(wire.issued_at),
            expires_at: Timestamp::from_millis(wire.expires_at),
            nonce: Nonce::new(wire.nonce),
            enforcer_session: EnforcerSessionId::from_bytes(wire.enforcer_session),
        })
    }
}

impl TryFrom<WireLeaseBodyV2> for LeaseBodyV2 {
    type Error = DecodeError;

    fn try_from(wire: WireLeaseBodyV2) -> Result<Self, Self::Error> {
        Ok(Self {
            core: wire.core.try_into()?,
            challenge: Challenge::from_bytes(wire.challenge),
        })
    }
}

// -- body bytes ---------------------------------------------------------------

/// Encodes a lease body into its canonical V1 bytes.
pub fn encode_body(body: &LeaseBody) -> Result<Vec<u8>, EncodeError> {
    let wire = WireLeaseBodyV1::from(body);
    let bytes = postcard::to_allocvec(&wire).map_err(|_| EncodeError::Serialization)?;
    if bytes.len() as u64 > MAX_BODY_BYTES as u64 {
        return Err(EncodeError::BodyTooLarge);
    }
    Ok(bytes)
}

/// Encodes a V2 lease body into its canonical bytes.
pub fn encode_body_v2(body: &LeaseBodyV2) -> Result<Vec<u8>, EncodeError> {
    let wire = WireLeaseBodyV2::from(body);
    let bytes = postcard::to_allocvec(&wire).map_err(|_| EncodeError::Serialization)?;
    if bytes.len() as u64 > MAX_BODY_BYTES as u64 {
        return Err(EncodeError::BodyTooLarge);
    }
    Ok(bytes)
}

/// Decodes canonical V2 body bytes into a semantic V2 lease body.
///
/// The result is **not authenticated**, exactly as for V1.
pub fn decode_body_v2(bytes: &[u8]) -> Result<LeaseBodyV2, DecodeError> {
    let (wire, rest) =
        postcard::take_from_bytes::<WireLeaseBodyV2>(bytes).map_err(|_| DecodeError::Malformed)?;
    if !rest.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }
    LeaseBodyV2::try_from(wire)
}

/// Encodes an already-built wire body.
///
/// Exposed so tests can construct deliberately non-canonical encodings and check
/// that decoding rejects them. It grants an attacker nothing they could not do
/// with any serializer.
pub fn encode_wire_body(wire: &WireLeaseBodyV1) -> Result<Vec<u8>, EncodeError> {
    postcard::to_allocvec(wire).map_err(|_| EncodeError::Serialization)
}

/// Decodes canonical V1 body bytes into a semantic lease body.
///
/// The result is **not authenticated**. Decoding proves the bytes are
/// well-formed and canonical, nothing more. Nothing in the returned body may be
/// trusted until a signature over the original bytes has verified.
pub fn decode_body(bytes: &[u8]) -> Result<LeaseBody, DecodeError> {
    let (wire, rest) =
        postcard::take_from_bytes::<WireLeaseBodyV1>(bytes).map_err(|_| DecodeError::Malformed)?;
    if !rest.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }
    LeaseBody::try_from(wire)
}

// -- signing input ------------------------------------------------------------

/// Builds the exact bytes a signature covers.
///
/// ```text
/// domain_for(version) || u16_le(version) || u32_le(body_len) || body_bytes
/// ```
///
/// The version is authenticated, so tampering with it can only cause a
/// fail-closed rejection rather than a schema confusion. The length prefix
/// removes any ambiguity about where one field ends and the next begins.
///
/// Callers must pass the body bytes **exactly as transmitted**. Signing or
/// verifying a re-encoding of a parsed body would let a decoder bug turn into a
/// signature bypass.
pub fn signing_input(version: ProtocolVersion, body_bytes: &[u8]) -> Vec<u8> {
    let domain = domain_for(version);
    let mut input =
        Vec::with_capacity(domain.len() + VERSION_BYTES + LENGTH_BYTES + body_bytes.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&version.as_u16().to_le_bytes());
    input.extend_from_slice(&(body_bytes.len() as u32).to_le_bytes());
    input.extend_from_slice(body_bytes);
    input
}

// -- envelope -----------------------------------------------------------------

/// Serializes a signed lease into its transport framing.
///
/// ```text
/// u16_le(version) || u32_le(body_len) || body_bytes || signature[64]
/// ```
pub fn encode(lease: &SignedLease) -> Result<Vec<u8>, EncodeError> {
    encode_envelope(lease.version, &encode_body(&lease.body)?, &lease.signature)
}

/// Serializes a signed V2 lease into its transport framing.
pub fn encode_v2(lease: &SignedLeaseV2) -> Result<Vec<u8>, EncodeError> {
    encode_envelope(
        lease.version,
        &encode_body_v2(&lease.body)?,
        &lease.signature,
    )
}

/// Frames an already-encoded body. Shared so the two versions cannot drift.
fn encode_envelope(
    version: ProtocolVersion,
    body: &[u8],
    signature: &Signature,
) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::with_capacity(VERSION_BYTES + LENGTH_BYTES + body.len() + SIGNATURE_BYTES);
    out.extend_from_slice(&version.as_u16().to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(signature.as_bytes());
    Ok(out)
}

/// A parsed envelope whose signature has **not** been checked.
///
/// Parsing before verification is allowed. Trusting before verification is not.
/// The raw body bytes are retained precisely so that verification can run over
/// what arrived rather than over a re-encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedLease<'a> {
    version: ProtocolVersion,
    body_bytes: &'a [u8],
    signature: Signature,
}

impl<'a> ParsedLease<'a> {
    /// The authenticated-once-verified protocol version.
    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// The body bytes exactly as they arrived.
    pub fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// The detached signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// The bytes a verifier must check the signature against.
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(self.version, self.body_bytes)
    }

    /// Decodes a V1 body without authenticating it.
    ///
    /// Use this to read `issuer` and `key_id` in order to *select* a candidate
    /// verification key. Those are lookup hints and carry no authority: nothing
    /// here is trustworthy until the signature verifies.
    pub fn decode_untrusted_body(&self) -> Result<LeaseBody, DecodeError> {
        if self.version != ProtocolVersion::V1 {
            return Err(DecodeError::UnsupportedVersion {
                found: self.version.as_u16(),
            });
        }
        decode_body(self.body_bytes)
    }

    /// Decodes a V2 body without authenticating it. Same caveat as the V1 form:
    /// nothing decoded here is trustworthy until the signature verifies.
    pub fn decode_untrusted_body_v2(&self) -> Result<LeaseBodyV2, DecodeError> {
        if self.version != ProtocolVersion::V2 {
            return Err(DecodeError::UnsupportedVersion {
                found: self.version.as_u16(),
            });
        }
        decode_body_v2(self.body_bytes)
    }
}

/// Parses transport framing, rejecting unsupported versions before touching the
/// body.
pub fn parse(bytes: &[u8]) -> Result<ParsedLease<'_>, DecodeError> {
    let mut cursor = bytes;

    if cursor.len() < VERSION_BYTES {
        return Err(DecodeError::Truncated);
    }
    let (version_bytes, rest) = cursor.split_at(VERSION_BYTES);
    let raw_version = u16::from_le_bytes([version_bytes[0], version_bytes[1]]);
    let version = ProtocolVersion::from_u16(raw_version)
        .ok_or(DecodeError::UnsupportedVersion { found: raw_version })?;
    cursor = rest;

    if cursor.len() < LENGTH_BYTES {
        return Err(DecodeError::Truncated);
    }
    let (length_bytes, rest) = cursor.split_at(LENGTH_BYTES);
    let body_len = u32::from_le_bytes([
        length_bytes[0],
        length_bytes[1],
        length_bytes[2],
        length_bytes[3],
    ]);
    if body_len > MAX_BODY_BYTES {
        return Err(DecodeError::BodyTooLarge);
    }
    cursor = rest;

    let body_len = body_len as usize;
    if cursor.len() < body_len {
        return Err(DecodeError::Truncated);
    }
    let (body_bytes, rest) = cursor.split_at(body_len);
    cursor = rest;

    if cursor.len() < SIGNATURE_BYTES {
        return Err(DecodeError::Truncated);
    }
    let (signature_bytes, rest) = cursor.split_at(SIGNATURE_BYTES);
    if !rest.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }

    let mut signature = [0u8; SIGNATURE_BYTES];
    signature.copy_from_slice(signature_bytes);

    Ok(ParsedLease {
        version,
        body_bytes,
        signature: Signature::from_bytes(signature),
    })
}
