//! Minting signed authority.

use core::fmt;

use kern_core::wire::{encode_body, encode_body_v2, signing_input, EncodeError};
use kern_core::{
    ChallengeTicket, Clock, EnforcerSessionId, IssuerId, LeaseBody, LeaseBodyV2, ProtocolVersion,
    SignedLease, SignedLeaseV2, Ttl,
};

use crate::lease_id::{LeaseIdError, LeaseIdSource};
use crate::nonce::{NonceError, NonceSource, Slot};
use crate::operation::AuthorizedOperation;
use crate::signer::{SignError, Signer};

/// A lease could not be issued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssueError {
    /// The requested lifetime was zero.
    ///
    /// A zero-length lease authorizes nothing, so asking for one is a caller
    /// mistake rather than a degenerate but valid request.
    ZeroTtl,
    /// `issued_at + ttl` overflows the timestamp space.
    ///
    /// Checked, never saturated: silently clamping would hand back a lease that
    /// outlives every bound the caller thought they were setting.
    TtlOverflow,
    /// The slot's nonce space is exhausted.
    Nonce(NonceError),
    /// The lease identifier source is exhausted.
    LeaseId(LeaseIdError),
    /// The signing backend refused.
    Signing(SignError),
    /// The body could not be encoded.
    Encoding(EncodeError),
    /// The ticket names a different issuer.
    ///
    /// A misrouted ticket is rejected before a lease exists, rather than
    /// producing one that installation would refuse.
    TicketIssuerMismatch,
    /// The ticket's slot bindings disagree with the authorized operation.
    ///
    /// Signing this would produce a lease whose freshness binding could never
    /// match, so it fails here where the error says something useful.
    TicketBindingMismatch,
}

impl From<NonceError> for IssueError {
    fn from(error: NonceError) -> Self {
        Self::Nonce(error)
    }
}

impl From<LeaseIdError> for IssueError {
    fn from(error: LeaseIdError) -> Self {
        Self::LeaseId(error)
    }
}

impl From<SignError> for IssueError {
    fn from(error: SignError) -> Self {
        Self::Signing(error)
    }
}

impl From<EncodeError> for IssueError {
    fn from(error: EncodeError) -> Self {
        Self::Encoding(error)
    }
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTtl => f.write_str("a lease lifetime of zero authorizes nothing"),
            Self::TtlOverflow => f.write_str("lease expiry overflows the timestamp space"),
            Self::Nonce(error) => write!(f, "{error}"),
            Self::LeaseId(error) => write!(f, "{error}"),
            Self::Signing(error) => write!(f, "{error}"),
            Self::Encoding(error) => write!(f, "{error}"),
            Self::TicketIssuerMismatch => {
                f.write_str("challenge ticket is addressed to a different issuer")
            }
            Self::TicketBindingMismatch => {
                f.write_str("challenge ticket bindings disagree with the authorized operation")
            }
        }
    }
}

impl core::error::Error for IssueError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Nonce(error) => Some(error),
            Self::LeaseId(error) => Some(error),
            Self::Signing(error) => Some(error),
            Self::Encoding(error) => Some(error),
            Self::ZeroTtl
            | Self::TtlOverflow
            | Self::TicketIssuerMismatch
            | Self::TicketBindingMismatch => None,
        }
    }
}

/// Issues signed leases for authorized operations.
///
/// Every source of non-determinism is injected — time, nonces, identifiers, and
/// the signing key — so an issuance is reproducible byte for byte in tests, which
/// is what makes golden signature vectors possible.
#[derive(Clone, Debug)]
pub struct LeaseIssuer<S, C, N, I> {
    issuer: IssuerId,
    signer: S,
    clock: C,
    nonces: N,
    ids: I,
}

impl<S, C, N, I> LeaseIssuer<S, C, N, I>
where
    S: Signer,
    C: Clock,
    N: NonceSource,
    I: LeaseIdSource,
{
    /// Assembles an issuer.
    pub fn new(issuer: IssuerId, signer: S, clock: C, nonces: N, ids: I) -> Self {
        Self {
            issuer,
            signer,
            clock,
            nonces,
            ids,
        }
    }

    /// This issuer's identity.
    pub fn issuer(&self) -> &IssuerId {
        &self.issuer
    }

    /// The nonce source, for inspection.
    pub fn nonces(&self) -> &N {
        &self.nonces
    }

    /// Issues a V1 lease for an authorized operation.
    ///
    /// V1 carries no challenge, so it cannot support freshness at first
    /// installation. It remains a complete, frozen, signable format; an
    /// enforcer wanting the strong freshness guarantee installs V2.
    ///
    /// The subject, device, capability, and constraints all come from the
    /// authorization. None of them is a parameter, which is what keeps a caller
    /// from widening what policy granted on the way to the signature.
    pub fn issue_v1(
        &mut self,
        operation: &AuthorizedOperation,
        ttl: Ttl,
        enforcer_session: EnforcerSessionId,
    ) -> Result<SignedLease, IssueError> {
        let body = self.build_body(operation, ttl, enforcer_session)?;
        let body_bytes = encode_body(&body)?;
        let signature = self
            .signer
            .sign(&signing_input(ProtocolVersion::V1, &body_bytes))?;

        Ok(SignedLease {
            version: ProtocolVersion::V1,
            body,
            signature,
        })
    }

    /// Issues a V2 lease answering an enforcer challenge.
    ///
    /// The session comes from the ticket rather than as a separate argument:
    /// passing both would let them disagree, and only one of them can be the
    /// session the enforcer checks against.
    ///
    /// The ticket's bindings are checked against the authorization first. A
    /// mismatch would produce a lease whose freshness binding could never match
    /// at installation, so it fails at the control plane instead.
    pub fn issue_v2(
        &mut self,
        operation: &AuthorizedOperation,
        ttl: Ttl,
        ticket: &ChallengeTicket,
    ) -> Result<SignedLeaseV2, IssueError> {
        if ticket.issuer != self.issuer {
            return Err(IssueError::TicketIssuerMismatch);
        }

        let proposal = operation.proposal();
        if &ticket.subject != proposal.actor()
            || &ticket.device != proposal.device()
            || &ticket.capability != proposal.capability()
        {
            return Err(IssueError::TicketBindingMismatch);
        }

        let core = self.build_body(operation, ttl, ticket.session)?;
        let body = LeaseBodyV2 {
            core,
            challenge: ticket.challenge,
        };

        let body_bytes = encode_body_v2(&body)?;
        let signature = self
            .signer
            .sign(&signing_input(ProtocolVersion::V2, &body_bytes))?;

        Ok(SignedLeaseV2 {
            version: ProtocolVersion::V2,
            body,
            signature,
        })
    }

    /// The fields both versions share, so the two paths cannot drift apart.
    fn build_body(
        &mut self,
        operation: &AuthorizedOperation,
        ttl: Ttl,
        enforcer_session: EnforcerSessionId,
    ) -> Result<LeaseBody, IssueError> {
        if ttl.is_zero() {
            return Err(IssueError::ZeroTtl);
        }

        let issued_at = self.clock.now();
        let expires_at = issued_at.checked_add(ttl).ok_or(IssueError::TtlOverflow)?;

        let proposal = operation.proposal();
        let slot = Slot {
            issuer: self.issuer.clone(),
            enforcer_session,
            subject: proposal.actor().clone(),
            device: proposal.device().clone(),
            capability: proposal.capability().clone(),
        };
        let nonce = self.nonces.next_nonce(&slot)?;

        Ok(LeaseBody {
            id: self.ids.next_lease_id()?,
            issuer: self.issuer.clone(),
            key_id: self.signer.key_id().clone(),
            subject: proposal.actor().clone(),
            device: proposal.device().clone(),
            capability: proposal.capability().clone(),
            constraints: operation.constraints().clone(),
            issued_at,
            expires_at,
            nonce,
            enforcer_session,
        })
    }
}
