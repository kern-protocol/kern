# Lease, Issuance, and Signing

A capability lease represents **temporary physical authority**. It is explicit,
scoped, bounded, signed, time-limited, replay-resistant, renewable, revocable,
and traceable. This document covers the lease representation, the issuance
pipeline, Ed25519 signing, the canonical wire protocol, nonces, and enforcer
sessions. Verification and installation are in
[edge-enforcement.md](edge-enforcement.md); the authority-loss contract that
governs a running operation is in
[execution-governor.md](execution-governor.md).

Types live in `kern-core` (`lease`, `wire`, `challenge`, `artifact`, `clock`)
and `kern-authority` (`issuer`, `signer`, `nonce`, `lease_id`, `operation`).

## 1. The lease representation

`AGENT.md` §4.4 sketches a conceptual `CapabilityLease`. The implementation
splits it into an authenticated body plus a detached signature, with V1 and V2
variants:

```rust
pub struct LeaseBody {            // V1 authenticated content (kern-core::lease)
    pub id: LeaseId,
    pub subject: SubjectId,
    pub device: DeviceId,
    pub capability: CapabilityName,
    pub constraints: ConstraintSet,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub nonce: Nonce,
    pub issuer: IssuerId,
    pub key_id: KeyId,
    pub enforcer_session: EnforcerSessionId,
}

pub struct SignedLease {          // V1: body + signature; a claim, not authority
    pub body: LeaseBody,
    pub signature: Signature,
}

pub struct LeaseBodyV2 { ... V1 fields ..., challenge: Challenge }
pub struct SignedLeaseV2 { pub body: LeaseBodyV2, pub signature: Signature }
```

All fields from the §4.4 sketch are present, plus `key_id` and
`enforcer_session` (added beyond the sketch). `Signature` is a detached
Ed25519 `[u8; 64]`.

### Scope is not a field

There is no `CapabilityScope` type. The scope of physical authority is fully
determined by four things a lease already carries:

```text
subject
device
capability
constraints
```

A second representation of scope alongside `ConstraintSet` would create two
sources of truth that can disagree (`CapabilityScope says destination = table_7`
vs `ConstraintSet says destination = table_8`). The word "scope" stays in prose
as a descriptive term; it is not a protocol type or lease field, and must not
become one.

A lease describes **why** an operation is currently authorized, never **how**
low-level motion is performed.

### Constructible data is not authenticated authority

`LeaseBody` and `SignedLease` have public fields and are constructible by
anyone. They are *claims*. Authority begins only after the enforcer verifies the
signature over the raw transmitted bytes and installs the lease into a
session-bound store (see [edge-enforcement.md](edge-enforcement.md)). The
private-constructor rule from `AGENT.md` §4.5 is applied where it matters:
`NormalizedActionProposal` (only via schema normalization), `AuthorizedOperation`
(only via `from_evaluation` on an `Authorized` decision), and `InstalledLease`
(only via `EnforcerStore::install`).

## 2. Identity, nonce, and session primitives (`kern-core::lease`)

```rust
LeaseId([u8; 16])             // identity, not a replay primitive
IssuerId                      // issuing authority id
KeyId                         // signing-key lookup HINT, not authority
Nonce(u64)                    // supersession counter per slot
EnforcerSessionId([u8; 32])   // boot-session binding
Signature([u8; 64])           // detached Ed25519
```

`LeaseId` identifies a lease for traceability; it is **not** the replay
primitive (that is the nonce + slot). `KeyId` is a lookup hint that carries no
authority by itself — finding a key for a claimed issuer is not authorization.

`ProtocolVersion` is a wire-tagged enum (`V1 | V2`) with `as_u16`/`from_u16` for
the wire numeric version. An unsupported version fails closed before the body is
decoded at all.

## 3. From decision to signed lease (`kern-authority::issuer`)

```text
PolicyDecision::Authorized { constraints }
    -> AuthorizedOperation::from_evaluation       (kern-authority::operation)
    -> LeaseIssuer::issue_v1 / issue_v2
        build_body        (zero-TTL / overflow checks)
        wire::encode_body[_v2]   (canonical postcard body)
        wire::signing_input      (domain || ver || len || body)
        Signer::sign             -> Signature
    -> SignedLease / SignedLeaseV2
```

`AuthorizedOperation::from_evaluation` returns `Some` only for an `Authorized`
decision; the advisory `grantable` from `NotAuthorizedAsProposed` is never
signed. This is the seam that prevents a "partially authorized" plan from
becoming authority.

### LeaseIssuer

```rust
pub struct LeaseIssuer<S, C, N, I> {
    issuer: IssuerId,
    signer: S,           // Signer
    clock: C,            // Clock
    nonces: N,           // NonceSource
    lease_ids: I,        // LeaseIdSource
}
```

Every source of non-determinism is injected: the signer, the clock, the nonce
source, the lease-id source. `build_body` checks `ttl.is_zero()` -> `ZeroTtl`
and `issued_at.checked_add(ttl)` -> `TtlOverflow` (no saturating expiry).

`issue_v2` additionally checks `ticket.issuer == self.issuer` (else
`TicketIssuerMismatch`) and `ticket.{subject,device,capability} == proposal.*`
(else `TicketBindingMismatch`) before signing. The enforcer session comes from
the challenge ticket, not a separate argument.

## 4. Nonces and supersession (`kern-authority::nonce`)

```rust
pub struct Slot {
    pub issuer: IssuerId,
    pub enforcer_session: EnforcerSessionId,
    pub subject: SubjectId,
    pub device: DeviceId,
    pub capability: CapabilityName,
}

pub trait NonceSource {
    fn next_nonce(&self, slot: &Slot) -> Result<Nonce, NonceError>;
}
```

`Slot` is the V1 supersession domain — all five components are justified in the
crate doc. `NonceSource::next_nonce` returns a strictly-increasing `Nonce` via
`checked_add`; it never wraps, and returns `NonceError::Exhausted` at `u64::MAX`.
Gaps are permitted (a failed issuance leaves a harmless hole).

`CountingNonces` is an in-memory `BTreeMap<Slot, u64>`. `resume` is the durable
seam, but **no nonce persistence exists in this phase**. On restart, seen
nonces would be re-emitted; the enforcer rejects them, fail-closed. Durable
nonce state is an unresolved production concern (see
[threat-model.md](threat-model.md)).

## 5. Lease IDs (`kern-authority::lease_id`)

```rust
pub trait LeaseIdSource { fn next_lease_id(&self) -> Result<LeaseId, LeaseIdError>; }
pub struct SequentialLeaseIds { /* u128 counter, no wrap */ }
```

`SequentialLeaseIds` is deterministic (start at 0 by default, or
`starting_at(n)`), for golden vectors and reproducible tests. Exhaustion fails
closed (`LeaseIdError::Exhausted`), never wraps or reuses an id.

## 6. Signing (`kern-authority::signer`)

```rust
pub trait Signer {
    fn key_id(&self) -> KeyId;
    fn sign(&self, input: &[u8]) -> Result<Signature, SignError>;
}

pub struct Ed25519Signer { key_id: KeyId, signing_key: SigningKey }
```

The `Signer` trait is deliberately narrow — `key_id()` + `sign(&[u8])` — and
lease-agnostic, so key storage can later move to a TPM, HSM, secure element, OS
keychain, or cloud KMS without touching issuance logic. `SignError::Unavailable`
is fallible on purpose: in-process Ed25519 cannot fail, but a remote backend
can.

`Ed25519Signer::from_seed` takes a 32-byte seed and is deterministic for golden
vectors. Its `Debug` impl never renders key material. The crate performs no
verification itself (verification lives in `kern-enforcer`).

### Cryptography rules (`AGENT.md` §15)

- No invented primitives. Use reviewed libraries (`ed25519-dalek`).
- JSON/YAML never define signed bytes — no canonical key order, so verification
  breaks across serializers and versions.
- The signed representation has: explicit protocol version, domain separation,
  fixed schema, fixed integer representations, no unordered maps or sets in
  signed structures, golden byte vectors, golden signature vectors,
  cross-platform compatibility tests.
- Keys are not hard-coded into production paths. Test fixtures may use
  deterministic development keys (the demo uses `DEV_SEED = [7u8; 32]`).
- Key loading, storage, signing, and verification stay behind explicit
  interfaces.
- No custom encryption.

## 7. The canonical wire protocol (`kern-core::wire`)

`postcard` is the encoding choice. It is **not** the protocol definition, and it
is not by itself sufficient evidence of canonicality. The signed representation
additionally pins a fixed schema, fixed integer representations, and excludes
unordered maps/sets from signed structures.

### The signing envelope

The signing input is:

```text
signing_input = domain_for(version)
              || u16_le(version)
              || u32_le(body_length)
              || body_bytes
```

with per-version domain separators `LEASE_DOMAIN_V1 = b"KERN-LEASE-V1"` and
`LEASE_DOMAIN_V2 = b"KERN-LEASE-V2"`.

> **Spec note:** `AGENT.md` §15 sketches the envelope as
> `"KERN-LEASE-V1" || postcard(LeaseBodyV1)`. The implementation additionally
> binds a `u16` version prefix and a `u32` length prefix between the domain and
> the body. These extra fields strengthen the fixed-schema and length-binding
> properties `AGENT.md` also requires, but they are a deliberate widening of the
> §15 sketch. This is recorded as spec/code drift, not a silent deviation.

Changing Rust field order, enum representation, integer representation, or
serialization semantics is a **protocol compatibility change**, not a refactor.
It requires a version bump and new golden vectors. `crates/kern-authority/tests/golden.rs`
and `golden_v2.rs` pin these vectors.

### Envelope framing

`encode` / `encode_v2` produce the transport envelope; `parse` consumes it. The
envelope is version-first: an unsupported `ProtocolVersion` fails closed before
the body is decoded at all. `MAX_BODY_BYTES` (64 KiB) bounds both encode and
decode.

### Wire types

`WireConstraint`, `WireConstraintSet`, `WireLeaseBodyV1`, `WireLeaseBodyV2` are
the postcard-serialized shapes. `From`/`TryFrom` impls convert between semantic
and wire types and validate canonicality. `WireParamValue` and `WireOperationV1`
encode a normalized operation; `encode_operation` produces canonical operation
bytes with **no decoder** — the operation encoding is for identity/digest
purposes (a `CommandDigest`), not a second command channel.

### Canonicality gate

A non-canonical encoding (`DecodeError::NonCanonicalEncoding`) is rejected. The
enforcer re-encodes the decoded body and checks byte-equality against the
original, catching the class of encoder/decoder asymmetry that would let two
byte-strings represent one authority. See [edge-enforcement.md](edge-enforcement.md).

## 8. Challenges and freshness (`kern-core::challenge`)

```rust
pub struct Challenge([u8; 32]);            // CSPRNG single-use value
pub struct ChallengeTicket {               // issuer/session/challenge + slot binding
    pub issuer: IssuerId,
    pub session: EnforcerSessionId,
    pub challenge: Challenge,
    pub subject: SubjectId,
    pub device: DeviceId,
    pub capability: CapabilityName,
}
```

V1 carries no challenge and therefore has no first-installation freshness
mechanism. V2 adds a `Challenge` plus session binding. The challenge is minted
by the enforcer (`EnforcerStore::mint_challenge`), carried to the issuer in a
`ChallengeTicket`, echoed into the signed `LeaseBodyV2`, and validated at
installation (outstanding, unexpired, unconsumed, slot-bound). This is the
chosen answer to the freshness-at-installation open problem from `AGENT.md` §7.
See [edge-enforcement.md](edge-enforcement.md) §freshness and
[threat-model.md](threat-model.md).

## 9. The authority artifact (`kern-core::artifact`)

```rust
pub struct AuthorityArtifactId([u8; 32]);   // SHA-256 digest
// compute = SHA-256(ARTIFACT_DOMAIN_V1 || u16_le(ver) || signing_input)
```

`AuthorityArtifactId` names an authenticated authority by digest, independent of
a particular signature instance. It excludes the signature bytes, so the same
authority leased under a rotated key keeps a stable identity. It supports the
`AGENT.md` §4.6 execution-trace goal: every mediated physical effect is
traceable to the authority that permitted it, by artifact id. `Debug` renders
only a truncated hex prefix.

## 10. Time (`kern-core::clock`)

Two distinct clock abstractions, per `AGENT.md` §7:

```rust
pub trait Clock { fn now(&self) -> Timestamp; }              // wall clock
pub trait MonotonicClock { fn uptime(&self) -> Duration; }   // enforcer lifetime
```

`Timestamp` is milliseconds since the Unix epoch, used by the issuer and the
trace. `Uptime` / `MonotonicDuration` are enforcer-side monotonic spans. The
enforcer measures an installed lease's remaining lifetime against monotonic
uptime anchored at installation, never a local wall clock (a constrained target
may have no RTC, a drifting RTC, or no network time source).

Provided implementations: `SystemClock` (std), `TestClock` / `TestMonotonicClock`
(`Rc`-backed, single-threaded, advanceable). The test clocks are `!Send`/`!Sync`
and documented as test-only.

A monotonic clock bounds lifetime **after** installation. It does not establish
that a lease was **freshly issued** — that is the delayed-delivery problem,
addressed by V2 challenges. See [threat-model.md](threat-model.md) §freshness.

## 11. How it is tested

- `crates/kern-authority/tests/issuance.rs` — V1/V2 issuance, zero-TTL, overflow,
  ticket binding mismatches.
- `crates/kern-authority/tests/golden.rs`, `golden_v2.rs` — frozen byte and
  signature vectors for V1 and V2.
- `crates/kern-core/tests/wire.rs` — envelope framing, version fail-closed,
  canonicality gate, truncation, trailing bytes, malformed.
- `crates/kern-core/tests/operation_encoding.rs` — canonical operation bytes.
- Negative tests required (`AGENT.md` §12): invalid signature, wrong issuer,
  replayed nonce, unsupported version, non-canonical encoding.