# Edge Enforcement

The edge enforcer is the last Kern-controlled authority boundary before the
executor. It is `kern-enforcer`: `no_std + alloc`, `#![forbid(unsafe_code)]`,
single-boot-session state held in fixed-capacity arrays (no heap allocation on
the hot path). This document covers the verify-once installation pipeline, the
freshness mechanism, the steady-state hot path, and the receipt-vs-authority
distinction. The layer that *uses* an installed lease to govern a running
operation is `kern-execution`, documented in
[execution-governor.md](execution-governor.md).

## 1. What problem it solves

A signed `SignedLease` is a *claim* anyone can construct. The enforcer turns a
claim into installed authority: it authenticates the signature, binds the lease
to this enforcer's boot session, replays-protects it, freshness-checks it,
anchors its lifetime, and exposes a comparisons-only check for the hot path.

## 2. What it explicitly does not solve

- It does not solve physical safety. Correct authority is not safe motion.
- It does not stop the machine when authority lapses; it stops granting
  authority and stops forwarding newly authorized operations. The authority-loss
  *contract* with a running operation is owned by the governor.
- It does not, by itself, solve delayed-delivery freshness within a session
  without the V2 challenge mechanism.
- It is not a wall-clock authority. Lifetime is measured against a monotonic
  clock anchored at installation.

## 3. Verification — parsing before verification is allowed, trusting before verification is not

A verifier cannot literally "verify before decoding": the `issuer` and `key_id`
needed to select a verification key live *inside* the signed body. The rule is
about **trust**, not order of operations (`AGENT.md` §4.5).

```text
parse the envelope framing            version, body length, signature
  -> unsupported version fails closed before the body is decoded
retain the EXACT raw body bytes
minimally decode the UNTRUSTED body   to obtain issuer and key_id
resolve a candidate verification key  a lookup hint, nothing more
verify the signature over the ORIGINAL raw body bytes
  -- only now are body fields authenticated --
validate canonical encoding, convert to a semantic LeaseBody
apply session, lifetime, and nonce checks
```

Implemented in `kern-enforcer::verify`:

- `verify_bytes` / `verify_parsed` frame -> canonical decode -> `issuer`/`key_id`
  lookup -> `TrustStore::key_for` (an untrusted key never reaches the verifier)
  -> Ed25519 verify over the **raw transmitted bytes** -> canonical re-encode
  byte-equality gate.
- Output: `VerifiedLease`, proving only "signature verified under an authorized
  key for the claimed issuer." It proves nothing about session, freshness, or
  lifetime.

**Never verify a re-encoding of the parsed body.** Verification runs over the
bytes that arrived, so a decoder bug cannot become a signature bypass. The
canonical re-encode gate catches the encoder/decoder asymmetry that would
otherwise let two byte-strings represent one authority.

## 4. Installation — verify once, at installation

Cryptographic verification belongs to installation, not to the per-operation
path (`AGENT.md` §4.5). `EnforcerStore::install` layers the authority checks on
top of a `VerifiedLease`:

```text
VerifiedLease
    |
    | session match        lease.enforcer_session == this boot's EnforcerSessionId
    |                      (reboot invalidates every pre-reboot lease)
    v
    | supersession
    |    same nonce + same artifact  -> Installed::Already  (retry; original deadline stands,
    |                                                       no challenge consumed)
    |    same nonce + diff artifact  -> ConflictingGeneration
    |    lower nonce                 -> SupersededNonce
    v
    | validate_challenge   outstanding, unexpired, unconsumed, full slot binding
    |                      (issuer/subject/device/capability)
    v
    | authority_deadline   anchored at CHALLENGE ISSUANCE, not arrival
    |                      (delivery delay charged against lease lifetime)
    v
    | two-write commit     into pre-allocated fixed-capacity arrays
    |                      (no allocation after the checks)
    v
InstalledLease + LeaseHandle
```

`InstalledLease` is a privileged type: its constructors are private/crate
restricted, so no public API can produce one without passing verification and
installation. It is not `Clone` and is borrow-only.

`Installed` is either `Fresh` (a challenge was consumed) or `Already` (a retry
of an already-installed lease; the original deadline stands and no challenge is
consumed). Both yield a `LeaseHandle`.

## 5. Freshness — lifetime after installation vs. freshness at installation

Two distinct problems (`AGENT.md` §7):

```text
lifetime-after-installation   solved by MonotonicClock
freshness-at-installation     NOT solved by MonotonicClock alone
```

### The delayed-delivery problem

```text
issuer:   issued_at = T, expires_at = T + 500ms
an attacker delays delivery by ten minutes
the enforcer anchors a 500ms TTL at installation
  => an already-expired lease receives a fresh 500ms of authority
```

An implementation must never treat "installed now" as evidence that a lease was
recently issued.

### The chosen mechanism: V2 challenges

The enforcer mints a `Challenge` (`EnforcerStore::mint_challenge`) and binds it
to the full slot. The issuer must obtain the `ChallengeTicket` and echo the
challenge into the signed `LeaseBodyV2`. At installation, `validate_challenge`
checks the challenge is outstanding, unexpired, unconsumed, and slot-bound, and
`authority_deadline` is **anchored at challenge issuance, not at arrival** — so
delivery delay is charged against the lease's own lifetime.

V1 carries no challenge and therefore has no first-installation freshness. V1 is
suitable where delayed delivery is out of the threat model. Whether delayed
delivery is in scope is a threat-model decision recorded in
[threat-model.md](threat-model.md), not something an implementation silently
assumes away.

## 6. Reboot and session binding

Invariant (`AGENT.md` §6):

```text
reboot invalidates every pre-reboot issued or installed lease
```

Nonce state held only in RAM is lost on reboot, which would reopen the replay
window. Leases are therefore bound to an `EnforcerSessionId` — a random 128/256-bit
value regenerated each boot — rather than reconstructing nonce history. After a
reboot the session differs, so every prior lease is rejected. This avoids flash
wear, torn-write recovery, and a persistent monotonic counter.

The issuer must learn the active enforcer session before it can issue a
session-bound lease (the session travels with the challenge ticket). Session
binding prevents cross-reboot replay. It does not by itself solve delayed
delivery within a single session — that is the V2 challenge's job.

`EnforcerStore` is `!Sync` (via `Cell`), single-threaded, and volatile across
boot by design. Session identity stays behind an abstraction; if the threat model
later includes targets without trustworthy entropy, or requires persistent
monotonic identity across boots, a persistent NVM epoch becomes the backend for
the same abstraction.

## 7. The hot path — comparisons only

Steady-state enforcement performs comparisons and local authority checks. It
does **not** repeat Ed25519 verification per operation.

```rust
EnforcerStore::check_authority(handle) -> Result<(), AuthorityStatusError>
//   liveness only: slot occupancy -> generation/artifact identity -> deadline -> clock trust
//   evaluates NO operation

EnforcerStore::enforce(handle, proposal) -> Result<(), EnforcementError>
//   liveness (via check_authority) THEN subject/device/capability/constraints
```

Both share a single liveness definition, `live_entry`: slot occupancy,
generation/artifact identity, deadline, and clock trust. Liveness and
authorization cannot drift because they are the same predicate.

The enforcer should fail closed for operations that require Kern authority. When
authority disappears, the enforcer stops forwarding newly authorized operations.
Refusing to forward new operations is necessary but not sufficient for an
operation that is already running — that is the governor's authority-loss
contract.

## 8. Receipt vs. authority

```rust
pub struct LeaseHandle {   // Clone, freely copyable
    slot: SlotKey,         // (issuer, subject, device, capability); session implicit
    lease_id: LeaseId,
    artifact: AuthorityArtifactId,
}
```

`LeaseHandle` is a **receipt**, not authority-by-possession. It names a lease by
slot, id, and artifact. Its storage position is deliberately absent, so a
superseded or reclaimed slot fails to resolve when the handle is later used.
Possessing a handle proves nothing; liveness is re-checked every time it is
used. `InstalledLease` is the authority; it is not `Clone` and is borrow-only.

There is no separate scope check. Scope **is** the subject, device, and
capability bindings together with the parameter bounds; checking each of those
is checking the scope (`AGENT.md` §4.4, §4.5).

## 9. Errors (`kern-enforcer::error`)

Errors are typed, never collapsed to generic strings (`AGENT.md` §14).

```text
ConfigError        ZeroChallengeTtl | ZeroCapacity
EntropyError       fatal; no degraded mode
MintError          ClockWentBackwards | DeadlineOverflow | CapacityExhausted | Entropy
InstallError       18 variants: framing -> auth -> binding -> freshness
                   -> lifetime -> supersession -> resources
AuthorityStatusError   liveness-only: Missing | Superseded | Deadline | Clock
EnforcementError        hot path: 4 liveness + 4 operation mismatches
```

`AuthorityStatusError` widens into `EnforcementError` on the hot path so the
governor can distinguish liveness loss from operation mismatch. Internal
granularity stays high (development, diagnostics, tests); an interface answering
untrusted callers may collapse `UnknownDevice`/`UnknownCapability` into
`UnknownTarget` — recorded as a boundary concern in
[threat-model.md](threat-model.md) (an enumeration oracle), not a reason to
blunt the internal types.

## 10. Trust store (`kern-enforcer::trust`)

```rust
pub struct TrustStore { /* (issuer, key_id) -> VerifyingKey, no wall-clock expiry */ }
```

`TrustStore::authorize` adds a key and refuses duplicates; `revoke_key` removes
one for rotation; `key_for` is a lookup hint that never authorizes alone. Finding
a key for a claimed issuer is not authorization; the signature must verify
against a trust-store entry accepted for that issuer.

## 11. How it is tested

- `crates/kern-enforcer/tests/installation.rs` — install pipeline: session
  mismatch, supersession (retry / conflicting / superseded), challenge
  validation, deadline anchoring, two-write commit.
- `crates/kern-enforcer/tests/liveness.rs` — hot-path liveness, expiry,
  revocation-by-supersession, clock-went-backwards.
- Required negative tests (`AGENT.md` §12): invalid signature, wrong issuer,
  wrong subject/device/capability, scope/bound exceeded, expired lease,
  replayed nonce, session mismatch, superseded nonce, unsupported version,
  non-canonical encoding.