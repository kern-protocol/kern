# Threat Model

This records the trust boundaries, failure semantics, and open problems of the
implemented Kern Protocol. `AGENT.md` §6, §7, §14, and §20 are the authoritative
source; this document restates them against the code and flags what is resolved,
what is mitigated, and what is still open.

Kern is a **research artifact and an engineering project**. It is not a
certified functional-safety mechanism. Threat-model boundaries are explicit.

## 1. The core threat

A model being compromised must not automatically imply that the model has
unrestricted physical authority. Kern bounds the lifetime of previously granted
authority and avoids treating a historical authorization decision as
indefinitely valid authority.

Kern **does not** solve physical TOCTOU and does not claim to. Use language such
as "Kern bounds the lifetime of previously granted authority," not "Kern solves
TOCTOU" (`AGENT.md` §7).

## 2. Trust boundaries

```text
upstream proposer  (AI / planner / human)        UNTRUSTED source of intent
        |
        | ActionProposal                          no implicit authority
        v
authority control plane (issuer side)            TRUSTED to mint authority
        |
        | signed CapabilityLease                  a claim; not yet trusted
        v
~~~~ transport ~~~~                              DELAY / REPLAY / REORDER possible
        |
        v
edge enforcer                                     TRUSTED to verify + install
        |
        | InstalledLease                          authority, session-bound
        v
execution governor                                TRUSTED to enforce the loss contract
        |
        | SemanticCommand                         authorized semantics, no lease
        v
executor / adapter                                UNTRUSTED to honor the contract
        |
        v
machine + functional-safety stack                OUT OF KERN'S TRUST BOUNDARY
```

Kern's trusted computing base for authority is: the issuer's signing key, the
enforcer's verification + install logic, the enforcer's session/nonce/challenge
state, and the governor's authority-loss contract. The executor adapter is
**not** trusted to decide policy or mint authority; it is trusted only to honor
the authority-loss contract it declared, and Kern records its behaviour rather
than assuming it.

## 3. Failure semantics (`AGENT.md` §6)

| Condition | Behaviour |
| --- | --- |
| Issuer unavailable | Existing leases remain valid only until expiration. No renewal means authority eventually disappears. Connectivity loss is never converted into indefinite permission. |
| Edge disconnected from issuer | The edge may honor an already-valid lease only within its remaining lifetime and local policy. |
| Expired lease | Cannot authorize a new effect. |
| Revocation | Not instantaneous. **Revocation latency is not yet measured or exposed** (open). |
| Replay | Signed leases include replay protection: Ed25519, monotonic nonce tracking, subject binding, device binding, validity interval, and (V2) session + challenge binding. |
| Reboot | Invalidates every pre-reboot issued or installed lease via `EnforcerSessionId` binding. |
| Lost acknowledgement | A physical operation that may have executed but whose acknowledgement is lost is **not** automatically retried. The record enters `ExecutionState::Unknown` until reconciled with the executor. |

### Session binding (reboot)

`EnforcerSessionId` is a random value regenerated each boot. The signed lease
body carries the session it is bound to. After a reboot the session differs, so
every prior lease is rejected. This avoids flash wear, torn-write recovery, and
a persistent monotonic counter. The issuer must learn the active session before
issuing a session-bound lease (the session travels with the challenge ticket).

### Concrete enforcement points in the Nav2 edge

Two invariants the Nav2 adapter makes concrete (`AGENT.md` §7, §17):

- **An authorized bound that nothing applies is never accepted.** The bridge
  verifies a `/speed_limit` subscriber exists before reporting the limit
  `Applied`; if not, it sends **no goal** and Kern records
  `NotStarted(Rejected(Unavailable))`. A ROS publish that no one receives cannot
  become authority over motion.
- **Authority lifetime does not move with simulation time.** Lease lifetime is
  measured against process monotonic uptime (`std::time::Instant`), never ROS or
  Gazebo `/clock`. The validation harness pauses Gazebo (`PAUSE_GZ`) and confirms
  the authority deadline does not freeze with it — a paused simulator cannot
  extend a lease.

Neither is a safety guarantee. The first is a *commanded* controller speed limit,
not a wheel-speed guarantee; the second bounds authority lifetime, not motion.

## 4. Freshness at installation — resolved for V2, open for V1

`AGENT.md` §7 marks this an open problem. The two sub-problems:

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

### V2 challenge mechanism (implemented)

V2 leases carry a `Challenge` minted by the enforcer and bound to the full slot.
At installation, `validate_challenge` checks the challenge is outstanding,
unexpired, unconsumed, and slot-bound, and `authority_deadline` is **anchored at
challenge issuance, not at arrival** — so delivery delay is charged against the
lease's own lifetime. This is the chosen mechanism.

### V1

V1 carries no challenge and has no first-installation freshness mechanism. V1 is
acceptable only where delayed delivery is out of the threat model. **Whether
delayed delivery is in scope is a threat-model decision that must be recorded
before an enforcer is deployed**, not something an implementation silently
assumes away. The current V2 mechanism uses: enforcer session identity,
request/response issuance challenge, and the issuance handshake implied by the
challenge ticket. Bounded issuer/enforcer clock synchronization is **not**
assumed.

## 5. Open problems

These are recorded and must not be silently assumed away:

- **Durable nonce state.** `CountingNonces` is in-memory only this phase. On
  restart, seen nonces would be re-emitted; the enforcer rejects them,
  fail-closed. There is no durable nonce persistence. Production deployment
  needs a durable backend behind the `NonceSource` abstraction.
- **Revocation latency.** Revocation is modelled (supersession; lease expiry)
  but revocation latency is not measured or exposed (`AGENT.md` §6, §29).
- **Freshness within a single session beyond the challenge window.** The V2
  challenge bounds first-installation freshness; it does not by itself solve
  arbitrary delayed delivery within an already-open session beyond the challenge
  TTL.
- **Targets without trustworthy entropy.** `EnforcerSessionId` and `Challenge`
  assume a CSPRNG. If the threat model later includes targets without trustworthy
  entropy, or requires persistent monotonic identity across boots, a persistent
  NVM epoch becomes the backend for the same abstraction.
- **Key management.** Keys must not be hard-coded into production paths. The demo
  uses `DEV_SEED = [7u8; 32]` and is explicitly disclaimed as a deployment
  topology (the issuer key lives in the edge process). Production needs key
  storage behind the `Signer`/`TrustStore` abstractions (TPM, HSM, secure
  element, OS keychain, cloud KMS).

## 6. The enumeration oracle (`AGENT.md` §14)

Library and control-plane errors stay granular: `UnknownDevice` and
`UnknownCapability` are distinct because the distinction is useful in
development, diagnostics, and tests. But an interface answering **untrusted
callers** may need to collapse them:

```text
UnknownDevice | UnknownCapability  ->  UnknownTarget
```

Distinguishable errors are a device-and-capability enumeration oracle. This is a
boundary concern for whichever layer first exposes evaluation to untrusted input.
It is **not** a reason to blunt the internal error types. Record the collapse
decision at the boundary that introduces it.

## 7. Cryptography (`AGENT.md` §15)

- No invented primitives. Reviewed libraries only (`ed25519-dalek`).
- Ed25519 for signing. No custom encryption.
- The signed representation is canonical binary (`postcard` under a versioned
  envelope), never JSON/YAML. Domain separation per version
  (`KERN-LEASE-V1` / `KERN-LEASE-V2`). Golden byte and signature vectors pin the
  encoding (`crates/kern-authority/tests/golden*.rs`).
- Verification runs over the **raw transmitted bytes**, never a re-encoding, so a
  decoder bug cannot become a signature bypass. A canonical re-encode gate
  catches encoder/decoder asymmetry.
- `kern-core` and `kern-enforcer` are `#![forbid(unsafe_code)]`.

## 8. Security language (`AGENT.md` §20)

Preferred wording: *authority enforcement, containment, bounded authority, scoped
capability, temporary authority, lease expiry, revocation, replay resistance,
execution provenance.*

Avoid overstating: *safe robot, unhackable, guaranteed secure, TOCTOU solved,
certified safety, zero-risk.* Never write "Kern is the first...", "Kern
solves...", or "Kern guarantees physical safety" without strong evidence.

The honest one-liner the demo prints on exit: *"Kern requested what it could and
recorded what it saw. It makes no claim about whether the machine physically
stopped."*