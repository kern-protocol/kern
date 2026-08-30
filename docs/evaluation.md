# Evaluation and Status

This documents what is implemented, what is tested, and what is planned. Per
`AGENT.md` §19 (Research Integrity), nothing here is fabricated. Until a property
is measured, it is described as *planned* or *designed*, not *measured*.

## 1. Implementation status

### Implemented

| Subsystem | Crate | Status |
| --- | --- | --- |
| Domain types, IDs, `ActionProposal`, `ParamValue` | `kern-core` | implemented |
| `CapabilitySchema`, normalization, `NormalizedActionProposal` | `kern-core` | implemented |
| `ConstraintSet` lattice (`meet`, TOP/BOTTOM, fail-closed) | `kern-core` | implemented |
| `PolicyDecision` | `kern-core` | implemented |
| V1/V2 canonical wire protocol, envelope framing, canonicality gate | `kern-core` | implemented |
| `Challenge`, `ChallengeTicket` (V2 freshness) | `kern-core` | implemented |
| `AuthorityArtifactId` (traceable authority identity) | `kern-core` | implemented |
| `Clock` / `MonotonicClock` abstractions + test/system impls | `kern-core` | implemented |
| `CapabilityRegistry` | `kern-policy` | implemented |
| `Policy` / `Selector` / `PolicySet`, unbounded-must-be-intentional | `kern-policy` | implemented |
| `Authority` evaluator (emptiness check, meet, three-way decision) | `kern-policy` | implemented |
| `LeaseIssuer` (V1/V2), `Signer` / `Ed25519Signer`, `NonceSource` / `CountingNonces`, `LeaseIdSource` | `kern-authority` | implemented |
| `AuthorizedOperation` (non-forgeable) | `kern-authority` | implemented |
| Edge verification (`verify_bytes`/`verify_parsed`, raw-bytes verify) | `kern-enforcer` | implemented |
| `TrustStore` | `kern-enforcer` | implemented |
| `EnforcerStore` install (session, supersession, challenge, deadline) | `kern-enforcer` | implemented |
| Hot-path `check_authority` / `enforce` (comparisons only) | `kern-enforcer` | implemented |
| `InstalledLease` / `LeaseHandle` (receipt vs. authority) | `kern-enforcer` | implemented |
| Execution governor (prepare/submit/tick, authority-loss contract) | `kern-execution` | implemented |
| Three orthogonal state axes, observation, reconcile, dispute, journal | `kern-execution` | implemented |
| Nav2 executor + `FakeNav2Backend` | `kern-execution-nav2` | implemented |
| `r2r` ROS 2 bridge + `kern-nav2-demo` binary | `adapters/nav2-bridge` | implemented |
| Gazebo world + Nav2 params + launch | `ros2/kern_nav2_demo` | implemented |
| Layer 3 integration harness (real `r2r` vs fake `rclpy` server) | `adapters/nav2-bridge/integration` | implemented |
| Phase 6 acceptance validation (launch / nav / e2e + fault injection) | `ros2/kern_nav2_demo/validation` | implemented |

### Planned / not yet built

- **`kern-cli`** — the CLI direction (`AGENT.md` §25) is not built. The
  `kern-nav2-demo` binary is the closest executable entry point.
- **A standalone `kern-sim` crate** — the deterministic simulator is served by
  `FakeNav2Backend` and per-crate test harnesses rather than a dedicated crate.
- **Other reference domains** — robot arm and rail/conveyor (`AGENT.md` §18) are
  not implemented. Only the café `navigate` capability exists.
- **Other café capabilities** — `wait`, `return_to_base`, `speak` are not
  implemented.
- **Durable nonce persistence** — `CountingNonces` is in-memory only.
- **Configuration parsing** — the YAML/JSON boundary layer and config syntax are
  not designed yet (`AGENT.md` §24).
- **Revocation latency measurement** — not measured or exposed.
- **Renewal tracker** — the `LeaseSupervisor` / `LeaseRenewalTracker` /
  `AuthorityLifetimeMonitor` component (`AGENT.md` §4.5) is not a separate
  component; renewal is exercised in the demo's `supersede` scenario by
  installing a newer lease into the same slot.

## 2. The initial milestone (`AGENT.md` §11)

The first milestone is complete when a deterministic test demonstrates:

```text
 1. An operation cannot execute without a lease.
 2. A lease cannot authorize another subject.
 3. A lease cannot authorize another device.
 4. A lease cannot authorize another capability.
 5. Scope cannot be exceeded.                (subject+device+capability+constraints)
 6. Parameter bounds cannot be exceeded.
 7. Expired authority is rejected.
 8. Revoked authority is rejected.           (supersession)
 9. Replayed authority is rejected.
10. Policy order does not affect authority.
11. Adding policy cannot expand authority.
12. Every executed operation references a valid authority trace.
```

These are covered by the test inventory below and by the end-to-end demo
scenarios (`allowed`, `expiry`, `supersede`). The deterministic first
end-to-end path runs without ROS, Gazebo, or hardware via `FakeNav2Backend`.

## 3. Test inventory

```text
kern-core
  tests/algebra.rs              meet-semilattice properties
  tests/schema.rs               normalization, unknown params, defaults, domains
  tests/operation_encoding.rs   canonical operation encoding
  tests/wire.rs                 envelope framing, version fail-closed, canonicality
  tests/examples.rs             crate-level doc examples

kern-policy
  tests/properties.rs           property-based policy algebra
  tests/evaluation.rs           evaluator paths, empty-set, BOTTOM, three-way decision

kern-authority
  tests/issuance.rs             V1/V2 issuance, zero-TTL, overflow, ticket binding
  tests/golden.rs               V1 frozen byte + signature vectors
  tests/golden_v2.rs            V2 frozen byte + signature vectors

kern-enforcer
  tests/installation.rs         install pipeline, session, supersession, challenge, deadline
  tests/liveness.rs             hot-path liveness, expiry, clock-went-backwards

kern-execution
  tests/submission.rs           prepare/submit, authority-lost-before-submit, abandon
  tests/lapse.rs                authority lapse, one-instruction invariant, session mismatch
  tests/observation.rs          observation mapping, drops, Disputed
  tests/reconcile.rs            echoed-id rebinding, unattributed ops, StartupPolicy
  tests/vocabulary.rs           state-enum coverage

kern-execution-nav2
  tests/governor.rs             Nav2 executor under governor, speed-limit, lapse->cancel
  tests/mapping.rs              unit conversion, NavigateRequest, command digest
  examples/demo.rs, harness.rs  runnable ROS-free demos

adapters/nav2-bridge (needs ROS; separate workspace)
  integration/                  Layer 3 harness: real r2r client vs fake rclpy
                                NavigateToPose server; speed-limit-before-goal proof,
                                dead-server -> Unknown{Result}, rejected -> NotStarted
  ros2/.../validation/          Phase 6 acceptance: stage1 launch/TF/lifecycle,
                                stage2 navigation + speed bound, stage3 Kern e2e
                                + KILL_BT (kill|deactivate) + PAUSE_GZ fault injection
```

### Phase 6 acceptance

Phase 6 (the Nav2 + Gazebo demonstration) was accepted through the validation
harness in `ros2/kern_nav2_demo/validation/`, run inside the `Dockerfile.sim`
container. The harness ran the real launch file, the real Nav2 stack, and the
real Kern bridge, and the three scenarios (`allowed`, `expiry`, `supersede`) plus
fault injection (`KILL_BT`, `PAUSE_GZ`) behaved as designed.

Three real defects the harness caught and the code now prevents:

- **Speed-limit silent drop.** An unmatched ROS publisher silently drops the
  message; the adapter once reported the limit as `Applied`. The worker now
  verifies a subscriber exists before reporting `Applied`, and the executor sends
  no goal otherwise (`NotStarted(Rejected(Unavailable))`).
- **Map/world disagreement.** The SDF corridor walls left a 0.2 m gap where the
  occupancy map said 2 m; Nav2 planned through a wall. The map is now regenerated
  from the same geometry as the world (`maps/generate_map.py`).
- **False-healthy availability.** An earlier availability check treated a
  creatable `is_available` future as proof the server was there, and reported a
  killed server as healthy. Availability now resolves the future against a
  budget and debounces over three misses.

### Required negative tests (`AGENT.md` §12)

Every authority feature has denial-path tests: invalid signature, wrong issuer,
wrong subject/device/capability, scope mismatch, bound exceeded, expired lease,
revoked (superseded) lease, replayed nonce, session mismatch, superseded nonce,
unknown capability, malformed proposal, missing trace. Happy-path tests alone
are insufficient.

## 4. Determinism (`AGENT.md` §13)

The first simulator is deterministic. Time is injected (`Clock` /
`MonotonicClock` / `TestClock` / `TestMonotonicClock`), never read from wall-clock
APIs in domain logic. Nonce generation, lease/execution IDs, simulated executor
state (`FakeNav2Backend`), and failure injection are all injectable and
scriptable. The demo's `FakeNav2Backend.sim_time_ms` is deliberately inert — Kern
never reads sim time; authority lifetime runs on the enforcer's monotonic clock
alone.

Reproducibility matters because the simulator is also intended to support
research evaluation.

## 5. Measurement plan (`AGENT.md` §29)

Do not optimize before measuring. Kern is not intended to run inside
motor-control frequencies. Relevant measurements:

```text
lease issuance latency
lease decode / verification / install latency
steady-state per-operation enforcement latency
policy evaluation latency
revocation latency
trace overhead
renewal frequency
memory footprint
```

**Report lease-install latency and steady-state enforcement latency as separate
numbers.** Averaging them hides the verify-once architecture: cryptographic
verification happens once at install; the per-operation path is comparisons
only. Report median, p95, and p99 when enough samples exist. Do not report a
single average as the complete latency story.

These measurements are **planned**, not yet taken. No latency numbers appear
anywhere in this documentation because none have been measured.

## 6. Experimental hooks (`AGENT.md` §30)

Design interfaces so experiments can inject:

```text
fake time                  TestClock / TestMonotonicClock / FakeNav2Backend.sim_time_ms
network partitions         FakeNav2Backend.disconnect / reconnect
issuer failure             issuers are injectable; CountingNonces exhaustion
lease expiry               demo scenario "expiry"; TestClock advancement
revocation                 supersession install into the same slot
replayed leases            nonce/supersession tests; duplicate install
malformed requests         schema/wire negative tests
capability escalation      evaluator unknown-capability tests
parameter escalation       constraint bound-exceeded tests
executor acknowledgement loss   governor Unknown state, reconcile
adversarial proposal streams     FakeNav2Backend scripting
```

This is not test-only convenience. It is part of making Kern scientifically
evaluable.

## 7. Definition of done (`AGENT.md` §31)

A feature is not done because the happy path works. A feature is done when:

```text
implementation exists
types are explicit
errors are typed
negative paths are tested
logs are structured
docs explain the boundary
failure semantics are defined
security implications are considered
```

For authority-sensitive features, also: replay behaviour considered, expiry
behaviour considered, revocation behaviour considered, traceability considered.