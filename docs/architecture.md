# Architecture

Kern is a capability-based authority layer for AI-controlled physical systems.
It sits between probabilistic decision-makers (AI agents, planners, humans) and
physical executors (robotics stacks, PLCs, vendor SDKs). A model being
compromised must not automatically imply that the model has unrestricted
physical authority.

> Agents propose actions. Kern grants bounded authority. Edge executors enforce
> that authority close to the machine.

Kern is **not** a robotics runtime, navigation stack, motion planner, motor
controller, safety PLC, or functional-safety system. It integrates with these
systems but never absorbs their responsibilities. Correct authority does not
imply safe motion. See [threat-model.md](threat-model.md).

## 1. The execution boundary

The intended path from intent to physical effect, and the layer that owns each
stage:

```text
AI / Agent / Human / Planner
        |
        | ActionProposal                  (intent, no authority)
        v
Kern Authority Control Plane
  - Capability Registry                   what a device understands
  - Policy Engine                         what a subject may request
  - Lease Issuer                          signed, bounded, time-limited authority
  - Signing / Nonce / Session management
        |
        | signed CapabilityLease          (claim, not yet trusted)
        v
Edge Authority Enforcer
  - verify signature over raw bytes
  - verify issuer trust
  - verify subject / device / capability binding
  - verify parameter bounds
  - verify lease lifetime
  - verify session / freshness binding
  - verify nonce / supersession / revocation state
        |
        | InstalledLease                  (authenticated, installed authority)
        v
Execution Governor
  - re-check liveness per operation
  - drive the executor adapter exactly once
  - enforce the authority-loss contract
  - observe, reconcile, record provenance
        |
        | SemanticCommand                 (authorized operation, no lease inside)
        v
Machine Executor / Adapter
  - ROS 2 / Nav2 / MoveIt / PLC / simulator / vendor SDK
        |
        v
Real-Time Controller  ->  Functional Safety (E-stop, safety PLC)
```

Kern is not placed inside a high-frequency motor-control loop. The enforcer
verifies a lease **once, at installation**; the steady-state per-operation path
is comparisons only. See [edge-enforcement.md](edge-enforcement.md) §verify-once.

## 2. Crate map

The workspace (`Cargo.toml`) members, in dependency order. `kern-core`,
`kern-policy`, and `kern-enforcer` are `no_std + alloc` with `std` behind a
default feature, so the enforcer can target constrained edge hardware. The
`no_std` split is decided up front because retrofitting it later is a rewrite,
not a refactor (`AGENT.md` §9).

```text
kern-core            domain vocabulary + wire protocol + clock abstractions
                     no_std + alloc, #![forbid(unsafe_code)]
                     deps: serde, postcard, sha2
        |
        +-- kern-policy        capability registry + policy algebra + evaluator
        |                       no_std + alloc
        |                       deps: kern-core
        |
        +-- kern-authority     lease issuance, Ed25519 signing, nonce/lease-id sources
        |                       std
        |                       deps: kern-core, kern-policy, ed25519-dalek
        |
        +-- kern-enforcer      edge verification + installed-lease store + freshness
        |                       no_std + alloc
        |                       deps: kern-core, ed25519-dalek
        |
        +-- kern-execution     execution governor: authority-loss contract, observation
        |                       std, synchronous, no I/O
        |                       deps: kern-core, kern-enforcer, sha2
        |
        +-- kern-execution-nav2  Nav2 executor + fake backend (ROS-free)
                                 default feature: fake-backend
                                 deps: kern-core, kern-execution

adapters/nav2-bridge    r2r (ROS 2) bridge binary: kern-nav2-demo
                        excluded from workspace (needs a sourced ROS install)
                        deps: kern-execution-nav2, r2r, ed25519-dalek, ...

ros2/kern_nav2_demo     Gazebo world + Nav2 params + launch (ament_cmake package)
                        validation/ — Phase 6 acceptance harness (3 stages + fault injection)

adapters/nav2-bridge/integration  Layer 3 harness: real r2r client vs fake rclpy
                                  NavigateToPose server; Dockerfiles for CI/sim
```

### Notable departures from `AGENT.md` §8

`AGENT.md` §8 lists a target structure with `kern-sim` and `kern-cli` and no
`kern-execution`. The implemented workspace differs:

- **`kern-execution` exists and is not in the §8 target.** It is the
  authority-loss contract layer between the enforcer and the executor adapter.
  It is documented in [execution-governor.md](execution-governor.md). This is
  the most significant structural addition over the spec.
- **`kern-sim` and `kern-cli` are not present.** The deterministic simulator is
  served by `FakeNav2Backend` inside `kern-execution-nav2` and by the test
  harnesses in each crate's `tests/`. The CLI direction (`AGENT.md` §25) is
  not yet built; the `kern-nav2-demo` binary in `adapters/nav2-bridge` is the
  closest thing to an executable entry point.
- **`kern-execution-nav2` exists** as the Nav2-specific executor crate, keeping
  all ROS dependency out of the core.

## 3. The end-to-end authority path (implemented)

This is the path the code actually takes, from an upstream proposal to a
governed physical operation, with the crate and type that owns each step.

```text
ActionProposal                                  kern-core::proposal
  actor, device, capability, params: ParamValue
        |
        | CapabilityRegistry::resolve(device, capability)   kern-policy::registry
        v                                           unknown device/capability -> error
CapabilitySchema
        |
        | schema.normalize(proposal)                kern-core::schema
        v                                           unknown/missing/wrong-domain -> error
NormalizedActionProposal
  (private fields; only constructible via normalization)
        |
        | Authority::evaluate                       kern-policy::evaluator
        |   1. resolve schema         (already done above)
        |   2. collect applicable policies (3-selector conjunction, id order)
        |   3. empty applicable set  -> Denied          (explicit, before fold)
        |   4. effective = meet_all(applicable constraints)
        |   5. effective == BOTTOM   -> Denied
        |   6. effective.permits(proposal) -> Authorized { constraints }
        |   7. otherwise               -> NotAuthorizedAsProposed { grantable }
        v
PolicyDecision
        |
        | AuthorizedOperation::from_evaluation      kern-authority::operation
        |   (None for any non-Authorized decision; grantable is advisory, never signed)
        v
AuthorizedOperation
        |
        | LeaseIssuer::issue_v1 / issue_v2          kern-authority::issuer
        |   build_body (zero-TTL / overflow checks)
        |   wire::encode_body[_v2] (canonical postcard)
        |   wire::signing_input(domain || ver || len || body)
        |   Signer::sign -> Signature
        v
SignedLease / SignedLeaseV2   (a claim; constructible by anyone, not yet authority)
        |
        | wire::encode[_v2] -> envelope bytes
        v
~~~~ transport ~~~~   (out of band; delayed delivery is a threat-model concern)
        |
        | wire::parse                                 kern-core::wire
        |   frame -> version (fail-closed) -> retain raw body bytes
        v
ParsedLease            (untrusted; raw body bytes retained for verification)
        |
        | verify_bytes / verify_parsed                kern-enforcer::verify
        |   minimal untrusted decode for issuer/key_id
        |   TrustStore::key_for (lookup hint, never authority)
        |   verify signature over the ORIGINAL raw body bytes
        |   canonical re-encode byte-equality gate
        v
VerifiedLease          (signature verified under a trusted key; no session/lifetime yet)
        |
        | EnforcerStore::install                      kern-enforcer::store
        |   session match  (lease bound to this boot's EnforcerSessionId)
        |   supersession   (same nonce+artifact = retry; lower nonce = superseded)
        |   validate_challenge  (outstanding, unexpired, unconsumed, slot-bound)
        |   authority_deadline    (anchored at CHALLENGE issuance, not arrival)
        |   two-write commit into fixed-capacity arrays (no allocation post-check)
        v
InstalledLease + LeaseHandle
  (InstalledLease: not Clone, borrow-only. LeaseHandle: Clone, names only, not authority)
        |
        | ExecutionGovernor::prepare(store, handle, operation)  kern-execution::governor
        |   enforce (liveness + bindings + constraints)
        |   reserve record slot
        |   CommandDigest = SHA-256(domain || canonical operation encoding)
        |   ExecutionId
        |   write ExecutionRecord    (nothing sent yet)
        v
PreparedExecution        (borrows governor &store &mut; not an authority reservation)
        |
        | prepared.submit(store, &mut adapter)
        |   session compare -> check_authority (liveness)
        |   authority lost here -> NotStarted(AuthorityLost); adapter NOT called
        |   adapter.submit(SemanticCommand) exactly once
        v
SubmitReceipt            (ExecutionId, CommandDigest, state, executor_invoked)
        |
        | governor.tick_observed(store, &mut adapter)   each tick
        |   authority_pass: per-record check_authority -> mark lapses
        |   lapse_pass: mark handled BEFORE adapter call -> one instruction per execution
        |                  adapter.on_authority_lapse(op, LapseAction)
        |   observation_pass: drain adapter observations -> update records + journal
        v
ExecutionRecord + Transition journal    (provenance; traceable to the lease that permitted it)
```

The adapter receives a `SemanticCommand` — the authorized, normalized operation
plus its `ExecutionId`. It never sees the lease, the `AuthorityArtifactId`, the
constraint set, or the policy. This is the `AGENT.md` §17 rule made structural:
the adapter decides no policy, mints no authority, and receives already
authorized semantics.

## 4. Layering rules

1. **Authority flows down; semantics flow down; observations flow up.** Nothing
   in a lower layer may mint or widen authority.
2. **`kern-core` stays portable.** It depends on no robotics, no ROS, no Gazebo,
   no vendor SDK, no async runtime. It is `no_std + alloc`. See `AGENT.md` §9.
3. **JSON/YAML are boundary and configuration formats only.** They never define
   authority semantics and never define signed bytes. The signed representation
   is canonical binary (`postcard` under a versioned envelope). See
   [lease-and-signing.md](lease-and-signing.md).
4. **No `f64` in the authority algebra.** `kern-core` compares normalized `i64`
   scalars. Floating point is neither `Ord` nor `Eq`, which breaks idempotence,
   structural equality, and deterministic comparison. Units and scaling live at
   the capability-schema boundary, which converts external representations
   (`0.5 m/s`) into canonical integers (`500 mm/s`) before policy evaluation.
5. **`no_std` crates use ordered collections only.** `BTreeMap`/`BTreeSet`, not
   `HashMap`. Determinism is a first-class property (`AGENT.md` §13).
6. **The governor is synchronous and I/O-free.** No `tokio`, no async traits, no
   filesystem. Time, nonces, IDs, and failure injection are injected. See
   [execution-governor.md](execution-governor.md).

## 5. The core principle

When any layer is uncertain, it returns to one rule (`AGENT.md` §35):

> **Decision capability is not execution authority.**

An AI system may decide what it wants to do. Kern determines what it is
temporarily authorized to cause. The machine stack determines how the authorized
operation is executed. The functional-safety stack remains responsible for
safety-critical physical protection. Kern stops granting authority, forwards
commands, requests cancellation, observes, and records; it does not stop the
machine and never claims to.