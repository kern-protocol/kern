# AGENT.md — Kern Protocol

This file defines how AI coding agents should reason about, modify, and extend the Kern Protocol repository.

Kern is a capability-based authority layer for AI-controlled physical systems. It sits between probabilistic decision-making systems and physical executors.

The core architectural principle is:

> Agents propose actions. Kern grants bounded authority. Edge executors enforce that authority close to the machine.

A model being compromised must not automatically imply that the model has unrestricted physical authority.

---

## 1. Project Mission

Kern explores how authority should be represented when AI-generated decisions can cause physical effects.

Kern is not a robotics runtime, navigation framework, motion planner, motor controller, or functional-safety system.

Kern should answer questions such as:

- Which subject is allowed to invoke which physical capability?
- On which device?
- Under what scope and parameter bounds?
- For how long?
- Under which policy decision?
- Can that authority be replayed?
- Can it be revoked?
- Can the system later explain which authority permitted an executed effect?

The primary authority primitive is a **capability lease**.

A capability lease is explicit, scoped, bounded, signed, time-limited, replay-resistant, renewable, revocable, and traceable.

---

## 2. Non-Goals

Do not turn Kern into any of the following:

- a generic AI agent runtime
- a ROS 2 replacement
- a navigation stack
- a motion planner
- a SLAM implementation
- a motor controller
- a safety PLC
- a certified functional-safety mechanism
- a collision-avoidance system
- a control-barrier-function implementation
- a model-confidence safety gate
- a cloud source of truth for fast-changing physical state

Kern may integrate with these systems, but must not absorb their responsibilities.

Never imply that Kern makes a robot physically safe.

Correct authority does not imply safe motion.

Physical emergency-stop circuits, safety PLCs, watchdogs, certified controllers, and low-level safety mechanisms remain outside Kern.

---

## 3. Architectural Boundary

The intended execution path is:

```text
AI / Agent / Human / Planner
        |
        | ActionProposal
        v
Kern Authority Control Plane
  - Capability Registry
  - Policy Engine
  - Lease Issuer
  - Signing / Nonce Management
  - Trace / Provenance
        |
        | signed CapabilityLease
        v
Edge Authority Enforcer
  - verify signature
  - verify subject/device/capability binding
  - verify parameter bounds
  - verify expiry
  - verify replay state
  - verify revocation state
  - verify session / freshness binding
        |
        | authorized semantic operation
        v
Machine Executor / Adapter
  - ROS 2
  - Nav2
  - MoveIt
  - PLC
  - simulator
  - vendor SDK
        |
        v
Real-Time Controller
  - MCU
  - motor loops
  - embedded firmware
        |
        v
Functional Safety
  - E-stop
  - safety PLC
  - certified controller
```

Kern should not be placed inside a high-frequency motor-control loop.

---

## 4. Core Concepts

### 4.1 ActionProposal

An upstream system proposes an action.

A proposal has no implicit authority.

Example:

```rust
pub struct ActionProposal {
    pub actor: SubjectId,
    pub device: DeviceId,
    pub capability: CapabilityName,
    pub params: BTreeMap<ParamName, ParamValue>,
}
```

`kern-core` operates on **normalized, typed** parameter values in an ordered map. It does not operate on `serde_json::Value`.

```rust
pub enum ParamValue {
    Scalar(i64),
    Symbol(Symbol),
}
```

JSON and YAML are boundary and configuration formats. They must never define authority semantics. A dynamically typed value reaching the policy engine would push type decisions into the authority path, where an unexpected type has to become an authority answer.

Normalization happens before policy evaluation:

```text
external request
    -> capability-schema validation and normalization
    -> ActionProposal with typed ParamValue arguments
    -> policy evaluation
```

Do not name this type `Command` if it has not yet been authorized.

Prefer:

- `ActionProposal`
- `CapabilityRequest`
- `ProposedOperation`

Avoid:

- `RobotCommand`
- `ExecuteCommand`

unless the object has already passed authority enforcement.

### 4.2 Capability

A capability is a semantic operation exposed by a device.

Examples:

```text
navigate(destination, max_speed)
return_to_base()
pick(object)
place(object, destination)
move_to_station(station)
inspect(target)
```

Avoid exposing raw actuation primitives to AI agents unless explicitly required.

Bad default capabilities:

```text
set_pwm(...)
set_gpio(...)
write_register(...)
set_motor_voltage(...)
```

The capability abstraction should preserve a semantic authority boundary.

#### Capability schema

A `CapabilitySchema` describes what a semantic operation means: its parameter names, each parameter's value domain, whether the parameter is required, and its normalized default if it has one.

A schema answers one question, and never the other:

```text
CapabilitySchema      can this device understand this operation
Policy                may this subject request it
```

A schema carries **capability identity only**. Device identity is never baked into a schema, so one schema stays reusable across every device exposing that capability. The device/capability binding belongs to the registry.

Unknown parameters are always a schema error. There is no allow-unknown escape hatch, and one must not be added until a concrete capability needs extensible parameters. A parameter no schema declares is a parameter no policy constrains, and unconstrained input must not reach an executor.

#### Defaults are capability semantics, not policy

A schema default is part of what the operation means. Normalization applies it **before** any policy evaluation:

```text
absent parameter
    -> schema default inserted during normalization
    -> normalized proposal
    -> policy evaluates the inserted value exactly as if the caller had supplied it
```

A default must never depend on the subject, on the applicable policies, on runtime state, or on any authority decision. A default that varies with who is asking is an authority decision wearing a schema's clothes.

#### Schema optionality does not bypass policy

Schema optionality and policy authority are separate concepts.

A parameter that is optional in the schema and absent from the proposal is still refused by any policy constraint on it, because parameter satisfaction fails closed (section 4.3):

```text
schema:     foo is Optional
policy:     foo <= 10
proposal:   foo absent
result:     not permitted under that authority
```

The policy engine must never read "optional in schema" as "this constraint can be skipped".

#### Capability registry

A `CapabilityRegistry` resolves:

```text
(device, capability) -> CapabilitySchema
```

The registry establishes what a requested operation means. It must not decide authority.

An unknown device or an unknown capability fails closed, as an error rather than as an authority decision.

Registration derives the capability key from the schema:

```text
register(device, schema)      key = schema.name()
```

rather than taking a separate capability argument, which would let a registry entry claim `(robot_1, navigate) -> schema(name = pick)`. One source of truth, enforced by the shape of the API rather than by a validation rule someone can forget to call.

### 4.3 ConstraintSet

Policies restrict authority.

Typical restrictions include:

```text
allowed destinations
allowed zones
allowed objects
allowed workspaces
maximum velocity
maximum force
mission identity
subject identity
device identity
```

Constraints must compose monotonically.

Adding policy must never increase authority.

#### Parameter satisfaction fails closed

A parameter constraint is satisfied only when the normalized `ActionProposal` explicitly contains that parameter **and** its value satisfies the constraint.

A constrained parameter that is absent from the proposal is refused.

Capability defaults, where a capability has any, are resolved by capability-schema validation **before** policy evaluation. The policy engine must never infer, invent, or substitute a default. A missing argument is not evidence that a bound was met.

#### Duration

Do not add a generic authority-duration field to `ConstraintSet`.

A duration may be constrained only where it is an explicit semantic parameter of a capability:

```text
wait(duration_ms)
inspect(timeout_ms)
```

Those are ordinary parameter bounds, constrained like any other parameter.

Lease TTL and authority lifetime are a different thing entirely, and belong to the future `CapabilityLease` protocol rather than to the constraint algebra.

Operation lifetime and authority lifetime remain distinct. See section 4.5.

#### Units and scaling live outside `kern-core`

`kern-core` compares normalized integer scalars. Floating point is deliberately excluded: `f64` is neither `Ord` nor `Eq`, which breaks idempotence, structural equality, and deterministic comparison.

The capability schema declares units and converts external representations into the canonical integer representation before policy evaluation:

```text
0.5 m/s
    -> capability-schema normalization
    -> 500 mm/s
    -> ParamValue::Scalar(500)
```

Do not add a generic quantity or unit system in Phase 1 or Phase 2 unless a concrete requirement forces it.

### 4.4 CapabilityLease

A lease represents temporary physical authority.

Conceptually:

```rust
pub struct CapabilityLease {
    pub id: LeaseId,
    pub subject: SubjectId,
    pub device: DeviceId,
    pub capability: CapabilityName,
    pub constraints: ConstraintSet,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub nonce: Nonce,
    pub issuer: IssuerId,
    pub signature: Signature,
}
```

The exact Rust representation may evolve, but preserve the semantics.

#### Scope is not a field

There is no `CapabilityScope` type. The scope of physical authority is already
fully determined by four things a lease already carries:

```text
subject
device
capability
constraints
```

A second representation of scope alongside `ConstraintSet` would create two
sources of truth that can disagree:

```text
CapabilityScope says   destination = table_7
ConstraintSet says     destination = table_8
```

The word "scope" stays in prose as a descriptive term — authority is scoped to a
subject, a device, a capability, and a constraint set — but it is not a
standalone protocol type or lease field, and it must not become one.

If a real use case later needs an authority dimension that
subject/device/capability/constraints genuinely cannot express, add a new
primitive then, with the use case written down.

A lease must never describe how low-level motion is performed.

It describes why an operation is currently authorized.

### 4.5 Edge Enforcer

The edge enforcer is the last Kern-controlled authority boundary before the executor.

It should verify:

```text
signature
issuer trust
subject binding
device binding
capability binding
parameter bounds
lease lifetime
session / freshness binding
nonce / supersession state
revocation
```

That list is exhaustive. There is no `AuthorityInvariant` abstraction, and one
must not be invented without a concrete requirement: the previous field was
undefined and overlapped with `ConstraintSet` and with edge-local execution
checks.

Physical and runtime conditions that the authority model does not represent are
not the enforcer's business. They belong to the executor and the safety system.

There is no separate scope check. Scope *is* the subject, device, and capability
bindings together with the parameter bounds, and checking each of those is
checking the scope (section 4.4).

The enforcer should fail closed for operations that require Kern authority.

When authority disappears, the enforcer must stop forwarding newly authorized operations.

Do not claim that Kern itself guarantees the machine enters a certified safe state. That response belongs to the downstream controller / safety architecture.

#### Verification happens once, at installation

Cryptographic verification belongs to installation, not to the per-operation path.

##### Parsing before verification is allowed. Trusting before verification is not.

A verifier cannot literally "verify before decoding": the `issuer` and `key_id`
needed to select a verification key live *inside* the signed body. The rule is
about trust, not about order of operations.

```text
parse the envelope framing            version, body length, signature
retain the EXACT raw body bytes
minimally decode the UNTRUSTED body   to obtain issuer and key_id
resolve a candidate verification key  a lookup hint, nothing more
verify the signature over the ORIGINAL raw body bytes
  -- only now are body fields authenticated --
validate canonical encoding, convert to a semantic LeaseBody
apply session, lifetime, and nonce checks
```

Never verify a re-encoding of the parsed body. Verification runs over the bytes
that arrived, so a decoder bug cannot become a signature bypass.

An `issuer` or `key_id` read before verification carries no authority. Finding a
key for a claimed issuer is not authorization; the signature must verify against
a trust-store entry accepted for that issuer.

An unsupported protocol version fails closed before the body is decoded at all.

```text
SerializedLease
      |
      v
envelope framing + version check
      |
      v
signature verified over raw body bytes
      |
      v
canonical decode -> VerifiedLease
      |
      v
session / lifetime / nonce checks
      |
      v
InstalledLease
```

`InstalledLease` is a privileged type. Its constructors must be private or crate-restricted so that no public API can produce one without passing verification and installation.

Steady-state enforcement performs comparisons and local authority checks. It must not repeat Ed25519 verification per operation.

Replay protection belongs primarily at installation.

#### Authority-loss contract

Refusing to forward new operations is not sufficient for an operation that is already running.

Once `navigate(table_7)` has been accepted by Nav2, expiry of the lease does not undo the accepted command. Kern must therefore define an explicit authority-loss contract with the executor.

```text
Active operation
      |
      | lease expires / revoked / renewal fails
      v
ExecutionState::AuthorityLapsed
      |
      v
adapter receives authority_lost(operation_handle)
      |
      v
adapter cancels / holds / terminates the governed operation
according to its executor contract
```

Kern terminates authorization and requests termination of the governed operation.

Kern does not stop the machine, and must never be described as doing so. The physical response remains the responsibility of the executor and the safety architecture.

An adapter that accepts long-running operations must expose an `operation_handle` and honour `authority_lost`. An adapter that cannot do so may only accept operations that complete within the authority window.

#### Operation lifetime is not authority lifetime

These are separate quantities and must not be collapsed into a single field:

```text
operation deadline / requested duration   (only if the domain has one)
authority lease TTL                       (how long authorization lasts)
```

A semantic operation may take an unpredictable amount of time because of replanning, congestion, or executor behaviour. Do not require a single lease to span an entire operation.

An operation may outlive a single lease only through explicit renewal.

The component that tracks renewal should be named one of:

```text
LeaseSupervisor
LeaseRenewalTracker
AuthorityLifetimeMonitor
```

Do not call it a watchdog. That term carries embedded and functional-safety connotations that Kern does not satisfy.

### 4.6 Execution Trace

Every mediated physical effect should be traceable to the authority that permitted it.

A trace should make it possible to answer:

```text
Who proposed the operation?
Which device was targeted?
Which capability was requested?
Which policies applied?
Which lease permitted execution?
What bounds were active?
Which executor handled it?
What was the observed result?
```

Do not store or depend on private model chain-of-thought.

Store structured decisions and execution metadata instead.

---

## 5. Policy Algebra

Policy composition is a core research property.

Let `A <= B` mean that `A` grants no more authority than `B`.

Effective authority should behave like a meet operation:

```text
A_effective = A1 ∧ A2 ∧ ... ∧ An
```

`ConstraintSet` is a **bounded** meet-semilattice, with explicit top and bottom elements:

```text
TOP    = unconstrained authority   (identity for meet, seed for a fold)
BOTTOM = no authority              (absorbing element, deny)
```

Without a top element, folding over an empty policy set is undefined.

Initial merge rules:

```text
allow sets       -> intersection
deny sets        -> union
numeric upper    -> min
numeric lower    -> max
numeric interval -> intersection
contradiction    -> BOTTOM
```

Note that deny sets merge by **union** while allow sets merge by **intersection**. Both directions restrict authority. Implementing deny with intersection fails open.

A deny decision maps to BOTTOM.

Required properties:

```text
commutativity
meet(A, B) == meet(B, A)

associativity
meet(meet(A, B), C) == meet(A, meet(B, C))

idempotence
meet(A, A) == A

restriction against both operands
meet(A, B) <= A
meet(A, B) <= B

bounds
meet(TOP, A)    == A
meet(BOTTOM, A) == BOTTOM

contradiction
an unsatisfiable merge collapses to BOTTOM
```

Do not derive restriction against `B` from commutativity. Assert both directions independently.

Use property-based tests for these properties.

Denial and restriction behaviour get their own dedicated property tests. An error in the allow path reduces availability; an error in the deny path expands physical authority.

Preferred Rust tool:

```text
proptest
```

Do not silently mutate arbitrary plans.

If a planner requests:

```text
max_force = 80N
```

and policy allows:

```text
max_force <= 15N
```

return a constrained authority result carrying the bounds that would be grantable:

```rust
pub enum PolicyDecision {
    Authorized { constraints: ConstraintSet },
    NotAuthorizedAsProposed { grantable: ConstraintSet },
    Denied,
}
```

Then let the planner explicitly re-plan or resubmit.

The `grantable` constraints are **advisory output**. They exist so a planner can replan against real bounds instead of guessing.

They must never be executed as a silently modified proposal. Kern reports what it would authorize; it does not decide what the planner meant.

Do not silently execute a semantically modified plan.

### Policy representation

A policy binds selectors to a constraint set. Nothing more.

```rust
pub struct Policy {
    pub id: PolicyId,
    pub subject: Selector<SubjectId>,
    pub device: Selector<DeviceId>,
    pub capability: Selector<CapabilityName>,
    pub constraints: ConstraintSet,
}

pub enum Selector<T> {
    Any,
    Exactly(T),
    AnyOf(BTreeSet<T>),
}
```

`AnyOf` is selector disjunction, and it cannot be modelled as several policies. Policies compose by `meet`, so two policies naming one subject each would intersect their constraints rather than cover either subject.

No globs, no regular expressions, no boolean expression trees, no scripting, no Rego-style evaluation. Selectors are deterministic and explicit.

### Applicability

A policy applies to a proposal if and only if all three selectors match:

```text
subject selector matches
AND device selector matches
AND capability selector matches
```

No precedence. No priority. No first-match. No deny-overrides. No insertion-order behaviour.

Every applicable policy contributes through `meet`, and only through `meet`.

### The empty applicable set is a denial, not an identity

```text
meet_all([]) == TOP
```

Mathematically correct, and authorization-dangerous: folding an empty set of applicable policies yields unconstrained authority.

An evaluator must check emptiness explicitly, **before** folding:

```text
1. resolve schema                       unknown   -> error
2. normalize proposal                   invalid   -> error
3. collect applicable policies
4. if applicable is empty                         -> Denied
5. effective = meet_all(applicable)
6. if effective is BOTTOM                         -> Denied
7. if effective permits the proposal              -> Authorized { constraints }
8. otherwise                                      -> NotAuthorizedAsProposed { grantable }
```

Step 4 is not an optimisation and must not be folded into step 5. Do not expose a generic evaluator that mechanically calls `meet_all(applicable)` without handling emptiness first.

Capability existence is not authority. That a device understands `navigate` implies nothing about whether a subject may request it.

### Evaluation consumes normalized proposals only

Constraint evaluation accepts a schema-validated proposal, never a raw one:

```text
schema validation
    -> NormalizedActionProposal
    -> constraint evaluation
```

`NormalizedActionProposal` has private fields and is constructible only through schema normalization. No public API should make it convenient to evaluate an unvalidated `ActionProposal` as though it were schema-valid, and there must not be a second public authority-evaluation path that accepts one.

### Unbounded authority must be intentional

TOP is a legitimate authority value and stays representable. An accidental TOP is not.

A constraint set with no constraints normalizes to TOP, so an empty or missing `bounds:` block at the configuration boundary would otherwise become "everything permitted", silently.

Ordinary policy construction therefore rejects a constraint set that arrived empty. Unbounded authority requires its own constructor:

```text
Policy::unbounded(...)          intentional, reviewable, greppable
Policy::new(..., constraints)   rejects an empty constraint set
```

Unbounded authority must be expressed on purpose, never inferred from "no constraints happened to parse".

### An invalid request is not a denial

Two different states, which must not collapse into one:

```text
unknown capability, malformed proposal      evaluation error
valid proposal, no authority granted        PolicyDecision::Denied
```

A schema error says the request does not describe a real operation. A denial says the request describes a real operation that this subject may not perform. Reporting the first as the second hides configuration bugs inside authority answers.

---

## 6. Failure Semantics

Distributed failure behavior must be explicit.

### Issuer unavailable

Existing leases remain valid only until expiration.

No renewal means authority eventually disappears.

Never convert connectivity loss into indefinite permission.

### Edge disconnected from issuer

The edge may honor an already valid lease only within its remaining lifetime and local policy.

### Expired lease

An expired lease cannot authorize a new effect.

### Revocation

Revocation is not instantaneous.

Measure and expose revocation latency.

### Replay

Signed leases must include replay protection.

The reference implementation should use:

```text
Ed25519
monotonic nonce tracking
subject binding
device binding
validity interval
```

### Reboot

Invariant:

```text
reboot invalidates every pre-reboot issued or installed lease
```

Nonce state held only in RAM is lost on reboot, which would reopen the replay window. Bind leases to an enforcer session rather than reconstructing nonce history.

Initial mechanism, for Linux / Pi-class enforcers:

```text
enforcer_session = random 128/256-bit value, regenerated each boot
```

The signed lease body carries the session it is bound to. After a reboot the session differs, so every prior lease is rejected.

This avoids flash wear, torn-write recovery, and a persistent monotonic counter.

The issuer must learn the active enforcer session before it can issue a session-bound lease.

Keep session identity behind an abstraction. If the threat model later includes targets without trustworthy entropy, or requires persistent monotonic identity across boots, a persistent NVM epoch becomes the better backend for the same abstraction.

Session binding prevents cross-reboot replay. It does not by itself solve delayed delivery within a single session. See section 7.

### Lost acknowledgement

Physical operations may be non-idempotent.

If an operation may have executed but acknowledgement is lost:

```text
DO NOT automatically retry.
```

Use:

```text
ExecutionState::Unknown
```

until reconciled with the executor.

---

## 7. Time and State

Do not assume remote world state is perfectly current.

The authority control plane should not become the authoritative source for rapidly changing physical state.

Prefer:

```text
cloud/control plane
    static or slow-changing authority decisions

edge enforcer
    local authority-relevant predicates

robotics stack
    navigation / motion state

MCU
    real-time actuation state

functional-safety hardware
    certified safety state
```

### Time at the enforcer

The enforcer must not trust a local wall clock. A constrained target may have no RTC, a drifting RTC, or no network time source.

Two distinct clock abstractions:

```text
Clock            issuer, simulator, tests, trace timestamps
MonotonicClock   enforcer lifetime accounting
```

`Timestamp` is milliseconds since the Unix epoch, used by the issuer and the trace.

The enforcer measures an installed lease's remaining lifetime against monotonic uptime anchored at installation:

```text
reject when
    uptime_now - uptime_at_install > (expires_at - issued_at)
```

### Freshness at installation is an open problem

A monotonic clock bounds lifetime **after** installation. It does not establish that a lease was **freshly issued**.

Delayed-delivery problem:

```text
issuer:
    issued_at  = T
    expires_at = T + 500ms

an attacker delays delivery by ten minutes

the enforcer anchors a 500ms TTL at installation
=> an already-expired lease receives a fresh 500ms of authority
```

Distinguish:

```text
lifetime-after-installation   solved by MonotonicClock
freshness-at-installation     NOT solved by MonotonicClock
```

An implementation must never treat "installed now" as evidence that a lease was recently issued.

Whether an attacker may arbitrarily delay a valid lease before first installation is a threat-model decision. It must be recorded in `docs/threat-model.md` before the enforcer is implemented.

If delayed delivery is in scope, the freshness mechanism will be chosen from building blocks such as:

```text
enforcer session identity
request/response issuance nonce
outstanding issuance challenge
authenticated issuance handshake
bounded issuer/enforcer clock synchronization, if explicitly assumed
```

The mechanism is deliberately not chosen yet. The requirement is that the problem is recorded, and that no implementation silently assumes it away.

### TOCTOU

Leases do not eliminate physical TOCTOU.

Do not write claims such as:

```text
"Kern solves TOCTOU."
```

Use language such as:

```text
"Kern bounds the lifetime of previously granted authority."

"Kern avoids treating a historical authorization decision as indefinitely valid authority."
```

---

## 8. Repository Structure

Target structure:

```text
kern/
├── Cargo.toml
├── README.md
├── LICENSE
├── AGENT.md
│
├── crates/
│   ├── kern-core/
│   ├── kern-policy/
│   ├── kern-authority/
│   ├── kern-enforcer/
│   ├── kern-sim/
│   └── kern-cli/
│
├── adapters/
│   ├── gazebo/
│   │   ├── mobile_robot/
│   │   ├── robot_arm/
│   │   └── rail_robot/
│   └── ros2/
│
├── examples/
│   ├── cafe-robot/
│   ├── robot-arm/
│   └── rail-inspection/
│
├── simulation/
│   └── gazebo/
│
├── experiments/
│   ├── containment/
│   ├── replay/
│   ├── lease-expiry/
│   ├── policy-algebra/
│   └── adversarial/
│
└── docs/
    ├── architecture.md
    ├── threat-model.md
    ├── capability-model.md
    └── evaluation.md
```

Do not create all directories prematurely if they contain no code.

Keep the initial repository minimal and grow it as each milestone becomes real.

---

## 9. Dependency Rules

The core must remain portable.

### `kern-core`

Must not directly depend on:

```text
ROS 2
Gazebo
MoveIt
Nav2
NVIDIA SDKs
Nebius SDKs
STM32
ESP32
Modbus
vendor robot SDKs
```

Recommended initial dependencies:

```toml
serde
serde_json
serde_yaml
thiserror
tracing
uuid
ed25519-dalek
time
```

Use `tokio` only in crates where async behavior is actually required.

Avoid adding dependencies for trivial helpers.

### `no_std` split

The edge enforcer is expected to run on constrained targets. This split is decided before implementation because retrofitting `no_std` afterwards is a rewrite, not a refactor.

```text
kern-core       no_std + alloc,  std behind a default feature
kern-policy     no_std + alloc,  std behind a default feature
kern-enforcer   no_std + alloc,  std behind a default feature

kern-authority  std
kern-sim        std
kern-cli        std
```

Dependencies used by the `no_std` crates must be checked for `no_std` support and added with default features disabled.

`serde_json`, `serde_yaml`, and `tracing` subscribers belong on the `std` side only.

---

## 10. Implementation Order

Do not begin with ROS, Gazebo, UI, cloud models, or the physical robot.

The implementation sequence is:

```text
Phase 1  Core domain types
Phase 2  Policy composition
Phase 3  Lease issuance + signatures + nonce
Phase 4  Edge verification
Phase 5  Deterministic simulator
Phase 6  Failure scenarios
Phase 7  CLI / developer UX
Phase 8  Gazebo adapters
Phase 9  ROS 2 bridge
Phase 10 AI integrations
Phase 11 Physical robot
```

The first end-to-end path should be:

```text
ActionProposal
    ↓
Capability Registry
    ↓
Policy Engine
    ↓
PolicyDecision
    ↓
Lease Issuer
    ↓
signed CapabilityLease
    ↓
Edge Enforcer
    ↓
deterministic simulated executor
    ↓
ExecutionTrace
```

---

## 11. Initial Milestone

The first milestone is complete when a deterministic test can demonstrate all of the following:

```text
1. An operation cannot execute without a lease.
2. A lease cannot authorize another subject.
3. A lease cannot authorize another device.
4. A lease cannot authorize another capability.
5. Scope cannot be exceeded.
6. Parameter bounds cannot be exceeded.
7. Expired authority is rejected.
8. Revoked authority is rejected.
9. Replayed authority is rejected.
10. Policy order does not affect authority.
11. Adding policy cannot expand authority.
12. Every executed operation references a valid authority trace.
```

Item 5 refers to the subject, device, and capability bindings taken together
with the constraint set. There is no separate scope field to exceed (section
4.4).

Do not proceed to robotics middleware before this milestone is green.

---

## 12. Testing Strategy

Testing is a first-class part of Kern.

Use:

```text
unit tests
integration tests
property-based tests
deterministic simulation
failure injection
adversarial tests
benchmarks
```

### Required negative tests

Every authority feature should have denial-path tests.

Examples:

```text
invalid signature
wrong issuer
wrong subject
wrong device
wrong capability
scope mismatch
bound exceeded
expired lease
revoked lease
replayed nonce
unknown capability
malformed proposal
missing trace
```

Happy-path tests alone are insufficient.

---

## 13. Determinism

The first simulator must be deterministic.

Inject time instead of calling wall-clock APIs from domain logic.

Prefer:

```rust
pub trait Clock {
    fn now(&self) -> Timestamp;
}

pub trait MonotonicClock {
    fn uptime(&self) -> Duration;
}
```

Provide:

```text
SystemClock
SystemMonotonicClock
TestClock              implements both, advanceable
```

Tests must be able to advance time deterministically.

See section 7 for why the enforcer uses `MonotonicClock`, and for why monotonic time does not establish issuance freshness.

Do the same for nonce generation, IDs where practical, simulated executor state, and failure injection.

Reproducibility matters because the simulator is also intended to support research evaluation.

---

## 14. Error Design

Do not collapse authority failures into generic strings.

Prefer explicit error enums.

Example:

```rust
pub enum EnforcementError {
    InvalidSignature,
    UntrustedIssuer,
    SubjectMismatch,
    DeviceMismatch,
    CapabilityMismatch,
    ScopeViolation,
    ConstraintViolation,
    Expired,
    Revoked,
    ReplayDetected,
    SessionMismatch,
    SupersededNonce,
}
```

Errors should be typed, observable, traceable, and safe to expose in logs where appropriate.

### Internal granularity, external opacity

Library and control-plane errors stay granular. `UnknownDevice` and `UnknownCapability` are distinct because that distinction is useful in development, diagnostics, and tests.

An interface answering untrusted callers may need to collapse them:

```text
UnknownDevice
UnknownCapability
    -> UnknownTarget
```

Distinguishable errors are a device and capability enumeration oracle. Record this in `docs/threat-model.md` as a boundary concern for whichever layer first exposes evaluation to untrusted input. It is not a reason to blunt the internal error types.

---

## 15. Cryptography

Do not invent cryptographic primitives.

Use reviewed libraries.

Initial signing scheme:

```text
Ed25519
```

### Signed representation

JSON and YAML must never define signed bytes. They have no canonical key order, so verification breaks across serializers and versions.

The initial binary encoding is `postcard`. Postcard is an encoding choice. It is not the protocol definition, and it is not by itself sufficient evidence of canonicality.

The signed representation must additionally have:

```text
explicit protocol version
domain separation
fixed schema
fixed integer representations
no unordered maps or sets in signed structures
golden byte vectors
golden signature vectors
cross-platform compatibility tests
```

Use a versioned signing envelope:

```text
"KERN-LEASE-V1" || postcard(LeaseBodyV1)
```

Changing Rust field order, enum representation, integer representation, or serialization semantics is a protocol compatibility change, not a refactor. It requires a version bump and new golden vectors.

JSON and YAML remain available for configuration and human inspection on the `std` side.

Keys must not be hard-coded into production paths.

Test fixtures may use deterministic development keys.

Keep key loading, storage, signing, and verification behind explicit interfaces so storage can later move to a TPM, HSM, secure element, OS keychain, or cloud KMS.

Do not build custom encryption.

---

## 16. AI Integration Rules

AI models are upstream proposal sources.

Kern core must not depend on Nemotron, Cosmos, OpenAI, Anthropic, or any other model provider.

Good:

```text
Nemotron
    ↓
ActionProposal
    ↓
Kern
```

Bad:

```text
kern-core imports NVIDIA model SDK
```

Model confidence must not be treated as a functional-safety guarantee.

AI integrations belong in adapters, examples, or services outside the core authority model.

---

## 17. Robotics Integration Rules

Kern should integrate through semantic executor interfaces.

Conceptual interface:

```rust
#[async_trait]
pub trait Executor {
    async fn execute(
        &self,
        lease: &CapabilityLease,
        operation: AuthorizedOperation,
    ) -> Result<ExecutionResult, ExecutorError>;
}
```

The exact interface may evolve.

The important rule is:

```text
Adapter does not decide policy.
Adapter does not mint authority.
Adapter receives already authorized semantics.
```

Gazebo, ROS 2, MoveIt, Nav2, PLC, and vendor-specific logic belong in adapters.

---

## 18. Reference Simulation Domains

The intended cross-domain examples are:

### Café mobile robot

Capabilities:

```text
navigate
wait
return_to_base
speak
```

Authority dimensions:

```text
destination
zone
max_speed
mission
lease lifetime
```

### Robot arm

Capabilities:

```text
move_to
pick
place
set_gripper_force
home
```

Authority dimensions:

```text
object
workspace
force
task
lease lifetime
```

### Rail / conveyor inspection robot

Capabilities:

```text
move_to_station
set_speed
inspect
stop
```

Authority dimensions:

```text
station
route segment
speed
inspection scope
lease lifetime
```

All three must use the same generic lease model.

Do not introduce `RobotLease`, `ArmLease`, or `DroneLease` unless a strong domain-modeling reason emerges.

Prefer `CapabilityLease` with domain-specific capability schemas.

---

## 19. Research Integrity

Kern is both an engineering project and a research artifact.

Do not fabricate benchmarks, latency numbers, success rates, security guarantees, user counts, evaluation results, hardware measurements, or novelty claims.

Until measured, use language such as:

```text
proposed
designed
intended
hypothesis
evaluation target
planned experiment
```

After measurement, use:

```text
implemented
measured
observed
evaluated
```

Never write:

```text
"Kern is the first..."
"Kern solves..."
"Kern guarantees physical safety..."
```

without strong evidence.

---

## 20. Security Language

Preferred wording:

```text
authority enforcement
containment
bounded authority
scoped capability
temporary authority
lease expiry
revocation
replay resistance
execution provenance
```

Avoid overstating:

```text
safe robot
unhackable
guaranteed secure
TOCTOU solved
certified safety
zero-risk
```

Threat-model boundaries must be explicit.

---

## 21. Logging and Observability

Use structured tracing.

Preferred crate:

```text
tracing
```

Events should include stable fields such as:

```text
trace_id
proposal_id
lease_id
subject_id
device_id
capability
decision
policy_ids
expires_at
executor
result
error_code
```

Avoid logs whose only meaning is human-readable prose.

---

## 22. Coding Style

Prefer boring, explicit Rust.

Priorities:

```text
correctness
readability
determinism
testability
observability
performance
cleverness
```

Avoid premature abstraction.

Avoid macro-heavy architecture unless it clearly improves correctness.

Prefer small domain types instead of passing raw strings everywhere.

Example:

```rust
pub struct SubjectId(String);
pub struct DeviceId(String);
pub struct LeaseId(Uuid);
pub struct CapabilityName(String);
```

Use exhaustive enums where the state space is known.

---

## 23. Public API Design

Do not stabilize APIs too early.

Before `v1.0`, optimize for correctness and conceptual clarity.

When designing public APIs:

- use semantic names
- expose authority concepts explicitly
- avoid leaking storage implementation
- avoid leaking transport implementation
- preserve room for future remote issuers and edge enforcers

Do not make ROS 2 concepts part of the core public model.

---

## 24. Configuration

Human-authored configuration may use YAML.

Example:

```yaml
device: cafe_bot_01

capabilities:
  navigate:
    parameters:
      destination:
        type: location
      max_speed:
        type: velocity
```

Policy example:

```yaml
policy: public_delivery

capability: navigate

allow:
  destinations:
    - table_1
    - table_2
    - table_7
    - counter

bounds:
  max_speed: 0.5

deny:
  zones:
    - staff_only
    - storage
```

Values such as `max_speed: 0.5` are external representations. The capability schema declares the unit and normalizes them into the canonical integer form before policy evaluation. See section 4.3.

The `capability: navigate` line above expresses `Selector::Exactly`. A policy's
subject, device, and capability dimensions are selectors, so a configuration
layer may later express `Any` and `AnyOf` explicitly. That syntax is not
designed yet, and no parser work is in scope until a phase requires one.

Configuration must be validated before use.

Invalid configuration should fail early.

Validation and normalization are the same boundary. Nothing unvalidated and nothing denormalized reaches the authority algebra.

---

## 25. CLI Direction

The CLI exists to inspect and exercise the authority model.

Potential commands:

```text
kern validate
kern capabilities
kern policy check
kern lease issue
kern lease inspect
kern lease verify
kern simulate
kern trace show
```

Do not overbuild the CLI before the core model is stable.

---

## 26. Documentation Rules

Every major subsystem should answer:

```text
What problem does this solve?
What does it explicitly not solve?
What are its invariants?
What happens when it fails?
How is it tested?
```

Architecture docs should be written for engineers.

README should remain approachable to new contributors.

Research claims belong in the paper or research docs, not disguised as marketing language.

---

## 27. Pull Request / Change Rules

Every non-trivial change should include:

```text
what changed
why it changed
authority/security implications
tests added or updated
compatibility implications
```

Changes to lease format, signature verification, nonce/replay handling, policy composition, revocation, expiry behavior, trusted computing base, or the executor boundary require extra scrutiny.

When changing any of these, add or update negative tests.

---

## 28. Commit Discipline

Prefer focused commits.

Examples:

```text
feat(core): add capability identifiers
feat(policy): implement monotonic constraint intersection
feat(authority): sign leases with ed25519
feat(enforcer): reject expired leases
test(policy): verify meet-semilattice properties
test(enforcer): reject replayed nonce
docs(threat): define trusted computing base
```

Avoid:

```text
update stuff
fix things
wip
final
```

---

## 29. Performance

Do not optimize before measuring.

Kern is not intended to run inside motor-control frequencies.

Relevant measurements include:

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

Report lease install latency and steady-state enforcement latency as separate numbers. Averaging them into one figure hides the verify-once architecture described in section 4.5.

Report median, p95, and p99 when enough samples exist.

Do not report a single average as the complete latency story.

---

## 30. Experimental Hooks

Design interfaces so experiments can inject:

```text
fake time
network partitions
issuer failure
lease expiry
revocation
replayed leases
malformed requests
capability escalation
parameter escalation
executor acknowledgement loss
adversarial proposal streams
```

This is not test-only convenience.

It is part of making Kern scientifically evaluable.

---

## 31. Definition of Done

A feature is not done because the happy path works.

A feature is done when:

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

For authority-sensitive features, also require:

```text
replay behavior considered
expiry behavior considered
revocation behavior considered
traceability considered
```

---

## 32. Initial Development Checklist

Start here:

```text
[ ] create Cargo workspace
[ ] create kern-core
[ ] define IDs and domain types
[ ] define ActionProposal
[ ] define Capability
[ ] define ConstraintSet
[ ] define PolicyDecision
[ ] implement policy meet operation
[ ] property-test policy algebra
[ ] define CapabilityLease
[ ] inject Clock abstraction
[ ] implement Ed25519 signing
[ ] implement nonce tracking
[ ] implement lease verification
[ ] implement deterministic simulator
[ ] implement ExecutionTrace
[ ] write first end-to-end integration test
[ ] add failure cases
[ ] add CLI only after the core path works
```

The first demonstration should run without ROS, Gazebo, NVIDIA, Nebius, or physical hardware.

### Phase 1 boundary

Phase 1 is deliberately narrow:

```text
SubjectId
DeviceId
CapabilityName
ActionProposal
ConstraintSet
PolicyDecision
ConstraintSet::meet()
property tests for the policy algebra
```

Explicitly out of scope for Phase 1:

```text
cryptography
networking
ROS 2
Gazebo
NVIDIA / Nebius integration
UI
```

The purpose of Phase 1 is to establish the domain vocabulary and the authority ordering before any protocol or robotics integration makes those choices expensive to change.

### Phase 2 boundary

Phase 2 makes the path from a normalized proposal to a decision explicit and testable:

```text
CapabilitySchema
NormalizedActionProposal
CapabilityRegistry
Policy, Selector, PolicySet
deterministic evaluator producing PolicyDecision
```

Explicitly out of scope for Phase 2:

```text
leases, signing, replay protection
enforcer sessions, freshness, revocation, renewal
async runtime, I/O, filesystem, networking
configuration parsing, the YAML/JSON boundary layer
ROS 2, Gazebo, AI integrations, CLI, UI
```

`CapabilityRegistry` and `PolicySet` are in-memory, synchronous, deterministic structures. Ordered collections only. No `tokio`, no async traits, no I/O.

Lease and cryptography work does not begin after Phase 2 without a separate review.

---

## 33. First End-to-End Test

The initial system test should look conceptually like this:

```rust
#[test]
fn cafe_robot_executes_only_with_valid_authority() {
    // 1. Register navigate capability.
    // 2. Define policies.
    // 3. Submit ActionProposal.
    // 4. Evaluate authority.
    // 5. Issue signed lease.
    // 6. Verify lease at edge.
    // 7. Execute in deterministic simulator.
    // 8. Produce ExecutionTrace.
    // 9. Advance time beyond expiry.
    // 10. Verify the same lease can no longer authorize execution.
}
```

Then add separate tests for:

```text
restricted destination
speed escalation
wrong subject
wrong device
invalid signature
expired lease
revoked lease
replay
issuer loss
lost acknowledgement
```

---

## 34. Agent Behavior

When working in this repository, coding agents should:

1. Read this file before proposing architectural changes.
2. Preserve the authority / execution / safety boundary.
3. Prefer a small correct core over broad feature coverage.
4. Write tests before integrating robotics middleware.
5. Challenge any change that increases implicit physical authority.
6. State assumptions explicitly.
7. Never fabricate experimental evidence.
8. Avoid introducing model-provider dependencies into the core.
9. Avoid coupling the authority model to one robot type.
10. Keep security-sensitive behavior deterministic and inspectable.

If a requested feature conflicts with these rules, explain the conflict before implementing it.

---

## 35. Core Principle

When uncertain, return to this rule:

> **Decision capability is not execution authority.**

An AI system may decide what it wants to do.

Kern determines what it is temporarily authorized to cause.

The machine stack determines how the authorized operation is executed.

The functional-safety stack remains responsible for safety-critical physical protection.
