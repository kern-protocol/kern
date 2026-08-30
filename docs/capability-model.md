# Capability Model and Policy Algebra

This document covers the authority *algebra*: how an upstream intent becomes a
typed proposal, how a capability schema normalizes it, how constraints compose,
and how policy evaluation turns that into a decision. The signing and lease
machinery built on top of a decision is in
[lease-and-signing.md](lease-and-signing.md).

Types live in `kern-core` (`ids`, `proposal`, `schema`, `constraint`,
`constraint_set`, `decision`) and `kern-policy` (`policy`, `registry`,
`evaluator`).

## 1. Identities

Thin newtypes in `kern-core/src/ids.rs`. They are identifiers, not authority.

```rust
SubjectId        // who proposes; carries no authority
DeviceId         // target device
CapabilityName   // semantic capability name; rejects empty
ParamName        // capability parameter name
Symbol           // opaque, comparable symbolic value
```

`CapabilityName::new` is the only fallible constructor (`InvalidId::Empty`). No
other validation rules are added without a concrete requirement — the crate
explicitly argues against inventing restrictions ahead of need.

## 2. ActionProposal — intent, not authority

```rust
pub enum ParamValue {
    Scalar(i64),
    Symbol(Symbol),
}

pub struct ActionProposal {
    pub actor: SubjectId,
    pub device: DeviceId,
    pub capability: CapabilityName,
    pub params: BTreeMap<ParamName, ParamValue>,
}
```

A proposal has **no implicit authority**. It is not signed, not authorized, and
not named `Command`. `kern-core` operates on normalized, typed `ParamValue`s in
an ordered map — never `serde_json::Value`, never `f64`.

**Naming rule** (`AGENT.md` §4.1): do not call an unauthorized object `Command`.
Prefer `ActionProposal`, `CapabilityRequest`, `ProposedOperation`. Reserve
`Command` for objects that have already passed authority enforcement (e.g.
`SemanticCommand`, which the governor hands an already-authorized adapter).

### Normalization happens before policy

```text
external request
    -> capability-schema validation and normalization
    -> ActionProposal with typed ParamValue arguments
    -> policy evaluation
```

JSON and YAML are boundary and configuration formats. A dynamically typed value
reaching the policy engine would push type decisions into the authority path,
where an unexpected type would have to become an authority answer. That is
refused by construction: `ConstraintSet::evaluate` consumes a
`NormalizedActionProposal`, not an `ActionProposal`.

## 3. Capability and schema

A capability is a semantic operation exposed by a device
(`navigate`, `pick`, `inspect`), not a raw actuation primitive. Raw primitives
(`set_pwm`, `write_register`) are not exposed to AI agents unless explicitly
required — the capability abstraction preserves a semantic authority boundary.

### CapabilitySchema

```rust
pub enum ParamDomain { Scalar, Symbol }
pub enum Requirement { Required, Optional, DefaultTo(ParamValue) }
pub struct ParamSpec { domain, requirement }

pub struct CapabilitySchema {
    name: CapabilityName,
    params: BTreeMap<ParamName, ParamSpec>,
}
```

A schema describes what a semantic operation **means**: parameter names, each
parameter's value domain, whether it is required, and its normalized default if
it has one. A schema answers one question, and never the other:

```text
CapabilitySchema      can this device understand this operation
Policy                may this subject request it
```

A schema carries **capability identity only**. Device identity is never baked
into a schema, so one schema is reusable across every device exposing that
capability. The `(device, capability)` binding belongs to the registry.

`CapabilitySchema::new` rejects duplicate parameters and defaults whose value
does not match the parameter's domain (`SchemaDefinitionError`).
`CapabilitySchema::normalize` validates a proposal against the schema and
produces a `NormalizedActionProposal` with private fields, constructible **only**
through normalization.

**Unknown parameters are always a schema error** (`SchemaError::UnknownParameter`).
There is no allow-unknown escape hatch, and one must not be added until a
concrete capability needs extensible parameters. A parameter no schema declares
is a parameter no policy constrains, and unconstrained input must not reach an
executor.

### Defaults are capability semantics, not policy

A schema default is part of what the operation means. Normalization applies it
**before** any policy evaluation:

```text
absent parameter
    -> schema default inserted during normalization
    -> normalized proposal
    -> policy evaluates the inserted value exactly as if the caller had supplied it
```

A default must never depend on the subject, the applicable policies, runtime
state, or any authority decision. A default that varies with who is asking is an
authority decision wearing a schema's clothes.

### Schema optionality does not bypass policy

Schema optionality and policy authority are separate concepts. A parameter that
is optional in the schema and absent from the proposal is still refused by any
policy constraint on it, because parameter satisfaction fails closed (§5):

```text
schema:     foo is Optional
policy:     foo <= 10
proposal:   foo absent
result:     not permitted under that authority
```

The policy engine never reads "optional in schema" as "this constraint can be
skipped".

### CapabilityRegistry

```text
(device, capability) -> CapabilitySchema
```

`kern-policy::registry::CapabilityRegistry` is a `BTreeMap<(DeviceId, CapabilityName), CapabilitySchema>`.
The registry establishes what a requested operation means; it does not decide
authority. An unknown device or unknown capability fails closed as an error
(`RegistryError::UnknownDevice` / `UnknownCapability`), not as an authority
decision.

Registration derives the capability key from the schema:

```text
register(device, schema)   key = schema.name()
```

rather than taking a separate capability argument. This prevents a registry
entry from claiming `(robot_1, navigate) -> schema(name = pick)`. One source of
truth, enforced by the shape of the API rather than by a validation rule someone
can forget to call.

## 4. ConstraintSet — the authority lattice

`kern-core::constraint_set`. Policies restrict authority; constraints are the
restriction. Typical restrictions: allowed destinations, allowed zones, maximum
velocity, subject/device/capability identity.

### Primitive constraints

```rust
pub struct Interval { lower: i64, upper: i64 }   // closed, never empty
pub enum SymbolSet { Allowed, Denied(BTreeSet<Symbol>) }
pub enum ParamConstraint { Numeric(Interval), Symbolic(SymbolSet) }
```

`Interval::meet` is intersection (`None` if disjoint). `SymbolSet::meet` is
`Allowed ∩ Allowed`, `Denied ∪ Denied` — note the **directional asymmetry**:
allow sets merge by intersection, deny sets merge by union. Both directions
restrict authority. Implementing deny with intersection fails open.

### The lattice

```rust
enum Repr { Unconstrained, Bounded, NoAuthority }  // private
pub struct ConstraintSet { repr: Repr }
```

```text
TOP    = ConstraintSet::unconstrained()   unconstrained authority
          identity for meet, seed for a fold
BOTTOM = ConstraintSet::no_authority()    no authority
          absorbing element, deny
```

`meet` is the greatest lower bound: `meet(A, B)` grants no more authority than
either operand. `meet_all` folds from `TOP`, so `meet_all([]) == TOP` —
mathematically correct and authorization-dangerous (see §6). `from_constraints`
meet-merges duplicate parameter names and collapses a contradiction to `BOTTOM`.

`ConstraintSet` implements `PartialOrd` via a structural decision procedure
(`is_subset_of`); the partial order agrees with `permits` and `meet`.

### Fail-closed parameter satisfaction

`ConstraintSet::permits` defines the operational permitted-set: a parameter
constraint is satisfied only when the normalized proposal **explicitly contains**
that parameter **and** its value satisfies the constraint. A constrained
parameter absent from the proposal is refused. A missing argument is not
evidence that a bound was met.

### Duration is not a generic constraint field

Do not add a generic authority-duration field to `ConstraintSet`. A duration may
be constrained only where it is an explicit semantic parameter of a capability
(`wait(duration_ms)`, `inspect(timeout_ms)`), and then it is an ordinary
parameter bound. Lease TTL and authority lifetime are a different thing entirely
and belong to the lease protocol, not the constraint algebra. Operation lifetime
and authority lifetime remain distinct. See [lease-and-signing.md](lease-and-signing.md)
and [execution-governor.md](execution-governor.md).

### Units and scaling live outside `kern-core`

`kern-core` compares normalized integer scalars. `f64` is deliberately excluded.
The capability schema declares units and converts external representations into
the canonical integer representation before policy evaluation:

```text
0.5 m/s
    -> capability-schema normalization
    -> 500 mm/s
    -> ParamValue::Scalar(500)
```

No generic quantity or unit system exists in `kern-core`. The Nav2 executor
performs the int→float boundary conversion at the adapter edge
(`kern-execution-nav2/src/units.rs`). See [nav2-integration.md](nav2-integration.md).

## 5. Policy and selectors

`kern-policy::policy`. A policy binds selectors to a constraint set. Nothing
more.

```rust
pub struct Policy {
    id: PolicyId,
    subject: Selector<SubjectId>,
    device: Selector<DeviceId>,
    capability: Selector<CapabilityName>,
    constraints: ConstraintSet,
}

pub enum Selector<T> {
    Any,
    Exactly(T),
    AnyOf(BTreeSet<T>),
}
```

`AnyOf` is selector disjunction and cannot be modelled as several policies:
policies compose by `meet`, so two policies naming one subject each would
intersect their constraints rather than cover either subject. No globs, no
regex, no boolean expression trees, no scripting, no Rego. Selectors are
deterministic and explicit.

> **Note:** `AGENT.md` §5 sketches `Policy` with all fields `pub`. The
> implementation keeps fields private with accessors, consistent with the
> non-forgeability philosophy of the evaluator. Behavioral intent matches; the
> representation is encapsulated.

### Applicability

A policy applies to a proposal iff all three selectors match
(subject ∧ device ∧ capability). No precedence. No priority. No first-match.
No deny-overrides. No insertion-order behaviour. Every applicable policy
contributes through `meet`, and only through `meet`.

### Unbounded authority must be intentional

`TOP` is a legitimate authority value and stays representable. An accidental
`TOP` is not. A constraint set with no constraints normalizes to `TOP`, so an
empty or missing `bounds:` block at the configuration boundary would otherwise
become "everything permitted" silently.

```text
Policy::unbounded(...)          intentional, reviewable, greppable
Policy::new(..., constraints)   rejects an empty constraint set
                                -> PolicyError::ImplicitUnboundedAuthority
```

`Selector::any_of` returns `None` on empty input — fail-closed against silent
no-op policies.

## 6. Evaluation

`kern-policy::evaluator`. `Authority` holds a `CapabilityRegistry` and a
`PolicySet`; `Authority::evaluate` resolves the schema, normalizes the proposal,
and decides. `Authority::decide` takes a normalized proposal only — there is no
public path that evaluates an unvalidated `ActionProposal` as though it were
schema-valid.

```text
1. resolve schema                       unknown   -> EvaluationError (Registry)
2. normalize proposal                   invalid   -> EvaluationError (Schema)
3. collect applicable policies          (3-selector conjunction, id order)
4. if applicable is empty               -> Denied
5. effective = meet_all(applicable)
6. if effective is BOTTOM               -> Denied
7. if effective permits the proposal    -> Authorized { constraints }
8. otherwise                            -> NotAuthorizedAsProposed { grantable }
```

**Step 4 is not an optimisation and is not folded into step 5.**
`meet_all([]) == TOP`, so mechanically folding an empty applicable set would
yield unconstrained authority. The evaluator checks emptiness explicitly first.
No generic evaluator that calls `meet_all(applicable)` without handling
emptiness is exposed.

Capability existence is not authority: that a device understands `navigate`
implies nothing about whether a subject may request it.

### PolicyDecision

```rust
pub enum PolicyDecision {
    Authorized { constraints: ConstraintSet },
    NotAuthorizedAsProposed { grantable: ConstraintSet },
    Denied,
}
```

Three distinct outcomes; the middle is never collapsed. If a planner requests
`max_force = 80N` and policy allows `max_force <= 15N`, Kern returns
`NotAuthorizedAsProposed { grantable: <= 15N }` so the planner can replan against
real bounds instead of guessing. The `grantable` constraints are **advisory
output**. They are never executed as a silently modified proposal. Kern reports
what it would authorize; it does not decide what the planner meant.

### An invalid request is not a denial

Two different states that must not collapse:

```text
unknown capability, malformed proposal      EvaluationError (Registry | Schema)
valid proposal, no authority granted        PolicyDecision::Denied
```

A schema error says the request does not describe a real operation. A denial
says the request describes a real operation that this subject may not perform.
Reporting the first as the second hides configuration bugs inside authority
answers.

### Evaluation is non-forgeable

`Evaluation` has private fields and no public constructor; only
`Authority::decide` builds one. Possessing an `Evaluation` is evidence that a
real registry and policy set produced it. `into_parts` is exposed because the
guarantee is about provenance, not secrecy.

## 7. Required algebraic properties

`ConstraintSet::meet` must satisfy (`AGENT.md` §5), enforced with `proptest`:

```text
commutativity     meet(A, B) == meet(B, A)
associativity     meet(meet(A, B), C) == meet(A, meet(B, C))
idempotence       meet(A, A) == A
restriction       meet(A, B) <= A   and   meet(A, B) <= B   (both, asserted independently)
bounds            meet(TOP, A) == A ;  meet(BOTTOM, A) == BOTTOM
contradiction     an unsatisfiable merge collapses to BOTTOM
```

Denial and restriction behaviour get their own dedicated property tests. An
error in the allow path reduces availability; an error in the deny path expands
physical authority. The deny path is the dangerous one.

## 8. What this is not

- Not a planner. Kern reports grantable bounds; the planner replans.
- Not a configuration parser. YAML/JSON parsing and the boundary layer are out
  of scope for the algebra (config syntax is not designed yet, `AGENT.md` §24).
- Not a unit system. Units normalize at the schema boundary.
- Not authority itself. A `PolicyDecision::Authorized` is permission; the
  authority that actually governs a physical operation is the installed lease
  (see [edge-enforcement.md](edge-enforcement.md)).

## 9. How it is tested

- `crates/kern-core/tests/algebra.rs` — meet-semilattice properties.
- `crates/kern-core/tests/schema.rs` — normalization, unknown parameters,
  defaults, domain mismatch.
- `crates/kern-policy/tests/properties.rs` — property-based policy algebra.
- `crates/kern-policy/tests/evaluation.rs` — evaluator paths: empty applicable
  set, BOTTOM, Authorized, NotAuthorizedAsProposed, invalid-request-vs-denial.
- `crates/kern-core/tests/operation_encoding.rs` — canonical operation encoding.
- `proptest` is the preferred property-test tool (`AGENT.md` §5, §12).