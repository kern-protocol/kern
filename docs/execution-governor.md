# Execution Governor (`kern-execution`)

`kern-execution` is the authority-loss contract layer between the edge enforcer
and the executor adapter. It is **not** in the `AGENT.md` §8 target structure;
it was added because refusing to forward *new* operations is not enough when an
operation is *already running*. Once `navigate(table_7)` has been accepted by
Nav2, expiry of the lease does not undo the accepted command. Kern must define
an explicit authority-loss contract with the executor.

This document covers what the governor is, the three orthogonal state axes, the
prepare/submit/tick lifecycle, observation and reconciliation, and provenance.

## 1. What problem it solves

The enforcer answers "is authority currently live?" The governor answers "given
live authority, how does a physical operation get submitted exactly once, how is
its authority re-checked while it runs, what happens to it when authority lapses,
and how is the outcome observed and recorded honestly?"

It is the bridge between *current authority* and *a running physical operation*.

## 2. What it explicitly does not solve

- It is not a runtime, scheduler, or timer. `tick` is pull-based; there is no
  thread and no internal clock. The caller drives it.
- It is not a safety system. It cannot guarantee motor removal, braking, e-stop,
  or any SIL/PL rating.
- It does not decide policy or mint authority. It receives an installed
  `LeaseHandle` and an `AuthorizedOperation`.
- It does not claim the machine stops when authority lapses. It requests
  termination of the *governed operation*; the physical response is the
  executor's and the safety architecture's responsibility.

The crate-level doc states the honest position plainly: Kern stops granting
authority, forwards commands, requests cancellation, observes, and records. It
cannot guarantee motor removal, braking, e-stop, or SIL/PL. **Correct authority
is not safe motion.**

## 3. Three orthogonal state axes

This is the central design idea. Authority lapse, execution state, and
cancellation are **three independent dimensions**. A fused enum would make
"authority lapsed" read as "execution stopped" — it does not.

```text
AuthorityState      Kern's position on authority. Always locally decidable.
                    Current | Lapsed { reason, at }
                    reason: LeaseExpired | Superseded | AuthorityMissing | ClockUntrusted
                    monotonic: once Lapsed, never returns to Current.

ExecutionState      Kern's belief about the machine. Sometimes unknown.
                    Prepared | NotStarted | Submitted | Running
                    | Completed | Failed | Cancelled
                    | Disputed { first, conflicting } | Unknown { phase, last_known }

CancellationState   Kern's cancellation request + the adapter's reply.
                    NotRequested | Requested | RequestAccepted | Confirmed
                    | Refused | RequestUnknown | Moot
```

An honest snapshot of a mid-flight authority lapse reads:

```text
execution: Running, authority: Lapsed(LeaseExpired), cancellation: Requested
```

There is deliberately **no "machine stopped" state**. Cancellation-requested is
not cancellation-confirmed, and cancellation-confirmed is not physical-stop.
Physical stop has no representation in Kern, by design.

## 4. The `Executor` trait and what the adapter sees

```rust
pub trait Executor {
    fn declaration(&self) -> &ExecutorDeclaration;
    fn submit(&mut self, command: SemanticCommand) -> SubmitOutcome<OperationId>;
    fn on_authority_lapse(&mut self, op: OperationId, action: LapseAction)
        -> CancelRequestOutcome;
}

pub trait ExecutorObservations { fn poll_observation(&mut self) -> ObservationPoll<OperationId>; }
pub trait ExecutorQuery        { fn query(&mut self, op: OperationId, ...) -> QueryOutcome<OperationId>; }
pub trait ExecutorReconcile    { fn reconcile_active_operations(&mut self) -> ReconcileOutcome<OperationId>; }
```

> **Spec note:** `AGENT.md` §17 sketches an `async execute(&lease, operation)
> -> Result<ExecutionResult, ExecutorError>`. The implemented trait is
> **synchronous** and returns `SubmitOutcome` / `ObservationPoll` /
> `CancelRequestOutcome` rather than a single `Result`. No `&CapabilityLease` or
> `AuthorizedOperation` crosses into the adapter — the governor consumes both
> and passes a `SemanticCommand`. The backend methods take no `Result`:
> uncertainty is classified by the backend into `Rejected` / `Unknown`, not
> propagated as an error. This is a refinement of §17, not a violation, and the
> spec explicitly allows the interface to evolve.

### `SemanticCommand` — what the adapter actually receives

```rust
pub struct SemanticCommand<'a> { /* crate-private constructor */ }
// exposes: execution_id, subject, device, capability, params
// exposes NOT: handle, lease, constraints, artifact
```

`SemanticCommand` exposes no handle, lease, constraint set, or artifact. The
adapter decides no policy, mints no authority, and receives already-authorized
semantics. `CommandDigest` is `SHA-256(COMMAND_DOMAIN_V1 || canonical operation
encoding)` — a stable identity for the command, not a second command channel.

### Outcomes

```text
SubmitOutcome<O>         Accepted { operation } | Rejected { reason } | Unknown
                          (Rejected only ever carries a proven reason)
CancelRequestOutcome     Accepted | AlreadyTerminal | Rejected | Unsupported | Unknown
ObservedReport           Running | Completed | Failed(FailureClass) | Cancelled
                          FailureClass: OperationFailed | AbortedByExecutor
ObservationPoll<O>       Observation | Idle | Disconnected
                          (Disconnected is distinct from Idle)
LapseAction              Cancel | Hold | Terminate | NoFurtherCommands
```

### `ExecutorDeclaration` — wiring-time contract

The adapter declares its capabilities up front so the governor can refuse an
adapter that cannot honour the configured lapse action **at wiring time**, not
at lapse time: `lapse_actions`, `accept_implies_running`, `confirms_cancellation`,
`reports_terminal_results`, `echoes_execution_id`, `ordering`
(Sequenced / Unordered). The Nav2 executor declares `accept_implies_running =
false` (goal acceptance is not motion), `echoes_execution_id = false` (Nav2
mints its own UUIDs), `ordering = Sequenced`.

## 5. The lifecycle: prepare -> submit -> tick

### prepare

```rust
governor.prepare(&store, &handle, &operation) -> PreparedExecution
```

`enforce` (liveness + bindings + constraints) -> reserve a record slot ->
compute `CommandDigest` -> mint `ExecutionId` -> write an `ExecutionRecord`.
**Nothing is sent.** `PreparedExecution` borrows the governor `&mut` and the
store; it is *not* an authority reservation.

### submit

```rust
prepared.submit(&store, &mut adapter) -> SubmitReceipt
```

Session compare -> `check_authority` (liveness). If authority is lost **here**:
`NotStarted(AuthorityLost)`, and the **adapter is not called**. Otherwise
`adapter.submit(SemanticCommand)` is invoked **exactly once** per `ExecutionId`,
and the outcome is applied. There is no `Result` return: once `submit` exists,
nothing can fail before the adapter runs, and the adapter's own uncertainty is
carried in `SubmitOutcome`, not an error.

### Drop

`Drop for PreparedExecution` records an unsubmitted prepared execution as
`NotStarted(Abandoned)` and touches no store and no executor. Provenance is
honest even about abandonment.

### tick / tick_observed

```rust
governor.tick(&store, &mut adapter) -> TickReport
governor.tick_observed(&store, &mut adapter) -> TickReport
```

Pull-based; no timer, no thread. Each tick runs an `authority_pass` and a
`lapse_pass` (and, for `tick_observed`, a bounded `observation_pass`).

- **`authority_pass`**: for every active record, `check_authority`. A lapsed
  authority marks the record. A session mismatch lapses every active execution
  as `AuthorityMissing` — the truth.
- **`lapse_pass`**: marks `lapse_handled` **before** calling the adapter, so the
  invariant "one lapse instruction per execution" holds even if the adapter
  misbehaves. Then `adapter.on_authority_lapse(op, LapseAction)`. An operation
  with no recorded identity (a lost submission) is recorded honestly as
  `LapseNotRequestedNoOperation` — Kern does not invent an operation to cancel.
- **`observation_pass`**: drains adapter observations, bounded by
  `observation_budget`. Applies each to the matching record.

## 6. Disconnection and the Unknown state

Lost knowledge is not evidence of failure. When the link to the adapter is
broken (`mark_disconnected`), active executions move to `Unknown { phase: Result,
last_known }` — **never** `Failed`. A contradictory pair of terminal results
moves a record to `Disputed { first, conflicting }`.

`Unknown` is quiescent, not terminal. It is exited only by reconciliation or a
later observation. `Failed` is reserved for evidence that the operation itself
failed (`OperationFailed`) or was aborted by the executor (`AbortedByExecutor`),
not for transport loss.

## 7. Recovery: query and reconcile

- **`query_unknown`** — recovery for an `Unknown { Result }` record that still
  holds its operation id. Asks the adapter directly.
- **`reconcile`** — enumerates the adapter's active operations. A result that
  **echoes** an `ExecutionId` rebinds a lost submission to its record. An
  unattributed operation gets **no record** — invented provenance is worse than
  none. Per `StartupPolicy`, unattributed operations either lapse
  (`LapseDiscovered`) or are reported only (`ReportOnly`).
- **`resolve_dispute`** — the only exit from `Disputed`. The resolution is
  **attributed** (it names which terminal observation is taken), never
  auto-chosen. A disputed state is never silently resolved.

## 8. Provenance: records and journal

```text
ExecutionRecord<O>    fixed-size; the LeaseHandle stored once (no drift);
                       stores CommandDigest, not params
Transition journal    bounded; fixed-size Copy transitions; no payload
```

The record holds the handle, command digest, authority state, execution state,
cancellation state, and timing. The journal is a ring of `Transition`s
(`subject: Execution(id) | Adapter`, `at`, `kind`) covering the full lifecycle:
prepared -> submitted -> running -> terminal, plus lapse, dispute, reconcile,
and link-state transitions. Transitions are **returned data**, not callbacks —
no host code runs inside a transition, so a transition cannot widen authority.

This is the `AGENT.md` §4.6 execution trace: every mediated physical effect is
traceable to the authority that permitted it. The trace answers who proposed,
which device/capability, which policies applied, which lease permitted
execution, what bounds were active, which executor handled it, and what was
observed. Kern does not store or depend on private model chain-of-thought; it
stores structured decisions and execution metadata.

## 9. Invariants

- **Govern error => executor never invoked.** `GovernError` (`Authorization` /
  `CapacityExhausted` / `IdentifierExhausted` / `SessionMismatch` /
  `CommandEncoding`) means the adapter was not called.
- **One lapse instruction per execution.** `lapse_handled` is set before the
  adapter call.
- **One submit per `ExecutionId`.** The adapter is driven exactly once.
- **Authority-lapsed != machine-stopped.** Three orthogonal axes.
- **Lost knowledge != failure.** Disconnection => `Unknown`, never `Failed`.
- **Disputed => attributed resolution only.** Never auto-chosen.
- **Unattributed operations get no record.** Invented provenance is worse than
  none.
- **`SemanticCommand` leaks no authority.** No handle/lease/constraints/artifact.

## 10. How it is tested

- `crates/kern-execution/tests/submission.rs` — prepare/submit, authority lost
  before submit (`NotStarted(AuthorityLost)`, adapter not called), abandonment
  on drop.
- `crates/kern-execution/tests/lapse.rs` — authority lapse, one-instruction
  invariant, lapse with no operation, session mismatch lapses all.
- `crates/kern-execution/tests/observation.rs` — running/completed/failed/
  cancelled, sequenced drops, unmatched observations, terminal contradiction ->
  `Disputed`.
- `crates/kern-execution/tests/reconcile.rs` — echoed-id rebinding,
  unattributed operations, `StartupPolicy` behaviour.
- `crates/kern-execution/tests/vocabulary.rs` — state enum coverage.
- The crate is deliberately tested with a fake executor so no ROS dependency is
  needed; the Nav2 fake backend exercises the same contract
  ([nav2-integration.md](nav2-integration.md)).