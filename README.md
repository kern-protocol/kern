# Kern Protocol

**A capability-based authority layer for AI-controlled physical systems.**

[![ci](https://github.com/Kern-Protocol/kern/actions/workflows/ci.yml/badge.svg)](https://github.com/Kern-Protocol/kern/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![rust](https://img.shields.io/badge/rust-1.81%2B-orange.svg)](https://www.rust-lang.org)

Kern sits between probabilistic decision-makers — AI agents, planners, humans —
and physical executors: robotics stacks, PLCs, vendor SDKs.

> Agents propose actions. Kern grants bounded authority. Edge executors enforce
> that authority close to the machine.

A model being compromised must not automatically imply that the model has
unrestricted physical authority.

---

## The problem this exists for

An agent asks a robot to drive to the lobby. It is allowed to. The robot starts
moving. Thirty seconds later the authority that permitted it expires — the shift
ended, the lease ran out, a narrower policy took effect.

Refusing the *next* command is not enough. Something is already moving.

Most systems have no answer here, because they conflate two questions that are
not the same question:

```text
"is this allowed?"          asked once, at the start
"is this still allowed?"    asked continuously, while a machine is in motion
```

Kern answers the second one, and is precise about what an answer is worth. When
authority ends mid-operation, Kern marks the lapse, refuses further commands
under it, asks the executor to cancel, and records exactly what came back —
without ever claiming the machine stopped.

## See it in 30 seconds

No ROS, no robot, no simulator. Just Rust:

```bash
cargo run -p kern-execution-nav2 --example demo -- expiry
```

```text
[t5 AUTHORITY LAPSED, t6 CANCELLATION REQUESTED]
exec 00001 navigate(4.000 m, 1.200 m, yaw 90.0°, <= 300 mm/s)
  lease 000000000000000000000000000000ab
  authority: LAPSED — LeaseExpired
  execution: Running
  cancellation: REQUEST ACCEPTED (received)
  note: authority is gone; the operation is still running.
        Kern asked Nav2 to cancel. Kern does not claim the robot stopped.
```

That middle frame is the whole point. **Authority: LAPSED. Execution: Running.**
Two facts, both true, held apart on purpose.

Other scenarios: `allowed`, `supersede`, `disconnect`.

## What Kern keeps apart

Every line below is a distinction that systems routinely collapse, and every
collapse is a lie about a physical machine:

| this | is not | this |
|---|---|---|
| authorization | ≠ | execution |
| a command accepted by an executor | ≠ | a physical effect completed |
| authority lapsed | ≠ | the machine stopped |
| cancellation requested | ≠ | cancellation confirmed |
| cancellation confirmed | ≠ | physical stop |
| a lost connection | ≠ | a failed operation |

The last row has no representation in the codebase at all, because Kern can
never establish it. There is no state named `Safe`, and there never will be.

## What Kern guarantees, and what it refuses to claim

**When authority lapses, Kern guarantees:**

- The lapse is recorded, with a typed reason and a monotonic timestamp.
- No further operation is authorized under that authority — structurally, not by
  convention.
- The configured lapse instruction reaches the executor exactly once per
  execution, for every operation Kern holds an identity for.
- Whatever the executor answers is recorded verbatim: accepted, already
  terminal, rejected, unsupported, or unknown.
- An adapter cannot silently downgrade that instruction to a no-op. An adapter
  that does not *declare* the capability is refused at construction.

**Kern does not guarantee, and never claims:**

- that the machine stopped, at any point, for any reason;
- motor power removal, braking distance, or safe torque off;
- certified emergency stop, collision avoidance, SIL or PL compliance;
- any bound on physical response time.

Those belong to lower-level controllers and functional-safety systems. **Correct
authority is not safe motion.** A green test run does not make Kern a
functional-safety mechanism.

## Evidence, not assertions

From the Gazebo Harmonic + Nav2 acceptance run
([docs/evaluation.md](docs/evaluation.md)):

| claim | how it was verified |
|---|---|
| the authorized speed bound reaches the controller | commanded `/cmd_vel` maximum was **0.1500 m/s** and **0.3500 m/s** for bounds of 150 and 350 mm/s, over 1906 and 829 samples |
| expiry mid-navigation cancels exactly once | lease expired while `/cmd_vel` still commanded 0.300 m/s; `Cancelled` appeared only from Nav2's `CANCELED` result, never from the acknowledgement |
| a lost link is not a failure | the Nav2 container was killed mid-goal; the execution became `Unknown{Result}`, and **the robot kept driving at 0.300 m/s for 90 seconds** while Kern recorded that it no longer knew |
| simulation time is not authority time | Gazebo was paused, `/clock` froze, and the lease expired on schedule against monotonic uptime |
| a superseding lease adopts nothing | the old execution lapsed as `Superseded` and kept naming its own lease |

The third row is the one worth staring at. Kern said "I don't know", the machine
kept moving, and both were correct.

## How it works

```text
ActionProposal            what an agent wants        carries no authority
  ↓ capability schema     typed, normalized, integer units only
  ↓ policy algebra        a bounded meet-semilattice; composition only narrows
PolicyDecision
  ↓ issuer                Ed25519, challenge-bound, nonce-ordered
signed CapabilityLease    scoped, time-limited, replay-resistant
  ↓ edge enforcer         verification once; the hot path is comparisons only
LeaseHandle               a receipt, not a credential — proves nothing alone
  ↓ execution governor    prepare → submit-time liveness re-check → executor
ExecutionRecord           authority / execution / cancellation, held apart
```

Two structural choices carry most of the weight:

- **A preparation is not a reservation.** `prepare` authorizes; `submit`
  re-checks liveness immediately before invoking the executor, and refuses
  without invoking anything if authority died in between. The submitting method
  returns no `Result`, so a post-invocation failure has nowhere to be
  misreported as "nothing happened".
- **Uncertainty is a first-class state.** `Unknown` is never resolved by a
  timeout, only by evidence. No physical operation is ever retried — there is no
  retry path in the crate to begin with.

## Repository layout

```text
crates/
  kern-core              domain vocabulary, wire protocol, clocks   (no_std + alloc)
  kern-policy            capability registry, policy algebra, evaluator
  kern-authority         lease issuance, Ed25519 signing, nonce and id sources
  kern-enforcer          edge verification, installed-lease store   (no_std + alloc)
  kern-execution         execution governor: the authority-loss contract
  kern-execution-nav2    Nav2 executor over a backend seam          (ROS-free)

adapters/nav2-bridge     r2r ROS 2 bridge + the kern-nav2-demo binary
                         (separate workspace; needs a sourced ROS 2 install)

ros2/kern_nav2_demo      Gazebo Harmonic world, Nav2 params, launch, validation

docs/                    architecture, threat model, evaluation
AGENT.md                 the authoritative spec and agent-behaviour contract
```

## Build and test

The core workspace needs nothing but a Rust toolchain (1.81+). No ROS, no
Gazebo, no hardware:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features                 # 306 tests
cargo build --no-default-features         # exercises the no_std split
```

`kern-core`, `kern-policy`, `kern-enforcer`, and `kern-execution` are
`no_std + alloc`, because the enforcer is meant to run close to the machine.

## The Nav2 + Gazebo demonstration

Targets **Ubuntu 24.04 · ROS 2 Jazzy · Nav2 · Gazebo Harmonic**. The ROS bridge
is a separate workspace: `r2r` generates its bindings from a sourced ROS
installation at build time, and keeping it outside means the gates above stay
runnable on any machine.

```bash
# robot side: world, robot, Nav2
ros2 launch kern_nav2_demo kern_demo.launch.py

# Kern side, in another shell
cd adapters/nav2-bridge
cargo run --bin kern-nav2-demo -- expiry --ttl-ms 6000 --x-mm 6000
```

Scenarios: `allowed`, `expiry`, `supersede`. The full acceptance harness,
including fault injection, lives in `ros2/kern_nav2_demo/validation/`, and a
ROS-only integration layer that needs no simulator lives in
`adapters/nav2-bridge/integration/`.

## Status

A research artifact and an engineering project, developed in explicit phases.

**Implemented and tested:** the domain algebra, policy composition, lease
issuance and signing, edge verification with challenge-bound freshness, the
execution governor and its authority-lapse contract, and a Nav2 adapter proven
end to end against Gazebo Harmonic.

**Deliberately not implemented yet:** lease renewal, revocation, persistence
across restarts, multi-enforcer coordination, and any model or cloud
integration. Each is a design decision with consequences, not an oversight —
[docs/evaluation.md](docs/evaluation.md) says which and why.

**Known limitation, stated plainly:** there is no persistence. If the Kern
process restarts while an executor is still running a command, the record is
gone; reconciliation can surface such an operation as unattributed, but cannot
restore its provenance.

## Documentation

- [docs/](docs/) — architecture, written for engineers.
- [docs/threat-model.md](docs/threat-model.md) — trust boundaries, failure
  semantics, open problems.
- [docs/evaluation.md](docs/evaluation.md) — what is implemented, what is
  verified, and how.
- [AGENT.md](AGENT.md) — the authoritative specification, and the contract for
  AI coding agents working in this repository. Read it before proposing
  architectural changes.

## Contributing

Contributions are welcome, and authority-affecting changes are held to a higher
bar than the rest: negative paths tested, failure semantics stated, and no claim
in a doc or a log line that the code cannot support. See
[CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and AGENT.md
§27.

If you find a place where Kern claims more than it can prove, that is a bug
report we want.

## License

Apache License 2.0 ([LICENSE](LICENSE)). Unless you state otherwise, any
contribution intentionally submitted for inclusion shall be licensed
Apache-2.0, without additional terms or conditions.
