# Kern Protocol

**A capability-based authority layer for AI-controlled physical systems.**

Kern sits between probabilistic decision-makers (AI agents, planners, humans) and
physical executors (robotics stacks, PLCs, vendor SDKs). A model being
compromised must not automatically imply that the model has unrestricted
physical authority.

> Agents propose actions. Kern grants bounded authority. Edge executors enforce
> that authority close to the machine.

**Decision capability is not execution authority.** An AI system may decide what
it wants to do. Kern determines what it is temporarily authorized to cause. The
machine stack determines how the authorized operation is executed. The
functional-safety stack remains responsible for safety-critical physical
protection.

## Status

Research artifact and engineering project. **Not a certified functional-safety
mechanism.** Kern does not make a robot physically safe, and never claims to.

The core authority model (proposal → schema → policy → signed lease → edge
enforcement → execution governor) is implemented and tested. A Nav2 + Gazebo
demonstration runs a navigation goal that outlives the capability lease that
authorized it. See [docs/evaluation.md](docs/evaluation.md) for what is
implemented versus planned.

## Repository layout

```text
crates/
  kern-core              domain vocabulary, wire protocol, clocks (no_std + alloc)
  kern-policy            capability registry + policy algebra + evaluator
  kern-authority         lease issuance, Ed25519 signing, nonce/lease-id sources
  kern-enforcer          edge verification + installed-lease store (no_std + alloc)
  kern-execution         execution governor: the authority-loss contract
  kern-execution-nav2    Nav2 executor + deterministic fake backend (ROS-free)

adapters/nav2-bridge     r2r (ROS 2) bridge + the kern-nav2-demo binary
                         (separate workspace; needs a sourced ROS 2 install)

ros2/kern_nav2_demo      Gazebo Harmonic world + Nav2 params + launch

docs/                    architecture documentation
AGENT.md                 the authoritative spec and agent-behavior contract
```

## Build and test (core, no ROS required)

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test  --all-features
cargo build --no-default-features      # exercises the no_std split
```

The core workspace builds and tests on any machine with a Rust toolchain
(1.81+). No ROS 2, Gazebo, Nav2, or hardware required. `kern-core`,
`kern-policy`, and `kern-enforcer` are `no_std + alloc`.

## The Nav2 + Gazebo demo

The ROS 2 bridge is a separate workspace because `r2r` generates bindings from a
sourced ROS 2 installation at build time. It targets **Ubuntu 24.04, ROS 2
Jazzy, Nav2 Jazzy, Gazebo Harmonic**.

```bash
# robot side: Gazebo + Nav2
ros2 launch kern_nav2_demo kern_demo.launch.py

# Kern side, in another shell
cd adapters/nav2-bridge
cargo run --bin kern-nav2-demo -- expiry --ttl-ms 6000 --x-mm 6000
```

Scenarios: `allowed` (lease outlasts the drive), `expiry` (authority lapses
mid-navigation), `supersede` (a newer lease lapses the running one). See
[docs/nav2-integration.md](docs/nav2-integration.md) and
`adapters/nav2-bridge/integration/` for the integration harness.

## Documentation

- [docs/](docs/) — architecture documentation, written for engineers.
- [AGENT.md](AGENT.md) — the authoritative specification and the contract for AI
  coding agents working in this repository. Read it before proposing
  architectural changes.
- [docs/threat-model.md](docs/threat-model.md) — trust boundaries, failure
  semantics, and open problems.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). For security-sensitive authority
changes, also see [SECURITY.md](SECURITY.md) and `AGENT.md` §27.

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)). Unless you
state otherwise, any contribution intentionally submitted for inclusion in this
project shall be licensed under Apache-2.0, without additional terms or
conditions.