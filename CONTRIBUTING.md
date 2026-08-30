# Contributing to Kern

Kern is both an engineering project and a research artifact. Contributions are
welcome, but the authority model is safety- and security-sensitive, so the bar
for changes to certain areas is higher than usual. **Read [AGENT.md](AGENT.md)
before proposing architectural changes** — it is the authoritative specification
and the contract every contributor (human or AI) works under.

## 1. The boundary

> Agents propose actions. Kern grants bounded authority. Edge executors enforce
> that authority close to the machine.

The authority / execution / safety boundary is the project's core invariant. A
change that increases implicit physical authority, blurs the boundary, or moves
safety responsibility into Kern will be challenged and likely rejected. When in
doubt, return to `AGENT.md` §35: *decision capability is not execution
authority*.

## 2. Before you start

- Read [AGENT.md](AGENT.md), especially the relevant sections for your change.
- Skim [docs/](docs/) for the implemented architecture.
- Check [docs/threat-model.md](docs/threat-model.md) for open problems and trust
  boundaries.

## 3. Build and test

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test  --all-features
cargo build --no-default-features      # the no_std split must stay green
```

The core workspace must build and test without ROS 2, Gazebo, Nav2, or hardware.
Do not introduce a dependency that breaks that. The ROS 2 bridge
(`adapters/nav2-bridge`) is a separate workspace precisely so the core gates stay
runnable everywhere; see its [README](adapters/nav2-bridge/README.md).

## 4. What every non-trivial change includes

Per `AGENT.md` §27, every non-trivial PR should include:

```text
what changed
why it changed
authority/security implications
tests added or updated
compatibility implications
```

## 5. Authority-sensitive changes require extra scrutiny

Changes to any of the following require extra review **and new or updated
negative tests** (`AGENT.md` §12, §27):

```text
lease format
signature verification
nonce / replay handling
policy composition
revocation
expiry behavior
the trusted computing base
the executor boundary
```

Happy-path tests alone are insufficient. Every authority feature has
denial-path tests: invalid signature, wrong issuer/subject/device/capability,
scope mismatch, bound exceeded, expired lease, superseded lease, replayed nonce,
session mismatch, malformed proposal, missing trace.

## 6. Research integrity

Do not fabricate benchmarks, latency numbers, success rates, security guarantees,
evaluation results, or novelty claims (`AGENT.md` §19). Until a property is
measured, describe it as *proposed* / *designed* / *planned*. After measurement,
use *implemented* / *measured* / *observed*. Never write "Kern is the first...",
"Kern solves...", or "Kern guarantees physical safety" without strong evidence.

## 7. Coding style

Boring, explicit Rust. Priorities, in order (`AGENT.md` §22):

```text
correctness, readability, determinism, testability, observability, performance, cleverness
```

Prefer small domain types over raw strings. Use exhaustive enums where the state
space is known. Avoid premature abstraction and macro-heavy architecture.
`kern-core`, `kern-policy`, and `kern-enforcer` are `no_std + alloc` and
`#![forbid(unsafe_code)]` — keep them that way.

## 8. Commit discipline

Focused commits, conventional prefixes (`AGENT.md` §28):

```text
feat(core): add capability identifiers
feat(policy): implement monotonic constraint intersection
test(enforcer): reject replayed nonce
docs(threat): define trusted computing base
```

Avoid `update stuff`, `fix things`, `wip`, `final`.

## 9. Pull requests

Use the PR template. Link the issue. For authority-sensitive changes, call out
the negative tests you added and any compatibility implications (a lease-format
or signing change is a **protocol compatibility change**, not a refactor — it
requires a version bump and new golden vectors; `AGENT.md` §15).

## 10. License

Licensed under the Apache License, Version 2.0 (see [LICENSE](LICENSE) and
[README.md](README.md) §License). Unless you state otherwise, any contribution
intentionally submitted for inclusion is licensed under Apache-2.0, without
additional terms or conditions.