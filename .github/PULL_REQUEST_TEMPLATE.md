<!-- Thank you. Read AGENT.md and CONTRIBUTING.md before submitting. -->

## What changed

<!-- A short description of the change. -->

## Why it changed

<!-- The reason. If this fixes an issue, link it: "Closes #123". -->

## Authority / security implications

<!-- Every non-trivial change should state these (AGENT.md §27).
     If this touches any of the list below, call it out explicitly and add
     negative tests:
       lease format, signature verification, nonce/replay handling,
       policy composition, revocation, expiry behavior,
       trusted computing base, executor boundary -->

## Tests added or updated

<!-- What tests cover this change? For authority-sensitive changes, list the
     negative (denial-path) tests added. -->

## Compatibility implications

<!-- A lease-format, signing, or wire change is a protocol compatibility change,
     not a refactor: it needs a version bump and new golden vectors (AGENT.md §15). -->

## Checklist

- [ ] Read the relevant sections of `AGENT.md`
- [ ] `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`,
      `cargo test --all-features`, `cargo build --no-default-features` all green
- [ ] No new ROS / robotics dependency drifted into the core (`kern-core`,
      `kern-policy`, `kern-enforcer`, `kern-execution`)
- [ ] No fabricated benchmarks, latency numbers, or safety claims (AGENT.md §19)
- [ ] Docs updated where the boundary changed