# Security Policy

Kern is an authority layer for AI-controlled physical systems. Its security
properties are the point of the project, so reports about authority bypass,
signature verification, replay, or scope/bound enforcement are taken seriously.

## Scope

In scope:

- Signature verification, canonical encoding, and the signed lease wire format
  (`kern-core::wire`, `kern-enforcer::verify`).
- Replay, supersession, session binding, and freshness at installation
  (`kern-authority::nonce`, `kern-enforcer::store`).
- Policy composition and the authority ordering — monotone composition, the
  empty-applicable-set denial, unbounded-authority prevention
  (`kern-core::constraint_set`, `kern-policy::evaluator`).
- The authority-loss contract and executor boundary — anything that could let an
  adapter receive authority it should not, or keep an operation running after
  authority lapsed (`kern-execution`).
- Parameter-bound enforcement and the speed-limit-before-goal invariant
  (`kern-enforcer::store::enforce`, `kern-execution-nav2::executor`).

Out of scope (but still welcome as hardening suggestions):

- The demo's development signing key (`DEV_SEED = [7u8; 32]`) and the demo
  topology that holds the issuer key in the edge process. These are explicitly
  disclaimed as non-deployment topologies (`AGENT.md` §15, §16; the demo binary
  header). Real deployments use a separate control plane and a real key backend.
- ROS 2, Nav2, Gazebo, or OS-level vulnerabilities. Report those upstream.
- Anything Kern explicitly does not claim to provide: physical safety, certified
  collision avoidance, motor power removal, braking, e-stop, SIL/PL compliance.
  Kern is not a functional-safety system.

## What Kern does not claim

Kern **does not guarantee physical safety**. Correct authority is not safe motion.
A correctly authorized operation can still be physically dangerous. Physical
emergency-stop circuits, safety PLCs, watchdogs, certified controllers, and
low-level safety mechanisms remain outside Kern (`AGENT.md` §2, §20). See
[docs/threat-model.md](docs/threat-model.md) for the trust boundaries and the
open problems that are recorded but not yet resolved (durable nonce state,
revocation latency, single-session freshness beyond the challenge window).

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Please report privately. Include:

- A description of the issue and its impact on authority.
- The component and, if possible, a `file:line` reference.
- A minimal reproduction or proof of concept.
- Any suggested remediation.

A maintainer will acknowledge receipt, assess scope, and coordinate a fix and
disclosure timeline with you. Please give reasonable time for remediation before
any public disclosure.

## Cryptography

Kern uses reviewed libraries (`ed25519-dalek`) and does not invent cryptographic
primitives (`AGENT.md` §15). Verification runs over the raw transmitted bytes,
never a re-encoding, so a decoder bug cannot become a signature bypass. The
`no_std` crates (`kern-core`, `kern-policy`, `kern-enforcer`) are
`#![forbid(unsafe_code)]`. Golden byte and signature vectors pin the wire format
(`crates/kern-authority/tests/golden*.rs`).

## Authority-change review

Changes to lease format, signature verification, nonce/replay handling, policy
composition, revocation, expiry behavior, the trusted computing base, or the
executor boundary require extra scrutiny and new or updated negative tests
(`AGENT.md` §27). A lease-format or signing change is a **protocol compatibility
change**, not a refactor: it requires a version bump and new golden vectors.