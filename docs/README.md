# Kern Protocol — Documentation

This directory documents the **implemented** architecture of the Kern Protocol.
It is written for engineers, against the source in `crates/`, `adapters/`, and
`ros2/`, not against aspirations. Where something is planned but not built, the
text says so.

`AGENT.md` remains the authoritative specification and agent-behavior contract.
These docs describe what the code currently is, how it fits together, and where
it departs from or extends the spec.

## The one-sentence model

Agents propose actions. Kern grants bounded authority. Edge executors enforce
that authority close to the machine. **Decision capability is not execution
authority.**

## Documents

| Document | Subject |
| --- | --- |
| [architecture.md](architecture.md) | System boundary, crate map, end-to-end authority path |
| [capability-model.md](capability-model.md) | `ActionProposal`, capability schemas, normalization, the constraint lattice, policy algebra |
| [lease-and-signing.md](lease-and-signing.md) | `CapabilityLease` representation, issuance, Ed25519 signing, the V1/V2 wire protocol, nonces, enforcer sessions |
| [edge-enforcement.md](edge-enforcement.md) | The edge enforcer: verify-once installation, freshness, the hot path, receipt-vs-authority |
| [execution-governor.md](execution-governor.md) | `kern-execution`: the authority-loss contract, the three orthogonal state axes, observation and reconciliation |
| [nav2-integration.md](nav2-integration.md) | The Nav2 executor, the `r2r` bridge adapter, and the Gazebo demo |
| [ai-proposal-plane.md](ai-proposal-plane.md) | `kern-ai`: untrusted model proposals, the strict parser, provenance, and why model compromise is not authority compromise |
| [adversarial-evaluation.md](adversarial-evaluation.md) | `kern-eval`: the adversarial evaluation harness, scenario format, metrics and their denominators, invariant violations, reproduction |
| [observation-grounding.md](observation-grounding.md) | Trusted physical-state context for the planner: where the pose comes from, why absence is never the origin, and why an observation is not authority |
| [heterogeneous-validation.md](heterogeneous-validation.md) | Three machine classes under one authority architecture: capability-scoped slots, device routing, per-machine policy, cross-device isolation |
| [threat-model.md](threat-model.md) | Trust boundaries, failure semantics, open problems, security language |
| [evaluation.md](evaluation.md) | Implementation status, test inventory, measurement plan |

## How to read this

Start with [architecture.md](architecture.md) for the layering and the
end-to-end path. Each subsystem doc follows the documentation rule from
`AGENT.md` §26: what problem it solves, what it explicitly does not solve, its
invariants, what happens when it fails, and how it is tested.

## Status language

Per `AGENT.md` §19 (Research Integrity), status words are used carefully:

- **implemented** — code exists and is tested.
- **planned** / **designed** — described in `AGENT.md` or here, not yet built.
- **open problem** — a real threat-model or design question recorded but not
  resolved, where no implementation may silently assume an answer away.