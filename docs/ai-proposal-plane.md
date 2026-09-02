# The AI proposal plane

> Kern does not make a model trustworthy.
> Kern makes model trust *insufficient* for physical authority.

Phase 7 puts a language model in front of the authority pipeline and changes
nothing about the pipeline. That is the entire result.

## The path

```text
natural-language instruction
        |
        v
   kern-ai  PlanningRequest        bounded; built from the trusted registry
        |
        v
   ProposalModel                   a provider adapter, a fixture, or an attacker
        |
        v
   RawModelResponse                attacker-controlled bytes, digested
        |
======================= KERN TRUST BOUNDARY =======================
        |
        v
   strict local parser             kern-ai::parse, fail-closed
        |
        v
   ParsedModelProposal
        |
        v
   ActionProposal                  intent; carries no authority
        |
        v
   CapabilityRegistry::resolve     trusted configuration decides meaning
   CapabilitySchema::normalize
        |
        v
   NormalizedActionProposal
        |
        v
   Authority::decide
       /                \
  DENIED              AUTHORIZED
      |                    |
      |                    v
      |            AuthorizedOperation
      |                    v
      |            EnforcerStore::mint_challenge
      |                    v
      |            LeaseIssuer::issue_v2
      |                    v
      |            EnforcerStore::install  ->  LeaseHandle
      |                    v
      |            ExecutionGovernor::prepare
      |                    v
      |            PreparedExecution::submit
      |                    v
      |            Nav2Executor -> ROS 2 -> Gazebo
      |
      +---- no challenge, no lease, no ExecutionId, no executor call
```

## What the model may and may not do

The model proposes intent, one capability, semantic parameters, and an
explanation.

It cannot mint a lease, sign anything, modify policy, install authority, choose
a TTL, an issuer, a key, a nonce, a challenge, an enforcer session, or any Kern
identifier, construct an `AuthorizedOperation`, a `SignedLease`, a `LeaseHandle`
or a `SemanticCommand`, skip normalization or evaluation, or reach an executor,
Nav2, or ROS.

None of that is a runtime rule. It is the shape of the types:

```rust
pub trait ProposalModel {
    fn propose(&mut self, request: &PlanningRequest) -> ModelOutcome;
    fn identity(&self) -> ModelIdentity;
}
```

`PlanningRequest` carries an instruction, a semantic context, a vocabulary built
from the registry, and the actor and device the *host* chose. `ModelOutcome` is
bytes or a failure. There is no parameter through which a model could receive a
key or a handle, and no return path through which it could hand back anything
the authority crates would accept. Every forbidden artifact is reachable only
through a constructor in another crate that consumes something a model cannot
produce — most of them ultimately consume a `kern_policy::Evaluation`, which has
private fields and one builder.

## Parsing is not authorization

Four separate questions, four separate answers, four separate places:

| question | answered by | a success means |
|---|---|---|
| are these bytes a well-formed proposal? | `kern_ai::parse_response` | syntax only |
| does this operation exist? | `CapabilityRegistry::resolve` | the device understands it |
| is the request well-formed for it? | `CapabilitySchema::normalize` | shape and domains |
| may this subject perform it? | `Authority::decide` | authority |

There is deliberately no `authorize_model_response()` helper. A single call that
hid schema, policy, authorization, freshness, installation, and execution would
be shorter to write and much harder to review, and every transition it hid is
one somebody needs to be able to watch happening.

## The response contract

```json
{
  "capability": "navigate",
  "arguments": {
    "destination_x_mm": 6000,
    "destination_y_mm": 0,
    "yaw_mdeg": 0,
    "max_speed_mm_s": 300
  },
  "reason": "Move to station B"
}
```

Exactly three keys, all required, no fourth. `"capability": "no_action"` with
empty arguments is the way to propose nothing. Zero or one proposal, never more.

Refused, always: malformed JSON, duplicate keys, unknown top-level keys, missing
keys, non-integer argument values (a float, an exponent form, a numeric string,
a boolean, an array), values outside `i64`, arrays where objects belong,
trailing bytes after the document, prose around it, more than one fenced block,
and any argument named `ttl`, `issuer`, `key_id`, `nonce`, `challenge`,
`enforcer_session`, `lease_id`, `policy_id`, or `execution_id`.

Exactly one deterministic unwrapping is performed: a single leading ` ```json `
or ` ``` ` line with a matching trailing fence around the whole document. There
is no scanning for the first `{`, no brace balancing, and no "largest
JSON-looking substring". Each of those turns a response the model did not mean
into a proposal Kern acts on.

## Frozen resource bounds

| bound | value |
|---|---|
| instruction | 4 096 B |
| robot context | 4 096 B |
| model response | 16 384 B |
| capability name | 64 B |
| argument name | 64 B |
| reason | 512 B |
| arguments per proposal | 16 |
| JSON depth | 8 |
| JSON object members | 64 |
| JSON array elements | 64 |
| JSON string | 8 192 B |
| proposals per response | 1 |
| replans per instruction | 1 |

They are constants, not configuration. A bound a deployment can raise is a bound
an attacker can argue about.

## Structured output is not trusted output

The adapter can ask a gateway for `{"type":"json_object"}` or a JSON schema
where the gateway supports it for the model in use. Kern parses the response
identically either way. Provider-side enforcement makes a well-behaved model
more likely to emit parseable output; it is not evidence about a model that is
not well-behaved, and it is no evidence at all about a response that did not
come from the provider Kern thinks it did.

## Provider failure is not a denial

```text
Unavailable        the gateway was not there
Timeout            the local deadline passed
TransportUnknown   the transport ended ambiguously
ProviderRejected   the gateway definitively refused — usually a config fault
```

No variant becomes a `PolicyDecision`, an authorization, or an execution
failure. No model response means: no proposal, no authorization, no lease, no
physical execution. One attempt per instruction; no automatic retry.

## Prompt injection

Kern does not detect prompt injection and does not try to.

```text
malicious instruction or context
  -> the model may well obey the attacker
  -> the model proposes something unauthorized
  -> strict parser / registry / schema
  -> deterministic Kern policy
  -> DENIED
  -> no authority, no execution
```

So: **Kern does not prevent prompt injection. Kern contains the physical
authority consequences of unauthorized model proposals.** Kern never has to
decide whether a model is compromised before enforcing authority boundaries on
what it proposes.

## Model identity is provenance, never authority

A `ModelIdentity` records which provider and model answered. Nothing that
decides authority reads it. Two identical normalized proposals are evaluated
identically whether one came from a hosted model and the other from a fixture
written to attack it — `crates/kern-ai/tests/containment.rs` asserts exactly
that, for both the denied and the authorized case.

## Provenance

```text
ProposalId  ->  AuthorityArtifactId  ->  ExecutionId
```

Three unrelated types. A `ProposalId` carries no authority, converts to nothing,
and permits nothing. A `ProposalRecord` records each stage in order and refuses
out-of-order or repeated writes, so it cannot claim an artifact for a proposal
policy never authorized — the one lie the provenance model would otherwise be
able to tell that the rest of the system cannot.

## Bounded replan

At most one, and only when policy reported grantable bounds
(`NotAuthorizedAsProposed`). The feedback is rendered from the evaluator's own
output and is advisory: proposal B gets a new `ProposalId`, a new invocation, and
a fresh evaluation. Proposal A is never mutated and its identifier is never
reused. An outright `Denied` names no grantable bounds, so it offers nothing to
replan against and the replan is refused rather than run against silence. There
is no "retry until policy allows".

## Layers, and what runs where

| layer | what | needs |
|---|---|---|
| 1 | raw bytes -> strict parser | nothing |
| 2 | parsed -> `ActionProposal` -> normalization | nothing |
| 3 | normalized -> `PolicyEvaluator` | nothing |
| 4 | fake and malicious models through the whole pipeline | nothing |
| 5 | a live gateway -> a live model | a reachable gateway |
| 6 | live model -> Kern -> Nav2 -> Gazebo | a gateway, ROS, a simulator |

Layers 1–4 are deterministic and offline, and are what `cargo test` runs. No
ordinary test run touches the network, a credential, ROS, or a simulator.

Layers 5 and 6 were run live for Phase 7 acceptance against Ollama serving
`gpt-oss:120b` over `POST /v1/chat/completions` — originally through a local
daemon, and now by default through Ollama Cloud on an API key, which is the
same request to a different host. The provider is
recorded because provenance records it, not because anything decided differently
on account of it: the same bytes from any other provider produce the same
decision.

## Grounding the planner in the machine's own state

A `PlanningRequest` may carry a `WorldObservation`: the device, and either a
pose in Kern's integer units with the age of the reading, or an explicit reason
there is none. It is rendered into the system message, it is read by nothing
downstream of the prompt, and it is not an input to any policy decision.

It exists because a hand-written sentence stating the robot's position went
stale the moment the robot moved, and a model that believed it answered
`no_action` to a perfectly reasonable instruction. See
[observation grounding](observation-grounding.md) for the failure, the fix, and
what the observation does and does not claim.
