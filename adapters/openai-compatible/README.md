# kern-model-openai-compatible

An OpenAI-compatible chat-completions adapter for the Kern proposal plane.

```text
kern-ai  --ProposalModel-->  this crate  --HTTPS-->  gateway  -->  model
```

It implements exactly one trait method, takes a bounded planning request, and
returns bytes or a failure. It holds no key material Kern owns, no challenge, no
lease, no handle, and no executor. **The bytes it returns are untrusted in
full**, and are parsed by `kern-ai`'s strict local parser before anything else
looks at them.

## Why it is outside the workspace

It carries an HTTP client and a TLS stack. Neither belongs in the build graph of
the crates that decide authority, so this crate is excluded from the workspace
exactly as `adapters/nav2-bridge` is, and is built and gated from here.

## Providers

| profile | base URL | key variable |
|---|---|---|
| `ollama-cloud` *(default)* | `https://ollama.com/v1` | `OLLAMA_API_KEY` |
| `ollama` | `http://localhost:11434/v1` | none — a local daemon needs no bearer |
| `nebius` | `https://api.tokenfactory.nebius.com/v1` | `NEBIUS_API_KEY` |
| `nebius-us-central1` | `https://api.tokenfactory.us-central1.nebius.com/v1` | `NEBIUS_API_KEY` |
| `nebius-eu-west1` | `https://api.tokenfactory.eu-west1.nebius.com/v1` | `NEBIUS_API_KEY` |
| `custom` | `KERN_MODEL_BASE_URL` | `KERN_MODEL_API_KEY` |

Several providers behind one type is not a weakening. A provider is an inference
vendor with no authority role, so which one answered changes nothing above the
trust boundary — that is precisely the property Phase 7 exists to demonstrate.

`ollama-cloud` is the default because inference has no business being tied to
the machine running the simulator. It runs in Ollama's account on an API key,
so a laptop or a VM with a software GL stack and no GPU can still put a large
model in front of the robot. `ollama`, the local daemon, remains available and
unchanged; the two names never swap meaning, because a name that quietly
changed which host answered would quietly change where a key is sent.

A local `ollama serve` daemon may hold its own cloud credentials and proxy
`:cloud` models. Kern never sees them, and the bytes that come back are exactly
as untrusted as any other model's. When a profile needs no bearer, the adapter
sends no `Authorization` header at all rather than a placeholder.

### The base URL travels with the key

`KERN_MODEL_BASE_URL` overrides a profile's base URL, and for a profile that
sends a bearer it is checked before anything is dialled: a plaintext `http://`
URL naming anything other than the loopback interface is refused, because it
would put the credential on the wire in the clear. The mistake this catches is
an ordinary one — a working local-daemon setup switched to a cloud provider with
the old base URL left behind — and the refusal names the variable without ever
printing the URL or the key. For `ollama-cloud`, leave it unset.

## Verify before you configure

There is no default model identifier and there will not be one. A name compiled
into this crate would be a claim about what an account can call, which this
crate cannot know.

```bash
cd adapters/openai-compatible
cargo run --bin verify              # list what this key can actually call
cargo run --bin verify -- --probe   # list, then one real inference into the parser
```

Then set `KERN_MODEL_ID` to an identifier that binary printed. Set
`KERN_MODEL_MATCH` to a substring to narrow a long catalogue; it filters the
printout and nothing else.

Ollama Cloud identifiers carry no `-cloud` suffix. That suffix belongs to a
local daemon proxying a cloud model, which is the `ollama` profile — so an id
that worked there is not the id to use here.

### A thinking model needs `KERN_MODEL_RESPONSE_FORMAT`

The demos are configured against `nemotron-3-super`, which reasons before it
answers. Where that reasoning arrives in a `reasoning_content` field beside the
answer, this adapter drops it and Kern never sees it. Where it arrives *inside*
the message content — `<think>…</think>`, or a paragraph before the JSON — the
response is no longer one document, and the parser refuses it.

That refusal is correct and is not going to be relaxed: teaching the parser to
scan for the JSON-looking part is how a response the model did not mean becomes
a proposal Kern acts on. The fix belongs in configuration, so the demos set
`KERN_MODEL_RESPONSE_FORMAT=json_schema` and ask the gateway to constrain the
output. It changes no trust decision — the strict local parser runs identically
either way — and if a gateway rejects the request outright, fall back to
`json_object`, then to `plain`.

`tests/cloud_wiring.rs` states both halves: a bare or singly-fenced proposal
parses, and a narrated one is refused.

## Live evidence

```bash
cargo run --example live            # the 15-prompt suite
cargo run --example live -- --demo  # the allowed and denied demonstrations
```

Both need credentials, which is why they are examples rather than tests. The
whole offline containment argument lives in `crates/kern-ai/tests` and passes
with no key, no network, no ROS, and no simulator.

## Gates

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo build
cargo test          # offline: no key, no network, no gateway
```

The tests are the wiring evidence: which base URL an environment resolves to,
what the request body carries and what it must never carry, how a thinking
model's envelope is read, and which HTTP status means which frozen failure. None
of them opens a socket.

## Credentials

Environment variables only, optionally via a gitignored `.env`. The key goes
into one `Authorization` header and nowhere else: not into logs, not into a
provenance record, not into a `ModelIdentity`, not into an error string, and not
into a prompt. `GatewayConfig`'s `Debug` prints it as `<set>`.
