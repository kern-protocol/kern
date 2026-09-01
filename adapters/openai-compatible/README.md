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
| `nebius` | `https://api.tokenfactory.nebius.com/v1` | `NEBIUS_API_KEY` |
| `nebius-us-central1` | `https://api.tokenfactory.us-central1.nebius.com/v1` | `NEBIUS_API_KEY` |
| `nebius-eu-west1` | `https://api.tokenfactory.eu-west1.nebius.com/v1` | `NEBIUS_API_KEY` |
| `ollama` | `http://localhost:11434/v1` | none — a local daemon needs no bearer |
| `ollama-cloud` | `https://ollama.com/v1` | `OLLAMA_API_KEY` |
| `custom` | `KERN_MODEL_BASE_URL` | `KERN_MODEL_API_KEY` |

Several providers behind one type is not a weakening. A provider is an inference
vendor with no authority role, so which one answered changes nothing above the
trust boundary — that is precisely the property Phase 7 exists to demonstrate.

A local `ollama serve` daemon may hold its own cloud credentials and proxy
`:cloud` models. Kern never sees them, and the bytes that come back are exactly
as untrusted as any other model's. When a profile needs no bearer, the adapter
sends no `Authorization` header at all rather than a placeholder.

## Verify before you configure

There is no default model identifier and there will not be one. A name compiled
into this crate would be a claim about what an account can call, which this
crate cannot know.

```bash
cd adapters/openai-compatible
cargo run --bin verify              # list what this key can actually call
cargo run --bin verify -- --probe   # list, then one real inference into the parser
```

Then set `KERN_MODEL_ID` to an identifier that binary printed.

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
```

## Credentials

Environment variables only, optionally via a gitignored `.env`. The key goes
into one `Authorization` header and nowhere else: not into logs, not into a
provenance record, not into a `ModelIdentity`, not into an error string, and not
into a prompt. `GatewayConfig`'s `Debug` prints it as `<set>`.
