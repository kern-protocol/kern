//! An OpenAI-compatible chat-completions adapter for the Kern proposal plane.
//!
//! ```text
//! kern-ai
//!    |  ProposalModel                     synchronous, bytes in, bytes out
//!    v
//! this crate
//!    |  HTTPS, blocking, one attempt
//!    v
//! provider gateway  (Nebius Token Factory | Ollama Cloud | any compatible host)
//!    |
//!    v
//! the model
//! ```
//!
//! # The provider has no authority role
//!
//! It is an inference vendor. It does not decide, sign, grant, or install
//! anything, and the bytes it returns are untrusted in full. That is why this
//! crate can offer several providers behind one type without weakening
//! anything: swapping the vendor changes nothing above the trust boundary,
//! because there is nothing above the trust boundary that depends on which
//! vendor answered.
//!
//! # Why it lives outside the workspace
//!
//! It carries an HTTP client, a TLS stack, and their transitive dependencies.
//! None of that belongs in the build graph of the crates that decide authority,
//! so this crate is excluded from the workspace exactly as the ROS bridge is,
//! and is built and gated from its own directory.
//!
//! # What it never receives
//!
//! No signing key, no verifying key, no trust store, no challenge, no nonce, no
//! lease, no `LeaseHandle`, no `AuthorizedOperation`, and no `SemanticCommand`.
//! The [`ProposalModel`](kern_ai::ProposalModel) signature has no parameter that
//! could carry one, and this crate imports none of the crates that define them.
//!
//! # Credentials
//!
//! The API key is a host secret. It is read from the environment (or a
//! gitignored `.env`), held in memory, and sent in exactly one place: the
//! `Authorization` header of the request. It is never logged, never digested,
//! never placed in a [`ModelIdentity`](kern_ai::ModelIdentity), never included
//! in an error string, and never sent to the model as part of a prompt.

#![forbid(unsafe_code)]

pub mod config;
pub mod env;
pub mod provider;
pub mod transport;

pub use config::{check_key_transport, ConfigError, GatewayConfig, ResponseFormat};
pub use env::load_dotenv;
pub use provider::{Provider, ProviderProfile};
pub use transport::{GatewayModel, ListModelsError, ModelEntry};
