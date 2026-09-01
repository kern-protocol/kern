//! The provider profiles this adapter knows about.
//!
//! Every one of them speaks the same OpenAI-compatible surface:
//!
//! ```text
//! GET  {base}/models              list what this account can actually call
//! POST {base}/chat/completions    one inference
//! Authorization: Bearer <key>
//! ```
//!
//! A profile is a base URL, an environment variable name for the key, and a
//! label for provenance. Nothing else, because nothing else differs and because
//! anything else would be a place for a provider to acquire meaning it must not
//! have.

use core::fmt;
use core::str::FromStr;

/// Which gateway to call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    /// Nebius Token Factory, the NVIDIA-hosted inference path.
    ///
    /// Base URL and endpoints per the Token Factory API reference; the exact
    /// model identifier must still be confirmed against `/v1/models` for the
    /// account in use.
    NebiusTokenFactory,
    /// Nebius Token Factory, US Central region.
    NebiusUsCentral,
    /// Nebius Token Factory, EU West region.
    NebiusEuWest,
    /// Ollama Cloud's OpenAI-compatible endpoint, called directly.
    OllamaCloud,
    /// A local `ollama serve` daemon's OpenAI-compatible endpoint.
    ///
    /// The daemon may serve local weights or proxy `:cloud` models on its own
    /// credentials, which it holds and Kern never sees. Either way the bytes
    /// that come back are exactly as untrusted as any other model's.
    OllamaLocal,
    /// Any other OpenAI-compatible gateway, with the base URL supplied by
    /// configuration.
    Custom,
}

impl Provider {
    /// The profile for this provider.
    pub fn profile(self) -> ProviderProfile {
        match self {
            Self::NebiusTokenFactory => ProviderProfile {
                label: "nebius-token-factory",
                base_url: "https://api.tokenfactory.nebius.com/v1",
                key_var: "NEBIUS_API_KEY",
                requires_key: true,
            },
            Self::NebiusUsCentral => ProviderProfile {
                label: "nebius-token-factory-us-central1",
                base_url: "https://api.tokenfactory.us-central1.nebius.com/v1",
                key_var: "NEBIUS_API_KEY",
                requires_key: true,
            },
            Self::NebiusEuWest => ProviderProfile {
                label: "nebius-token-factory-eu-west1",
                base_url: "https://api.tokenfactory.eu-west1.nebius.com/v1",
                key_var: "NEBIUS_API_KEY",
                requires_key: true,
            },
            Self::OllamaCloud => ProviderProfile {
                label: "ollama-cloud",
                base_url: "https://ollama.com/v1",
                key_var: "OLLAMA_API_KEY",
                requires_key: true,
            },
            Self::OllamaLocal => ProviderProfile {
                label: "ollama-local",
                base_url: "http://localhost:11434/v1",
                key_var: "OLLAMA_API_KEY",
                requires_key: false,
            },
            Self::Custom => ProviderProfile {
                label: "custom-openai-compatible",
                base_url: "",
                key_var: "KERN_MODEL_API_KEY",
                requires_key: true,
            },
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.profile().label)
    }
}

impl FromStr for Provider {
    type Err = UnknownProvider;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "nebius" | "nebius-token-factory" | "token-factory" => Ok(Self::NebiusTokenFactory),
            "nebius-us-central1" | "us-central1" => Ok(Self::NebiusUsCentral),
            "nebius-eu-west1" | "eu-west1" => Ok(Self::NebiusEuWest),
            "ollama" | "ollama-local" | "local" => Ok(Self::OllamaLocal),
            "ollama-cloud" => Ok(Self::OllamaCloud),
            "custom" => Ok(Self::Custom),
            _ => Err(UnknownProvider),
        }
    }
}

/// The configuration name for a provider was not recognised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownProvider;

impl fmt::Display for UnknownProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "unknown provider: expected nebius, nebius-us-central1, nebius-eu-west1, \
             ollama, ollama-cloud, or custom",
        )
    }
}

impl std::error::Error for UnknownProvider {}

/// Where a provider lives, and where its key comes from.
///
/// Deliberately not `Serialize`, `Debug`-with-secrets, or anything else that
/// could carry a credential: it holds the *name* of the environment variable,
/// never its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderProfile {
    /// The provenance label recorded in a [`ModelIdentity`](kern_ai::ModelIdentity).
    pub label: &'static str,
    /// The API base, with no trailing slash. Empty for [`Provider::Custom`].
    pub base_url: &'static str,
    /// The environment variable holding the API key.
    pub key_var: &'static str,
    /// Whether this gateway requires a bearer credential at all.
    ///
    /// A local daemon on the loopback interface does not. When this is false
    /// and no key is configured, the adapter sends no `Authorization` header —
    /// rather than a placeholder, which would be a credential-shaped value in
    /// a request that never needed one.
    pub requires_key: bool,
}
