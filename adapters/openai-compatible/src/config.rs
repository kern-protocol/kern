//! What the adapter needs to know, and where it refuses to get it from.

use core::fmt;
use core::str::FromStr;
use core::time::Duration;

use kern_ai::ModelIdentity;

use crate::provider::{Provider, UnknownProvider};

/// How the response format is requested from the provider.
///
/// # None of these is a trust decision
///
/// Provider-side schema enforcement makes a well-behaved model more likely to
/// emit parseable output. It is not evidence about a model that is not
/// well-behaved, and Kern's strict local parser runs identically in all three
/// cases. The setting exists because gateways differ in what they accept, not
/// because one of them is safer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ResponseFormat {
    /// Send no `response_format` field at all.
    ///
    /// The default, and the only setting guaranteed to be accepted everywhere:
    /// a gateway that does not implement structured output rejects the request
    /// outright rather than ignoring the field. Constrained prompting plus the
    /// local parser carries the contract.
    #[default]
    Plain,
    /// Ask for `{"type": "json_object"}`.
    JsonObject,
    /// Ask for `{"type": "json_schema", ...}` with the frozen response schema.
    JsonSchema,
}

impl fmt::Display for ResponseFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Plain => "plain",
            Self::JsonObject => "json_object",
            Self::JsonSchema => "json_schema",
        })
    }
}

impl FromStr for ResponseFormat {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "plain" | "text" | "none" => Ok(Self::Plain),
            "json_object" | "json" => Ok(Self::JsonObject),
            "json_schema" | "schema" => Ok(Self::JsonSchema),
            _ => Err(ConfigError::BadValue {
                var: "KERN_MODEL_RESPONSE_FORMAT",
                expected: "plain, json_object, or json_schema",
            }),
        }
    }
}

/// The adapter could not be configured.
///
/// Every variant names a variable. None of them ever carries a value, because
/// one of the variables is a credential and an error type that sometimes
/// prints values will eventually print that one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// A required variable is absent.
    Missing {
        /// Which variable.
        var: String,
        /// What it is for.
        purpose: &'static str,
    },
    /// A variable is present but unusable.
    BadValue {
        /// Which variable.
        var: &'static str,
        /// What would have been acceptable.
        expected: &'static str,
    },
    /// The provider name was not recognised.
    UnknownProvider(UnknownProvider),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { var, purpose } => write!(f, "{var} is not set ({purpose})"),
            Self::BadValue { var, expected } => write!(f, "{var} must be {expected}"),
            Self::UnknownProvider(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Everything the adapter needs to make one inference call.
///
/// # The key is not `Debug`
///
/// `GatewayConfig` implements [`fmt::Debug`] by hand and prints the key as
/// `<set>` or `<unset>`. A derived `Debug` would put a live credential into the
/// first log line somebody adds while chasing a bug, which is exactly when
/// nobody is thinking about credentials.
#[derive(Clone)]
pub struct GatewayConfig {
    provider: Provider,
    base_url: String,
    api_key: String,
    model: String,
    timeout: Duration,
    temperature: Option<f32>,
    max_tokens: u32,
    response_format: ResponseFormat,
}

impl GatewayConfig {
    /// Builds a configuration explicitly.
    pub fn new(
        provider: Provider,
        api_key: impl Into<String>,
        model: impl Into<String>,
    ) -> Result<Self, ConfigError> {
        let profile = provider.profile();
        if profile.base_url.is_empty() {
            return Err(ConfigError::Missing {
                var: "KERN_MODEL_BASE_URL".to_string(),
                purpose: "the custom provider has no built-in base URL",
            });
        }
        Ok(Self {
            provider,
            base_url: profile.base_url.to_string(),
            api_key: api_key.into(),
            model: model.into(),
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            temperature: Some(DEFAULT_TEMPERATURE),
            max_tokens: DEFAULT_MAX_TOKENS,
            response_format: ResponseFormat::Plain,
        })
    }

    /// Reads the configuration from the environment.
    ///
    /// ```text
    /// KERN_MODEL_PROVIDER         nebius | nebius-us-central1 | nebius-eu-west1
    ///                             | ollama | custom          (default: nebius)
    /// NEBIUS_API_KEY              the key, for the nebius profiles
    /// OLLAMA_API_KEY              the key, for the ollama profile
    /// KERN_MODEL_API_KEY          the key, for the custom profile; also
    ///                             overrides the profile's own variable
    /// KERN_MODEL_ID               the model identifier, verified against
    ///                             /v1/models                (required)
    /// KERN_MODEL_BASE_URL         overrides the profile's base URL
    /// KERN_MODEL_TIMEOUT_MS       inference deadline        (default: 60000)
    /// KERN_MODEL_MAX_TOKENS       completion bound          (default: 512)
    /// KERN_MODEL_TEMPERATURE      sampling temperature      (default: 0.2)
    /// KERN_MODEL_RESPONSE_FORMAT  plain | json_object | json_schema
    ///                                                       (default: plain)
    /// ```
    ///
    /// There is no default model identifier, and there will not be one. A model
    /// id compiled into this crate would be a claim about what an account can
    /// call, and this crate has no way to know that: the identifier must be
    /// verified against `/v1/models` and then configured.
    pub fn from_env() -> Result<Self, ConfigError> {
        let provider = match std::env::var("KERN_MODEL_PROVIDER") {
            Ok(value) => value
                .parse::<Provider>()
                .map_err(ConfigError::UnknownProvider)?,
            Err(_) => Provider::NebiusTokenFactory,
        };
        let profile = provider.profile();

        let api_key = std::env::var("KERN_MODEL_API_KEY")
            .ok()
            .or_else(|| std::env::var(profile.key_var).ok())
            .filter(|key| !key.trim().is_empty());
        // A gateway that needs no credential is not given a placeholder one.
        let api_key = match (api_key, profile.requires_key) {
            (Some(key), _) => key,
            (None, false) => String::new(),
            (None, true) => {
                return Err(ConfigError::Missing {
                    var: profile.key_var.to_string(),
                    purpose: "the provider API key",
                })
            }
        };

        let model = std::env::var("KERN_MODEL_ID")
            .ok()
            .filter(|model| !model.trim().is_empty())
            .ok_or(ConfigError::Missing {
                var: "KERN_MODEL_ID".to_string(),
                purpose: "the verified model identifier; list it with the `verify` binary",
            })?;

        let base_url = std::env::var("KERN_MODEL_BASE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty())
            .unwrap_or_else(|| profile.base_url.to_string());
        if base_url.is_empty() {
            return Err(ConfigError::Missing {
                var: "KERN_MODEL_BASE_URL".to_string(),
                purpose: "the custom provider has no built-in base URL",
            });
        }

        Ok(Self {
            provider,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.trim().to_string(),
            model: model.trim().to_string(),
            timeout: Duration::from_millis(parse_var("KERN_MODEL_TIMEOUT_MS", DEFAULT_TIMEOUT_MS)?),
            temperature: Some(parse_var("KERN_MODEL_TEMPERATURE", DEFAULT_TEMPERATURE)?),
            max_tokens: parse_var("KERN_MODEL_MAX_TOKENS", DEFAULT_MAX_TOKENS)?,
            response_format: match std::env::var("KERN_MODEL_RESPONSE_FORMAT") {
                Ok(value) => value.parse()?,
                Err(_) => ResponseFormat::Plain,
            },
        })
    }

    /// Overrides the base URL.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_string();
        self
    }

    /// Overrides the inference deadline.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Overrides how the response format is requested.
    #[must_use]
    pub fn with_response_format(mut self, format: ResponseFormat) -> Self {
        self.response_format = format;
        self
    }

    /// The provider.
    pub fn provider(&self) -> Provider {
        self.provider
    }

    /// The API base, with no trailing slash.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The configured model identifier.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The inference deadline.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The sampling temperature, if one is set.
    pub fn temperature(&self) -> Option<f32> {
        self.temperature
    }

    /// The completion token bound.
    pub fn max_tokens(&self) -> u32 {
        self.max_tokens
    }

    /// How the response format is requested.
    pub fn response_format(&self) -> ResponseFormat {
        self.response_format
    }

    /// The API key. Crate-internal: it goes into one header and nowhere else.
    pub(crate) fn api_key(&self) -> &str {
        &self.api_key
    }

    /// The provenance identity for this configuration.
    ///
    /// Provider label and model identifier only. No key, no digest of a key,
    /// and no header material.
    pub fn identity(&self) -> ModelIdentity {
        ModelIdentity::new(self.provider.profile().label, &self.model)
    }
}

impl fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayConfig")
            .field("provider", &self.provider)
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("timeout", &self.timeout)
            .field("temperature", &self.temperature)
            .field("max_tokens", &self.max_tokens)
            .field("response_format", &self.response_format)
            .field(
                "api_key",
                &if self.api_key.is_empty() {
                    "<unset>"
                } else {
                    "<set>"
                },
            )
            .finish()
    }
}

/// 60 s. Long enough for a large reasoning model, short enough that a wedged
/// gateway does not hold a demo open forever.
pub const DEFAULT_TIMEOUT_MS: u64 = 60_000;
/// 512 completion tokens. The frozen response contract is a few dozen.
pub const DEFAULT_MAX_TOKENS: u32 = 512;
/// Low, because this is a structured extraction task rather than a creative one.
pub const DEFAULT_TEMPERATURE: f32 = 0.2;

fn parse_var<T>(var: &'static str, default: T) -> Result<T, ConfigError>
where
    T: FromStr,
{
    match std::env::var(var) {
        Err(_) => Ok(default),
        Ok(value) if value.trim().is_empty() => Ok(default),
        Ok(value) => value
            .trim()
            .parse::<T>()
            .map_err(|_| ConfigError::BadValue {
                var,
                expected: "a number",
            }),
    }
}
