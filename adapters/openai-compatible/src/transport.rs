//! The HTTPS transport, the request contract, and the failure mapping.
//!
//! # One attempt
//!
//! [`GatewayModel::propose`] issues exactly one request and never retries.
//! Inference has no physical side effect, so a retry would be safe — but Phase 7
//! does not need the complexity, and a retry policy with unstated semantics is
//! how "one inference per instruction" quietly becomes "as many as it takes".
//!
//! # Synchronous on purpose
//!
//! A blocking client, no runtime, no task, no thread. The whole point of the
//! [`ProposalModel`](kern_ai::ProposalModel) signature is that a networked
//! provider does not oblige Kern's trusted crates to grow an async runtime, and
//! the simplest way to keep that promise is to not need one here either.
//!
//! # Failure mapping
//!
//! | condition | outcome |
//! |---|---|
//! | 2xx with a message body | `Response(bytes)` — untrusted |
//! | 400, 401, 403, 404, 422 | `ProviderRejected` — a configuration fault |
//! | 408, 429, 5xx | `Unavailable` |
//! | local deadline passed | `Timeout` |
//! | connection refused, DNS failure | `Unavailable` |
//! | anything else, including a truncated body | `TransportUnknown` |
//!
//! No row produces a denial, an authorization, or an execution failure. Those
//! are different facts about different subsystems, and a provider is not
//! qualified to have an opinion about any of them.

use core::fmt;

use kern_ai::json::{self, Json};
use kern_ai::{
    ModelIdentity, ModelOutcome, PlanningRequest, ProposalModel, ProviderFailure, RawModelResponse,
};

use crate::config::{GatewayConfig, ResponseFormat};

/// How many bytes of provider envelope the adapter will read.
///
/// Larger than Kern's response bound because the envelope carries usage counts,
/// identifiers, and possibly a reasoning trace around the message content. The
/// content itself still has to fit
/// [`MAX_RESPONSE_BYTES`](kern_ai::bounds::MAX_RESPONSE_BYTES), which
/// [`RawModelResponse::new`] enforces.
pub const MAX_ENVELOPE_BYTES: usize = 262_144;

/// One model as the gateway lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelEntry {
    /// The identifier to put in `KERN_MODEL_ID`.
    pub id: String,
    /// Who the gateway says owns it.
    pub owned_by: Option<String>,
    /// The gateway's status string, where it reports one.
    pub status: Option<String>,
}

/// Listing the available models failed.
#[derive(Clone, Debug)]
pub enum ListModelsError {
    /// The gateway refused or could not be reached.
    Provider(ProviderFailure),
    /// The gateway answered with something that is not a model list.
    Malformed(String),
}

impl fmt::Display for ListModelsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(failure) => write!(f, "{failure}"),
            Self::Malformed(detail) => write!(f, "malformed model list: {detail}"),
        }
    }
}

impl std::error::Error for ListModelsError {}

/// A [`ProposalModel`](kern_ai::ProposalModel) backed by an OpenAI-compatible
/// gateway.
///
/// Holds a configuration and an HTTP agent. It holds no Kern state whatsoever:
/// no registry, no policy, no key, no challenge, no lease, no handle. There is
/// nothing in this struct that could be persuaded to grant anything.
pub struct GatewayModel {
    config: GatewayConfig,
    agent: ureq::Agent,
}

impl GatewayModel {
    /// Builds a client for one configuration.
    pub fn new(config: GatewayConfig) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(config.timeout()))
            .build()
            .into();
        Self { config, agent }
    }

    /// The configuration, for the demo banner. Never prints the key.
    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    /// Lists the models this account can actually call.
    ///
    /// This is the only honest way to establish a model identifier. A name in
    /// documentation, in a blog post, or in a design document is a hint; what
    /// the gateway answers here for these credentials is the fact.
    pub fn list_models(&self) -> Result<Vec<ModelEntry>, ListModelsError> {
        let url = format!("{}/models", self.config.base_url());
        let mut request = self.agent.get(&url);
        if let Some(bearer) = self.bearer() {
            request = request.header("Authorization", &bearer);
        }
        let response = request.call();

        let body = match response {
            Ok(mut response) => response
                .body_mut()
                .with_config()
                .limit(MAX_ENVELOPE_BYTES as u64)
                .read_to_string()
                .map_err(|_| ListModelsError::Provider(ProviderFailure::TransportUnknown))?,
            Err(error) => return Err(ListModelsError::Provider(map_error(&error))),
        };

        let document = json::parse(body.as_bytes())
            .map_err(|error| ListModelsError::Malformed(error.to_string()))?;
        let entries = document
            .get("data")
            .and_then(Json::as_array)
            .ok_or_else(|| ListModelsError::Malformed("no `data` array".to_string()))?;

        Ok(entries
            .iter()
            .filter_map(|entry| {
                Some(ModelEntry {
                    id: entry.get("id")?.as_str()?.to_string(),
                    owned_by: entry
                        .get("owned_by")
                        .and_then(Json::as_str)
                        .map(str::to_string),
                    status: entry
                        .get("status")
                        .and_then(Json::as_str)
                        .map(str::to_string),
                })
            })
            .collect())
    }

    /// The request body, exactly as it goes on the wire.
    ///
    /// Public so the live demo can show what was sent, and so a reviewer can
    /// check that it carries a prompt and nothing else: no key, no identifier,
    /// no tool definition, and no provider-side execution of anything.
    pub fn request_body(&self, request: &PlanningRequest) -> String {
        let mut body = String::from("{\"model\":");
        push_string(&mut body, self.config.model());
        body.push_str(",\"messages\":[{\"role\":\"system\",\"content\":");
        push_string(&mut body, &kern_ai::system_prompt(request));
        body.push_str("},{\"role\":\"user\",\"content\":");
        push_string(&mut body, &kern_ai::user_prompt(request));
        body.push_str("}]");

        if let Some(temperature) = self.config.temperature() {
            body.push_str(&format!(",\"temperature\":{temperature}"));
        }
        body.push_str(&format!(",\"max_tokens\":{}", self.config.max_tokens()));
        body.push_str(",\"n\":1,\"stream\":false");

        match self.config.response_format() {
            ResponseFormat::Plain => {}
            ResponseFormat::JsonObject => {
                body.push_str(",\"response_format\":{\"type\":\"json_object\"}");
            }
            ResponseFormat::JsonSchema => {
                body.push_str(
                    ",\"response_format\":{\"type\":\"json_schema\",\"json_schema\":{\"name\":\"kern_action_proposal\",\"strict\":true,\"schema\":",
                );
                body.push_str(kern_ai::response_schema());
                body.push_str("}}");
            }
        }

        body.push('}');
        body
    }

    /// The bearer header value, or `None` when the gateway needs no credential.
    fn bearer(&self) -> Option<String> {
        let key = self.config.api_key();
        (!key.is_empty()).then(|| format!("Bearer {key}"))
    }

    /// Sends one request and returns the message content as raw bytes.
    fn call(&self, request: &PlanningRequest) -> Result<Vec<u8>, ProviderFailure> {
        let url = format!("{}/chat/completions", self.config.base_url());
        let body = self.request_body(request);

        let mut request = self
            .agent
            .post(&url)
            .header("Content-Type", "application/json");
        if let Some(bearer) = self.bearer() {
            request = request.header("Authorization", &bearer);
        }
        let response = request.send(&body);

        let envelope = match response {
            Ok(mut response) => response
                .body_mut()
                .with_config()
                .limit(MAX_ENVELOPE_BYTES as u64)
                .read_to_string()
                .map_err(|_| ProviderFailure::TransportUnknown)?,
            Err(error) => return Err(map_error(&error)),
        };

        extract_content(&envelope)
    }
}

impl ProposalModel for GatewayModel {
    fn propose(&mut self, request: &PlanningRequest) -> ModelOutcome {
        match self.call(request) {
            Ok(bytes) => match RawModelResponse::new(bytes) {
                Ok(response) => ModelOutcome::Response(response),
                // Over Kern's response bound. Refused here, before a parser
                // sees it, and reported as a rejection rather than as a
                // transport problem: the network worked perfectly.
                Err(error) => ModelOutcome::Failed(ProviderFailure::ProviderRejected {
                    detail: error.to_string(),
                }),
            },
            Err(failure) => ModelOutcome::Failed(failure),
        }
    }

    fn identity(&self) -> ModelIdentity {
        self.config.identity()
    }
}

/// Pulls `choices[0].message.content` out of the envelope.
///
/// The envelope is untrusted too, and is read by the same hostile JSON reader
/// Kern uses for the proposal itself. A missing, null, or non-string content
/// field yields empty bytes, which the proposal parser then refuses as an empty
/// response — the same outcome as a model that said nothing, which is what it
/// is.
///
/// A `reasoning_content` sibling, where a reasoning model emits one, is
/// deliberately ignored rather than concatenated. Kern parses the answer, not
/// the thinking.
fn extract_content(envelope: &str) -> Result<Vec<u8>, ProviderFailure> {
    let document = json::parse(envelope.as_bytes()).map_err(|_| {
        // Well-formed HTTP carrying something that is not the documented
        // response shape. Not a denial, and not a timeout.
        ProviderFailure::TransportUnknown
    })?;

    if let Some(error) = document.get("error") {
        let detail = error
            .get("message")
            .and_then(Json::as_str)
            .unwrap_or("the gateway returned an error object");
        return Err(ProviderFailure::ProviderRejected {
            detail: truncate(detail),
        });
    }

    let content = document
        .get("choices")
        .and_then(Json::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Json::as_str)
        .unwrap_or_default();

    Ok(content.as_bytes().to_vec())
}

/// Maps a transport or status error onto the frozen failure vocabulary.
fn map_error(error: &ureq::Error) -> ProviderFailure {
    match error {
        ureq::Error::StatusCode(code) => match code {
            400 | 401 | 403 | 404 | 405 | 409 | 413 | 422 => ProviderFailure::ProviderRejected {
                detail: format!("http {code}"),
            },
            408 | 429 => ProviderFailure::Unavailable,
            code if *code >= 500 => ProviderFailure::Unavailable,
            code => ProviderFailure::ProviderRejected {
                detail: format!("http {code}"),
            },
        },
        ureq::Error::Timeout(_) => ProviderFailure::Timeout,
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => ProviderFailure::Unavailable,
        // Everything else — a TLS fault, a protocol fault, an I/O fault
        // mid-body — leaves Kern unable to say what the gateway did. That is a
        // different fact from "it was not there", and it is recorded as one.
        _ => ProviderFailure::TransportUnknown,
    }
}

/// Keeps an error detail short, and free of anything that might have been
/// echoed back at length.
fn truncate(detail: &str) -> String {
    const LIMIT: usize = 200;
    let cleaned: String = detail
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(LIMIT)
        .collect();
    cleaned
}

/// Appends `value` as a JSON string literal.
///
/// Hand-written because this crate serializes exactly two shapes and pulling in
/// a serialization framework to do it would put a much larger dependency in the
/// build for no gain. Escapes every control character, the quote, and the
/// backslash, which is the whole of what RFC 8259 requires.
fn push_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chat-completions envelope carrying `content`, and optionally the
    /// `reasoning_content` sibling a thinking model emits beside it.
    fn envelope(content: &str, reasoning: Option<&str>) -> String {
        let reasoning = reasoning
            .map(|text| format!(",\"reasoning_content\":\"{text}\""))
            .unwrap_or_default();
        format!(
            "{{\"id\":\"chatcmpl-1\",\"object\":\"chat.completion\",\
             \"model\":\"nemotron-3-super\",\"choices\":[{{\"index\":0,\
             \"message\":{{\"role\":\"assistant\",\"content\":\"{content}\"{reasoning}}},\
             \"finish_reason\":\"stop\"}}],\
             \"usage\":{{\"prompt_tokens\":900,\"completion_tokens\":64,\"total_tokens\":964}}}}"
        )
    }

    #[test]
    fn the_answer_is_taken_and_the_thinking_is_left_behind() {
        // `nemotron-3-super` is a thinking model. Kern parses the answer, not
        // the reasoning: concatenating them would let a model's own narration
        // become part of the document the parser reads.
        let body = envelope(
            "{\\\"capability\\\":\\\"navigate\\\"}",
            Some("The corridor is clear, so station B is reachable."),
        );
        let content = extract_content(&body).expect("a well-formed envelope");
        let content = String::from_utf8(content).expect("utf-8");

        assert_eq!(content, "{\"capability\":\"navigate\"}");
        assert!(!content.contains("corridor"));
    }

    #[test]
    fn an_envelope_with_no_reasoning_sibling_reads_the_same() {
        let body = envelope("{\\\"capability\\\":\\\"navigate\\\"}", None);
        assert_eq!(
            extract_content(&body).expect("a well-formed envelope"),
            b"{\"capability\":\"navigate\"}".to_vec()
        );
    }

    #[test]
    fn a_model_that_returned_only_thinking_yields_no_bytes() {
        // An empty `content` is a model that said nothing, and the proposal
        // parser refuses it as exactly that.
        let body = envelope("", Some("I am still considering it."));
        assert!(extract_content(&body).expect("well-formed").is_empty());
    }

    #[test]
    fn a_gateway_error_object_is_a_provider_rejection_and_not_a_denial() {
        // The distinction the whole failure vocabulary exists for: a gateway
        // saying no is a configuration fact, never a policy decision.
        let body = "{\"error\":{\"message\":\"model \\\"nemotron-3-supre\\\" not found\",\
                    \"type\":\"invalid_request_error\"}}";
        match extract_content(body) {
            Err(ProviderFailure::ProviderRejected { detail }) => {
                assert!(detail.contains("not found"), "got: {detail}");
            }
            other => panic!("expected a provider rejection, got {other:?}"),
        }
    }

    #[test]
    fn an_envelope_that_is_not_json_is_a_transport_fault() {
        // Well-formed HTTP carrying something that is not the documented shape.
        // Not a denial, not a timeout, and not a proposal.
        assert!(matches!(
            extract_content("<html>502 Bad Gateway</html>"),
            Err(ProviderFailure::TransportUnknown)
        ));
    }

    #[test]
    fn a_missing_choices_array_yields_no_bytes_rather_than_a_guess() {
        let body = "{\"id\":\"chatcmpl-1\",\"object\":\"chat.completion\",\"choices\":[]}";
        assert!(extract_content(body).expect("well-formed json").is_empty());
    }

    #[test]
    fn an_error_detail_is_bounded_and_stripped_of_control_characters() {
        let long = "x".repeat(1_000);
        let body = format!("{{\"error\":{{\"message\":\"{long}\\nsecond line\"}}}}");
        match extract_content(&body) {
            Err(ProviderFailure::ProviderRejected { detail }) => {
                assert!(detail.chars().count() <= 200);
                assert!(!detail.contains('\n'));
            }
            other => panic!("expected a provider rejection, got {other:?}"),
        }
    }

    #[test]
    fn rate_limiting_and_outages_are_unavailability_not_rejection() {
        // A key that is out of quota must not read as a model that refused.
        assert!(matches!(
            map_error(&ureq::Error::StatusCode(429)),
            ProviderFailure::Unavailable
        ));
        assert!(matches!(
            map_error(&ureq::Error::StatusCode(503)),
            ProviderFailure::Unavailable
        ));
    }

    #[test]
    fn a_bad_key_or_a_bad_model_id_is_a_configuration_fault() {
        // 401: the key is wrong. 404: the model identifier is wrong. Both are
        // things an operator fixes in configuration, and neither is a fact
        // about the robot.
        for code in [400, 401, 403, 404, 422] {
            assert!(
                matches!(
                    map_error(&ureq::Error::StatusCode(code)),
                    ProviderFailure::ProviderRejected { .. }
                ),
                "http {code} should be a provider rejection"
            );
        }
    }
}
