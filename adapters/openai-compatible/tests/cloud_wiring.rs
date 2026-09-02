//! What the adapter puts on the wire for the Ollama Cloud path, and what it
//! refuses to put there.
//!
//! These are offline. There is no gateway, no key, and no network: every one of
//! them inspects a configuration or a request body that was built but never
//! sent. That is the point — the wiring between an environment and an HTTPS
//! request is exactly the part that silently breaks when a provider changes,
//! and it is the part no live run can check without spending a credential.
//!
//! The live evidence lives in `examples/live.rs` and in `verify --probe`.

use std::sync::{Mutex, MutexGuard};

use kern_ai::{parse_response, ProposalModel, RawModelResponse};
use kern_model_openai_compatible::{
    check_key_transport, ConfigError, GatewayConfig, GatewayModel, Provider, ResponseFormat,
};

// The single canonical demo host, shared with the offline tests and the live
// example so all three provably build the same request.
#[path = "../../../crates/kern-ai/tests/support/mod.rs"]
mod support;

/// The model this project's demos are configured against.
///
/// A `thinking` model, which is why several of these tests are about what
/// happens to prose that arrives wrapped around a proposal.
const DEMO_MODEL: &str = "nemotron-3-super";

/// Environment variables are process-global, so the tests that read them take
/// this lock rather than racing each other across `cargo test`'s threads.
static ENV: Mutex<()> = Mutex::new(());

/// Clears every variable `from_env` consults, then applies `vars`.
///
/// Returns the guard, so the caller holds the lock for as long as the
/// configuration it built is being asserted about.
fn with_env(vars: &[(&str, &str)]) -> MutexGuard<'static, ()> {
    // A panicking test poisons the lock; the environment is reset on entry
    // regardless, so the poison carries no state worth honouring.
    let guard = ENV.lock().unwrap_or_else(|poison| poison.into_inner());
    for var in [
        "KERN_MODEL_PROVIDER",
        "KERN_MODEL_API_KEY",
        "KERN_MODEL_BASE_URL",
        "KERN_MODEL_ID",
        "KERN_MODEL_TIMEOUT_MS",
        "KERN_MODEL_MAX_TOKENS",
        "KERN_MODEL_TEMPERATURE",
        "KERN_MODEL_RESPONSE_FORMAT",
        "OLLAMA_API_KEY",
        "NEBIUS_API_KEY",
    ] {
        std::env::remove_var(var);
    }
    for (var, value) in vars {
        std::env::set_var(var, value);
    }
    guard
}

/// The environment a demo container is handed: a key, a model, nothing else.
fn cloud_env() -> Vec<(&'static str, &'static str)> {
    vec![
        ("KERN_MODEL_PROVIDER", "ollama-cloud"),
        ("OLLAMA_API_KEY", "test-key-not-a-real-credential"),
        ("KERN_MODEL_ID", DEMO_MODEL),
    ]
}

// ---- the profile -------------------------------------------------------

#[test]
fn the_cloud_profile_is_https_and_carries_a_key() {
    let profile = Provider::OllamaCloud.profile();
    assert_eq!(profile.base_url, "https://ollama.com/v1");
    assert_eq!(profile.key_var, "OLLAMA_API_KEY");
    assert!(profile.requires_key);
    assert_eq!(profile.label, "ollama-cloud");
    assert!(
        profile.base_url.starts_with("https://"),
        "a keyed profile must not have a plaintext base URL"
    );
}

#[test]
fn the_cloud_and_local_names_never_swap_meaning() {
    // `ollama` moving to the cloud profile would silently change which host a
    // key is sent to, for every configuration that already used the name.
    for name in ["ollama", "ollama-local", "local"] {
        assert_eq!(name.parse::<Provider>().unwrap(), Provider::OllamaLocal);
    }
    for name in ["ollama-cloud", "ollama-api", "cloud", "  Ollama-Cloud  "] {
        assert_eq!(name.parse::<Provider>().unwrap(), Provider::OllamaCloud);
    }
    assert!(Provider::OllamaLocal
        .profile()
        .base_url
        .contains("localhost"));
    assert!(!Provider::OllamaLocal.profile().requires_key);
}

// ---- resolving an environment -----------------------------------------

#[test]
fn a_cloud_environment_resolves_to_ollamas_own_base_url() {
    let _guard = with_env(&cloud_env());
    let config = GatewayConfig::from_env().expect("a key and a model is enough");

    assert_eq!(config.provider(), Provider::OllamaCloud);
    assert_eq!(config.base_url(), "https://ollama.com/v1");
    assert_eq!(config.model(), DEMO_MODEL);
    assert_eq!(config.identity().provider(), "ollama-cloud");
    assert_eq!(config.identity().model(), DEMO_MODEL);
}

#[test]
fn the_cloud_is_the_default_when_no_provider_is_named() {
    let _guard = with_env(&[
        ("OLLAMA_API_KEY", "test-key-not-a-real-credential"),
        ("KERN_MODEL_ID", DEMO_MODEL),
    ]);
    let config = GatewayConfig::from_env().expect("the default needs no KERN_MODEL_PROVIDER");
    assert_eq!(config.provider(), Provider::OllamaCloud);
}

#[test]
fn a_missing_key_is_reported_by_name_and_never_by_value() {
    let _guard = with_env(&[
        ("KERN_MODEL_PROVIDER", "ollama-cloud"),
        ("KERN_MODEL_ID", DEMO_MODEL),
    ]);
    let error = GatewayConfig::from_env().expect_err("the cloud profile requires a key");
    let message = error.to_string();
    assert!(message.contains("OLLAMA_API_KEY"), "got: {message}");
}

#[test]
fn a_blank_key_is_the_same_as_a_missing_one() {
    // The shape a half-filled `.env` has: the line is present, the value is not.
    let _guard = with_env(&[
        ("KERN_MODEL_PROVIDER", "ollama-cloud"),
        ("OLLAMA_API_KEY", "   "),
        ("KERN_MODEL_ID", DEMO_MODEL),
    ]);
    assert!(matches!(
        GatewayConfig::from_env(),
        Err(ConfigError::Missing { .. })
    ));
}

#[test]
fn there_is_still_no_default_model_identifier() {
    let _guard = with_env(&[
        ("KERN_MODEL_PROVIDER", "ollama-cloud"),
        ("OLLAMA_API_KEY", "test-key-not-a-real-credential"),
    ]);
    let error = GatewayConfig::from_env().expect_err("a model id is required");
    assert!(error.to_string().contains("KERN_MODEL_ID"));
}

#[test]
fn a_stale_local_base_url_never_receives_the_cloud_key() {
    // The exact migration hazard: provider switched to the cloud, the base URL
    // from the local-daemon era still sitting in the environment.
    let mut vars = cloud_env();
    vars.push((
        "KERN_MODEL_BASE_URL",
        "http://host.docker.internal:11434/v1",
    ));
    let _guard = with_env(&vars);

    assert_eq!(
        GatewayConfig::from_env().err(),
        Some(ConfigError::InsecureBaseUrl {
            var: "KERN_MODEL_BASE_URL"
        })
    );
}

#[test]
fn the_local_daemon_may_still_be_addressed_over_plaintext() {
    // It needs no bearer, so there is no credential to expose.
    let _guard = with_env(&[
        ("KERN_MODEL_PROVIDER", "ollama"),
        (
            "KERN_MODEL_BASE_URL",
            "http://host.docker.internal:11434/v1",
        ),
        ("KERN_MODEL_ID", "nemotron-3-super:cloud"),
    ]);
    let config = GatewayConfig::from_env().expect("the local profile requires no key");
    assert_eq!(config.base_url(), "http://host.docker.internal:11434/v1");
    assert_eq!(config.identity().provider(), "ollama-local");
}

#[test]
fn the_guard_is_about_the_key_and_not_about_the_scheme() {
    assert!(check_key_transport("V", "http://host.docker.internal/v1", false).is_ok());
    assert!(check_key_transport("V", "https://ollama.com/v1", true).is_ok());
}

// ---- what actually goes on the wire ------------------------------------

fn cloud_client(format: ResponseFormat) -> GatewayModel {
    let config = GatewayConfig::new(
        Provider::OllamaCloud,
        "test-key-not-a-real-credential",
        DEMO_MODEL,
    )
    .expect("the cloud profile has a built-in base URL")
    .with_response_format(format);
    GatewayModel::new(config)
}

#[test]
fn the_request_body_names_the_model_and_carries_no_credential() {
    let authority = support::control_plane();
    let request = support::planning_request(&authority, "Take the parcel to station B.");
    let body = cloud_client(ResponseFormat::Plain).request_body(&request);

    assert!(
        body.contains(&format!("\"model\":\"{DEMO_MODEL}\"")),
        "{body}"
    );
    assert!(body.contains("\"stream\":false"));
    assert!(body.contains("Take the parcel to station B."));

    // The one claim worth making twice: the key reaches a header, never a body.
    assert!(
        !body.contains("test-key-not-a-real-credential"),
        "the API key must never appear in the request body"
    );
    // The word `authorization` does legitimately appear — the system prompt
    // tells the model that a separate authorization system decides what is
    // permitted. What must never appear is header material.
    assert!(!body.contains("Bearer "));
    // And no tool definitions: the provider is asked for text, never for an
    // action it could take itself.
    assert!(!body.contains("\"tools\""));
    assert!(!body.contains("\"tool_choice\""));
}

#[test]
fn plain_is_the_format_that_asks_the_gateway_for_nothing() {
    let authority = support::control_plane();
    let request = support::planning_request(&authority, "Take the parcel to station B.");
    let body = cloud_client(ResponseFormat::Plain).request_body(&request);
    assert!(!body.contains("response_format"));
}

#[test]
fn json_schema_puts_the_frozen_schema_on_the_wire() {
    // Defence in depth for a thinking model, and nothing more: the local parser
    // runs identically whether or not the gateway honoured this.
    let authority = support::control_plane();
    let request = support::planning_request(&authority, "Take the parcel to station B.");
    let body = cloud_client(ResponseFormat::JsonSchema).request_body(&request);

    assert!(body.contains("\"response_format\""));
    assert!(body.contains("\"json_schema\""));
    assert!(body.contains("kern_action_proposal"));
    assert!(body.contains("\"capability\""));

    let object = cloud_client(ResponseFormat::JsonObject).request_body(&request);
    assert!(object.contains("{\"type\":\"json_object\"}"));
}

#[test]
fn a_configured_gateway_never_prints_its_key() {
    let config = GatewayConfig::new(
        Provider::OllamaCloud,
        "test-key-not-a-real-credential",
        DEMO_MODEL,
    )
    .expect("built");
    let rendered = format!("{config:?}");
    assert!(
        !rendered.contains("test-key-not-a-real-credential"),
        "{rendered}"
    );
    assert!(rendered.contains("<set>"));
    assert!(rendered.contains(DEMO_MODEL));

    let identity = cloud_client(ResponseFormat::Plain).identity();
    let rendered = format!("{identity:?}");
    assert!(
        !rendered.contains("test-key-not-a-real-credential"),
        "{rendered}"
    );
}

// ---- a thinking model, and the trust boundary --------------------------

/// A proposal exactly as the contract wants it.
const CLEAN: &str = r#"{"capability":"navigate","arguments":{"destination_x_mm":6000,"destination_y_mm":0,"yaw_mdeg":0,"max_speed_mm_s":300},"reason":"deliver the parcel"}"#;

#[test]
fn a_bare_proposal_parses() {
    let response = RawModelResponse::new(CLEAN.as_bytes().to_vec()).expect("within bounds");
    let parsed = parse_response(&response).expect("the contract shape");
    assert_eq!(parsed.capability(), Some("navigate"));
}

#[test]
fn a_fenced_proposal_parses() {
    // One fence is the whole of the extraction logic, and a chat model emitting
    // ```json is common enough to be worth stating as a passing case.
    let fenced = format!("```json\n{CLEAN}\n```");
    let response = RawModelResponse::new(fenced.into_bytes()).expect("within bounds");
    assert!(parse_response(&response).is_ok());
}

#[test]
fn a_thinking_model_that_narrates_around_its_answer_is_refused() {
    // This is the practical reason the demos set KERN_MODEL_RESPONSE_FORMAT.
    // `nemotron-3-super` is a thinking model; when its reasoning lands inside
    // the message content rather than beside it, the response is no longer one
    // JSON document, and the parser does not go looking for the part that is.
    //
    // The outcome is a refusal, not a proposal — containment holds. What it
    // costs is a usable run, which is a configuration problem and is fixed in
    // configuration, never by teaching the parser to scan.
    for narrated in [
        format!("<think>The corridor is clear, so station B is reachable.</think>{CLEAN}"),
        format!("Let me think about this step by step.\n\n{CLEAN}"),
        format!("{CLEAN}\n\nI chose 300 mm/s because the instruction said gently."),
        format!("```json\n{CLEAN}\n```\n```json\n{CLEAN}\n```"),
    ] {
        let response = RawModelResponse::new(narrated.clone().into_bytes()).expect("within bounds");
        assert!(
            parse_response(&response).is_err(),
            "the parser must refuse a response carrying more than one document: {narrated}"
        );
    }
}

#[test]
fn a_response_that_is_only_reasoning_yields_nothing() {
    let response =
        RawModelResponse::new(b"<think>I should probably navigate somewhere.</think>".to_vec())
            .expect("within bounds");
    assert!(parse_response(&response).is_err());
}
