//! Establishes what this account can actually call, and proves the plane works
//! end to end at the parser.
//!
//! ```text
//! cargo run --bin verify                 # list the models the key can call
//! cargo run --bin verify -- --probe      # list, then run one real inference
//! ```
//!
//! Run this **before** setting `KERN_MODEL_ID`. A model identifier taken from
//! documentation is a hint; the identifier this prints for these credentials is
//! the fact, and it is the one that belongs in configuration and in the report.
//!
//! Nothing here touches policy, authority, or execution. It is a configuration
//! tool, and it can grant nothing.

use std::process::ExitCode;

use kern_model_openai_compatible::{
    check_key_transport, load_dotenv, GatewayConfig, GatewayModel, Provider,
};

fn main() -> ExitCode {
    if let Some(path) = load_dotenv(std::env::current_dir().unwrap_or_default()) {
        eprintln!("loaded environment from {}", path.display());
    }

    let probe = std::env::args().any(|argument| argument == "--probe");

    // Listing needs a key and a base URL, but not a model identifier, so the
    // config is assembled by hand here rather than through `from_env`, which
    // requires one.
    let provider = std::env::var("KERN_MODEL_PROVIDER")
        .ok()
        .map(|value| value.parse::<Provider>())
        .transpose();
    let provider = match provider {
        Ok(provider) => provider.unwrap_or(Provider::OllamaCloud),
        Err(error) => {
            eprintln!("configuration error: {error}");
            return ExitCode::from(2);
        }
    };
    let profile = provider.profile();

    let key = std::env::var("KERN_MODEL_API_KEY")
        .ok()
        .or_else(|| std::env::var(profile.key_var).ok())
        .filter(|key| !key.trim().is_empty());
    let key = match (key, profile.requires_key) {
        (Some(key), _) => key,
        (None, false) => String::new(),
        (None, true) => {
            eprintln!(
                "no API key: set {} (or KERN_MODEL_API_KEY) in the environment or in .env",
                profile.key_var
            );
            return ExitCode::from(2);
        }
    };

    let config = match GatewayConfig::new(provider, key.clone(), "unset") {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration error: {error}");
            return ExitCode::from(2);
        }
    };
    let config = match std::env::var("KERN_MODEL_BASE_URL") {
        Ok(url) if !url.trim().is_empty() => {
            // The same refusal `from_env` makes, made here too: this binary is
            // where an operator first points a key at a URL, so it is where a
            // key aimed at a plaintext off-host address should stop.
            if let Err(error) = check_key_transport("KERN_MODEL_BASE_URL", &url, !key.is_empty()) {
                eprintln!("configuration error: {error}");
                return ExitCode::from(2);
            }
            config.with_base_url(url)
        }
        _ => config,
    };

    println!("provider: {provider}");
    println!("base URL: {}", config.base_url());
    if key.is_empty() {
        println!("key: <none needed by this provider>");
    } else {
        println!("key: <set, {} bytes, not printed>", key.trim().len());
    }

    let client = GatewayModel::new(config);
    match client.list_models() {
        Ok(models) if models.is_empty() => {
            println!("\nthe gateway listed no models for this key");
        }
        Ok(models) => {
            println!("\n{} model(s) available to this key:", models.len());
            for model in &models {
                let owner = model.owned_by.as_deref().unwrap_or("-");
                let status = model.status.as_deref().unwrap_or("-");
                println!("  {:<56}  owner={owner:<16} status={status}", model.id);
            }
            // An optional substring filter, because a cloud catalogue is long
            // and an operator usually arrives with a family in mind. It is a
            // convenience for reading the list; the list above is the fact.
            if let Some(needle) = std::env::var("KERN_MODEL_MATCH")
                .ok()
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
            {
                let candidates: Vec<&str> = models
                    .iter()
                    .map(|model| model.id.as_str())
                    .filter(|id| id.to_ascii_lowercase().contains(&needle))
                    .collect();
                if candidates.is_empty() {
                    println!(
                        "\nno model identifier containing `{needle}` is available to this key."
                    );
                } else {
                    println!("\nidentifiers containing `{needle}`:");
                    for id in candidates {
                        println!("  {id}");
                    }
                }
            }
            println!("\nset the chosen one as KERN_MODEL_ID.");
        }
        Err(error) => {
            eprintln!("\ncould not list models: {error}");
            return ExitCode::from(1);
        }
    }

    if probe {
        return probe_once();
    }
    ExitCode::SUCCESS
}

/// One real inference, straight into Kern's strict parser.
fn probe_once() -> ExitCode {
    use kern_ai::{parse_response, ProposalModel};

    let config = match GatewayConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("\nprobe skipped: {error}");
            return ExitCode::from(2);
        }
    };
    println!("\nprobe: {config:?}");

    let mut client = GatewayModel::new(config);
    let request = probe_request();
    match client.propose(&request) {
        kern_ai::ModelOutcome::Failed(failure) => {
            println!("probe failed: {failure}");
            println!("no proposal, therefore no authorization and no execution.");
            ExitCode::from(1)
        }
        kern_ai::ModelOutcome::Response(response) => {
            println!(
                "probe response: {} bytes, digest {}",
                response.len(),
                response.digest()
            );
            match parse_response(&response) {
                Ok(parsed) => {
                    println!("parsed: capability={:?}", parsed.capability());
                    println!("reason: {}", parsed.reason());
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    println!("parser refused it: {error}");
                    println!("raw bytes follow, untrusted and unparsed:");
                    println!("{}", String::from_utf8_lossy(response.as_bytes()));
                    ExitCode::from(1)
                }
            }
        }
    }
}

/// The smallest possible real planning request, using the demo world.
fn probe_request() -> kern_ai::PlanningRequest {
    use kern_ai::{CapabilityVocabulary, Instruction, PlanningRequest, RobotContext};
    use kern_core::{
        CapabilityName, CapabilitySchema, DeviceId, ParamDomain, ParamName, ParamSpec, SubjectId,
    };
    use kern_policy::CapabilityRegistry;

    let device = DeviceId::new("cafe_bot_01");
    let schema = CapabilitySchema::new(
        CapabilityName::new("navigate").expect("non-empty"),
        [
            (
                ParamName::new("destination_x_mm"),
                ParamSpec::required(ParamDomain::Scalar),
            ),
            (
                ParamName::new("destination_y_mm"),
                ParamSpec::required(ParamDomain::Scalar),
            ),
            (
                ParamName::new("yaw_mdeg"),
                ParamSpec::required(ParamDomain::Scalar),
            ),
            (
                ParamName::new("max_speed_mm_s"),
                ParamSpec::required(ParamDomain::Scalar),
            ),
        ],
    )
    .expect("well-formed schema");

    let mut registry = CapabilityRegistry::new();
    registry
        .register(device.clone(), schema)
        .expect("registered");

    PlanningRequest::new(
        SubjectId::new("planner_a"),
        device.clone(),
        Instruction::new("Take the parcel to station B.").expect("bounded"),
        RobotContext::new(
            "The robot is in a straight corridor. station_b is at x = 6000, y = 0. \
             The robot is at the origin, idle.",
        )
        .expect("bounded"),
        CapabilityVocabulary::from_registry(&registry, &device).expect("navigate exists"),
    )
}
