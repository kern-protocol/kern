//! The Phase 7 live demo driver: a language model proposes, Kern decides, and
//! only then does anything reach Nav2.
//!
//! ```text
//! ros2 launch kern_nav2_demo kern_demo.launch.py
//! cargo run --bin kern-ai-demo -- --instruction "Take the parcel to station B, gently."
//! ```
//!
//! # Why this is a separate binary
//!
//! `kern-nav2-demo` is the Phase 6 driver and is left exactly as it was. This
//! one adds a model in front of the same pipeline and changes nothing behind
//! it: the registry, the schema, the policy, the issuer, the enforcer, the
//! governor, and the adapter are the same types called in the same order.
//!
//! # The denied path touches no ROS at all
//!
//! The model is invoked, parsed, normalized, and evaluated **before** the ROS
//! node is created. A proposal policy refuses therefore cannot publish a speed
//! limit or send a goal, because at the moment it is refused there is no action
//! client in the process to send one with. That is a stronger statement than
//! "we checked and did not send it".
//!
//! # This is a demo driver, not a deployment topology
//!
//! It holds an issuing key in the same process as the enforcer, which a real
//! deployment never does. Everything below issuance is what a deployment has.

use std::time::{Duration, Instant};

use kern_ai::{
    render_proposal, CapabilityVocabulary, Instruction, NormalizationOutcome, PlanningRequest,
    PolicyOutcome, ProposalPlane, RobotContext, SequentialProposalIds,
};
use kern_authority::{
    AuthorizedOperation, CountingNonces, Ed25519Signer, LeaseIssuer, SequentialLeaseIds,
};
use kern_core::wire::encode_v2;
use kern_core::{
    Challenge, ConstraintSet, DeviceId, EnforcerSessionId, Interval, IssuerId, KeyId,
    MonotonicClock, MonotonicDuration, ParamConstraint, ParamName, PolicyDecision, SubjectId,
    SystemClock, Ttl, Uptime,
};
use kern_enforcer::{ChallengeSource, EnforcerStore, EntropyError, TrustStore};
use kern_execution::{
    ExecutionGovernor, Executor, GovernorConfig, LapseAction, SequentialExecutionIds, StartupPolicy,
};
use kern_execution_nav2::{
    navigate_label, navigate_schema, render_execution, Nav2Config, Nav2Executor, DESTINATION_X_MM,
    DESTINATION_Y_MM, MAX_SPEED_MM_S, NAVIGATE, YAW_MDEG,
};
use kern_model_openai_compatible::{load_dotenv, GatewayConfig, GatewayModel};
use kern_nav2_bridge::{ros::BridgeConfig, RosNav2Backend};
use kern_policy::{Authority, CapabilityRegistry, Policy, PolicyId, PolicySet, Selector};

const SUBJECT: &str = "planner_a";
const DEVICE: &str = "cafe_bot_01";
const ISSUER: &str = "issuer_dev";
/// Demo signing key. A deployment's issuer key never lives in the edge process.
const DEV_SEED: [u8; 32] = [7u8; 32];

/// The Phase 6 corridor, in Kern's integer units.
const POLICY_MAX_SPEED_MM_S: i64 = 400;
const WORLD_X_MM: (i64, i64) = (-7_000, 7_000);
const WORLD_Y_MM: (i64, i64) = (-1_000, 1_000);
const WORLD_YAW_MDEG: (i64, i64) = (-180_000, 180_000);

/// The semantic world. Named places and nothing else: no topics, no frames, no
/// action names, and nothing a planner could use to address the machine.
const ROBOT_CONTEXT: &str = "\
The robot is a delivery base in a straight corridor.
Named places, in millimetres from the origin:
  station_a: x = -6000, y = 0
  origin:    x = 0,     y = 0
  station_b: x = 6000,  y = 0
The corridor runs along x. Staying near y = 0 keeps the robot in the corridor.
The robot is currently at the origin, idle.";

/// Process uptime. The only clock authority lifetime is measured against.
struct UptimeClock {
    start: Instant,
}

impl MonotonicClock for UptimeClock {
    fn uptime(&self) -> Uptime {
        Uptime::from_millis(self.start.elapsed().as_millis() as u64)
    }
}

impl Clone for UptimeClock {
    fn clone(&self) -> Self {
        Self { start: self.start }
    }
}

/// Challenges from the OS CSPRNG. Entropy failure is fatal, by design.
struct OsChallenges;

impl ChallengeSource for OsChallenges {
    fn next_challenge(&mut self) -> Result<Challenge, EntropyError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| EntropyError)?;
        Ok(Challenge::from_bytes(bytes))
    }
}

struct Options {
    instruction: String,
    ttl_ms: u64,
    action: String,
    run_for: Duration,
    settle: Duration,
}

impl Options {
    fn parse() -> Self {
        let mut options = Self {
            instruction: String::from("Take the parcel to station B, gently and carefully."),
            ttl_ms: 60_000,
            action: String::from("/navigate_to_pose"),
            run_for: Duration::from_secs(120),
            settle: Duration::from_secs(5),
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            let mut value = || args.next().unwrap_or_default();
            match arg.as_str() {
                "--instruction" => options.instruction = value(),
                "--ttl-ms" => options.ttl_ms = value().parse().unwrap_or(options.ttl_ms),
                "--action" => options.action = value(),
                "--run-for-s" => {
                    options.run_for = Duration::from_secs(value().parse().unwrap_or(120))
                }
                "--settle-s" => options.settle = Duration::from_secs(value().parse().unwrap_or(5)),
                _ => {}
            }
        }
        options
    }
}

/// The trusted control plane: what `navigate` means, and who may request it.
fn control_plane() -> Result<Authority, Box<dyn std::error::Error>> {
    let mut registry = CapabilityRegistry::new();
    registry.register(DeviceId::new(DEVICE), navigate_schema()?)?;

    let bounded = |bounds: (i64, i64)| {
        ParamConstraint::Numeric(Interval::between(bounds.0, bounds.1).expect("ordered bounds"))
    };
    let policy = Policy::new(
        PolicyId::new("delivery"),
        Selector::Exactly(SubjectId::new(SUBJECT)),
        Selector::Exactly(DeviceId::new(DEVICE)),
        Selector::Exactly(kern_core::CapabilityName::new(NAVIGATE)?),
        ConstraintSet::from_constraints([
            (
                ParamName::new(MAX_SPEED_MM_S),
                ParamConstraint::at_most(POLICY_MAX_SPEED_MM_S),
            ),
            (ParamName::new(DESTINATION_X_MM), bounded(WORLD_X_MM)),
            (ParamName::new(DESTINATION_Y_MM), bounded(WORLD_Y_MM)),
            (ParamName::new(YAW_MDEG), bounded(WORLD_YAW_MDEG)),
        ]),
    )?;

    Ok(Authority::new(
        registry,
        PolicySet::from_policies([policy])?,
    ))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse();
    if let Some(path) = load_dotenv(std::env::current_dir().unwrap_or_default()) {
        eprintln!("loaded environment from {}", path.display());
    }

    let authority = control_plane()?;
    let vocabulary =
        CapabilityVocabulary::from_registry(authority.registry(), &DeviceId::new(DEVICE))?;
    let request = PlanningRequest::new(
        SubjectId::new(SUBJECT),
        DeviceId::new(DEVICE),
        Instruction::new(options.instruction.as_str())?,
        RobotContext::new(ROBOT_CONTEXT)?,
        vocabulary,
    );

    let config = GatewayConfig::from_env()?;
    println!("provider: {}", config.provider());
    println!("base URL: {}", config.base_url());
    println!("model:    {}", config.model());
    println!("\nINSTRUCTION\n  {}\n", options.instruction);

    // ---- the model, and the trust boundary -------------------------------
    let mut plane = ProposalPlane::new(GatewayModel::new(config), SequentialProposalIds::new());
    let proposal = plane.propose(&request);
    let (mut record, action) = proposal.into_parts();

    let Some(action) = action else {
        println!("{}", render_proposal(&record, None, None));
        println!("\nNo proposal, so no authorization, no lease, and no goal.");
        return Ok(());
    };

    // ---- meaning, then shape, then authority ------------------------------
    let schema = match authority
        .registry()
        .resolve(&action.device, &action.capability)
    {
        Ok(schema) => schema.clone(),
        Err(error) => {
            record.record_normalization(NormalizationOutcome::Rejected(error.to_string()))?;
            println!(
                "{}",
                render_proposal(&record, Some(&action), Some(&error.to_string()))
            );
            println!("\nNo registered capability, so nothing was evaluated and nothing was sent.");
            return Ok(());
        }
    };
    let normalized = match schema.normalize(&action) {
        Ok(normalized) => normalized,
        Err(error) => {
            record.record_normalization(NormalizationOutcome::Rejected(error.to_string()))?;
            println!(
                "{}",
                render_proposal(&record, Some(&action), Some(&error.to_string()))
            );
            println!("\nMalformed operation, so nothing was evaluated and nothing was sent.");
            return Ok(());
        }
    };
    record.record_normalization(NormalizationOutcome::Normalized)?;

    // Kept so a refusal can name the bounds this proposal actually broke,
    // rather than reciting every bound that exists.
    let proposed_params = normalized.params().clone();
    let evaluation = authority.decide(normalized);
    let decision = evaluation.decision().clone();
    record.record_policy(PolicyOutcome::from_decision(&decision))?;

    let Some(operation) = AuthorizedOperation::from_evaluation(evaluation) else {
        let detail = denial_detail(&decision, &proposed_params);
        println!("{}", render_proposal(&record, Some(&action), Some(&detail)));
        println!(
            "\nPolicy refused it. No challenge was minted, no lease was issued, no execution \
             identifier was allocated, and no ROS node was ever created — so no speed limit was \
             published and no NavigateToPose goal was sent."
        );
        return Ok(());
    };

    // ==== everything past this point requires an authorization ============

    let clock = UptimeClock {
        start: Instant::now(),
    };
    let mut session_bytes = [0u8; 32];
    getrandom::getrandom(&mut session_bytes).map_err(|_| "entropy source unavailable")?;
    let session = EnforcerSessionId::from_bytes(session_bytes);

    let signer = Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED);
    let mut trust = TrustStore::new();
    trust.authorize(
        IssuerId::new(ISSUER),
        KeyId::new("dev-1"),
        signer.verifying_key_bytes(),
    )?;

    let mut store = EnforcerStore::new(
        session,
        trust,
        clock.clone(),
        OsChallenges,
        MonotonicDuration::from_millis(2_000),
        4,
        4,
    )?;
    let mut issuer = LeaseIssuer::new(
        IssuerId::new(ISSUER),
        signer,
        SystemClock,
        CountingNonces::new(),
        SequentialLeaseIds::starting_at(1),
    );

    // Freshness, then issuance, then installation. The TTL is host
    // configuration; nothing the model said is an input to it.
    let ticket = store.mint_challenge(
        &IssuerId::new(ISSUER),
        operation.proposal().actor(),
        operation.proposal().device(),
        operation.proposal().capability(),
    )?;
    let lease = issuer.issue_v2(&operation, Ttl::from_millis(options.ttl_ms), &ticket)?;
    let bytes = encode_v2(&lease)?;
    let handle = store.install(&bytes)?.handle().clone();
    record.record_authority(*handle.artifact())?;

    let backend = RosNav2Backend::start(BridgeConfig {
        action_name: options.action.clone(),
        ..BridgeConfig::default()
    })?;
    let mut adapter = Nav2Executor::new(backend, Nav2Config::default())?;

    // ROS discovery time, not authority time. A node created a moment ago has
    // not necessarily matched the action server or the controller's
    // speed-limit subscription yet, and the adapter correctly refuses to send a
    // goal it cannot bound. Waiting here is the demo driver being patient with
    // the middleware; it changes nothing about the lease, whose lifetime is
    // already running against process uptime.
    if !options.settle.is_zero() {
        println!("waiting {:?} for ROS discovery", options.settle);
        std::thread::sleep(options.settle);
    }
    let mut governor = ExecutionGovernor::new(
        session,
        GovernorConfig {
            capacity: 4,
            journal_capacity: 128,
            lapse_action: LapseAction::Cancel,
            startup_policy: StartupPolicy::ReportOnly,
            observation_budget: 16,
        },
        clock,
        SequentialExecutionIds::starting_at(1),
        adapter.declaration(),
    )?;

    let operation_proposal = operation.proposal().clone();
    let prepared = governor.prepare(&store, &handle, &operation_proposal)?;
    let execution = prepared.execution_id();
    record.record_execution(execution)?;

    println!("{}", render_proposal(&record, Some(&action), None));
    println!(
        "\nPROVENANCE\n  {}  ->  {:?}  ->  {}\n  lease {:?}   command digest {:?}",
        record.proposal_id(),
        handle.artifact(),
        execution,
        handle.lease_id(),
        prepared.command_digest(),
    );

    let receipt = prepared.submit(&store, &mut adapter);
    println!(
        "\nsubmitted: state {:?}, executor invoked {}",
        receipt.state(),
        receipt.executor_invoked()
    );

    let label = label_for(&operation_proposal);
    let deadline = Instant::now() + options.run_for;
    while Instant::now() < deadline {
        let report = governor.tick_observed(&store, &mut adapter);
        if !governor.journal().is_empty() {
            let observed = governor.record(execution).expect("recorded");
            println!(
                "\n{}",
                render_execution(observed, &label, governor.journal().last())
            );
            if report.session_mismatch {
                println!("  WIRING FAULT: the store is not this governor's session");
            }
        }
        if let Some(observed) = governor.record(execution) {
            if observed.execution().is_terminal() {
                println!("\nterminal: {:?}", observed.execution());
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    adapter.shutdown();
    println!("\nKern requested what it could and recorded what it saw.");
    println!("It makes no claim about whether the machine physically stopped.");
    Ok(())
}

fn label_for(operation: &kern_core::NormalizedActionProposal) -> String {
    let scalar = |name: &str| match operation.params().get(&ParamName::new(name)) {
        Some(kern_core::ParamValue::Scalar(value)) => *value,
        _ => 0,
    };
    navigate_label(
        scalar(DESTINATION_X_MM),
        scalar(DESTINATION_Y_MM),
        scalar(YAW_MDEG),
        scalar(MAX_SPEED_MM_S),
    )
}

/// A readable reason, rendered from the evaluator's own output.
///
/// Kern never rewrites the proposal to fit. It says what would have been
/// grantable and stops.
fn denial_detail(
    decision: &PolicyDecision,
    params: &std::collections::BTreeMap<ParamName, kern_core::ParamValue>,
) -> String {
    match decision {
        PolicyDecision::Authorized { .. } => "authorized".to_string(),
        PolicyDecision::Denied => "no policy grants this operation".to_string(),
        PolicyDecision::NotAuthorizedAsProposed { .. } => {
            let feedback = kern_ai::ConstraintFeedback::violations(decision, params);
            if feedback.is_empty() {
                "outside the grantable bounds".to_string()
            } else {
                feedback.to_text().replace('\n', "; ")
            }
        }
    }
}
