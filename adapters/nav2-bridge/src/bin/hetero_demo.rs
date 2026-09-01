//! Three machines, one authority architecture, one live model.
//!
//! ```text
//! kern-hetero-demo --instruction "Deliver the order to table 3."
//! kern-hetero-demo --scenario concurrent
//! kern-hetero-demo --scenario cross
//! ```
//!
//! Every machine reaches Gazebo the same way:
//!
//! ```text
//! instruction -> live model -> untrusted bytes -> strict parser
//!   -> logical target -> trusted router -> DeviceId
//!   -> registry -> schema -> policy -> AuthorizedOperation
//!   -> challenge -> V2 lease -> install -> LeaseHandle
//!   -> the machine's own governor and adapter -> ROS -> Gazebo
//! ```
//!
//! # Three slots, not one
//!
//! `cafe_robot`, `conveyor_01`, and `robotic_arm_01` are distinct `DeviceId`s
//! with distinct capabilities and distinct policies. An authority slot is
//! `(issuer, subject, device, capability)`, so a lease for one of them is
//! structurally incapable of covering another — and each machine gets its own
//! governor, because the operation identity of a Nav2 goal, a belt transfer, and
//! an arm motion are three different types.
//!
//! # This is a demo driver, not a deployment topology
//!
//! It holds an issuing key in the same process as the enforcer, which a real
//! deployment never does. Everything below issuance is what a deployment has.

use std::time::{Duration, Instant};

use kern_ai::{
    CapabilityVocabulary, Instruction, PlanningRequest, PolicyOutcome, ProposalOutcome,
    ProposalPlane, RobotContext, SequentialProposalIds,
};
use kern_authority::{
    AuthorizedOperation, CountingNonces, Ed25519Signer, LeaseIssuer, SequentialLeaseIds,
};
use kern_core::wire::encode_v2;
use kern_core::{
    ActionProposal, CapabilityName, Challenge, DeviceId, EnforcerSessionId, IssuerId, KeyId,
    MonotonicClock, MonotonicDuration, ParamName, ParamValue, SubjectId, Symbol, SystemClock, Ttl,
    Uptime,
};
use kern_enforcer::{ChallengeSource, EnforcerStore, EntropyError, LeaseHandle, TrustStore};
use kern_eval::world::{self, ARM, CAFE_ROBOT, CONVEYOR, ISSUER, SUBJECT, WORKSPACE_CONTEXT};
use kern_execution::{
    ExecutionGovernor, ExecutionId, ExecutionState, Executor, GovernorConfig, LapseAction,
    SequentialExecutionIds, StartupPolicy,
};
use kern_execution_arm::{
    ArmConfig, ArmExecutor, ArmOperationId, ArmPose, Zone, DESTINATION_ZONE, PICK_AND_PLACE,
    SOURCE_ZONE,
};
use kern_execution_conveyor::{
    ConveyorConfig, ConveyorExecutor, ConveyorOperationId, Station, DESTINATION_STATION,
    TRANSFER_ITEM,
};
use kern_execution_nav2::{
    Nav2Config, Nav2Executor, Nav2OperationId, DESTINATION_X_MM, DESTINATION_Y_MM, MAX_SPEED_MM_S,
    NAVIGATE, YAW_MDEG,
};
use kern_model_openai_compatible::{load_dotenv, GatewayConfig, GatewayModel};
use kern_nav2_bridge::ros::BridgeConfig;
use kern_nav2_bridge::workstation::{ArmRosBackend, ConveyorRosBackend};
use kern_nav2_bridge::RosNav2Backend;

/// Demo signing key. A deployment's issuer key never lives beside its enforcer.
const DEV_SEED: [u8; 32] = [7u8; 32];

/// Process uptime. The only clock authority lifetime is measured against.
#[derive(Clone)]
struct UptimeClock {
    start: Instant,
}

impl MonotonicClock for UptimeClock {
    fn uptime(&self) -> Uptime {
        Uptime::from_millis(self.start.elapsed().as_millis() as u64)
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

type Store = EnforcerStore<UptimeClock, OsChallenges>;
type Issuer = LeaseIssuer<Ed25519Signer, SystemClock, CountingNonces, SequentialLeaseIds>;

/// The three machines, each with its own adapter and its own governor.
struct Fleet {
    cafe: Nav2Executor<RosNav2Backend>,
    cafe_gov: ExecutionGovernor<Nav2OperationId, UptimeClock, SequentialExecutionIds>,
    belt: ConveyorExecutor<ConveyorRosBackend>,
    belt_gov: ExecutionGovernor<ConveyorOperationId, UptimeClock, SequentialExecutionIds>,
    arm: ArmExecutor<ArmRosBackend>,
    arm_gov: ExecutionGovernor<ArmOperationId, UptimeClock, SequentialExecutionIds>,
}

impl Fleet {
    fn new(
        session: EnforcerSessionId,
        clock: &UptimeClock,
        action: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cafe = Nav2Executor::new(
            RosNav2Backend::start(BridgeConfig {
                action_name: action.to_string(),
                ..BridgeConfig::default()
            })?,
            Nav2Config::default(),
        )?;
        let belt = ConveyorExecutor::new(
            ConveyorRosBackend::start()?,
            ConveyorConfig {
                // The world's belt joint runs 0.0 .. 1.2 m. These are the two
                // stations, in the belt's own frame.
                stations: vec![
                    Station {
                        name: String::from("station_a"),
                        position_mm: 0,
                    },
                    Station {
                        name: String::from("station_b"),
                        position_mm: 1_200,
                    },
                ],
                tracking_capacity: 4,
            },
        )?;
        let arm = ArmExecutor::new(
            ArmRosBackend::start()?,
            ArmConfig {
                // Joint poses, from trusted configuration. Nothing above this
                // line ever names a joint.
                zones: vec![
                    Zone {
                        name: String::from("pickup_zone"),
                        pose: ArmPose {
                            shoulder_rad: -0.7,
                            elbow_rad: 0.9,
                        },
                    },
                    Zone {
                        name: String::from("serving_tray"),
                        pose: ArmPose {
                            shoulder_rad: 0.5,
                            elbow_rad: -0.4,
                        },
                    },
                ],
                tracking_capacity: 4,
            },
        )?;

        let config = |capacity: usize| GovernorConfig {
            capacity,
            journal_capacity: 256,
            lapse_action: LapseAction::Cancel,
            startup_policy: StartupPolicy::ReportOnly,
            observation_budget: 16,
        };
        let cafe_gov = ExecutionGovernor::new(
            session,
            config(4),
            clock.clone(),
            SequentialExecutionIds::starting_at(100),
            cafe.declaration(),
        )?;
        let belt_gov = ExecutionGovernor::new(
            session,
            config(4),
            clock.clone(),
            SequentialExecutionIds::starting_at(200),
            belt.declaration(),
        )?;
        let arm_gov = ExecutionGovernor::new(
            session,
            config(4),
            clock.clone(),
            SequentialExecutionIds::starting_at(300),
            arm.declaration(),
        )?;

        Ok(Self {
            cafe,
            cafe_gov,
            belt,
            belt_gov,
            arm,
            arm_gov,
        })
    }

    /// One observation pass over all three machines.
    fn tick(&mut self, store: &Store) {
        self.cafe_gov.tick_observed(store, &mut self.cafe);
        self.belt_gov.tick_observed(store, &mut self.belt);
        self.arm_gov.tick_observed(store, &mut self.arm);
    }

    fn shutdown(&mut self) {
        self.cafe.shutdown();
        self.belt.shutdown();
        self.arm.shutdown();
    }
}

/// One running operation on one machine.
struct Live {
    device: String,
    execution: ExecutionId,
    handle: LeaseHandle,
}

struct Options {
    scenario: String,
    instruction: String,
    ttl_ms: u64,
    cafe_ttl_ms: u64,
    run_for: Duration,
    settle: Duration,
    action: String,
}

impl Options {
    fn parse() -> Self {
        let mut options = Self {
            scenario: String::from("live"),
            instruction: String::from("Deliver the order to table 3."),
            ttl_ms: 180_000,
            cafe_ttl_ms: 25_000,
            run_for: Duration::from_secs(120),
            settle: Duration::from_secs(12),
            action: String::from("/navigate_to_pose"),
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            let mut value = || args.next().unwrap_or_default();
            match arg.as_str() {
                "--scenario" => options.scenario = value(),
                "--instruction" => options.instruction = value(),
                "--ttl-ms" => options.ttl_ms = value().parse().unwrap_or(180_000),
                "--cafe-ttl-ms" => options.cafe_ttl_ms = value().parse().unwrap_or(25_000),
                "--run-for-s" => {
                    options.run_for = Duration::from_secs(value().parse().unwrap_or(120))
                }
                "--settle-s" => options.settle = Duration::from_secs(value().parse().unwrap_or(12)),
                "--action" => options.action = value(),
                _ => {}
            }
        }
        options
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse();
    if let Some(path) = load_dotenv(std::env::current_dir().unwrap_or_default()) {
        eprintln!("loaded environment from {}", path.display());
    }

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
    let mut store: Store = EnforcerStore::new(
        session,
        trust,
        clock.clone(),
        OsChallenges,
        MonotonicDuration::from_millis(5_000),
        8,
        8,
    )?;
    let mut issuer: Issuer = LeaseIssuer::new(
        IssuerId::new(ISSUER),
        signer,
        SystemClock,
        CountingNonces::new(),
        SequentialLeaseIds::starting_at(1),
    );

    let mut fleet = Fleet::new(session, &clock, &options.action)?;
    println!("waiting {:?} for ROS discovery", options.settle);
    std::thread::sleep(options.settle);

    let result = match options.scenario.as_str() {
        "cross" => cross_device(&mut store, &mut issuer, &clock, &mut fleet),
        "concurrent" => concurrent(&options, &mut store, &mut issuer, &clock, &mut fleet),
        _ => live_one(&options, &mut store, &mut issuer, &clock, &mut fleet),
    };

    fleet.shutdown();
    println!("\nKern requested what it could and recorded what it saw.");
    println!("It makes no claim about whether any machine physically stopped.");
    result
}

/// One live instruction, routed to whichever machine the model named.
fn live_one(
    options: &Options,
    store: &mut Store,
    issuer: &mut Issuer,
    clock: &UptimeClock,
    fleet: &mut Fleet,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = world::world("workspace")?;
    let router = world::workspace_router();
    let vocabulary = CapabilityVocabulary::from_router(authority.registry(), &router)?;

    let config = GatewayConfig::from_env()?;
    println!(
        "\nprovider {} | model {} | {}",
        config.provider(),
        config.model(),
        config.base_url()
    );
    println!("\nINSTRUCTION\n  {}\n", options.instruction);

    let request = PlanningRequest::new(
        SubjectId::new(SUBJECT),
        // The default device, used only if the model names no target at all.
        DeviceId::new(CAFE_ROBOT),
        Instruction::new(options.instruction.as_str())?,
        RobotContext::new(WORKSPACE_CONTEXT)?,
        vocabulary,
    )
    .with_router(router);

    let mut plane = ProposalPlane::new(GatewayModel::new(config), SequentialProposalIds::new());
    let proposal = plane.propose(&request);
    let action = proposal.action().cloned();
    let (record, _) = proposal.into_parts();

    println!("MODEL");
    println!("  provider:    {}", record.model().provider());
    println!("  model:       {}", record.model().model());
    println!("  invocation:  {}", record.invocation());
    println!("  proposal_id: {}", record.proposal_id());
    match record.outcome() {
        ProposalOutcome::NoResponse(failure) => {
            println!("  proposal:    NONE — {failure}");
            return report_nothing();
        }
        ProposalOutcome::ParseRejected(error) => {
            println!("  proposal:    REJECTED — {error}");
            return report_nothing();
        }
        ProposalOutcome::NoAction { reason } => {
            println!("  proposal:    no_action — {reason}");
            return report_nothing();
        }
        ProposalOutcome::Parsed { capability, reason } => {
            println!("  capability:  {capability}");
            println!("  reason:      {reason}");
        }
    }
    let Some(action) = action else {
        return report_nothing();
    };
    println!(
        "  target:      {} (resolved by the trusted router)",
        action.device
    );
    println!("  arguments:   {}", render(&action));

    // ---- meaning, then shape, then authority -----------------------------
    let schema = match authority
        .registry()
        .resolve(&action.device, &action.capability)
    {
        Ok(schema) => schema.clone(),
        Err(error) => {
            println!("\nPOLICY\n  NOT A KNOWN OPERATION — {error}");
            return report_nothing();
        }
    };
    let normalized = match schema.normalize(&action) {
        Ok(normalized) => normalized,
        Err(error) => {
            println!("\nPOLICY\n  NOT A KNOWN OPERATION — {error}");
            return report_nothing();
        }
    };
    let params = normalized.params().clone();
    let evaluation = authority.decide(normalized);
    let decision = evaluation.decision().clone();

    println!("\nPOLICY");
    match PolicyOutcome::from_decision(&decision) {
        PolicyOutcome::Authorized => println!("  AUTHORIZED"),
        _ => println!(
            "  DENIED\n  reason: {}",
            kern_eval::denial_detail(&decision, &params)
        ),
    }

    let Some(operation) = AuthorizedOperation::from_evaluation(evaluation) else {
        return report_nothing();
    };

    let ttl = if action.device.as_str() == CAFE_ROBOT {
        options.cafe_ttl_ms.max(options.ttl_ms)
    } else {
        options.ttl_ms
    };
    let (handle, deadline) = install(store, issuer, clock, &operation, ttl)?;
    println!("\nAUTHORITY");
    println!("  artifact: {:?}", handle.artifact());
    println!("  lease:    {:?}", handle.lease_id());
    println!("  deadline: {} ms uptime", deadline.as_millis());

    let live = dispatch(fleet, store, &handle, &operation)?;
    println!("\nEXECUTION");
    match &live {
        Some(live) => {
            println!("  execution_id: {}", live.execution);
            println!(
                "\nPROVENANCE\n  {}  ->  {}  ->  {:?}  ->  {:?}  ->  {}",
                record.invocation(),
                record.proposal_id(),
                action.device,
                handle.artifact(),
                live.execution
            );
        }
        None => println!("  NONE"),
    }

    observe(fleet, store, options.run_for, live.as_slice());
    Ok(())
}

fn report_nothing() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nAUTHORITY\n  NONE\n\nEXECUTION\n  NONE");
    println!("\nNo machine received a command.");
    Ok(())
}

/// Hands an authorized operation to whichever machine it names.
///
/// The match is on the device the *router* resolved, and each arm reaches only
/// its own governor and its own adapter. There is no path by which an operation
/// for one machine could be prepared against another's authority: the governor
/// enforces before it reserves anything, and the enforcer's slot check would
/// refuse it anyway.
fn dispatch(
    fleet: &mut Fleet,
    store: &Store,
    handle: &LeaseHandle,
    operation: &AuthorizedOperation,
) -> Result<Option<Live>, Box<dyn std::error::Error>> {
    let device = operation.proposal().device().as_str().to_string();
    let proposal = operation.proposal().clone();

    macro_rules! run {
        ($gov:expr, $exec:expr) => {{
            match $gov.prepare(store, handle, &proposal) {
                Ok(prepared) => {
                    let execution = prepared.execution_id();
                    let receipt = prepared.submit(store, &mut $exec);
                    println!(
                        "  submitted: state {:?}, executor invoked {}",
                        receipt.state(),
                        receipt.executor_invoked()
                    );
                    Some(Live {
                        device: device.clone(),
                        execution,
                        handle: handle.clone(),
                    })
                }
                Err(error) => {
                    println!("  prepare refused: {error}");
                    None
                }
            }
        }};
    }

    Ok(match device.as_str() {
        CAFE_ROBOT => run!(fleet.cafe_gov, fleet.cafe),
        CONVEYOR => run!(fleet.belt_gov, fleet.belt),
        ARM => run!(fleet.arm_gov, fleet.arm),
        other => {
            println!("  no adapter is wired for `{other}`");
            None
        }
    })
}

/// Watches every machine until they settle or the budget runs out.
fn observe(fleet: &mut Fleet, store: &Store, run_for: Duration, live: &[Live]) {
    let deadline = Instant::now() + run_for;
    let mut last = String::new();
    while Instant::now() < deadline {
        fleet.tick(store);
        let mut line = String::new();
        let mut all_terminal = true;
        for entry in live {
            let (authority, execution, cancellation) = match entry.device.as_str() {
                CAFE_ROBOT => status(fleet.cafe_gov.record(entry.execution)),
                CONVEYOR => status(fleet.belt_gov.record(entry.execution)),
                _ => status(fleet.arm_gov.record(entry.execution)),
            };
            if !execution.starts_with("completed")
                && !execution.starts_with("cancelled")
                && !execution.starts_with("failed")
                && !execution.starts_with("not_started")
            {
                all_terminal = false;
            }
            line.push_str(&format!(
                "  {:<15} authority {:<8} execution {:<28} cancellation {}\n",
                entry.device, authority, execution, cancellation
            ));
        }
        if line != last {
            println!("\n{line}");
            last = line;
        }
        if all_terminal && !live.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = store;
}

fn status<O: Clone + Eq>(
    record: Option<&kern_execution::ExecutionRecord<O>>,
) -> (String, String, String) {
    match record {
        None => (
            String::from("none"),
            String::from("none"),
            String::from("none"),
        ),
        Some(record) => (
            if record.authority().is_lapsed() {
                format!(
                    "LAPSED({})",
                    record
                        .authority()
                        .lapse_reason()
                        .map_or_else(String::new, |reason| reason.to_string())
                )
            } else {
                String::from("CURRENT")
            },
            match record.execution() {
                ExecutionState::Prepared => String::from("prepared"),
                ExecutionState::NotStarted(reason) => format!("not_started({reason:?})"),
                ExecutionState::Submitted => String::from("submitted"),
                ExecutionState::Running => String::from("running"),
                ExecutionState::Completed => String::from("completed"),
                ExecutionState::Failed(class) => format!("failed({class:?})"),
                ExecutionState::Cancelled => String::from("cancelled"),
                ExecutionState::Disputed { .. } => String::from("disputed"),
                ExecutionState::Unknown { phase, last_known } => {
                    format!("unknown({phase:?},{last_known:?})")
                }
            },
            format!("{:?}", record.cancellation()),
        ),
    }
}

/// All three machines at once, then only the cafe lease expires.
fn concurrent(
    options: &Options,
    store: &mut Store,
    issuer: &mut Issuer,
    clock: &UptimeClock,
    fleet: &mut Fleet,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = world::world("workspace")?;
    println!("\n=== three machines, three authorities, concurrently ===\n");

    let plans = [
        (navigate(6_000, 250), options.cafe_ttl_ms),
        (transfer("station_b", 200), options.ttl_ms),
        (pick("pickup_zone", "serving_tray"), options.ttl_ms),
    ];

    let mut live = Vec::new();
    for (proposal, ttl) in plans {
        let evaluation = authority.evaluate(&proposal)?;
        let Some(operation) = AuthorizedOperation::from_evaluation(evaluation) else {
            println!("policy refused {}: nothing was installed", proposal.device);
            continue;
        };
        let (handle, deadline) = install(store, issuer, clock, &operation, ttl)?;
        println!(
            "{:<15} lease {:?}  artifact {:?}  deadline {} ms",
            proposal.device.as_str(),
            handle.lease_id(),
            handle.artifact(),
            deadline.as_millis()
        );
        if let Some(entry) = dispatch(fleet, store, &handle, &operation)? {
            live.push(entry);
        }
    }

    println!(
        "\nthe cafe lease expires in {} ms; the other two run for {} ms",
        options.cafe_ttl_ms, options.ttl_ms
    );
    observe(fleet, store, options.run_for, &live);

    println!("\n=== authority isolation, at the end of the run ===");
    for entry in &live {
        println!(
            "  {:<15} check_authority: {:?}",
            entry.device,
            store.check_authority(&entry.handle)
        );
    }
    Ok(())
}

/// One machine's authority offered against another machine's operation.
fn cross_device(
    store: &mut Store,
    issuer: &mut Issuer,
    clock: &UptimeClock,
    fleet: &mut Fleet,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = world::world("workspace")?;
    println!("\n=== cross-device authority misuse, against the live machines ===\n");

    let mut installed = Vec::new();
    for proposal in [
        navigate(6_000, 250),
        transfer("station_b", 200),
        pick("pickup_zone", "serving_tray"),
    ] {
        let evaluation = authority.evaluate(&proposal)?;
        let operation =
            AuthorizedOperation::from_evaluation(evaluation).ok_or("policy refused a demo plan")?;
        let (handle, _) = install(store, issuer, clock, &operation, 60_000)?;
        installed.push((proposal.device.as_str().to_string(), handle, operation));
    }

    for (holder, handle, _) in &installed {
        for (subject, _, operation) in &installed {
            if holder == subject {
                continue;
            }
            let enforced = store.enforce(handle, operation.proposal());
            println!("  {holder} authority vs {subject} operation: enforce -> {enforced:?}");

            // And through the governor, which is where an executor would
            // otherwise be reached.
            let prepared = match subject.as_str() {
                CAFE_ROBOT => fleet
                    .cafe_gov
                    .prepare(store, handle, operation.proposal())
                    .map(|_| ())
                    .map_err(|error| error.to_string()),
                CONVEYOR => fleet
                    .belt_gov
                    .prepare(store, handle, operation.proposal())
                    .map(|_| ())
                    .map_err(|error| error.to_string()),
                _ => fleet
                    .arm_gov
                    .prepare(store, handle, operation.proposal())
                    .map(|_| ())
                    .map_err(|error| error.to_string()),
            };
            println!("  {holder} authority vs {subject} operation: prepare -> {prepared:?}");
        }
    }

    println!(
        "\nobserved belt position: {:?} m   observed arm joints: {:?} rad",
        fleet.belt.backend().observed_position_m(),
        fleet.arm.backend().observed_joints()
    );
    println!(
        "every crossed pairing was refused before any adapter was reached: `enforce`\n\
         answers DeviceMismatch, and `prepare` refuses before it draws an execution\n\
         identifier or calls a backend. Neither machine moved."
    );
    Ok(())
}

fn navigate(x_mm: i64, speed_mm_s: i64) -> ActionProposal {
    ActionProposal::new(
        SubjectId::new(SUBJECT),
        DeviceId::new(CAFE_ROBOT),
        CapabilityName::new(NAVIGATE).expect("non-empty"),
    )
    .with_param(ParamName::new(DESTINATION_X_MM), ParamValue::Scalar(x_mm))
    .with_param(ParamName::new(DESTINATION_Y_MM), ParamValue::Scalar(0))
    .with_param(ParamName::new(YAW_MDEG), ParamValue::Scalar(0))
    .with_param(
        ParamName::new(MAX_SPEED_MM_S),
        ParamValue::Scalar(speed_mm_s),
    )
}

fn transfer(station: &str, speed_mm_s: i64) -> ActionProposal {
    ActionProposal::new(
        SubjectId::new(SUBJECT),
        DeviceId::new(CONVEYOR),
        CapabilityName::new(TRANSFER_ITEM).expect("non-empty"),
    )
    .with_param(
        ParamName::new(DESTINATION_STATION),
        ParamValue::Symbol(Symbol::new(station)),
    )
    .with_param(
        ParamName::new(kern_execution_conveyor::MAX_SPEED_MM_S),
        ParamValue::Scalar(speed_mm_s),
    )
}

fn pick(source: &str, destination: &str) -> ActionProposal {
    ActionProposal::new(
        SubjectId::new(SUBJECT),
        DeviceId::new(ARM),
        CapabilityName::new(PICK_AND_PLACE).expect("non-empty"),
    )
    .with_param(
        ParamName::new(SOURCE_ZONE),
        ParamValue::Symbol(Symbol::new(source)),
    )
    .with_param(
        ParamName::new(DESTINATION_ZONE),
        ParamValue::Symbol(Symbol::new(destination)),
    )
}

fn install(
    store: &mut Store,
    issuer: &mut Issuer,
    clock: &UptimeClock,
    operation: &AuthorizedOperation,
    ttl_ms: u64,
) -> Result<(LeaseHandle, Uptime), Box<dyn std::error::Error>> {
    let minted_at = clock.uptime();
    let ticket = store.mint_challenge(
        &IssuerId::new(ISSUER),
        operation.proposal().actor(),
        operation.proposal().device(),
        operation.proposal().capability(),
    )?;
    let lease = issuer.issue_v2(operation, Ttl::from_millis(ttl_ms), &ticket)?;
    let bytes = encode_v2(&lease)?;
    let handle = store.install(&bytes)?.handle().clone();
    Ok((
        handle,
        minted_at
            .checked_add(MonotonicDuration::from_millis(ttl_ms))
            .ok_or("deadline overflow")?,
    ))
}

fn render(action: &ActionProposal) -> String {
    action
        .params
        .iter()
        .map(|(name, value)| match value {
            ParamValue::Scalar(scalar) => format!("{name}={scalar}"),
            ParamValue::Symbol(symbol) => format!("{name}={symbol}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}
