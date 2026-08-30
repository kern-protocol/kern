//! The live Phase 6 demo driver: policy, lease, governor, Nav2, Gazebo.
//!
//! ```text
//! ros2 launch kern_nav2_demo demo.launch.py          # world + Nav2 + robot
//! cargo run --bin kern-nav2-demo -- expiry --ttl-ms 6000
//! ```
//!
//! Scenarios:
//!
//! ```text
//! allowed     a lease long enough to reach the goal
//! expiry      a lease shorter than the drive, so authority lapses mid-navigation
//! supersede   a second lease installed into the same slot while the first runs
//! ```
//!
//! # This is a demo driver, not a deployment topology
//!
//! It holds an issuing key in the same process as the enforcer, which a real
//! deployment never does: the issuer is a separate control plane, and the point
//! of a signed lease is that the edge does not have to trust the requester. What
//! it does share with a deployment is everything below the issuance step — the
//! enforcer, the governor, the adapter, and the authority semantics.
//!
//! # Time
//!
//! Lease lifetime is measured against process uptime from a monotonic
//! `std::time::Instant`. ROS time and Gazebo simulation time are deliberately
//! not consulted: simulation time can pause, jump, or reset, and authority
//! lifetime must not move when it does.

use std::time::{Duration, Instant};

use kern_authority::{
    AuthorizedOperation, CountingNonces, Ed25519Signer, LeaseIssuer, SequentialLeaseIds,
};
use kern_core::wire::encode_v2;
use kern_core::{
    ActionProposal, CapabilityName, Challenge, ConstraintSet, DeviceId, EnforcerSessionId,
    Interval, IssuerId, KeyId, MonotonicClock, MonotonicDuration, NormalizedActionProposal,
    ParamConstraint, ParamName, ParamValue, SubjectId, SystemClock, Ttl, Uptime,
};
use kern_enforcer::{ChallengeSource, EnforcerStore, EntropyError, LeaseHandle, TrustStore};
use kern_execution::{
    ExecutionGovernor, Executor, GovernorConfig, LapseAction, SequentialExecutionIds, StartupPolicy,
};
use kern_execution_nav2::{
    navigate_label, navigate_schema, render_execution, Nav2Config, Nav2Executor, DESTINATION_X_MM,
    DESTINATION_Y_MM, MAX_SPEED_MM_S, NAVIGATE, YAW_MDEG,
};
use kern_nav2_bridge::{ros::BridgeConfig, RosNav2Backend};
use kern_policy::{Authority, CapabilityRegistry, Policy, PolicyId, PolicySet, Selector};

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
    scenario: String,
    ttl_ms: u64,
    x_mm: i64,
    y_mm: i64,
    yaw_mdeg: i64,
    speed_mm_s: i64,
    action: String,
    run_for: Duration,
    authority_watch: Duration,
}

impl Options {
    fn parse() -> Self {
        let mut options = Self {
            scenario: String::from("expiry"),
            ttl_ms: 6_000,
            x_mm: 6_000,
            y_mm: 0,
            yaw_mdeg: 0,
            speed_mm_s: 300,
            action: String::from("/navigate_to_pose"),
            run_for: Duration::from_secs(90),
            authority_watch: Duration::ZERO,
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            let mut value = || args.next().unwrap_or_default();
            match arg.as_str() {
                "--ttl-ms" => options.ttl_ms = value().parse().unwrap_or(options.ttl_ms),
                "--x-mm" => options.x_mm = value().parse().unwrap_or(options.x_mm),
                "--y-mm" => options.y_mm = value().parse().unwrap_or(options.y_mm),
                "--yaw-mdeg" => options.yaw_mdeg = value().parse().unwrap_or(options.yaw_mdeg),
                "--speed-mm-s" => {
                    options.speed_mm_s = value().parse().unwrap_or(options.speed_mm_s)
                }
                "--action" => options.action = value(),
                "--run-for-s" => {
                    options.run_for = Duration::from_secs(value().parse().unwrap_or(90))
                }
                "--authority-watch-s" => {
                    options.authority_watch = Duration::from_secs(value().parse().unwrap_or(0))
                }
                other => options.scenario = other.to_string(),
            }
        }
        options
    }
}

const SUBJECT: &str = "planner_a";
const DEVICE: &str = "cafe_bot_01";
const ISSUER: &str = "issuer_dev";
/// Demo signing key. A deployment's issuer key never lives in the edge process.
const DEV_SEED: [u8; 32] = [7u8; 32];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse();
    let clock = UptimeClock {
        start: Instant::now(),
    };

    let mut session_bytes = [0u8; 32];
    // A predictable session identifier is a replayable one, so entropy failure
    // is fatal here exactly as it is inside the enforcer.
    getrandom::getrandom(&mut session_bytes).map_err(|_| "entropy source unavailable")?;
    let session = EnforcerSessionId::from_bytes(session_bytes);

    let signer = Ed25519Signer::from_seed(KeyId::new("dev-1"), DEV_SEED);
    let mut trust = TrustStore::new();
    trust.authorize(
        IssuerId::new(ISSUER),
        KeyId::new("dev-1"),
        signer.verifying_key_bytes(),
    )?;

    let watch_clock = clock.clone();
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

    let backend = RosNav2Backend::start(BridgeConfig {
        action_name: options.action.clone(),
        ..BridgeConfig::default()
    })?;
    let mut adapter = Nav2Executor::new(backend, Nav2Config::default())?;
    let mut governor = ExecutionGovernor::new(
        session,
        GovernorConfig {
            capacity: 4,
            journal_capacity: 128,
            lapse_action: LapseAction::Cancel,
            // Kern holds no record of anything that ran before this process, so
            // it neither adopts nor instructs what it cannot attribute.
            startup_policy: StartupPolicy::ReportOnly,
            observation_budget: 16,
        },
        clock,
        SequentialExecutionIds::starting_at(1),
        adapter.declaration(),
    )?;

    let operation = authorized_operation(&options)?;
    let handle = install(&mut store, &mut issuer, &operation, options.ttl_ms)?;

    let label = navigate_label(
        options.x_mm,
        options.y_mm,
        options.yaw_mdeg,
        options.speed_mm_s,
    );
    println!(
        "scenario {} | lease ttl {} ms",
        options.scenario, options.ttl_ms
    );

    let prepared = governor.prepare(&store, &handle, &operation)?;
    let execution = prepared.execution_id();
    // Provenance is written before anything can move: the host owns the
    // parameters, Kern owns the digest that names them.
    println!(
        "prepared exec {execution}\n  lease    {:?}\n  artifact {:?}\n  digest   {:?}",
        prepared.handle().lease_id(),
        prepared.handle().artifact(),
        prepared.command_digest(),
    );
    let receipt = prepared.submit(&store, &mut adapter);
    println!(
        "submitted: state {:?}, executor invoked {}",
        receipt.state(),
        receipt.executor_invoked()
    );

    let deadline = Instant::now() + options.run_for;
    let mut superseded = false;
    let started = Instant::now();

    while Instant::now() < deadline {
        let report = governor.tick_observed(&store, &mut adapter);

        if !governor.journal().is_empty() {
            let record = governor.record(execution).expect("recorded");
            println!(
                "\n{}",
                render_execution(record, &label, governor.journal().last())
            );
            if report.session_mismatch {
                println!("  WIRING FAULT: the store is not this governor's session");
            }
        }

        if options.scenario == "supersede"
            && !superseded
            && started.elapsed() > Duration::from_secs(4)
        {
            let newer = install(&mut store, &mut issuer, &operation, options.ttl_ms)?;
            println!(
                "\ninstalled a newer lease {:?} into the same slot",
                newer.lease_id()
            );
            superseded = true;
        }

        if let Some(record) = governor.record(execution) {
            if record.execution().is_terminal() {
                println!("\nterminal: {:?}", record.execution());
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Authority lifetime is measured against this process's monotonic uptime and
    // nothing else. Watching it after the execution ends is how a paused
    // simulator can be seen not to freeze a lease: /clock stops, the deadline
    // does not.
    if !options.authority_watch.is_zero() {
        println!("\nwatching authority lifetime against process uptime");
        let until = Instant::now() + options.authority_watch;
        while Instant::now() < until {
            println!(
                "  uptime {:>6} ms   check_authority: {:?}",
                watch_clock.uptime().as_millis(),
                store.check_authority(&handle)
            );
            std::thread::sleep(Duration::from_secs(3));
        }
    }

    adapter.shutdown();
    println!("\nKern requested what it could and recorded what it saw.");
    println!("It makes no claim about whether the machine physically stopped.");
    Ok(())
}

fn authorized_operation(
    options: &Options,
) -> Result<NormalizedActionProposal, Box<dyn std::error::Error>> {
    let mut registry = CapabilityRegistry::new();
    registry.register(DeviceId::new(DEVICE), navigate_schema()?)?;

    let bounded = |lower, upper| {
        ParamConstraint::Numeric(Interval::between(lower, upper).expect("ordered bounds"))
    };
    let policy = Policy::new(
        PolicyId::new("delivery"),
        Selector::Exactly(SubjectId::new(SUBJECT)),
        Selector::Exactly(DeviceId::new(DEVICE)),
        Selector::Exactly(CapabilityName::new(NAVIGATE)?),
        ConstraintSet::from_constraints([
            (
                ParamName::new(MAX_SPEED_MM_S),
                ParamConstraint::at_most(400),
            ),
            (ParamName::new(DESTINATION_X_MM), bounded(-20_000, 20_000)),
            (ParamName::new(DESTINATION_Y_MM), bounded(-20_000, 20_000)),
            (ParamName::new(YAW_MDEG), bounded(-180_000, 180_000)),
        ]),
    )?;
    let authority = Authority::new(registry, PolicySet::from_policies([policy])?);

    let proposal = ActionProposal::new(
        SubjectId::new(SUBJECT),
        DeviceId::new(DEVICE),
        CapabilityName::new(NAVIGATE)?,
    )
    .with_param(
        ParamName::new(DESTINATION_X_MM),
        ParamValue::Scalar(options.x_mm),
    )
    .with_param(
        ParamName::new(DESTINATION_Y_MM),
        ParamValue::Scalar(options.y_mm),
    )
    .with_param(
        ParamName::new(YAW_MDEG),
        ParamValue::Scalar(options.yaw_mdeg),
    )
    .with_param(
        ParamName::new(MAX_SPEED_MM_S),
        ParamValue::Scalar(options.speed_mm_s),
    );

    let evaluation = authority.evaluate(&proposal)?;
    let authorized = AuthorizedOperation::from_evaluation(evaluation)
        .ok_or("policy did not authorize this navigation")?;
    Ok(authorized.proposal().clone())
}

fn install(
    store: &mut EnforcerStore<UptimeClock, OsChallenges>,
    issuer: &mut LeaseIssuer<Ed25519Signer, SystemClock, CountingNonces, SequentialLeaseIds>,
    operation: &NormalizedActionProposal,
    ttl_ms: u64,
) -> Result<LeaseHandle, Box<dyn std::error::Error>> {
    let ticket = store.mint_challenge(
        &IssuerId::new(ISSUER),
        operation.actor(),
        operation.device(),
        operation.capability(),
    )?;

    let mut registry = CapabilityRegistry::new();
    registry.register(DeviceId::new(DEVICE), navigate_schema()?)?;
    let authorized = re_authorize(operation)?;
    let lease = issuer.issue_v2(&authorized, Ttl::from_millis(ttl_ms), &ticket)?;
    let bytes = encode_v2(&lease)?;
    Ok(store.install(&bytes)?.handle().clone())
}

/// Re-runs the authorization so issuance receives an `AuthorizedOperation`
/// rather than a proposal: nothing signs bounds that policy did not grant.
fn re_authorize(
    operation: &NormalizedActionProposal,
) -> Result<AuthorizedOperation, Box<dyn std::error::Error>> {
    let mut registry = CapabilityRegistry::new();
    registry.register(DeviceId::new(DEVICE), navigate_schema()?)?;

    let bounded = |lower, upper| {
        ParamConstraint::Numeric(Interval::between(lower, upper).expect("ordered bounds"))
    };
    let policy = Policy::new(
        PolicyId::new("delivery"),
        Selector::Exactly(operation.actor().clone()),
        Selector::Exactly(operation.device().clone()),
        Selector::Exactly(operation.capability().clone()),
        ConstraintSet::from_constraints([
            (
                ParamName::new(MAX_SPEED_MM_S),
                ParamConstraint::at_most(400),
            ),
            (ParamName::new(DESTINATION_X_MM), bounded(-20_000, 20_000)),
            (ParamName::new(DESTINATION_Y_MM), bounded(-20_000, 20_000)),
            (ParamName::new(YAW_MDEG), bounded(-180_000, 180_000)),
        ]),
    )?;
    let authority = Authority::new(registry, PolicySet::from_policies([policy])?);

    let mut proposal = ActionProposal::new(
        operation.actor().clone(),
        operation.device().clone(),
        operation.capability().clone(),
    );
    for (name, value) in operation.params() {
        proposal = proposal.with_param(name.clone(), value.clone());
    }
    let evaluation = authority.evaluate(&proposal)?;
    AuthorizedOperation::from_evaluation(evaluation)
        .ok_or_else(|| "policy did not authorize this navigation".into())
}
