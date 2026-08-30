//! The Phase 6 demo, without a robot.
//!
//! ```text
//! cargo run -p kern-execution-nav2 --example demo -- allowed
//! cargo run -p kern-execution-nav2 --example demo -- expiry
//! cargo run -p kern-execution-nav2 --example demo -- supersede
//! cargo run -p kern-execution-nav2 --example demo -- disconnect
//! ```
//!
//! Same governor, same adapter, and the same terminal view the ROS bridge
//! prints. Only the backend differs: this one is deterministic and speaks no
//! ROS, so the authority story can be shown and re-shown without a simulator.
//!
//! What the `expiry` scenario exists to make visible:
//!
//! ```text
//! authority: LAPSED — LeaseExpired
//! execution: Running
//! ```
//!
//! Kern stopped granting authority. Nothing here claims the machine stopped.

#[path = "harness.rs"]
mod harness;

use kern_execution::{ExecutionId, Executor};
use kern_execution_nav2::backend::BackendEvent;
use kern_execution_nav2::{navigate_label, render_execution, FakeNav2Backend, Nav2OperationId};

use harness::{adapter, governor, operation, Harness, LEASE_TTL_MS};

const GOAL: Nav2OperationId =
    Nav2OperationId::from_uuid([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
const SPEED_MM_S: i64 = 300;

fn main() {
    let scenario = std::env::args().nth(1).unwrap_or_else(|| "expiry".into());
    match scenario.as_str() {
        "allowed" => allowed(),
        "expiry" => expiry(),
        "supersede" => supersede(),
        "disconnect" => disconnect(),
        other => {
            eprintln!("unknown scenario {other}: try allowed | expiry | supersede | disconnect");
            std::process::exit(2);
        }
    }
}

fn banner(title: &str) {
    println!("\n=== {title} ===");
}

fn show(governor: &harness::Governor, execution: ExecutionId, note: &str) {
    let record = governor.record(execution).expect("recorded");
    let latest = governor.journal().last();
    println!(
        "\n[{note}]\n{}",
        render_execution(
            record,
            &navigate_label(4_000, 1_200, 90_000, SPEED_MM_S),
            latest
        )
    );
}

/// Demo A: authority live from goal to completion.
fn allowed() {
    banner("Demo A — authorized navigation");
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);
    let op = operation(SPEED_MM_S);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("policy and lease permit it")
        .submit(&harness.store, &mut adapter);
    show(&governor, receipt.execution_id(), "goal accepted by Nav2");

    adapter
        .backend_mut()
        .emit(BackendEvent::Feedback { operation: GOAL });
    governor.tick_observed(&harness.store, &mut adapter);
    show(&governor, receipt.execution_id(), "robot navigating");

    adapter
        .backend_mut()
        .emit(BackendEvent::Succeeded { operation: GOAL });
    governor.tick_observed(&harness.store, &mut adapter);
    show(&governor, receipt.execution_id(), "goal reached");

    println!(
        "\nspeed limit applied then released: {:?}",
        adapter.backend().speed_limits
    );
}

/// Demo B: the lease expires while the robot is still moving.
fn expiry() {
    banner("Demo B — lease expiry mid-navigation");
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);
    let op = operation(SPEED_MM_S);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("policy and lease permit it")
        .submit(&harness.store, &mut adapter);
    adapter
        .backend_mut()
        .emit(BackendEvent::Feedback { operation: GOAL });
    governor.tick_observed(&harness.store, &mut adapter);
    show(&governor, receipt.execution_id(), "t2 robot moving");

    harness.clock.advance(LEASE_TTL_MS + 1);
    governor.tick_observed(&harness.store, &mut adapter);
    show(
        &governor,
        receipt.execution_id(),
        "t5 AUTHORITY LAPSED, t6 CANCELLATION REQUESTED",
    );
    println!("  note: authority is gone; the operation is still running.");
    println!("        Kern asked Nav2 to cancel. Kern does not claim the robot stopped.");

    adapter
        .backend_mut()
        .emit(BackendEvent::Canceled { operation: GOAL });
    governor.tick_observed(&harness.store, &mut adapter);
    show(
        &governor,
        receipt.execution_id(),
        "t8 CANCELLATION CONFIRMED by Nav2",
    );
}

/// Demo C: a newer lease supersedes the one an execution runs under.
fn supersede() {
    banner("Demo C — supersession");
    let mut harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);
    let op = operation(SPEED_MM_S);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("policy and lease permit it")
        .submit(&harness.store, &mut adapter);
    adapter
        .backend_mut()
        .emit(BackendEvent::Feedback { operation: GOAL });
    governor.tick_observed(&harness.store, &mut adapter);

    let newer = harness.supersede();
    governor.tick_observed(&harness.store, &mut adapter);
    show(
        &governor,
        receipt.execution_id(),
        "newer lease installed in the same slot",
    );
    println!(
        "  execution still names lease {:?}; the new lease {:?} did not adopt it.",
        governor
            .record(receipt.execution_id())
            .unwrap()
            .handle()
            .lease_id(),
        newer.lease_id()
    );
}

/// The disconnect case: knowledge is lost, and nothing is invented to replace it.
fn disconnect() {
    banner("Demo D — adapter disconnect during navigation");
    let harness = Harness::new();
    let mut adapter = adapter(FakeNav2Backend::new());
    let mut governor = governor(harness.clock.clone(), &adapter);
    let op = operation(SPEED_MM_S);

    let receipt = governor
        .prepare(&harness.store, &harness.handle, &op)
        .expect("policy and lease permit it")
        .submit(&harness.store, &mut adapter);
    adapter
        .backend_mut()
        .emit(BackendEvent::Feedback { operation: GOAL });
    governor.tick_observed(&harness.store, &mut adapter);

    adapter.backend_mut().disconnect();
    governor.tick_observed(&harness.store, &mut adapter);
    show(&governor, receipt.execution_id(), "action link lost");
    println!("  Kern no longer knows what the machine is doing. That is not a failure,");
    println!("  and the robot may still be moving under Nav2's own control.");

    let _ = adapter.declaration();
}
