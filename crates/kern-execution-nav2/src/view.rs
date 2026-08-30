//! A terminal view of what Kern knows.
//!
//! Its whole job is to make one distinction visible:
//!
//! ```text
//! authority: LAPSED — LeaseExpired
//! execution: Running
//! ```
//!
//! Lapsed authority is not a stopped machine. The wording here never claims a
//! physical state, and there is deliberately no rendering for the words "safe"
//! or "stopped".

use std::format;
use std::string::String;

use kern_execution::{
    AuthorityState, CancellationState, ExecutionRecord, ExecutionState, NotStartedReason,
    TerminalOutcome, Transition, TransitionKind,
};

/// The lease identifier, as hex. Short enough to read off a terminal, long
/// enough to correlate with an issuance record.
fn lease_hex(lease: kern_core::LeaseId) -> String {
    let mut out = String::with_capacity(32);
    for byte in lease.as_bytes() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn authority_line(state: AuthorityState) -> String {
    match state {
        AuthorityState::Current => String::from("authority: CURRENT"),
        AuthorityState::Lapsed { reason, .. } => {
            format!("authority: LAPSED — {reason:?}")
        }
    }
}

fn execution_line(state: ExecutionState) -> String {
    let text = match state {
        ExecutionState::Prepared => String::from("Prepared"),
        ExecutionState::NotStarted(reason) => match reason {
            NotStartedReason::AuthorityLost(why) => format!("NotStarted — AuthorityLost({why:?})"),
            NotStartedReason::Rejected(why) => format!("NotStarted — Rejected({why:?})"),
            NotStartedReason::Abandoned => String::from("NotStarted — Abandoned"),
        },
        ExecutionState::Submitted => String::from("Submitted"),
        ExecutionState::Running => String::from("Running"),
        ExecutionState::Completed => String::from("Completed"),
        ExecutionState::Failed(class) => format!("Failed({class:?})"),
        ExecutionState::Cancelled => String::from("Cancelled"),
        ExecutionState::Disputed { first, conflicting } => format!(
            "Disputed — contradictory evidence: {} vs {}",
            outcome(first),
            outcome(conflicting)
        ),
        ExecutionState::Unknown { phase, last_known } => {
            format!("Unknown({phase:?}) — last known {last_known:?}")
        }
    };
    format!("execution: {text}")
}

fn outcome(outcome: TerminalOutcome) -> &'static str {
    match outcome {
        TerminalOutcome::Completed => "Completed",
        TerminalOutcome::Failed(_) => "Failed",
        TerminalOutcome::Cancelled => "Cancelled",
    }
}

fn cancellation_line(state: CancellationState) -> String {
    let text = match state {
        CancellationState::NotRequested => String::from("NotRequested"),
        CancellationState::Requested { .. } => String::from("REQUESTED"),
        CancellationState::RequestAccepted { .. } => String::from("REQUEST ACCEPTED (received)"),
        CancellationState::Confirmed { .. } => String::from("CONFIRMED by executor"),
        CancellationState::Refused(refusal) => format!("Refused({refusal:?})"),
        CancellationState::RequestUnknown => String::from("RequestUnknown"),
        CancellationState::Moot => String::from("Moot"),
    };
    format!("cancellation: {text}")
}

/// Renders one execution, with a caller-supplied operation label.
///
/// The label comes from the caller because the record holds only a
/// [`CommandDigest`](kern_execution::CommandDigest): the parameters are the
/// host's to keep, and the view does not pretend Kern stored them.
pub fn render_execution<O>(
    record: &ExecutionRecord<O>,
    label: &str,
    latest: Option<&Transition>,
) -> String {
    let mut out = format!(
        "exec {:05} {label}\n  lease {}\n  {}\n  {}\n  {}",
        record.execution_id().as_u128(),
        lease_hex(record.handle().lease_id()),
        authority_line(record.authority()),
        execution_line(record.execution()),
        cancellation_line(record.cancellation()),
    );
    if let Some(transition) = latest {
        out.push_str(&format!("\n  last: {}", transition_label(transition.kind)));
    }
    out
}

/// A short label for one journal entry.
pub fn transition_label(kind: TransitionKind) -> String {
    match kind {
        TransitionKind::Prepared { .. } => String::from("Prepared"),
        TransitionKind::SubmissionAccepted => String::from("SubmissionAccepted"),
        TransitionKind::SubmissionUnknown => String::from("SubmissionUnknown"),
        TransitionKind::NotStarted(reason) => format!("NotStarted({reason:?})"),
        TransitionKind::ObservedRunning => String::from("ObservedRunning"),
        TransitionKind::AuthorityLapsed(reason) => format!("AuthorityLapsed({reason:?})"),
        TransitionKind::CancellationRequested(action) => {
            format!("CancellationRequested({action:?})")
        }
        TransitionKind::CancellationRequestOutcome(outcome) => {
            format!("CancellationRequestOutcome({outcome:?})")
        }
        TransitionKind::CancellationConfirmed => String::from("CancellationConfirmed"),
        TransitionKind::CancellationMoot => String::from("CancellationMoot"),
        TransitionKind::LapseNotRequestedNoOperation => {
            String::from("LapseNotRequested(no operation identity)")
        }
        TransitionKind::Terminal(result) => format!("Terminal({})", outcome(result)),
        TransitionKind::BecameUnknown { phase, .. } => format!("BecameUnknown({phase:?})"),
        TransitionKind::DisputeOpened { .. } => String::from("DisputeOpened"),
        TransitionKind::DisputeObservedAgain => String::from("DisputeObservedAgain"),
        TransitionKind::DisputeResolved { .. } => String::from("DisputeResolved"),
        TransitionKind::StaleObservationDropped => String::from("StaleObservationDropped"),
        TransitionKind::UnmatchedObservation => String::from("UnmatchedObservation"),
        TransitionKind::LinkDisconnected => String::from("LinkDisconnected"),
        TransitionKind::LinkRestored => String::from("LinkRestored"),
        TransitionKind::UnknownResolvedByReconcile => String::from("UnknownResolvedByReconcile"),
        TransitionKind::ReconciliationDiscovered { .. } => String::from("ReconciliationDiscovered"),
        TransitionKind::ReconciliationUnsupported => String::from("ReconciliationUnsupported"),
        TransitionKind::LapseRequestedForUnattributed => {
            String::from("LapseRequestedForUnattributed")
        }
        TransitionKind::RecordReclaimed => String::from("RecordReclaimed"),
    }
}

/// A one-line label for a navigate operation, in metres, from Kern's integer
/// units.
pub fn navigate_label(x_mm: i64, y_mm: i64, yaw_mdeg: i64, max_speed_mm_s: i64) -> String {
    format!(
        "navigate({:.3} m, {:.3} m, yaw {:.1}°, <= {} mm/s)",
        x_mm as f64 / 1000.0,
        y_mm as f64 / 1000.0,
        yaw_mdeg as f64 / 1000.0,
        max_speed_mm_s
    )
}
