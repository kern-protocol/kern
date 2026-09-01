//! The Kern adversarial evaluation harness.
//!
//! # What this measures
//!
//! Whether unauthorized proposals become physical authority. Not whether a
//! language model behaves, not whether a robot is safe, and not whether any of
//! this is certified for anything.
//!
//! ```text
//! Scenario
//!   -> ExperimentRunner        fixture model | live model | authority probe
//!   -> the existing public Kern APIs, with no privileged path
//!   -> ObservationCollector    the governor's own journal
//!   -> ExperimentRecord        one JSON object
//!   -> report                  counts, denominators, latencies
//! ```
//!
//! # What it deliberately is not
//!
//! It is not a safety evaluation. Kern governs authority; it does not certify
//! physical safety, and no metric in this crate is named as though it did. The
//! word "safe" does not appear as a measurement anywhere, and
//! [`crate::report`] refuses to emit a rate without its numerator and
//! denominator beside it.
//!
//! # No backdoors
//!
//! The evaluator respects exactly the boundaries production respects. It holds
//! no test-only constructor for an `AuthorizedOperation`, a `SignedLease`, or a
//! `LeaseHandle`; it contains no `unsafe`; and it reaches no private state. Its
//! fault-injection surface is the set of seams an operator also has: an injected
//! clock, another lease, a backend that can lose its link, and a proposal source
//! that can say anything it likes.
//!
//! If the evaluator could manufacture authority, its evidence would be evidence
//! about the evaluator.

#![forbid(unsafe_code)]

pub mod authority_probe;
pub mod invariant;
pub mod json;
pub mod record;
pub mod report;
pub mod runner;
pub mod scenario;
pub mod world;

use std::collections::BTreeMap;

use kern_core::{
    ActionProposal, CapabilityName, DeviceId, ParamName, ParamValue, PolicyDecision, SubjectId,
};
use kern_execution_nav2::{DESTINATION_X_MM, DESTINATION_Y_MM, MAX_SPEED_MM_S, NAVIGATE, YAW_MDEG};

pub use invariant::Violation;
pub use record::{ExperimentRecord, Mode, Stage};
pub use runner::{run_scenario, RunConfig};
pub use scenario::{Category, Expect, Scenario, ScenarioError, SCENARIO_VERSION};

/// Builds a `navigate` proposal for the scenarios that do not go through a model.
///
/// Still an `ActionProposal`: intent, carrying no authority, which the registry
/// and the evaluator then judge exactly as they judge a model's.
pub fn navigate_proposal(x_mm: i64, y_mm: i64, yaw_mdeg: i64, speed_mm_s: i64) -> ActionProposal {
    ActionProposal::new(
        SubjectId::new(world::SUBJECT),
        DeviceId::new(world::DEVICE),
        CapabilityName::new(NAVIGATE).expect("a non-empty literal"),
    )
    .with_param(ParamName::new(DESTINATION_X_MM), ParamValue::Scalar(x_mm))
    .with_param(ParamName::new(DESTINATION_Y_MM), ParamValue::Scalar(y_mm))
    .with_param(ParamName::new(YAW_MDEG), ParamValue::Scalar(yaw_mdeg))
    .with_param(
        ParamName::new(MAX_SPEED_MM_S),
        ParamValue::Scalar(speed_mm_s),
    )
}

/// A readable reason for a refusal, rendered from the evaluator's own output.
///
/// Only the bounds the proposal actually broke. Kern never rewrites a proposal
/// to fit, so this is a description of the refusal and never a counter-offer the
/// harness acts on.
pub fn denial_detail(
    decision: &PolicyDecision,
    params: &BTreeMap<ParamName, ParamValue>,
) -> String {
    match decision {
        PolicyDecision::Authorized { .. } => String::from("authorized"),
        PolicyDecision::Denied => String::from("no policy grants this operation"),
        PolicyDecision::NotAuthorizedAsProposed { .. } => {
            let feedback = kern_ai::ConstraintFeedback::violations(decision, params);
            if feedback.is_empty() {
                String::from("outside the grantable bounds")
            } else {
                feedback.to_text().replace('\n', "; ")
            }
        }
    }
}

/// The source revision, when the harness can read one.
///
/// Best effort, and `None` rather than a guess. A record that named the wrong
/// revision would be worse than one that admits it does not know.
pub fn git_revision() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let revision = String::from_utf8(output.stdout).ok()?;
    let revision = revision.trim().to_string();
    (!revision.is_empty()).then_some(revision)
}
