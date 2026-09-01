//! The demo view of one proposal.
//!
//! Four blocks, always in this order, always all four:
//!
//! ```text
//! MODEL       what was proposed, and by whom
//! POLICY      what Kern decided about it
//! AUTHORITY   what authority exists, if any
//! EXECUTION   what is running, if anything
//! ```
//!
//! The blocks are printed even when they are empty, and an empty block prints
//! `NONE` rather than being omitted. That is the whole point of the view: on a
//! denied proposal, the reader should *see* `AUTHORITY: NONE` and
//! `EXECUTION: NONE` sitting under a real model proposal, rather than having to
//! notice that two sections are missing.
//!
//! Nothing here is authority. This module formats a
//! [`ProposalRecord`](crate::ProposalRecord), which is evidence.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use kern_core::{ActionProposal, ParamValue};

use crate::provenance::{NormalizationOutcome, PolicyOutcome, ProposalOutcome, ProposalRecord};

/// Renders a proposal, its decision, and its consequences.
///
/// `proposal` is the [`ActionProposal`](kern_core::ActionProposal) the plane
/// built, when there was one; `detail` is an optional human-readable reason for
/// a refusal, which the host takes from the evaluator's own error or decision.
pub fn render_proposal(
    record: &ProposalRecord,
    proposal: Option<&ActionProposal>,
    detail: Option<&str>,
) -> String {
    let mut out = String::new();

    out.push_str("MODEL\n");
    out.push_str(&format!("  provider: {}\n", record.model().provider()));
    out.push_str(&format!("  model: {}\n", record.model().model()));
    out.push_str(&format!("  invocation: {}\n", record.invocation()));
    out.push_str(&format!("  proposal_id: {}\n", record.proposal_id()));
    if let Some(previous) = record.replan_of() {
        out.push_str(&format!("  replan_of: {previous}\n"));
    }
    match record.response() {
        Some(digest) => out.push_str(&format!("  response: {digest}\n")),
        None => out.push_str("  response: NONE\n"),
    }

    match record.outcome() {
        ProposalOutcome::NoResponse(failure) => {
            out.push_str(&format!("  proposal: NONE — {failure}\n"));
        }
        ProposalOutcome::ParseRejected(error) => {
            out.push_str(&format!("  proposal: REJECTED — {error}\n"));
        }
        ProposalOutcome::NoAction { reason } => {
            out.push_str("  proposal: no_action\n");
            out.push_str(&format!("  reason: {reason}\n"));
        }
        ProposalOutcome::Parsed { capability, reason } => {
            out.push_str(&format!("  proposal: {}\n", label(capability, proposal)));
            out.push_str(&format!("  reason: {reason}\n"));
        }
    }

    out.push_str("\nPOLICY\n");
    match (record.normalization(), record.policy()) {
        (None, _) => out.push_str("  NOT EVALUATED\n"),
        (Some(NormalizationOutcome::Rejected(why)), _) => {
            out.push_str("  NOT A KNOWN OPERATION\n");
            out.push_str(&format!("  reason: {why}\n"));
        }
        (Some(NormalizationOutcome::Normalized), None) => out.push_str("  NOT EVALUATED\n"),
        (Some(NormalizationOutcome::Normalized), Some(outcome)) => {
            out.push_str(match outcome {
                PolicyOutcome::Authorized => "  AUTHORIZED\n",
                PolicyOutcome::NotAuthorizedAsProposed => "  DENIED — not authorized as proposed\n",
                PolicyOutcome::Denied => "  DENIED\n",
            });
            if let Some(detail) = detail {
                out.push_str(&format!("  reason: {detail}\n"));
            }
        }
    }

    out.push_str("\nAUTHORITY\n");
    match record.artifact() {
        Some(artifact) => out.push_str(&format!("  artifact: {artifact:?}\n")),
        None => out.push_str("  NONE\n"),
    }

    out.push_str("\nEXECUTION\n");
    match record.execution() {
        Some(execution) => out.push_str(&format!("  execution_id: {execution}\n")),
        None => out.push_str("  NONE\n"),
    }

    out
}

/// `navigate(destination_x_mm=6000, ...)`, in parameter-name order.
fn label(capability: &str, proposal: Option<&ActionProposal>) -> String {
    let Some(proposal) = proposal else {
        return capability.to_string();
    };
    let args: Vec<String> = proposal
        .params
        .iter()
        .map(|(name, value)| match value {
            ParamValue::Scalar(scalar) => format!("{name}={scalar}"),
            ParamValue::Symbol(symbol) => format!("{name}={symbol}"),
        })
        .collect();
    format!("{capability}({})", args.join(", "))
}
