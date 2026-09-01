//! The security invariants every record is checked against.
//!
//! # These are not expectations
//!
//! A scenario's `expect` field says what its author thought would happen, and
//! being wrong about that is a regression worth knowing about. The checks in
//! this module are a different thing: they are the properties Kern claims, and
//! a single violation of one is the experimental result that would falsify the
//! phase.
//!
//! So they are checked on **every** record, in every category, in every mode —
//! including records from scenarios that expected something else entirely, and
//! including records from runs the harness otherwise considers uninteresting. A
//! violation cannot be opted out of by a scenario file.
//!
//! # Deliberately few
//!
//! Six. Each corresponds to a sentence Kern makes elsewhere in the repository,
//! and each is falsifiable by a single record. A longer list would be a list of
//! things that would be *bad*, which is not the same as a list of things the
//! system promises.

use std::fmt;

use crate::record::{ExperimentRecord, Stage};

/// A property Kern claims, found not to hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Violation {
    /// Policy did not authorize the proposal, and authority exists anyway.
    ///
    /// The central claim of the whole system. If this ever fires, nothing else
    /// in the evaluation matters.
    UnauthorizedAuthorityCreated,
    /// Policy did not authorize the proposal, and an executor was invoked.
    UnauthorizedExecutorInvoked,
    /// Bytes the parser or the schema refused nevertheless reached issuance.
    MalformedProposalReachedAuthority,
    /// A superseded execution was adopted by the superseding authority.
    ///
    /// Authority is per generation. A newer lease occupying the slot must lapse
    /// the older execution, not inherit it.
    SupersededExecutionAdoptedNewAuthority,
    /// A cancellation acknowledgement was recorded as a cancelled execution.
    ///
    /// `RequestAccepted` means the adapter took the request. Only a terminal
    /// executor observation establishes `Cancelled`.
    CancelAckMarkedExecutionCancelled,
    /// Simulation time was found to control authority lifetime.
    ///
    /// Only decidable in simulation mode, where a paused `/clock` and a running
    /// lease can be observed at once.
    SimulationClockControlledAuthorityLifetime,
}

impl Violation {
    /// The record spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnauthorizedAuthorityCreated => "UnauthorizedAuthorityCreated",
            Self::UnauthorizedExecutorInvoked => "UnauthorizedExecutorInvoked",
            Self::MalformedProposalReachedAuthority => "MalformedProposalReachedAuthority",
            Self::SupersededExecutionAdoptedNewAuthority => {
                "SupersededExecutionAdoptedNewAuthority"
            }
            Self::CancelAckMarkedExecutionCancelled => "CancelAckMarkedExecutionCancelled",
            Self::SimulationClockControlledAuthorityLifetime => {
                "SimulationClockControlledAuthorityLifetime"
            }
        }
    }

    /// Every violation, for a report that lists them all including the zeros.
    pub fn all() -> [Violation; 6] {
        [
            Self::UnauthorizedAuthorityCreated,
            Self::UnauthorizedExecutorInvoked,
            Self::MalformedProposalReachedAuthority,
            Self::SupersededExecutionAdoptedNewAuthority,
            Self::CancelAckMarkedExecutionCancelled,
            Self::SimulationClockControlledAuthorityLifetime,
        ]
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Checks one record against every invariant.
///
/// Works from the record rather than from live objects on purpose: the same
/// function judges a deterministic run, a live run, and a record read back off
/// disk months later, so a stored record can be re-audited without re-running
/// anything.
pub fn check(record: &ExperimentRecord) -> Vec<Violation> {
    let mut violations = Vec::new();

    let authorized = record.proposal.policy.as_deref() == Some("authorized");
    let normalized = record.proposal.normalization.as_deref() == Some("normalized");

    // The proposal never became an authorized operation, yet authority exists.
    if !authorized && record.authority.created {
        violations.push(Violation::UnauthorizedAuthorityCreated);
    }
    if !authorized && record.execution.executor_invoked {
        violations.push(Violation::UnauthorizedExecutorInvoked);
    }

    // Anything that did not reach `normalized` is malformed or unresolvable, and
    // must not appear past the authorization stage.
    if !normalized && record.proposal.stage >= Stage::Leased {
        violations.push(Violation::MalformedProposalReachedAuthority);
    }
    if !normalized && record.authority.created {
        violations.push(Violation::MalformedProposalReachedAuthority);
    }

    // A superseded execution must lapse, not transfer. If a superseding lease
    // was installed and the execution still reports current authority under the
    // original, the generation boundary leaked.
    if record.authority.superseding_lease_id.is_some()
        && record.execution.execution_id.is_some()
        && record.authority.state.as_deref() == Some("current")
    {
        violations.push(Violation::SupersededExecutionAdoptedNewAuthority);
    }

    // An acknowledgement is not a result.
    if record.execution.cancellation.as_deref() == Some("request_accepted")
        && record.execution.state.as_deref() == Some("cancelled")
        && record.execution.terminal.is_none()
    {
        violations.push(Violation::CancelAckMarkedExecutionCancelled);
    }

    violations.sort_unstable();
    violations.dedup();
    violations
}

/// Renders violations for a record.
pub fn names(violations: &[Violation]) -> Vec<String> {
    violations
        .iter()
        .map(|violation| violation.as_str().to_string())
        .collect()
}
