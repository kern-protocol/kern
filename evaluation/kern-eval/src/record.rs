//! One machine-readable record per experiment.
//!
//! # Why every field is explicit
//!
//! A record has to be readable by somebody who was not present and who does not
//! trust the person who ran it. So an unmeasured value is `null` rather than
//! absent, an unknown execution says `unknown` rather than nothing, and a
//! latency that could not be computed does not become zero. The most important
//! property of this format is that it cannot express "we did not look" and "it
//! did not happen" with the same bytes.
//!
//! # What never goes in
//!
//! API keys, signing keys, verifying keys, challenges, nonces, and raw lease
//! bytes. A record names authority by its artifact digest and its lease
//! identifier, which are identifiers rather than secrets, and carries no
//! material anybody could use to install anything.

use std::fmt;

use crate::json::Obj;

/// The record schema version.
pub const SCHEMA_VERSION: i64 = 1;

/// How far down the trust pipeline a proposal reached.
///
/// This is the single most useful field in the whole record for the malformed
/// and policy-violation categories: it says exactly where the system stopped,
/// rather than only that it did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// Nothing came back from the provider.
    NoResponse,
    /// Bytes arrived and were not parsed.
    Raw,
    /// The strict parser accepted them.
    Parsed,
    /// The registry and schema accepted the operation.
    Normalized,
    /// Policy authorized it.
    Authorized,
    /// A lease was issued for it.
    Leased,
    /// The lease was installed and a handle exists.
    Installed,
    /// The executor was invoked.
    Submitted,
}

impl Default for Stage {
    /// Nothing has been established yet.
    fn default() -> Self {
        Self::NoResponse
    }
}

impl Stage {
    /// The record spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoResponse => "no_response",
            Self::Raw => "raw",
            Self::Parsed => "parsed",
            Self::Normalized => "normalized",
            Self::Authorized => "authorized",
            Self::Leased => "leased",
            Self::Installed => "installed",
            Self::Submitted => "submitted",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which evaluation mode produced a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Fixtures, fake backend, injected clock. No network, no ROS.
    Deterministic,
    /// A live model behind the same trust boundary.
    Live,
    /// A live model, real ROS, real Nav2, real simulator.
    Simulation,
}

impl Mode {
    /// The record spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::Live => "live",
            Self::Simulation => "simulation",
        }
    }

    /// Whether a record from this mode is reproducible byte for byte.
    ///
    /// False for anything involving a live model. A language model's output is
    /// not deterministic, and a record that claimed otherwise would be
    /// inviting a reader to re-run it and conclude the harness is broken.
    pub fn is_reproducible(self) -> bool {
        matches!(self, Self::Deterministic)
    }
}

/// Which provenance a proposal claimed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModelFacts {
    /// The provider label.
    pub provider: String,
    /// The model identifier.
    pub model: String,
    /// The invocation identifier, if a model was invoked.
    pub invocation_id: Option<String>,
}

/// What happened to the proposal, stage by stage.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposalFacts {
    /// The proposal identifier, if a proposal was made.
    pub proposal_id: Option<String>,
    /// The digest of the model's response bytes, if any arrived.
    pub response_digest: Option<String>,
    /// What the parser concluded.
    pub parse: Option<String>,
    /// What normalization concluded.
    pub normalization: Option<String>,
    /// What policy concluded.
    pub policy: Option<String>,
    /// The capability the model named, if it named one.
    pub capability: Option<String>,
    /// The arguments it proposed, rendered in name order.
    pub arguments: Option<String>,
    /// Why it was refused, where a refusal has a reason.
    pub detail: Option<String>,
    /// How far it got.
    pub stage: Stage,
}

/// What authority, if any, came to exist.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthorityFacts {
    /// Whether an authority artifact was installed for this proposal.
    pub created: bool,
    /// The artifact digest, if one exists.
    pub artifact_id: Option<String>,
    /// The lease identifier, if one exists.
    pub lease_id: Option<String>,
    /// Kern's authority position at the end of the run.
    pub state: Option<String>,
    /// Why authority lapsed, if it did.
    pub lapse_reason: Option<String>,
    /// The enforcer's verdict on an installation attempt, for probe scenarios.
    pub install_outcome: Option<String>,
    /// A superseding lease identifier, where one was installed.
    pub superseding_lease_id: Option<String>,
}

/// What the executor was asked to do, and what came back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionFacts {
    /// The execution identifier, if one was allocated.
    pub execution_id: Option<String>,
    /// Whether the adapter was called at all.
    pub executor_invoked: bool,
    /// Kern's belief about progress at the end of the run.
    pub state: Option<String>,
    /// Kern's cancellation position at the end of the run.
    pub cancellation: Option<String>,
    /// The terminal result the executor reported, if it reported one.
    pub terminal: Option<String>,
    /// How many goals reached the backend.
    pub goals_sent: u64,
    /// How many speed limits the adapter applied or cleared.
    pub speed_limit_events: u64,
    /// The largest speed bound the adapter commanded, in metres per second.
    ///
    /// A *commanded* limit. Nothing here is a claim about wheels.
    pub max_commanded_speed_m_s: Option<String>,
}

/// When things happened, in the run's own clock.
///
/// Deterministic runs use the injected test clock, so these are exact
/// millisecond values rather than measurements of a machine. Simulation runs
/// use process uptime. The `clock` field says which.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TimingFacts {
    /// Which clock the values are in.
    pub clock: Option<String>,
    /// When the execution was submitted.
    pub submitted_at_ms: Option<u64>,
    /// When authority was expected to end, where the run knows.
    pub authority_deadline_ms: Option<u64>,
    /// When Kern observed the lapse.
    pub lapse_observed_at_ms: Option<u64>,
    /// When Kern issued a cancellation request.
    pub cancel_requested_at_ms: Option<u64>,
    /// When Kern observed a cancellation confirmation.
    pub cancel_confirmed_at_ms: Option<u64>,
    /// When the last non-zero velocity command was observed.
    ///
    /// Simulation only, and named for exactly what it is. Not a stopping time.
    pub last_nonzero_cmd_vel_at_ms: Option<u64>,
    /// Whether the lapse is measurable against the lease deadline.
    ///
    /// True only when authority ended *because the lease expired*. A lapse
    /// caused by supersession happens whenever the newer lease is installed,
    /// which has nothing to do with the older lease's deadline — subtracting
    /// one from the other produces a large negative number that looks like a
    /// measurement and is not one. Those runs contribute no lapse latency, and
    /// the record says why rather than quietly reporting a nonsense value.
    pub lapse_measurable_against_deadline: bool,
}

impl TimingFacts {
    /// `lapse_observed - authority_deadline`, when the difference means something.
    pub fn lapse_latency_ms(&self) -> Option<i64> {
        if !self.lapse_measurable_against_deadline {
            return None;
        }
        difference(self.lapse_observed_at_ms, self.authority_deadline_ms)
    }

    /// `cancel_requested - lapse_observed`, when both exist.
    pub fn cancel_request_latency_ms(&self) -> Option<i64> {
        difference(self.cancel_requested_at_ms, self.lapse_observed_at_ms)
    }

    /// `cancel_confirmed - cancel_requested`, when both exist.
    pub fn cancel_confirm_latency_ms(&self) -> Option<i64> {
        difference(self.cancel_confirmed_at_ms, self.cancel_requested_at_ms)
    }

    /// `last_nonzero_cmd_vel - lapse_observed`, when both exist.
    pub fn last_command_latency_ms(&self) -> Option<i64> {
        difference(self.last_nonzero_cmd_vel_at_ms, self.lapse_observed_at_ms)
    }
}

/// A latency, or `None` when either end was not observed.
///
/// Never zero for a missing endpoint. A missing timestamp means the event was
/// not observed, and "not observed" arriving in a report as "0 ms" is the exact
/// way a latency table comes to flatter the system it describes.
fn difference(later: Option<u64>, earlier: Option<u64>) -> Option<i64> {
    Some(later? as i64 - earlier? as i64)
}

/// Everything one experiment established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExperimentRecord {
    /// The record schema version.
    pub schema_version: i64,
    /// Identifies the batch this record came from.
    pub run_id: String,
    /// Which evaluation mode produced it.
    pub mode: Mode,
    /// Whether this record is byte-for-byte reproducible.
    pub reproducible: bool,
    /// The source revision, when the harness could read one.
    pub git_revision: Option<String>,
    /// The scenario schema version the scenario was written against.
    pub scenario_version: i64,
    /// Which scenario.
    pub scenario_id: String,
    /// Its category.
    pub category: String,
    /// Its one-line description.
    pub description: String,
    /// The named world it ran against.
    pub world: String,
    /// That world spelled out, so a reader can check it.
    pub world_description: String,
    /// The lease lifetime this run configured, in milliseconds.
    pub ttl_ms: u64,
    /// The perturbation applied.
    pub perturbation: String,
    /// The seed, where the run had one.
    pub seed: Option<u64>,
    /// Provenance.
    pub model: ModelFacts,
    /// The proposal's journey.
    pub proposal: ProposalFacts,
    /// The authority, if any.
    pub authority: AuthorityFacts,
    /// The execution, if any.
    pub execution: ExecutionFacts,
    /// The timing.
    pub timing: TimingFacts,
    /// What the scenario author expected.
    pub expectation: String,
    /// Whether that expectation held, or `None` when the scenario asserts none.
    pub expectation_met: Option<bool>,
    /// Security invariants this record violates. Empty is the only good answer.
    pub violations: Vec<String>,
    /// Anything the harness could not observe, said out loud.
    pub notes: Vec<String>,
}

impl ExperimentRecord {
    /// Renders the record as one JSON object.
    pub fn to_json(&self) -> String {
        let model = Obj::new()
            .str("provider", &self.model.provider)
            .str("model", &self.model.model)
            .opt_str("invocation_id", self.model.invocation_id.as_deref());

        let proposal = Obj::new()
            .opt_str("proposal_id", self.proposal.proposal_id.as_deref())
            .opt_str("response_digest", self.proposal.response_digest.as_deref())
            .opt_str("parse", self.proposal.parse.as_deref())
            .opt_str("normalization", self.proposal.normalization.as_deref())
            .opt_str("policy", self.proposal.policy.as_deref())
            .opt_str("capability", self.proposal.capability.as_deref())
            .opt_str("arguments", self.proposal.arguments.as_deref())
            .opt_str("detail", self.proposal.detail.as_deref())
            .str("stage", self.proposal.stage.as_str());

        let authority = Obj::new()
            .bool("created", self.authority.created)
            .opt_str("artifact_id", self.authority.artifact_id.as_deref())
            .opt_str("lease_id", self.authority.lease_id.as_deref())
            .opt_str("state", self.authority.state.as_deref())
            .opt_str("lapse_reason", self.authority.lapse_reason.as_deref())
            .opt_str("install_outcome", self.authority.install_outcome.as_deref())
            .opt_str(
                "superseding_lease_id",
                self.authority.superseding_lease_id.as_deref(),
            );

        let execution = Obj::new()
            .opt_str("execution_id", self.execution.execution_id.as_deref())
            .bool("executor_invoked", self.execution.executor_invoked)
            .opt_str("state", self.execution.state.as_deref())
            .opt_str("cancellation", self.execution.cancellation.as_deref())
            .opt_str("terminal", self.execution.terminal.as_deref())
            .uint("goals_sent", self.execution.goals_sent)
            .uint("speed_limit_events", self.execution.speed_limit_events)
            .opt_str(
                "max_commanded_speed_m_s",
                self.execution.max_commanded_speed_m_s.as_deref(),
            );

        let timing = Obj::new()
            .opt_str("clock", self.timing.clock.as_deref())
            .opt_int(
                "submitted_at_ms",
                self.timing.submitted_at_ms.map(|v| v as i64),
            )
            .opt_int(
                "authority_deadline_ms",
                self.timing.authority_deadline_ms.map(|v| v as i64),
            )
            .opt_int(
                "lapse_observed_at_ms",
                self.timing.lapse_observed_at_ms.map(|v| v as i64),
            )
            .opt_int(
                "cancel_requested_at_ms",
                self.timing.cancel_requested_at_ms.map(|v| v as i64),
            )
            .opt_int(
                "cancel_confirmed_at_ms",
                self.timing.cancel_confirmed_at_ms.map(|v| v as i64),
            )
            .opt_int(
                "last_nonzero_cmd_vel_at_ms",
                self.timing.last_nonzero_cmd_vel_at_ms.map(|v| v as i64),
            )
            .opt_int("lapse_latency_ms", self.timing.lapse_latency_ms())
            .opt_int(
                "cancel_request_latency_ms",
                self.timing.cancel_request_latency_ms(),
            )
            .opt_int(
                "cancel_confirm_latency_ms",
                self.timing.cancel_confirm_latency_ms(),
            )
            .opt_int(
                "last_command_latency_ms",
                self.timing.last_command_latency_ms(),
            );

        Obj::new()
            .int("schema_version", self.schema_version)
            .str("run_id", &self.run_id)
            .str("mode", self.mode.as_str())
            .bool("reproducible", self.reproducible)
            .opt_str("git_revision", self.git_revision.as_deref())
            .int("scenario_version", self.scenario_version)
            .str("scenario_id", &self.scenario_id)
            .str("category", &self.category)
            .str("description", &self.description)
            .str("world", &self.world)
            .str("world_description", &self.world_description)
            .uint("ttl_ms", self.ttl_ms)
            .str("perturbation", &self.perturbation)
            .opt_int("seed", self.seed.map(|v| v as i64))
            .obj("model", model)
            .obj("proposal", proposal)
            .obj("authority", authority)
            .obj("execution", execution)
            .obj("timing", timing)
            .str("expectation", &self.expectation)
            .opt_str(
                "expectation_met",
                self.expectation_met
                    .map(|met| if met { "yes" } else { "no" }),
            )
            .str_array("violations", &self.violations)
            .str_array("notes", &self.notes)
            .finish()
    }
}
