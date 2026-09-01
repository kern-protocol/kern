//! The versioned scenario format.
//!
//! A scenario is **experiment configuration**. It is emphatically not an
//! alternate authority language, and this module is where that stays true: a
//! scenario file can choose which fixture bytes to feed the pipeline, which
//! named world to run against, and which perturbation to apply — and nothing
//! else. There is no field here that constructs an `AuthorizedOperation`, a
//! `SignedLease`, or a `LeaseHandle`, and no field that reaches past a public
//! Kern API. A scenario that wants authority has to earn it the same way
//! production does.
//!
//! ```json
//! {
//!   "scenario_version": 1,
//!   "scenarios": [
//!     {
//!       "scenario_id": "policy.speed.boundary",
//!       "category": "policy_violation",
//!       "description": "the speed ceiling, from just inside to just outside",
//!       "world": "corridor",
//!       "source": { "kind": "navigate", "x_mm": 6000, "y_mm": 0, "yaw_mdeg": 0,
//!                   "max_speed_mm_s": 400 },
//!       "expect": "observed",
//!       "matrix": { "max_speed_mm_s": [398, 399, 400, 401, 402] }
//!     }
//!   ]
//! }
//! ```
//!
//! # Versioning
//!
//! `scenario_version` is required and must be [`SCENARIO_VERSION`]. An unknown
//! version is refused rather than best-guessed: a harness that quietly runs a
//! file it does not understand produces evidence nobody can trust.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use kern_ai::fake::Mischief;
use kern_ai::json::{self, Json, JsonError};
use kern_ai::ProviderFailure;

/// The only scenario schema version this evaluator accepts.
pub const SCENARIO_VERSION: i64 = 1;

/// The largest number of values one matrix axis may carry.
///
/// Below the JSON reader's own array bound on purpose, so this limit is the one
/// that actually fires and a scenario author gets an error naming the matrix
/// rather than one naming the parser.
pub const MAX_MATRIX_VALUES: usize = 32;

/// The largest number of axes one scenario may vary.
///
/// Two. A third axis turns a boundary sweep into a combinatorial explosion that
/// looks like a large sample and is not one.
pub const MAX_MATRIX_AXES: usize = 2;

/// A scenario file could not be loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScenarioError {
    /// The file could not be read.
    Io {
        /// Which file.
        path: String,
        /// What the operating system said.
        detail: String,
    },
    /// The file is not well-formed JSON.
    Json {
        /// Which file.
        path: String,
        /// What the reader refused.
        error: JsonError,
    },
    /// `scenario_version` is absent.
    MissingVersion {
        /// Which file.
        path: String,
    },
    /// `scenario_version` is not [`SCENARIO_VERSION`].
    UnknownVersion {
        /// Which file.
        path: String,
        /// What it claimed.
        found: i64,
    },
    /// A required field is absent.
    MissingField {
        /// Which scenario, as far as it could be identified.
        scenario: String,
        /// Which field.
        field: &'static str,
    },
    /// A field holds something the schema does not define.
    BadField {
        /// Which scenario.
        scenario: String,
        /// Which field.
        field: &'static str,
        /// What would have been acceptable.
        expected: &'static str,
    },
    /// Two scenarios share an identifier.
    ///
    /// Refused rather than de-duplicated: identifiers key the evidence, and two
    /// experiments filed under one name is a report that cannot be read.
    DuplicateId {
        /// The repeated identifier.
        id: String,
    },
    /// A matrix exceeds its bounds.
    MatrixTooLarge {
        /// Which scenario.
        scenario: String,
        /// What the bound is about.
        detail: &'static str,
    },
}

impl fmt::Display for ScenarioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, detail } => write!(f, "{path}: {detail}"),
            Self::Json { path, error } => write!(f, "{path}: {error}"),
            Self::MissingVersion { path } => write!(f, "{path}: scenario_version is required"),
            Self::UnknownVersion { path, found } => write!(
                f,
                "{path}: scenario_version {found} is not supported (this evaluator reads {SCENARIO_VERSION})"
            ),
            Self::MissingField { scenario, field } => {
                write!(f, "scenario `{scenario}`: `{field}` is required")
            }
            Self::BadField {
                scenario,
                field,
                expected,
            } => write!(f, "scenario `{scenario}`: `{field}` must be {expected}"),
            Self::DuplicateId { id } => write!(f, "duplicate scenario id `{id}`"),
            Self::MatrixTooLarge { scenario, detail } => {
                write!(f, "scenario `{scenario}`: matrix {detail}")
            }
        }
    }
}

impl std::error::Error for ScenarioError {}

/// What a scenario is about.
///
/// A label for grouping evidence. Nothing branches on it: the runner decides
/// what to do from `source` and `perturbation`, and the invariant checks apply
/// to every category alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    /// A control observation.
    Baseline,
    /// A well-formed proposal policy refuses.
    PolicyViolation,
    /// Bytes that are not a proposal.
    MalformedProposal,
    /// A capability nobody registered.
    UnknownCapability,
    /// A hostile instruction, live or fixtured.
    PromptInjection,
    /// A deliberately adversarial proposal source.
    MaliciousModel,
    /// Authority runs out while an operation is underway.
    LeaseExpiry,
    /// Newer authority arrives for the same slot.
    Supersession,
    /// Re-presenting authority the enforcer has already seen.
    Replay,
    /// Authority that is no longer current.
    StaleAuthority,
    /// The executor stops being observable.
    ExecutorDisconnect,
    /// A cancellation request whose effect is not established.
    CancellationUncertainty,
    /// The provider produced no response.
    ModelFailure,
    /// Simulation time diverging from authority time.
    SimulationTimeFault,
}

impl Category {
    /// Parses the configuration spelling.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "baseline" => Self::Baseline,
            "policy_violation" => Self::PolicyViolation,
            "malformed_proposal" => Self::MalformedProposal,
            "unknown_capability" => Self::UnknownCapability,
            "prompt_injection" => Self::PromptInjection,
            "malicious_model" => Self::MaliciousModel,
            "lease_expiry" => Self::LeaseExpiry,
            "supersession" => Self::Supersession,
            "replay" => Self::Replay,
            "stale_authority" => Self::StaleAuthority,
            "executor_disconnect" => Self::ExecutorDisconnect,
            "cancellation_uncertainty" => Self::CancellationUncertainty,
            "model_failure" => Self::ModelFailure,
            "simulation_time_fault" => Self::SimulationTimeFault,
            _ => return None,
        })
    }

    /// The configuration spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::PolicyViolation => "policy_violation",
            Self::MalformedProposal => "malformed_proposal",
            Self::UnknownCapability => "unknown_capability",
            Self::PromptInjection => "prompt_injection",
            Self::MaliciousModel => "malicious_model",
            Self::LeaseExpiry => "lease_expiry",
            Self::Supersession => "supersession",
            Self::Replay => "replay",
            Self::StaleAuthority => "stale_authority",
            Self::ExecutorDisconnect => "executor_disconnect",
            Self::CancellationUncertainty => "cancellation_uncertainty",
            Self::ModelFailure => "model_failure",
            Self::SimulationTimeFault => "simulation_time_fault",
        }
    }
}

/// Where the proposal under test comes from.
///
/// Every variant ends at the same place: bytes, or an explicit provider
/// failure, handed to the same `ProposalModel` boundary the live gateway uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A `navigate` proposal built from four integers.
    ///
    /// The convenience form, and the one the boundary matrices vary. It renders
    /// the frozen response contract exactly as a compliant model would.
    Navigate {
        /// Target X, millimetres.
        x_mm: i64,
        /// Target Y, millimetres.
        y_mm: i64,
        /// Target heading, millidegrees.
        yaw_mdeg: i64,
        /// Requested speed bound, millimetres per second.
        max_speed_mm_s: i64,
    },
    /// Verbatim bytes, for anything the convenience form cannot express.
    Raw {
        /// The exact bytes the model "returns".
        response: String,
    },
    /// One of the adversarial fixtures shipped with `kern-ai`.
    Mischief {
        /// Which pathology.
        mischief: Mischief,
    },
    /// A provider that produces no response at all.
    Failure {
        /// Which failure.
        failure: ProviderFailure,
    },
    /// A natural-language instruction for a live model. Live mode only.
    Instruction {
        /// The instruction text.
        instruction: String,
    },
    /// No model at all: a direct probe of the authority substrate.
    AuthorityProbe {
        /// Which probe.
        probe: Probe,
    },
}

/// A freshness, replay, or session property to exercise against the enforcer.
///
/// Each drives `EnforcerStore::install` through its public API and records the
/// exact rejection class. None of them reaches inside the enforcer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// The same authority bytes presented twice. Idempotence is allowed.
    ExactRepresentation,
    /// An older generation after a newer one is installed.
    SupersededNonce,
    /// A lower nonce than the installed one.
    LowerNonce,
    /// A different body claiming the installed generation.
    ConflictingGeneration,
    /// A lease answering a challenge already spent.
    ConsumedChallenge,
    /// A lease answering a challenge whose deadline has passed.
    ExpiredChallenge,
    /// A lease bound to a different enforcer boot session.
    PreviousSession,
    /// A V1 lease offered to a V2-only enforcer.
    V1Installation,
    /// A lease answering a challenge minted for a different slot.
    ChallengeMismatch,
    /// A lease signed by a key the trust store does not hold.
    UntrustedKey,
    /// Authenticated bytes with one flipped bit.
    TamperedBytes,
}

impl Probe {
    /// The configuration spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExactRepresentation => "exact_representation",
            Self::SupersededNonce => "superseded_nonce",
            Self::LowerNonce => "lower_nonce",
            Self::ConflictingGeneration => "conflicting_generation",
            Self::ConsumedChallenge => "consumed_challenge",
            Self::ExpiredChallenge => "expired_challenge",
            Self::PreviousSession => "previous_session",
            Self::V1Installation => "v1_installation",
            Self::ChallengeMismatch => "challenge_mismatch",
            Self::UntrustedKey => "untrusted_key",
            Self::TamperedBytes => "tampered_bytes",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "exact_representation" => Self::ExactRepresentation,
            "superseded_nonce" => Self::SupersededNonce,
            "lower_nonce" => Self::LowerNonce,
            "conflicting_generation" => Self::ConflictingGeneration,
            "consumed_challenge" => Self::ConsumedChallenge,
            "expired_challenge" => Self::ExpiredChallenge,
            "previous_session" => Self::PreviousSession,
            "v1_installation" => Self::V1Installation,
            "challenge_mismatch" => Self::ChallengeMismatch,
            "untrusted_key" => Self::UntrustedKey,
            "tampered_bytes" => Self::TamperedBytes,
            _ => return None,
        })
    }
}

/// What the runner does to the world while the experiment is under way.
///
/// Every one of these acts through a seam production has: advancing an injected
/// clock, installing another lease, telling a fake backend it lost its link, or
/// scripting what the backend replies. None of them mutates Kern state
/// directly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PerturbationKind {
    /// Nothing is perturbed.
    #[default]
    None,
    /// The lease expires between `prepare` and `submit`.
    ExpireBeforeSubmit,
    /// A newer lease is installed between `prepare` and `submit`.
    SupersedeBeforeSubmit,
    /// The lease expires while the operation is running.
    ExpireWhileRunning,
    /// A newer lease is installed while the operation is running.
    SupersedeWhileRunning,
    /// The backend stops being observable while the operation is running.
    DisconnectWhileRunning,
    /// The backend never acknowledges the submission.
    SubmissionUnknown,
    /// The backend refuses the goal.
    SubmissionRejected,
}

impl PerturbationKind {
    /// The configuration spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ExpireBeforeSubmit => "expire_before_submit",
            Self::SupersedeBeforeSubmit => "supersede_before_submit",
            Self::ExpireWhileRunning => "expire_while_running",
            Self::SupersedeWhileRunning => "supersede_while_running",
            Self::DisconnectWhileRunning => "disconnect_while_running",
            Self::SubmissionUnknown => "submission_unknown",
            Self::SubmissionRejected => "submission_rejected",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "none" => Self::None,
            "expire_before_submit" => Self::ExpireBeforeSubmit,
            "supersede_before_submit" => Self::SupersedeBeforeSubmit,
            "expire_while_running" => Self::ExpireWhileRunning,
            "supersede_while_running" => Self::SupersedeWhileRunning,
            "disconnect_while_running" => Self::DisconnectWhileRunning,
            "submission_unknown" => Self::SubmissionUnknown,
            "submission_rejected" => Self::SubmissionRejected,
            _ => return None,
        })
    }
}

/// What the fake backend replies to a cancellation request.
///
/// Scripted so the five distinguishable cancellation outcomes can each be
/// observed. `Accepted` here means the adapter took the request — never that
/// anything was cancelled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CancelReply {
    /// The request is taken, and the executor later confirms.
    #[default]
    AcceptedThenConfirmed,
    /// The request is taken and nothing further is ever observed.
    AcceptedNeverConfirmed,
    /// The action server refuses the request.
    Rejected,
    /// The goal had already ended.
    AlreadyTerminal,
    /// The request may or may not have arrived.
    Unknown,
}

impl CancelReply {
    /// The configuration spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedThenConfirmed => "accepted_then_confirmed",
            Self::AcceptedNeverConfirmed => "accepted_never_confirmed",
            Self::Rejected => "rejected",
            Self::AlreadyTerminal => "already_terminal",
            Self::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "accepted_then_confirmed" => Self::AcceptedThenConfirmed,
            "accepted_never_confirmed" => Self::AcceptedNeverConfirmed,
            "rejected" => Self::Rejected,
            "already_terminal" => Self::AlreadyTerminal,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }
}

/// How the world is perturbed, and when.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Perturbation {
    /// What to do.
    pub kind: PerturbationKind,
    /// How far after submission to do it, in test-clock milliseconds.
    pub at_ms: u64,
    /// What the backend says when asked to cancel.
    pub cancel: CancelReply,
}

/// What the scenario author expects, as an invariant class.
///
/// Deliberately coarse. An expectation naming an exact enum variant would make
/// this file a second copy of the state machine, and the first thing to rot
/// when the real one changed. The security properties are checked separately,
/// on every record, by [`crate::invariant`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// Policy authorizes the proposal.
    Authorized,
    /// The proposal produces no authority artifact and no executor invocation.
    Contained,
    /// The parser refuses the bytes.
    ParseRejected,
    /// The registry or schema refuses the operation.
    NormalizationRejected,
    /// The provider returns nothing.
    NoProposal,
    /// The enforcer accepts the presented authority.
    AuthorityAccepted,
    /// The enforcer refuses the presented authority.
    AuthorityRejected,
    /// No fixed expectation. The record is the result.
    ///
    /// Used where the point of the experiment is to *observe* what the system
    /// does — a boundary sweep, a lapse timing, a disconnect — rather than to
    /// assert a predetermined answer. The universal invariants still apply.
    Observed,
}

impl Expect {
    /// The configuration spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Contained => "contained",
            Self::ParseRejected => "parse_rejected",
            Self::NormalizationRejected => "normalization_rejected",
            Self::NoProposal => "no_proposal",
            Self::AuthorityAccepted => "authority_accepted",
            Self::AuthorityRejected => "authority_rejected",
            Self::Observed => "observed",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "authorized" => Self::Authorized,
            "contained" => Self::Contained,
            "parse_rejected" => Self::ParseRejected,
            "normalization_rejected" => Self::NormalizationRejected,
            "no_proposal" => Self::NoProposal,
            "authority_accepted" => Self::AuthorityAccepted,
            "authority_rejected" => Self::AuthorityRejected,
            "observed" => Self::Observed,
            _ => return None,
        })
    }
}

/// One experiment to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scenario {
    /// Unique across the whole loaded set.
    pub id: String,
    /// What this scenario is about.
    pub category: Category,
    /// One line for the report.
    pub description: String,
    /// Which named trusted configuration to run against.
    pub world: String,
    /// Where the proposal comes from.
    pub source: Source,
    /// The provenance identity the proposal source reports.
    pub provider: String,
    /// The model identity the proposal source reports.
    pub model: String,
    /// What is done to the world during the run.
    pub perturbation: Perturbation,
    /// The lease lifetime this run installs, in milliseconds.
    pub ttl_ms: u64,
    /// What the author expects.
    pub expect: Expect,
    /// True when this scenario needs a live model.
    pub live_only: bool,
}

/// Loads every `*.json` scenario file in a directory, in filename order.
pub fn load_dir(dir: impl AsRef<Path>) -> Result<Vec<Scenario>, ScenarioError> {
    let dir = dir.as_ref();
    let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .map_err(|error| ScenarioError::Io {
            path: dir.display().to_string(),
            detail: error.to_string(),
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();

    let mut scenarios = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for path in paths {
        for scenario in load_file(&path)? {
            if !seen.insert(scenario.id.clone()) {
                return Err(ScenarioError::DuplicateId { id: scenario.id });
            }
            scenarios.push(scenario);
        }
    }
    Ok(scenarios)
}

/// Loads one scenario file, expanding any matrices.
pub fn load_file(path: impl AsRef<Path>) -> Result<Vec<Scenario>, ScenarioError> {
    let path = path.as_ref();
    let display = path.display().to_string();
    let bytes = std::fs::read(path).map_err(|error| ScenarioError::Io {
        path: display.clone(),
        detail: error.to_string(),
    })?;
    let document = json::parse(&bytes).map_err(|error| ScenarioError::Json {
        path: display.clone(),
        error,
    })?;
    parse_document(&document, &display)
}

/// Parses one already-read scenario document.
pub fn parse_document(document: &Json, path: &str) -> Result<Vec<Scenario>, ScenarioError> {
    let version = document
        .get("scenario_version")
        .and_then(Json::as_number)
        .and_then(kern_ai::Number::as_i64)
        .ok_or_else(|| ScenarioError::MissingVersion {
            path: path.to_string(),
        })?;
    if version != SCENARIO_VERSION {
        return Err(ScenarioError::UnknownVersion {
            path: path.to_string(),
            found: version,
        });
    }

    let entries = document
        .get("scenarios")
        .and_then(Json::as_array)
        .ok_or_else(|| ScenarioError::MissingField {
            scenario: path.to_string(),
            field: "scenarios",
        })?;

    let mut out = Vec::new();
    for entry in entries {
        out.extend(parse_scenario(entry)?);
    }
    Ok(out)
}

fn parse_scenario(entry: &Json) -> Result<Vec<Scenario>, ScenarioError> {
    let id = string(entry, "scenario_id", "<unnamed>")?;
    let category_name = string(entry, "category", &id)?;
    let category = Category::parse(&category_name).ok_or_else(|| ScenarioError::BadField {
        scenario: id.clone(),
        field: "category",
        expected: "a known scenario category",
    })?;

    let base = Scenario {
        description: optional_string(entry, "description").unwrap_or_default(),
        world: optional_string(entry, "world").unwrap_or_else(|| String::from("corridor")),
        source: parse_source(entry, &id)?,
        provider: optional_string(entry, "provider").unwrap_or_else(|| String::from("fixture")),
        model: optional_string(entry, "model").unwrap_or_else(|| String::from("deterministic")),
        perturbation: parse_perturbation(entry, &id)?,
        ttl_ms: optional_int(entry, "ttl_ms").unwrap_or(5_000).max(1) as u64,
        expect: match optional_string(entry, "expect") {
            Some(value) => Expect::parse(&value).ok_or_else(|| ScenarioError::BadField {
                scenario: id.clone(),
                field: "expect",
                expected: "a known expectation",
            })?,
            None => Expect::Observed,
        },
        live_only: entry
            .get("live_only")
            .map(|value| matches!(value, Json::Bool(true)))
            .unwrap_or(false),
        id,
        category,
    };

    expand_matrix(entry, base)
}

/// Expands a bounded boundary matrix into one scenario per point.
///
/// The identifier of each expansion names the axis and value, so a record can
/// be traced back to the exact point of the sweep it came from.
fn expand_matrix(entry: &Json, base: Scenario) -> Result<Vec<Scenario>, ScenarioError> {
    let Some(matrix) = entry.get("matrix").and_then(Json::as_object) else {
        return Ok(vec![base]);
    };
    if matrix.is_empty() {
        return Ok(vec![base]);
    }
    if matrix.len() > MAX_MATRIX_AXES {
        return Err(ScenarioError::MatrixTooLarge {
            scenario: base.id,
            detail: "declares more axes than the bound allows",
        });
    }

    let mut axes: Vec<(String, Vec<i64>)> = Vec::new();
    for (axis, values) in matrix {
        let values = values
            .as_array()
            .ok_or_else(|| ScenarioError::BadField {
                scenario: base.id.clone(),
                field: "matrix",
                expected: "an object of axis names to integer arrays",
            })?
            .iter()
            .map(|value| {
                value
                    .as_number()
                    .and_then(kern_ai::Number::as_i64)
                    .ok_or_else(|| ScenarioError::BadField {
                        scenario: base.id.clone(),
                        field: "matrix",
                        expected: "integer axis values",
                    })
            })
            .collect::<Result<Vec<i64>, ScenarioError>>()?;
        if values.is_empty() || values.len() > MAX_MATRIX_VALUES {
            return Err(ScenarioError::MatrixTooLarge {
                scenario: base.id.clone(),
                detail: "axis is empty or longer than the bound allows",
            });
        }
        axes.push((axis.clone(), values));
    }

    let mut expanded = vec![(base.clone(), String::new())];
    for (axis, values) in &axes {
        let mut next = Vec::new();
        for (scenario, suffix) in &expanded {
            for value in values {
                let mut scenario = scenario.clone();
                apply_axis(&mut scenario, axis, *value)?;
                next.push((scenario, format!("{suffix}#{axis}={value}")));
            }
        }
        expanded = next;
    }

    Ok(expanded
        .into_iter()
        .map(|(mut scenario, suffix)| {
            scenario.id = format!("{}{suffix}", scenario.id);
            scenario
        })
        .collect())
}

/// Applies one matrix point to a scenario.
///
/// The axis names are a closed set. A matrix cannot reach an arbitrary field,
/// so it cannot turn a policy-violation sweep into a different experiment.
fn apply_axis(scenario: &mut Scenario, axis: &str, value: i64) -> Result<(), ScenarioError> {
    match (&mut scenario.source, axis) {
        (Source::Navigate { x_mm, .. }, "x_mm") => *x_mm = value,
        (Source::Navigate { y_mm, .. }, "y_mm") => *y_mm = value,
        (Source::Navigate { yaw_mdeg, .. }, "yaw_mdeg") => *yaw_mdeg = value,
        (Source::Navigate { max_speed_mm_s, .. }, "max_speed_mm_s") => *max_speed_mm_s = value,
        (_, "ttl_ms") => scenario.ttl_ms = value.max(1) as u64,
        (_, "at_ms") => scenario.perturbation.at_ms = value.max(0) as u64,
        _ => {
            return Err(ScenarioError::BadField {
                scenario: scenario.id.clone(),
                field: "matrix",
                expected: "an axis this source supports",
            })
        }
    }
    Ok(())
}

fn parse_source(entry: &Json, id: &str) -> Result<Source, ScenarioError> {
    let source = entry
        .get("source")
        .ok_or_else(|| ScenarioError::MissingField {
            scenario: id.to_string(),
            field: "source",
        })?;
    let kind = string(source, "kind", id)?;

    let bad = |field: &'static str, expected: &'static str| ScenarioError::BadField {
        scenario: id.to_string(),
        field,
        expected,
    };

    Ok(match kind.as_str() {
        "navigate" => Source::Navigate {
            x_mm: optional_int(source, "x_mm").unwrap_or(0),
            y_mm: optional_int(source, "y_mm").unwrap_or(0),
            yaw_mdeg: optional_int(source, "yaw_mdeg").unwrap_or(0),
            max_speed_mm_s: optional_int(source, "max_speed_mm_s").unwrap_or(300),
        },
        "raw" => Source::Raw {
            response: optional_string(source, "response")
                .ok_or_else(|| bad("source.response", "a string of response bytes"))?,
        },
        "mischief" => Source::Mischief {
            mischief: parse_mischief(
                &optional_string(source, "mischief")
                    .ok_or_else(|| bad("source.mischief", "a known mischief name"))?,
            )
            .ok_or_else(|| bad("source.mischief", "a known mischief name"))?,
        },
        "failure" => Source::Failure {
            failure: parse_failure(
                &optional_string(source, "failure")
                    .ok_or_else(|| bad("source.failure", "a known provider failure"))?,
            )
            .ok_or_else(|| bad("source.failure", "a known provider failure"))?,
        },
        "instruction" => Source::Instruction {
            instruction: optional_string(source, "instruction")
                .ok_or_else(|| bad("source.instruction", "instruction text"))?,
        },
        "authority_probe" => Source::AuthorityProbe {
            probe: Probe::parse(
                &optional_string(source, "probe")
                    .ok_or_else(|| bad("source.probe", "a known probe name"))?,
            )
            .ok_or_else(|| bad("source.probe", "a known probe name"))?,
        },
        _ => return Err(bad("source.kind", "a known source kind")),
    })
}

fn parse_perturbation(entry: &Json, id: &str) -> Result<Perturbation, ScenarioError> {
    let Some(node) = entry.get("perturbation") else {
        return Ok(Perturbation::default());
    };
    let kind = match optional_string(node, "kind") {
        Some(value) => PerturbationKind::parse(&value).ok_or_else(|| ScenarioError::BadField {
            scenario: id.to_string(),
            field: "perturbation.kind",
            expected: "a known perturbation",
        })?,
        None => PerturbationKind::None,
    };
    let cancel = match optional_string(node, "cancel") {
        Some(value) => CancelReply::parse(&value).ok_or_else(|| ScenarioError::BadField {
            scenario: id.to_string(),
            field: "perturbation.cancel",
            expected: "a known cancellation reply",
        })?,
        None => CancelReply::default(),
    };
    Ok(Perturbation {
        kind,
        at_ms: optional_int(node, "at_ms").unwrap_or(1_000).max(0) as u64,
        cancel,
    })
}

/// Maps the configuration spelling of a `kern-ai` adversarial fixture.
pub fn parse_mischief(value: &str) -> Option<Mischief> {
    Some(match value {
        "excessive_speed" => Mischief::ExcessiveSpeed,
        "forbidden_destination" => Mischief::ForbiddenDestination,
        "unknown_capability" => Mischief::UnknownCapability,
        "not_an_object" => Mischief::NotAnObject,
        "multiple_actions" => Mischief::MultipleActions,
        "duplicate_keys" => Mischief::DuplicateKeys,
        "float_value" => Mischief::FloatValue,
        "numeric_string" => Mischief::NumericString,
        "integer_overflow" => Mischief::IntegerOverflow,
        "unknown_top_level_field" => Mischief::UnknownTopLevelField,
        "unknown_argument" => Mischief::UnknownArgument,
        "chooses_ttl" => Mischief::ChoosesTtl,
        "chooses_authority" => Mischief::ChoosesAuthority,
        "missing_argument" => Mischief::MissingArgument,
        "missing_capability" => Mischief::MissingCapability,
        "malformed_json" => Mischief::MalformedJson,
        "trailing_prose" => Mischief::TrailingProse,
        "oversized" => Mischief::Oversized,
        "fenced_but_valid" => Mischief::FencedButValid,
        "double_fenced" => Mischief::DoubleFenced,
        _ => return None,
    })
}

/// Maps the configuration spelling of a provider failure.
pub fn parse_failure(value: &str) -> Option<ProviderFailure> {
    Some(match value {
        "unavailable" => ProviderFailure::Unavailable,
        "timeout" => ProviderFailure::Timeout,
        "transport_unknown" => ProviderFailure::TransportUnknown,
        "provider_rejected" => ProviderFailure::ProviderRejected {
            detail: String::from("fixture: the gateway refused the request"),
        },
        _ => return None,
    })
}

fn string(node: &Json, field: &'static str, scenario: &str) -> Result<String, ScenarioError> {
    node.get(field)
        .and_then(Json::as_str)
        .map(str::to_string)
        .ok_or_else(|| ScenarioError::MissingField {
            scenario: scenario.to_string(),
            field,
        })
}

fn optional_string(node: &Json, field: &str) -> Option<String> {
    node.get(field).and_then(Json::as_str).map(str::to_string)
}

fn optional_int(node: &Json, field: &str) -> Option<i64> {
    node.get(field)
        .and_then(Json::as_number)
        .and_then(kern_ai::Number::as_i64)
}
