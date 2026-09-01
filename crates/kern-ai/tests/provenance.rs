//! Provenance, resource bounds, and the promise that the parser never panics.
//!
//! Deterministic and offline. The robustness pass uses a fixed-seed generator
//! rather than a fuzzing framework: the bytes are reproducible, the run is
//! bounded, and no new dependency joins the workspace for the sake of one phase.

mod support;

use kern_ai::bounds::{MAX_INSTRUCTION_BYTES, MAX_RESPONSE_BYTES, MAX_ROBOT_CONTEXT_BYTES};
use kern_ai::fake::{navigate_json, CompliantModel, MaliciousModel, Mischief};
use kern_ai::{
    parse_response, Instruction, ModelInvocationId, NormalizationOutcome, PolicyOutcome,
    ProposalId, ProposalPlane, ProposalRecord, ProvenanceError, RawModelResponse, RequestError,
    RobotContext, SequentialProposalIds,
};
use kern_core::AuthorityArtifactId;
use kern_execution::ExecutionId;

use support::{control_plane, fixture_model, planning_request, Pipeline};

// -------------------------------------------------------------------- the chain

#[test]
fn provenance_links_proposal_to_artifact_to_execution() {
    let authority = control_plane();
    let request = planning_request(&authority, "Take the parcel to station B.");
    let mut plane = ProposalPlane::new(
        CompliantModel::navigating(fixture_model("compliant"), 6_000, 0, 0, 300, "Station B"),
        SequentialProposalIds::new(),
    );
    let mut pipeline = Pipeline::new();

    let proposal = plane.propose(&request);
    let walk = pipeline.walk(proposal);
    let record = &walk.record;

    assert_eq!(record.proposal_id(), ProposalId::from_u64(0));
    assert_eq!(record.invocation(), ModelInvocationId::from_u64(0));
    assert!(record.response().is_some(), "the response bytes are named");
    assert_eq!(
        record.normalization(),
        Some(&NormalizationOutcome::Normalized)
    );
    assert_eq!(record.policy(), Some(&PolicyOutcome::Authorized));
    assert!(record.artifact().is_some());
    assert!(record.execution().is_some());
}

#[test]
fn the_three_identifiers_are_different_types_with_different_spellings() {
    // Same underlying number, three unrelated identities. Nothing in Kern can
    // pass one where another is meant, because none of them converts.
    let proposal = ProposalId::from_u64(7);
    let execution = ExecutionId::from_u128(7);
    assert_eq!(proposal.to_string(), "P-7");
    assert_ne!(proposal.to_string(), execution.to_string());

    // And in a real record they are genuinely different values, drawn from
    // different sources at different stages.
    let authority = control_plane();
    let request = planning_request(&authority, "Go to station B.");
    let mut plane = ProposalPlane::new(
        CompliantModel::navigating(fixture_model("compliant"), 6_000, 0, 0, 300, "B"),
        SequentialProposalIds::starting_at(17),
    );
    let mut pipeline = Pipeline::new();
    let walk = pipeline.walk(plane.propose(&request));

    assert_eq!(walk.record.proposal_id(), ProposalId::from_u64(17));
    assert_eq!(walk.record.execution(), Some(ExecutionId::from_u128(1)));
}

/// A `ProposalId` cannot stand in for authority, and the compiler says so.
///
/// ```compile_fail
/// use kern_ai::ProposalId;
/// use kern_execution::ExecutionId;
///
/// let proposal = ProposalId::from_u64(1);
/// let execution: ExecutionId = proposal;
/// ```
#[allow(dead_code)]
struct IdentifiersDoNotConvert;

// ------------------------------------------------------- stages cannot be faked

#[test]
fn a_record_refuses_an_artifact_it_was_not_authorized_for() {
    let authority = control_plane();
    let request = planning_request(&authority, "Go too fast.");
    let mut plane = ProposalPlane::new(
        MaliciousModel::new(fixture_model("hostile"), Mischief::ExcessiveSpeed),
        SequentialProposalIds::new(),
    );
    let mut pipeline = Pipeline::new();
    let walk = pipeline.walk(plane.propose(&request));
    let mut record: ProposalRecord = walk.record;

    assert_eq!(
        record.record_authority(AuthorityArtifactId::from_bytes([0u8; 32])),
        Err(ProvenanceError::OutOfOrder {
            stage: "an authority artifact",
            requires: "an authorized policy outcome",
        })
    );
    assert!(record.artifact().is_none());
    assert_eq!(
        record.record_execution(ExecutionId::from_u128(1)),
        Err(ProvenanceError::OutOfOrder {
            stage: "an execution",
            requires: "an authority artifact",
        })
    );
}

#[test]
fn a_record_refuses_a_policy_outcome_before_normalization() {
    let authority = control_plane();
    let request = planning_request(&authority, "Go to station B.");
    let mut plane = ProposalPlane::new(
        MaliciousModel::new(fixture_model("hostile"), Mischief::MalformedJson),
        SequentialProposalIds::new(),
    );
    let mut record = plane.propose(&request).record().clone();

    assert_eq!(
        record.record_policy(PolicyOutcome::Authorized),
        Err(ProvenanceError::OutOfOrder {
            stage: "a policy outcome",
            requires: "normalization",
        })
    );
}

#[test]
fn a_stage_cannot_be_recorded_twice() {
    let authority = control_plane();
    let request = planning_request(&authority, "Go to station B.");
    let mut plane = ProposalPlane::new(
        CompliantModel::navigating(fixture_model("compliant"), 6_000, 0, 0, 300, "B"),
        SequentialProposalIds::new(),
    );
    let mut pipeline = Pipeline::new();
    let mut record = pipeline.walk(plane.propose(&request)).record;

    assert_eq!(
        record.record_normalization(NormalizationOutcome::Normalized),
        Err(ProvenanceError::AlreadyRecorded {
            stage: "normalization"
        })
    );
    assert_eq!(
        record.record_policy(PolicyOutcome::Authorized),
        Err(ProvenanceError::AlreadyRecorded {
            stage: "a policy outcome"
        })
    );
}

// -------------------------------------------------------------- resource bounds

#[test]
fn an_oversized_instruction_is_refused() {
    let text = "a".repeat(MAX_INSTRUCTION_BYTES + 1);
    assert_eq!(
        Instruction::new(text),
        Err(RequestError::InstructionTooLong {
            bytes: MAX_INSTRUCTION_BYTES + 1
        })
    );
    assert!(Instruction::new("a".repeat(MAX_INSTRUCTION_BYTES)).is_ok());
}

#[test]
fn an_empty_instruction_is_refused() {
    assert_eq!(Instruction::new(""), Err(RequestError::EmptyInstruction));
}

#[test]
fn an_oversized_context_is_refused() {
    let text = "a".repeat(MAX_ROBOT_CONTEXT_BYTES + 1);
    assert_eq!(
        RobotContext::new(text),
        Err(RequestError::ContextTooLong {
            bytes: MAX_ROBOT_CONTEXT_BYTES + 1
        })
    );
}

#[test]
fn an_oversized_response_never_becomes_a_proposal() {
    let authority = control_plane();
    let request = planning_request(&authority, "Go to station B.");
    let mut plane = ProposalPlane::new(
        MaliciousModel::new(fixture_model("verbose"), Mischief::Oversized),
        SequentialProposalIds::new(),
    );
    let mut pipeline = Pipeline::new();
    let proposal = plane.propose(&request);
    assert!(proposal.action().is_none());
    let walk = pipeline.walk(proposal);
    assert!(walk.is_inert());
    assert_eq!(pipeline.goals_sent(), 0);
}

#[test]
fn an_empty_vocabulary_is_refused_rather_than_sent() {
    use kern_ai::CapabilityVocabulary;
    use kern_policy::CapabilityRegistry;
    let empty = CapabilityRegistry::new();
    assert!(matches!(
        CapabilityVocabulary::from_registry(&empty, &support::device()),
        Err(RequestError::EmptyVocabulary { .. })
    ));
}

// --------------------------------------------------------- the parser never panics

/// A tiny deterministic generator. Reproducible, and no new dependency.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

#[test]
fn arbitrary_bytes_never_panic_the_parser() {
    let mut rng = Xorshift(0x5eed_1234_abcd_ef01);
    for _ in 0..4_000 {
        let len = rng.below(512);
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        // Anything within the bound is parseable-or-rejected, never a panic.
        let response = RawModelResponse::new(bytes).expect("within the bound");
        let _ = parse_response(&response);
    }
}

#[test]
fn structured_mutations_of_a_valid_response_never_panic() {
    // Bit-flips, truncations, and splices of a real proposal: the shapes a
    // parser is most likely to get wrong, because they are nearly valid.
    let valid = navigate_json(6_000, 0, 0, 300, "Move to station B");
    let mut rng = Xorshift(0x0bad_c0de_0bad_c0de);

    for _ in 0..4_000 {
        let mut bytes = valid.clone();
        match rng.below(5) {
            0 => {
                let at = rng.below(bytes.len());
                bytes[at] ^= 1 << rng.below(8);
            }
            1 => bytes.truncate(rng.below(bytes.len().max(1))),
            2 => {
                let at = rng.below(bytes.len());
                bytes.insert(at, rng.byte());
            }
            3 => {
                let at = rng.below(bytes.len());
                bytes.splice(at..at, b"[[[[[[[[[[[[[[[[".iter().copied());
            }
            _ => bytes.extend_from_slice(&valid),
        }
        if bytes.len() > MAX_RESPONSE_BYTES {
            continue;
        }
        let response = RawModelResponse::new(bytes).expect("within the bound");
        let _ = parse_response(&response);
    }
}

#[test]
fn deeply_nested_bytes_never_panic() {
    // Far past the depth bound, in both directions, and unbalanced.
    for depth in [16usize, 64, 512, 4_000] {
        for pattern in ["[", "{", "[{", "{\"a\":["] {
            let bytes = pattern.repeat(depth).into_bytes();
            if bytes.len() > MAX_RESPONSE_BYTES {
                continue;
            }
            let response = RawModelResponse::new(bytes).expect("within the bound");
            assert!(parse_response(&response).is_err());
        }
    }
}

#[test]
fn every_hostile_fixture_is_rejected_somewhere_before_authority() {
    for mischief in [
        Mischief::ExcessiveSpeed,
        Mischief::ForbiddenDestination,
        Mischief::UnknownCapability,
        Mischief::NotAnObject,
        Mischief::MultipleActions,
        Mischief::DuplicateKeys,
        Mischief::FloatValue,
        Mischief::NumericString,
        Mischief::IntegerOverflow,
        Mischief::UnknownTopLevelField,
        Mischief::UnknownArgument,
        Mischief::ChoosesTtl,
        Mischief::ChoosesAuthority,
        Mischief::MissingArgument,
        Mischief::MissingCapability,
        Mischief::MalformedJson,
        Mischief::TrailingProse,
        Mischief::Oversized,
        Mischief::DoubleFenced,
    ] {
        let authority = control_plane();
        let request = planning_request(&authority, "Do the thing.");
        let mut plane = ProposalPlane::new(
            MaliciousModel::new(fixture_model("hostile"), mischief),
            SequentialProposalIds::new(),
        );
        let mut pipeline = Pipeline::new();
        let walk = pipeline.walk(plane.propose(&request));
        assert!(
            walk.is_inert(),
            "{mischief:?} produced authority or physical effect"
        );
        assert_eq!(pipeline.goals_sent(), 0, "{mischief:?} reached Nav2");
        assert!(
            pipeline.speed_limits().is_empty(),
            "{mischief:?} published a speed limit"
        );
    }
}
