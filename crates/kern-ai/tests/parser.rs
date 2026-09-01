//! Layer 1: raw provider bytes against the strict local parser.
//!
//! Offline, deterministic, and network-free. Nothing here builds a proposal,
//! resolves a capability, or evaluates a policy: these tests are only about
//! whether bytes describe a well-formed proposal, which is the narrowest of the
//! four questions Kern asks about a model response.

use kern_ai::bounds::{
    MAX_ARGUMENTS, MAX_CAPABILITY_NAME_BYTES, MAX_JSON_DEPTH, MAX_REASON_BYTES, MAX_RESPONSE_BYTES,
};
use kern_ai::fake::{navigate_json, MaliciousModel, Mischief};
use kern_ai::json::JsonError;
use kern_ai::{parse_response, ParseError, ParsedModelProposal, RawModelResponse};

fn parse(bytes: &[u8]) -> Result<ParsedModelProposal, ParseError> {
    let response = RawModelResponse::new(bytes.to_vec()).expect("within the response bound");
    parse_response(&response)
}

fn parse_mischief(mischief: Mischief) -> Result<ParsedModelProposal, ParseError> {
    parse(&MaliciousModel::payload(mischief))
}

#[test]
fn valid_navigate_json_parses() {
    let parsed = parse(&navigate_json(6_000, 0, 0, 300, "Move to station B")).expect("well-formed");
    let ParsedModelProposal::Capability {
        target,
        capability,
        arguments,
        reason,
    } = parsed
    else {
        panic!("expected a capability proposal");
    };
    assert_eq!(target, None, "a response may omit the target");
    assert_eq!(capability, "navigate");
    assert_eq!(reason, "Move to station B");
    assert_eq!(arguments.len(), 4);
    let speed = arguments
        .iter()
        .find(|argument| argument.name == "max_speed_mm_s")
        .expect("the speed bound is present");
    assert_eq!(speed.value, kern_ai::ProposedValue::Integer(300));
}

#[test]
fn no_action_parses() {
    let parsed = parse(br#"{"capability":"no_action","arguments":{},"reason":"Nothing to do"}"#)
        .expect("well-formed");
    assert!(matches!(parsed, ParsedModelProposal::NoAction { .. }));
    assert_eq!(parsed.reason(), "Nothing to do");
    assert_eq!(parsed.capability(), None);
}

#[test]
fn no_action_with_arguments_is_rejected() {
    let error = parse(
        br#"{"capability":"no_action","arguments":{"destination_x_mm":1},"reason":"sneaky"}"#,
    )
    .expect_err("no_action carries nothing");
    assert!(matches!(
        error,
        ParseError::NoActionWithArguments { count: 1 }
    ));
}

#[test]
fn duplicate_json_key_is_rejected() {
    let error = parse_mischief(Mischief::DuplicateKeys).expect_err("duplicate key");
    assert!(matches!(
        error,
        ParseError::Json(JsonError::DuplicateKey { .. })
    ));
}

#[test]
fn duplicate_top_level_key_is_rejected() {
    let error =
        parse(br#"{"capability":"navigate","capability":"no_action","arguments":{},"reason":"x"}"#)
            .expect_err("duplicate key");
    assert!(matches!(
        error,
        ParseError::Json(JsonError::DuplicateKey { .. })
    ));
}

#[test]
fn unknown_top_level_field_is_rejected() {
    let error = parse_mischief(Mischief::UnknownTopLevelField).expect_err("fourth key");
    let ParseError::UnknownKey { key } = error else {
        panic!("expected an unknown-key rejection, got {error}");
    };
    assert_eq!(key, "authorized");
}

#[test]
fn missing_capability_is_rejected() {
    let error = parse_mischief(Mischief::MissingCapability).expect_err("no capability");
    assert!(matches!(
        error,
        ParseError::MissingKey { key: "capability" }
    ));
}

#[test]
fn missing_arguments_is_rejected() {
    let error =
        parse(br#"{"capability":"navigate","reason":"no arguments"}"#).expect_err("no arguments");
    assert!(matches!(error, ParseError::MissingKey { key: "arguments" }));
}

#[test]
fn missing_reason_is_rejected() {
    let error = parse(br#"{"capability":"navigate","arguments":{}}"#).expect_err("no reason");
    assert!(matches!(error, ParseError::MissingKey { key: "reason" }));
}

#[test]
fn float_numeric_value_is_rejected() {
    let error = parse_mischief(Mischief::FloatValue).expect_err("a float");
    let ParseError::NotAnInteger { name, found } = error else {
        panic!("expected an integer rejection");
    };
    assert_eq!(name, "max_speed_mm_s");
    assert_eq!(found, "300.0");
}

#[test]
fn a_boolean_argument_is_rejected() {
    let error =
        parse(br#"{"capability":"navigate","arguments":{"max_speed_mm_s":true},"reason":"bool"}"#)
            .expect_err("a boolean");
    assert!(matches!(error, ParseError::NotAValue { .. }));
}

#[test]
fn a_null_argument_is_rejected() {
    let error =
        parse(br#"{"capability":"navigate","arguments":{"max_speed_mm_s":null},"reason":"null"}"#)
            .expect_err("a null");
    assert!(matches!(error, ParseError::NotAValue { .. }));
}

#[test]
fn a_nested_object_argument_is_rejected() {
    let error = parse(
        br#"{"capability":"navigate","arguments":{"max_speed_mm_s":{"value":300}},"reason":"x"}"#,
    )
    .expect_err("an object");
    assert!(matches!(error, ParseError::NotAValue { .. }));
}

#[test]
fn a_target_is_accepted_and_bounded() {
    let parsed = parse(
        br#"{"target":"conveyor_01","capability":"transfer_item","arguments":{"destination_station":"station_b","max_speed_mm_s":200},"reason":"move it"}"#,
    )
    .expect("well-formed");
    assert_eq!(parsed.target(), Some("conveyor_01"));
    assert_eq!(parsed.capability(), Some("transfer_item"));

    let long = "t".repeat(kern_ai::parse::MAX_TARGET_BYTES + 1);
    let body =
        format!(r#"{{"target":"{long}","capability":"navigate","arguments":{{}},"reason":"x"}}"#);
    assert!(matches!(
        parse(body.as_bytes()),
        Err(ParseError::TooLong {
            field: "target",
            ..
        })
    ));

    assert!(matches!(
        parse(br#"{"target":"","capability":"navigate","arguments":{},"reason":"x"}"#),
        Err(ParseError::EmptyTarget)
    ));
}

#[test]
fn a_no_action_proposal_may_name_a_target_and_it_changes_nothing() {
    // Accepted and ignored: no proposal is built for any machine either way.
    let parsed = parse(
        br#"{"target":"conveyor_01","capability":"no_action","arguments":{},"reason":"idle"}"#,
    )
    .expect("well-formed");
    assert!(matches!(parsed, ParsedModelProposal::NoAction { .. }));
    assert_eq!(parsed.target(), None, "no_action names no machine");
    assert_eq!(parsed.capability(), None);

    // Arguments are still refused: `no_action` carries nothing.
    assert!(matches!(
        parse(br#"{"capability":"no_action","arguments":{"x":1},"reason":"x"}"#),
        Err(ParseError::NoActionWithArguments { count: 1 })
    ));
}

#[test]
fn exponent_form_is_rejected() {
    let error = parse(
        br#"{"capability":"navigate","arguments":{"max_speed_mm_s":3e2},"reason":"exponent"}"#,
    )
    .expect_err("an exponent");
    assert!(matches!(error, ParseError::NotAnInteger { .. }));
}

#[test]
fn a_numeric_string_parses_as_a_symbol_and_is_refused_by_the_schema() {
    // The parser has not met a schema, so it cannot know that
    // `destination_x_mm` wants a scalar. It accepts the string as a symbol and
    // the schema refuses the domain one stage later — still before policy,
    // still before any authority exists. The containment property is unchanged;
    // only the stage that reports the refusal moved.
    let parsed = parse_mischief(Mischief::NumericString).expect("a symbol-valued argument");
    let ParsedModelProposal::Capability { arguments, .. } = &parsed else {
        panic!("expected a capability proposal");
    };
    let x = arguments
        .iter()
        .find(|argument| argument.name == "destination_x_mm")
        .expect("present");
    assert_eq!(x.value, kern_ai::ProposedValue::Text(String::from("6000")));

    let schema = kern_execution_nav2::navigate_schema().expect("well-formed");
    let action = kern_ai::to_action_proposal(&support::request(), &parsed).expect("built");
    assert!(matches!(
        schema.normalize(&action),
        Err(kern_core::SchemaError::WrongDomain { .. })
    ));
}

#[test]
fn i64_overflow_is_rejected() {
    let error = parse_mischief(Mischief::IntegerOverflow).expect_err("out of range");
    assert!(matches!(error, ParseError::IntegerOutOfRange { .. }));
}

#[test]
fn i64_boundaries_are_accepted_and_one_past_is_not() {
    let ok = alloc_json(i64::MIN.to_string().as_str());
    assert!(parse(ok.as_bytes()).is_ok());

    let over = alloc_json("9223372036854775808");
    assert!(matches!(
        parse(over.as_bytes()),
        Err(ParseError::IntegerOutOfRange { .. })
    ));
}

fn alloc_json(value: &str) -> String {
    format!(
        r#"{{"capability":"navigate","arguments":{{"destination_x_mm":{value}}},"reason":"b"}}"#
    )
}

#[test]
fn malformed_json_is_rejected() {
    let error = parse_mischief(Mischief::MalformedJson).expect_err("truncated");
    assert!(matches!(error, ParseError::Json(JsonError::UnexpectedEnd)));
}

#[test]
fn trailing_prose_is_rejected() {
    let error = parse_mischief(Mischief::TrailingProse).expect_err("prose after the object");
    assert!(matches!(
        error,
        ParseError::Json(JsonError::TrailingBytes { .. })
    ));
}

#[test]
fn trailing_second_document_is_rejected() {
    let mut bytes = navigate_json(6_000, 0, 0, 300, "first");
    bytes.extend_from_slice(&navigate_json(0, 0, 0, 900, "second"));
    let error = parse(&bytes).expect_err("two documents");
    assert!(matches!(
        error,
        ParseError::Json(JsonError::TrailingBytes { .. })
    ));
}

#[test]
fn an_array_of_actions_is_rejected() {
    let error = parse_mischief(Mischief::MultipleActions).expect_err("an array");
    assert!(matches!(error, ParseError::NotAnObject { found: "array" }));
}

#[test]
fn a_top_level_array_is_rejected() {
    let error = parse_mischief(Mischief::NotAnObject).expect_err("an array");
    assert!(matches!(error, ParseError::NotAnObject { found: "array" }));
}

#[test]
fn arguments_must_be_an_object() {
    let error = parse(br#"{"capability":"navigate","arguments":[6000],"reason":"array"}"#)
        .expect_err("an array");
    assert!(matches!(error, ParseError::WrongType { .. }));
}

#[test]
fn reserved_argument_names_are_rejected() {
    for name in [
        "ttl",
        "issuer",
        "key_id",
        "nonce",
        "challenge",
        "enforcer_session",
        "lease_id",
        "policy_id",
        "execution_id",
    ] {
        let body = format!(
            r#"{{"capability":"navigate","arguments":{{"{name}":1}},"reason":"mine now"}}"#
        );
        let error = parse(body.as_bytes())
            .unwrap_err_or_panic(&format!("`{name}` was accepted as an argument name"));
        assert!(
            matches!(&error, ParseError::ReservedArgument { name: found } if found == name),
            "expected `{name}` to be reserved, got {error}"
        );
    }
}

/// `Result::unwrap_err` with a message that names the offending case.
trait UnwrapErrOrPanic<E> {
    fn unwrap_err_or_panic(self, message: &str) -> E;
}

impl<T, E> UnwrapErrOrPanic<E> for Result<T, E> {
    fn unwrap_err_or_panic(self, message: &str) -> E {
        match self {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }
}

#[test]
fn oversized_response_cannot_even_be_constructed() {
    let bytes = vec![b'a'; MAX_RESPONSE_BYTES + 1];
    let error = RawModelResponse::new(bytes).expect_err("over the bound");
    assert_eq!(error.bytes, MAX_RESPONSE_BYTES + 1);

    // And the bound is inclusive: exactly the bound is allowed to exist, and is
    // then rejected by the parser on its merits rather than on its size.
    let at_bound = RawModelResponse::new(vec![b'a'; MAX_RESPONSE_BYTES]).expect("at the bound");
    assert!(parse_response(&at_bound).is_err());
}

#[test]
fn an_empty_response_is_rejected() {
    let response = RawModelResponse::new(Vec::new()).expect("empty");
    assert_eq!(parse_response(&response), Err(ParseError::Empty));
}

#[test]
fn an_oversized_capability_name_is_rejected() {
    let name = "n".repeat(MAX_CAPABILITY_NAME_BYTES + 1);
    let body = format!(r#"{{"capability":"{name}","arguments":{{}},"reason":"x"}}"#);
    let error = parse(body.as_bytes()).expect_err("over the bound");
    assert!(matches!(
        error,
        ParseError::TooLong {
            field: "capability",
            ..
        }
    ));
}

#[test]
fn an_oversized_reason_is_rejected() {
    let reason = "r".repeat(MAX_REASON_BYTES + 1);
    let body = format!(r#"{{"capability":"navigate","arguments":{{}},"reason":"{reason}"}}"#);
    let error = parse(body.as_bytes()).expect_err("over the bound");
    assert!(matches!(
        error,
        ParseError::TooLong {
            field: "reason",
            ..
        }
    ));
}

#[test]
fn too_many_arguments_are_rejected() {
    let arguments: Vec<String> = (0..=MAX_ARGUMENTS)
        .map(|index| format!(r#""arg_{index}":{index}"#))
        .collect();
    let body = format!(
        r#"{{"capability":"navigate","arguments":{{{}}},"reason":"many"}}"#,
        arguments.join(",")
    );
    let error = parse(body.as_bytes()).expect_err("over the bound");
    assert!(matches!(error, ParseError::TooManyArguments { .. }));
}

#[test]
fn deep_nesting_is_rejected() {
    let depth = MAX_JSON_DEPTH + 2;
    let body = format!(
        r#"{{"capability":"navigate","arguments":{{"x":{}{}}},"reason":"deep"}}"#,
        "[".repeat(depth),
        "]".repeat(depth)
    );
    let error = parse(body.as_bytes()).expect_err("too deep");
    assert!(matches!(
        error,
        ParseError::Json(JsonError::DepthExceeded { .. })
    ));
}

#[test]
fn one_json_fence_is_unwrapped() {
    let parsed = parse_mischief(Mischief::FencedButValid).expect("one fence is unwrapped");
    assert_eq!(parsed.capability(), Some("navigate"));
}

#[test]
fn a_bare_fence_is_unwrapped() {
    let mut bytes = b"```\n".to_vec();
    bytes.extend_from_slice(&navigate_json(6_000, 0, 0, 300, "fenced"));
    bytes.extend_from_slice(b"\n```");
    assert_eq!(
        parse(&bytes).expect("unwrapped").capability(),
        Some("navigate")
    );
}

#[test]
fn two_fences_are_refused() {
    let error = parse_mischief(Mischief::DoubleFenced).expect_err("two documents");
    // Left exactly as it arrived, so the JSON reader refuses the backticks.
    assert!(matches!(
        error,
        ParseError::Json(JsonError::Unexpected { .. })
    ));
}

#[test]
fn prose_before_the_json_is_not_extracted() {
    // The deliberate absence of a feature: no scanning for the first `{`.
    let mut bytes = b"Sure! Here is the plan:\n".to_vec();
    bytes.extend_from_slice(&navigate_json(6_000, 0, 0, 300, "chatty"));
    let error = parse(&bytes).expect_err("prose is not stripped");
    assert!(matches!(
        error,
        ParseError::Json(JsonError::Unexpected { .. })
    ));
}

#[test]
fn a_reasoning_preamble_is_not_extracted() {
    let mut bytes = b"<think>The user wants station B.</think>\n".to_vec();
    bytes.extend_from_slice(&navigate_json(6_000, 0, 0, 300, "reasoning leaked"));
    assert!(parse(&bytes).is_err());
}

#[test]
fn invalid_utf8_is_rejected() {
    let error = parse(&[0xff, 0xfe, 0x00]).expect_err("not utf-8");
    assert_eq!(error, ParseError::Json(JsonError::NotUtf8));
}

#[test]
fn a_structured_provider_response_still_passes_the_local_parser() {
    // What a provider's JSON-schema mode would emit for the frozen contract:
    // exactly the same bytes, which the local parser checks exactly the same
    // way. Provider-side enforcement is never a reason to skip this step.
    let bytes = br#"{"capability": "navigate", "arguments": {"destination_x_mm": 6000, "destination_y_mm": 0, "yaw_mdeg": 0, "max_speed_mm_s": 300}, "reason": "Station B"}"#;
    assert_eq!(
        parse(bytes).expect("well-formed").capability(),
        Some("navigate")
    );
}

#[test]
fn a_provider_that_ignores_the_schema_is_still_refused() {
    // The same provider, the same schema request, a model that answered with a
    // tool call instead. Structured output is not trusted output.
    let bytes = br#"{"tool_calls":[{"function":{"name":"navigate","arguments":"{\"max_speed_mm_s\":900}"}}]}"#;
    assert!(matches!(parse(bytes), Err(ParseError::UnknownKey { .. })));
}

/// The trusted request the domain test builds a proposal against.
mod support {
    use kern_ai::{CapabilityVocabulary, Instruction, PlanningRequest, RobotContext};
    use kern_core::{DeviceId, SubjectId};
    use kern_policy::CapabilityRegistry;

    pub fn request() -> PlanningRequest {
        let device = DeviceId::new("cafe_bot_01");
        let mut registry = CapabilityRegistry::new();
        registry
            .register(
                device.clone(),
                kern_execution_nav2::navigate_schema().expect("well-formed"),
            )
            .expect("registered");
        PlanningRequest::new(
            SubjectId::new("planner_a"),
            device.clone(),
            Instruction::new("fixture").expect("bounded"),
            RobotContext::default(),
            CapabilityVocabulary::from_registry(&registry, &device).expect("navigate exists"),
        )
    }
}
