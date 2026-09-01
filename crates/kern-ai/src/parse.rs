//! The strict local parser. Kern's side of the trust boundary.
//!
//! ```text
//! RawModelResponse       attacker-controlled bytes
//!   -> one optional fence unwrap, deterministic
//!   -> crate::json        a hostile JSON reader
//!   -> shape check        exactly three keys, exactly one proposal
//!   -> ParsedModelProposal
//! ```
//!
//! # The frozen response contract
//!
//! ```json
//! {
//!   "capability": "navigate",
//!   "arguments": {
//!     "destination_x_mm": 6000,
//!     "destination_y_mm": 0,
//!     "yaw_mdeg": 0,
//!     "max_speed_mm_s": 300
//!   },
//!   "reason": "Move to station B"
//! }
//! ```
//!
//! All three keys are required, no fourth key is accepted, and the capability
//! `no_action` is the reserved way to propose nothing:
//!
//! ```json
//! { "capability": "no_action", "arguments": {}, "reason": "Nothing to do" }
//! ```
//!
//! # Parsing is not authorization
//!
//! Success here means one thing: the bytes describe a syntactically acceptable
//! proposal. It does not mean the capability exists, that the arguments name
//! real parameters, that the values are in range, or that anybody may request
//! it. Those are the registry's, the schema's, and policy's answers, in that
//! order, and each is a separate call in a separate crate.
//!
//! # Structured output is not trusted output
//!
//! When a provider can enforce a JSON schema server-side, the adapter is welcome
//! to ask it to. It changes nothing here. Provider-side enforcement improves the
//! odds that a well-behaved model produces parseable output; it is not evidence
//! about a model that is not well-behaved, and it is not evidence at all about a
//! response that did not come from the provider Kern thinks it did.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use crate::bounds::{
    MAX_ARGUMENTS, MAX_ARGUMENT_NAME_BYTES, MAX_CAPABILITY_NAME_BYTES, MAX_REASON_BYTES,
};
use crate::json::{self, Json, JsonError};
use crate::model::RawModelResponse;

/// The capability name that means "propose nothing".
///
/// Reserved at the parser, so it can never travel further as an ordinary
/// capability name. Registering a Kern capability under this name would not
/// make it reachable from a model: the parser turns it into
/// [`ParsedModelProposal::NoAction`] before any registry sees it.
pub const NO_ACTION: &str = "no_action";

/// The keys the response contract allows, and nothing else.
///
/// `target` is optional and names a *logical* machine, never a `DeviceId`. It
/// was added when Kern began governing more than one machine; a response
/// omitting it is still valid, and the host's own default device is used. See
/// [`crate::proposal`] for why a model-supplied target is not authority.
pub const RESPONSE_KEYS: [&str; 4] = ["target", "capability", "arguments", "reason"];

/// The largest logical target name a model may write.
pub const MAX_TARGET_BYTES: usize = 64;

/// The largest symbolic argument value a model may write.
pub const MAX_SYMBOL_BYTES: usize = 64;

/// Argument names a model may never use.
///
/// Every one of these names something the model does not get to choose: the
/// lifetime of authority, who issued it, which key signed it, the freshness
/// binding, the enforcer's session, or an identifier Kern allocates. None of
/// them is a capability parameter, so all of them would be refused at schema
/// normalization anyway.
///
/// They are refused *here* as well, one stage earlier, because a proposal that
/// tries to set its own TTL is worth being able to point at as its own
/// rejection rather than as a generic unknown-parameter error.
pub const RESERVED_ARGUMENT_NAMES: [&str; 9] = [
    "ttl",
    "issuer",
    "key_id",
    "nonce",
    "challenge",
    "enforcer_session",
    "lease_id",
    "policy_id",
    "execution_id",
];

/// The response does not describe an acceptable proposal.
///
/// # Not a denial
///
/// A `ParseError` says the bytes do not describe a proposal at all. It shares
/// nothing with `PolicyDecision::Denied`, which says the bytes described a real
/// operation that nobody may perform. Collapsing them would make "the model
/// emitted garbage" and "the model asked for something forbidden" the same
/// event in a log, and they are not the same event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The response was empty.
    Empty,
    /// The JSON reader refused the bytes.
    Json(JsonError),
    /// The document is a JSON value, but not an object.
    ///
    /// A top-level array is refused here, which is also how "several proposals
    /// at once" is refused: there is no shape in this contract that can carry
    /// more than one.
    NotAnObject {
        /// What the top level actually was.
        found: &'static str,
    },
    /// A required key is absent.
    MissingKey {
        /// Which one.
        key: &'static str,
    },
    /// The response declares a key the contract does not define.
    ///
    /// This is where `ttl`, `issuer`, `lease_id`, and every other
    /// authority-shaped field a model might invent is refused.
    UnknownKey {
        /// The offending key.
        key: String,
    },
    /// A value has the wrong JSON type.
    WrongType {
        /// Which key.
        key: String,
        /// What the contract requires.
        expected: &'static str,
        /// What was found.
        found: &'static str,
    },
    /// The capability name is empty.
    EmptyCapability,
    /// The target name is empty.
    EmptyTarget,
    /// A name or text field exceeds its frozen bound.
    TooLong {
        /// Which field.
        field: &'static str,
        /// How many bytes it held.
        bytes: usize,
        /// The bound it exceeded.
        bound: usize,
    },
    /// The proposal carries more arguments than the bound allows.
    TooManyArguments {
        /// How many were offered.
        count: usize,
    },
    /// An argument name is reserved and can never be a capability parameter.
    ReservedArgument {
        /// The offending name.
        name: String,
    },
    /// An argument value is not an integer literal.
    ///
    /// Covers a float, an exponent form, a numeric string, a boolean, a null,
    /// an array, and an object. Kern's parameter domain is `i64`, and there is
    /// no conversion step here that could round one thing into another.
    NotAnInteger {
        /// Which argument.
        name: String,
        /// What was found, as written.
        found: String,
    },
    /// An integer literal does not fit in an `i64`.
    IntegerOutOfRange {
        /// Which argument.
        name: String,
        /// The literal, as written.
        literal: String,
    },
    /// A `no_action` proposal carried arguments.
    NoActionWithArguments {
        /// How many.
        count: usize,
    },
    /// An argument value is not a value any parameter domain accepts.
    ///
    /// Covers a float, an exponent form, a boolean, a null, an array, and an
    /// object. Kern's parameter domains are integers and symbols, and there is
    /// no conversion step here that could round one thing into another.
    NotAValue {
        /// Which argument.
        name: String,
        /// What was found, as written.
        found: String,
    },
}

impl From<JsonError> for ParseError {
    fn from(error: JsonError) -> Self {
        Self::Json(error)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("model returned no bytes"),
            Self::Json(error) => write!(f, "{error}"),
            Self::NotAnObject { found } => {
                write!(f, "response must be a json object, found {found}")
            }
            Self::MissingKey { key } => write!(f, "response is missing `{key}`"),
            Self::UnknownKey { key } => write!(f, "response declares unknown key `{key}`"),
            Self::WrongType {
                key,
                expected,
                found,
            } => write!(f, "`{key}` must be {expected}, found {found}"),
            Self::EmptyCapability => f.write_str("capability name is empty"),
            Self::EmptyTarget => f.write_str("target name is empty"),
            Self::TooLong {
                field,
                bytes,
                bound,
            } => write!(f, "{field} is {bytes} bytes, over the {bound} byte bound"),
            Self::TooManyArguments { count } => write!(
                f,
                "proposal carries {count} arguments, over the {MAX_ARGUMENTS} bound"
            ),
            Self::ReservedArgument { name } => write!(f, "`{name}` is a reserved argument name"),
            Self::NotAnInteger { name, found } => {
                write!(f, "argument `{name}` must be an integer, found {found}")
            }
            Self::IntegerOutOfRange { name, literal } => {
                write!(f, "argument `{name}` value {literal} does not fit in i64")
            }
            Self::NoActionWithArguments { count } => write!(
                f,
                "a `{NO_ACTION}` proposal must carry no arguments, found {count}"
            ),
            Self::NotAValue { name, found } => write!(
                f,
                "argument `{name}` must be an integer or a string, found {found}"
            ),
        }
    }
}

impl core::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

/// A value a model proposed for an argument.
///
/// Two shapes, matching the two value domains
/// [`ParamDomain`](kern_core::ParamDomain) declares. The parser does not know
/// which domain any particular parameter wants — it has not met a schema — so it
/// accepts either and lets [`CapabilitySchema::normalize`](kern_core::CapabilitySchema::normalize)
/// refuse the mismatch. A quoted `"6000"` offered for a scalar parameter is
/// therefore a *domain* rejection rather than a parse rejection, one stage
/// later and just as closed.
///
/// Everything else a JSON value can be — a float, an exponent form, a boolean,
/// null, an array, an object, an integer outside `i64` — is refused here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposedValue {
    /// An integer literal.
    Integer(i64),
    /// A string literal, bounded.
    Text(String),
}

impl ProposedValue {
    /// A short name for the kind of value, for error messages.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Integer(_) => "integer",
            Self::Text(_) => "string",
        }
    }
}

/// One argument a model proposed.
///
/// The name is still a string and the value has still met no schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposedArgument {
    /// The argument name, exactly as the model wrote it.
    pub name: String,
    /// The value, exactly as the model wrote it.
    pub value: ProposedValue,
}

/// A model response that survived parsing.
///
/// Holding one proves the bytes were well-formed against the response contract.
/// It proves nothing else. In particular a `Capability` variant may name a
/// capability that does not exist, arguments that are not parameters, and values
/// no policy would ever permit — all three are expected, and all three are
/// somebody else's rejection to make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedModelProposal {
    /// The model proposed nothing.
    NoAction {
        /// The model's stated reason.
        reason: String,
    },
    /// The model proposed one capability invocation.
    Capability {
        /// The logical machine the model asked for, if it named one.
        ///
        /// A *request*, not a selection. Only a trusted
        /// [`DeviceRouter`](crate::DeviceRouter) turns it into a `DeviceId`,
        /// and an unknown name resolves to nothing at all.
        target: Option<String>,
        /// The capability name the model asked for.
        capability: String,
        /// The arguments, in the order the model wrote them.
        arguments: Vec<ProposedArgument>,
        /// The model's stated reason.
        reason: String,
    },
}

impl ParsedModelProposal {
    /// The model's stated reason, whichever variant this is.
    ///
    /// Free text a model wrote. Print it, log it, show it in a demo; never
    /// branch authority on it.
    pub fn reason(&self) -> &str {
        match self {
            Self::NoAction { reason } | Self::Capability { reason, .. } => reason,
        }
    }

    /// The capability name, when the model proposed one.
    pub fn capability(&self) -> Option<&str> {
        match self {
            Self::Capability { capability, .. } => Some(capability),
            Self::NoAction { .. } => None,
        }
    }

    /// The logical target the model asked for, if it named one.
    pub fn target(&self) -> Option<&str> {
        match self {
            Self::Capability { target, .. } => target.as_deref(),
            Self::NoAction { .. } => None,
        }
    }
}

/// Parses one model response.
///
/// The only entry point. There is no lenient variant, no "best effort" mode,
/// and no way to recover a partial proposal from a rejected response.
pub fn parse_response(response: &RawModelResponse) -> Result<ParsedModelProposal, ParseError> {
    if response.is_empty() {
        return Err(ParseError::Empty);
    }
    parse_bytes(unwrap_fence(response.as_bytes()))
}

/// Strips exactly one supported code fence, or returns the input unchanged.
///
/// Supported, exhaustively: a leading <code>```json</code> or <code>```</code>
/// line and a trailing <code>```</code>, around the whole trimmed document.
///
/// This is the entire extraction logic and it will not grow. No scanning for
/// the first `{`, no balancing braces, no regular expression, no "take the
/// largest JSON-looking substring". Every one of those turns a response the
/// model did not mean into a proposal Kern acts on, and each is a well-worn way
/// to smuggle a second document past a reader. A response this function does
/// not recognise is left exactly as it arrived, and the JSON reader refuses it.
fn unwrap_fence(bytes: &[u8]) -> &[u8] {
    let trimmed = trim_ascii(bytes);
    let Some(rest) = strip_prefix(trimmed, b"```") else {
        return bytes;
    };
    let rest = strip_prefix(rest, b"json").unwrap_or(rest);
    // The opening fence must end its line; `` ```jsonp `` is not a fence Kern
    // recognises.
    let Some(rest) = strip_prefix(rest, b"\n").or_else(|| strip_prefix(rest, b"\r\n")) else {
        return bytes;
    };
    let rest = trim_ascii(rest);
    let Some(inner) = strip_suffix(rest, b"```") else {
        return bytes;
    };
    let inner = trim_ascii(inner);
    // A second fence anywhere inside means the response carries more than one
    // block, and the contract allows exactly one document.
    if contains(inner, b"```") {
        return bytes;
    }
    inner
}

fn parse_bytes(bytes: &[u8]) -> Result<ParsedModelProposal, ParseError> {
    let document = json::parse(bytes)?;
    let Some(members) = document.as_object() else {
        return Err(ParseError::NotAnObject {
            found: document.kind(),
        });
    };

    for (key, _) in members {
        if !RESPONSE_KEYS.contains(&key.as_str()) {
            return Err(ParseError::UnknownKey { key: key.clone() });
        }
    }

    let capability = required(&document, "capability")?;
    let arguments = required(&document, "arguments")?;
    let reason = required(&document, "reason")?;

    // Optional, and a request rather than a selection. A response that omits it
    // is the Phase 7 shape, and the host's own device is used.
    let target = match document.get("target") {
        None => None,
        Some(value) => {
            let target = expect_string(value, "target")?;
            if target.is_empty() {
                return Err(ParseError::EmptyTarget);
            }
            bound_field(&target, "target", MAX_TARGET_BYTES)?;
            Some(target)
        }
    };

    let capability = expect_string(capability, "capability")?;
    let reason = expect_string(reason, "reason")?;
    bound_field(&reason, "reason", MAX_REASON_BYTES)?;

    if capability.is_empty() {
        return Err(ParseError::EmptyCapability);
    }
    bound_field(&capability, "capability", MAX_CAPABILITY_NAME_BYTES)?;

    let Some(members) = arguments.as_object() else {
        return Err(ParseError::WrongType {
            key: "arguments".to_string(),
            expected: "an object",
            found: arguments.kind(),
        });
    };

    if capability == NO_ACTION {
        // A target alongside `no_action` is accepted and ignored. It names the
        // machine the model was thinking about, and no proposal is built for any
        // machine either way — refusing it would report a malformed response
        // where the truthful answer is that nothing was proposed.
        if !members.is_empty() {
            return Err(ParseError::NoActionWithArguments {
                count: members.len(),
            });
        }
        return Ok(ParsedModelProposal::NoAction { reason });
    }

    if members.len() > MAX_ARGUMENTS {
        return Err(ParseError::TooManyArguments {
            count: members.len(),
        });
    }

    let mut arguments = Vec::with_capacity(members.len());
    for (name, value) in members {
        bound_field(name, "argument name", MAX_ARGUMENT_NAME_BYTES)?;
        if RESERVED_ARGUMENT_NAMES.contains(&name.as_str()) {
            return Err(ParseError::ReservedArgument { name: name.clone() });
        }
        let value = match value {
            Json::Number(number) => {
                if !number.is_integral() {
                    return Err(ParseError::NotAnInteger {
                        name: name.clone(),
                        found: number.lexeme().to_string(),
                    });
                }
                let Some(value) = number.as_i64() else {
                    return Err(ParseError::IntegerOutOfRange {
                        name: name.clone(),
                        literal: number.lexeme().to_string(),
                    });
                };
                ProposedValue::Integer(value)
            }
            Json::String(text) => {
                bound_field(text, "argument value", MAX_SYMBOL_BYTES)?;
                ProposedValue::Text(text.clone())
            }
            other => {
                return Err(ParseError::NotAValue {
                    name: name.clone(),
                    found: other.kind().to_string(),
                })
            }
        };
        arguments.push(ProposedArgument {
            name: name.clone(),
            value,
        });
    }

    Ok(ParsedModelProposal::Capability {
        target,
        capability,
        arguments,
        reason,
    })
}

fn required<'a>(document: &'a Json, key: &'static str) -> Result<&'a Json, ParseError> {
    document.get(key).ok_or(ParseError::MissingKey { key })
}

fn expect_string(value: &Json, key: &'static str) -> Result<String, ParseError> {
    value
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| ParseError::WrongType {
            key: key.to_string(),
            expected: "a string",
            found: value.kind(),
        })
}

fn bound_field(value: &str, field: &'static str, bound: usize) -> Result<(), ParseError> {
    if value.len() > bound {
        return Err(ParseError::TooLong {
            field,
            bytes: value.len(),
            bound,
        });
    }
    Ok(())
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}

fn strip_prefix<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    bytes.starts_with(prefix).then(|| &bytes[prefix.len()..])
}

fn strip_suffix<'a>(bytes: &'a [u8], suffix: &[u8]) -> Option<&'a [u8]> {
    bytes
        .ends_with(suffix)
        .then(|| &bytes[..bytes.len() - suffix.len()])
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
