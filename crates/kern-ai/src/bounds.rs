//! The frozen resource bounds of the proposal plane.
//!
//! Every one of these is a constant rather than a configuration knob. A bound a
//! deployment can raise is a bound an attacker can argue about, and the whole
//! point of this module is that the answer to "how large may attacker-controlled
//! input be" does not depend on who is asking.
//!
//! The numbers are deliberately small. A `navigate` proposal is four integers, a
//! capability name, and a sentence; nothing legitimate comes close to these
//! ceilings, so a response that does is already not the response Kern asked for.

/// The largest natural-language instruction the plane will send to a model.
pub const MAX_INSTRUCTION_BYTES: usize = 4_096;

/// The largest robot-context block the plane will send to a model.
pub const MAX_ROBOT_CONTEXT_BYTES: usize = 4_096;

/// The largest model response the plane will read.
///
/// A provider is free to return more. The plane refuses to look at it: the
/// response is truncated *and rejected*, never truncated and parsed.
pub const MAX_RESPONSE_BYTES: usize = 16_384;

/// The largest capability name a model may name.
///
/// Naming a capability is not obtaining one. This bound exists so an unknown
/// capability is cheap to reject, not because a long name would be dangerous.
pub const MAX_CAPABILITY_NAME_BYTES: usize = 64;

/// The largest argument name a model may name.
pub const MAX_ARGUMENT_NAME_BYTES: usize = 64;

/// The largest free-text reason a model may attach to a proposal.
pub const MAX_REASON_BYTES: usize = 512;

/// The largest number of arguments one proposal may carry.
pub const MAX_ARGUMENTS: usize = 16;

/// How deeply the JSON reader will nest before refusing.
///
/// The reader recurses, so this is also the bound on its stack use. The
/// proposal contract is two levels deep; the provider envelope is four.
pub const MAX_JSON_DEPTH: usize = 8;

/// The largest number of members one JSON object may declare.
pub const MAX_JSON_OBJECT_MEMBERS: usize = 64;

/// The largest number of elements one JSON array may hold.
pub const MAX_JSON_ARRAY_ELEMENTS: usize = 64;

/// The largest JSON string, in bytes of decoded UTF-8.
pub const MAX_JSON_STRING_BYTES: usize = 8_192;

/// How many proposals one model response may contain.
///
/// One. This is a constant so it is greppable, not because it is expected to
/// change: an autonomous multi-step plan is a different security problem than
/// the one this phase solves.
pub const MAX_PROPOSALS: usize = 1;

/// How many replans a single instruction may ever trigger.
///
/// One. The second attempt is evaluated from scratch, and there is no third.
pub const MAX_REPLANS: u8 = 1;
