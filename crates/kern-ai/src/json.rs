//! A deliberately hostile JSON reader.
//!
//! Kern does not need a general JSON library. It needs a reader that refuses
//! everything it is not required to accept, and that says exactly why. This one
//! is written rather than pulled in because the interesting requirements —
//! rejecting duplicate keys, refusing a float where an integer belongs,
//! refusing trailing bytes, bounding depth and width before recursing — are
//! precisely the ones a permissive general-purpose parser is designed to
//! smooth over.
//!
//! # What it refuses
//!
//! ```text
//! invalid UTF-8            malformed JSON          trailing bytes after a value
//! duplicate object keys    unescaped controls      lone surrogates
//! nesting past the bound   objects/arrays past the width bound
//! strings past the byte bound
//! ```
//!
//! Numbers are kept as their source lexeme plus an integral flag, and are never
//! converted to a float. `900` and `900.0` are therefore distinguishable, which
//! is what lets the proposal parser refuse the second one:
//! [`Number::as_i64`] returns `None` for anything that is not an exact `i64`.
//!
//! # Recursion
//!
//! [`Reader::value`] recurses, and the depth bound is checked *before* each
//! descent, so the reader's stack use is bounded by
//! [`MAX_JSON_DEPTH`](crate::bounds::MAX_JSON_DEPTH) regardless of input.
//! Nothing here panics, indexes unchecked, or allocates without a bound.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::bounds::{
    MAX_JSON_ARRAY_ELEMENTS, MAX_JSON_DEPTH, MAX_JSON_OBJECT_MEMBERS, MAX_JSON_STRING_BYTES,
};

/// A JSON number, kept as written.
///
/// The lexeme is retained rather than a parsed value because the *shape* of the
/// number is load-bearing: a proposal parameter must be an integer literal, and
/// only the source text can tell `300` from `300.0` after the fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Number {
    lexeme: String,
    integral: bool,
}

impl Number {
    /// The number exactly as the document wrote it.
    pub fn lexeme(&self) -> &str {
        &self.lexeme
    }

    /// True when the literal had neither a fraction nor an exponent.
    ///
    /// `1e3` is not integral. It denotes an integer, but it is not written as
    /// one, and a model that writes it is not following the contract it was
    /// given. Accepting it would mean owning a float-to-integer conversion on
    /// the path to physical authority.
    pub fn is_integral(&self) -> bool {
        self.integral
    }

    /// The value as an `i64`, or `None` if it is not exactly one.
    ///
    /// `None` for a non-integral literal and for anything outside the `i64`
    /// range. There is no saturating variant and there will not be one: a
    /// clamped coordinate is a different destination.
    pub fn as_i64(&self) -> Option<i64> {
        if !self.integral {
            return None;
        }
        self.lexeme.parse::<i64>().ok()
    }
}

/// One JSON value.
///
/// Object members keep document order and are guaranteed key-unique: the reader
/// refuses a duplicate rather than letting a later member win. "Last one wins"
/// is how two readers of the same bytes come to disagree about what was said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as written.
    Number(Number),
    /// A string, with escapes decoded.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object, in document order, with unique keys.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// The member named `key`, if this is an object that declares it.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Self::Object(members) => members
                .iter()
                .find_map(|(name, value)| (name == key).then_some(value)),
            _ => None,
        }
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// The number, if this is one.
    pub fn as_number(&self) -> Option<&Number> {
        match self {
            Self::Number(value) => Some(value),
            _ => None,
        }
    }

    /// The object members, if this is an object.
    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Self::Object(members) => Some(members),
            _ => None,
        }
    }

    /// The array elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Self::Array(elements) => Some(elements),
            _ => None,
        }
    }

    /// A short name for the kind of value this is, for error messages.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Number(_) => "number",
            Self::String(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }
}

/// The reader refused the input.
///
/// Every variant carries the byte offset it refused at, so a rejection can be
/// pointed at rather than described.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsonError {
    /// The bytes are not valid UTF-8.
    NotUtf8,
    /// The document ended in the middle of a value.
    UnexpectedEnd,
    /// A byte appeared where it cannot.
    Unexpected {
        /// Where.
        offset: usize,
    },
    /// A value parsed, but bytes followed it.
    TrailingBytes {
        /// Where the extra bytes start.
        offset: usize,
    },
    /// An object declared the same key twice.
    DuplicateKey {
        /// The repeated key.
        key: String,
        /// Where the repeat starts.
        offset: usize,
    },
    /// The value nests deeper than the bound allows.
    DepthExceeded {
        /// Where the offending descent starts.
        offset: usize,
    },
    /// An object or array holds more members than the bound allows.
    TooManyMembers {
        /// Where the offending member starts.
        offset: usize,
    },
    /// A string is longer than the bound allows.
    StringTooLong {
        /// Where the string starts.
        offset: usize,
    },
    /// A number literal is malformed.
    MalformedNumber {
        /// Where the literal starts.
        offset: usize,
    },
    /// A string escape is malformed, or encodes a lone surrogate.
    MalformedEscape {
        /// Where the escape starts.
        offset: usize,
    },
    /// A raw control byte appeared inside a string.
    ControlCharacter {
        /// Where.
        offset: usize,
    },
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8 => f.write_str("response is not valid UTF-8"),
            Self::UnexpectedEnd => f.write_str("json ended mid-value"),
            Self::Unexpected { offset } => write!(f, "unexpected byte at {offset}"),
            Self::TrailingBytes { offset } => {
                write!(f, "trailing bytes after the value at {offset}")
            }
            Self::DuplicateKey { key, offset } => write!(f, "duplicate key `{key}` at {offset}"),
            Self::DepthExceeded { offset } => write!(f, "json nests too deeply at {offset}"),
            Self::TooManyMembers { offset } => write!(f, "too many members at {offset}"),
            Self::StringTooLong { offset } => write!(f, "string too long at {offset}"),
            Self::MalformedNumber { offset } => write!(f, "malformed number at {offset}"),
            Self::MalformedEscape { offset } => write!(f, "malformed escape at {offset}"),
            Self::ControlCharacter { offset } => {
                write!(f, "unescaped control character in string at {offset}")
            }
        }
    }
}

impl core::error::Error for JsonError {}

/// Reads exactly one JSON value from `bytes`, refusing anything after it.
///
/// The whole document must be one value. A response that is a value followed by
/// prose, or by a second value, is refused rather than partially believed.
pub fn parse(bytes: &[u8]) -> Result<Json, JsonError> {
    let text = core::str::from_utf8(bytes).map_err(|_| JsonError::NotUtf8)?;
    let mut reader = Reader {
        input: text.as_bytes(),
        offset: 0,
    };
    reader.skip_whitespace();
    let value = reader.value(0)?;
    reader.skip_whitespace();
    if reader.offset != reader.input.len() {
        return Err(JsonError::TrailingBytes {
            offset: reader.offset,
        });
    }
    Ok(value)
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.offset += 1;
        Some(byte)
    }

    fn expect(&mut self, byte: u8) -> Result<(), JsonError> {
        match self.peek() {
            Some(found) if found == byte => {
                self.offset += 1;
                Ok(())
            }
            Some(_) => Err(JsonError::Unexpected {
                offset: self.offset,
            }),
            None => Err(JsonError::UnexpectedEnd),
        }
    }

    /// Only the four bytes RFC 8259 calls whitespace. No comments, no BOM, no
    /// trailing commas: this reader implements JSON, not a dialect of it.
    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.offset += 1;
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), JsonError> {
        let start = self.offset;
        if self.input.len() - start < word.len() {
            return Err(JsonError::UnexpectedEnd);
        }
        if &self.input[start..start + word.len()] != word {
            return Err(JsonError::Unexpected { offset: start });
        }
        self.offset += word.len();
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<Json, JsonError> {
        match self.peek().ok_or(JsonError::UnexpectedEnd)? {
            b'n' => self.literal(b"null").map(|()| Json::Null),
            b't' => self.literal(b"true").map(|()| Json::Bool(true)),
            b'f' => self.literal(b"false").map(|()| Json::Bool(false)),
            b'"' => self.string().map(Json::String),
            b'-' | b'0'..=b'9' => self.number().map(Json::Number),
            b'[' => self.array(depth),
            b'{' => self.object(depth),
            _ => Err(JsonError::Unexpected {
                offset: self.offset,
            }),
        }
    }

    /// Checks the depth bound before descending, so recursion is bounded by
    /// construction rather than by how the input happens to be shaped.
    fn descend(&self, depth: usize) -> Result<usize, JsonError> {
        if depth + 1 > MAX_JSON_DEPTH {
            return Err(JsonError::DepthExceeded {
                offset: self.offset,
            });
        }
        Ok(depth + 1)
    }

    fn array(&mut self, depth: usize) -> Result<Json, JsonError> {
        let inner = self.descend(depth)?;
        self.expect(b'[')?;
        let mut elements = Vec::new();

        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.offset += 1;
            return Ok(Json::Array(elements));
        }

        loop {
            self.skip_whitespace();
            if elements.len() == MAX_JSON_ARRAY_ELEMENTS {
                return Err(JsonError::TooManyMembers {
                    offset: self.offset,
                });
            }
            elements.push(self.value(inner)?);
            self.skip_whitespace();
            match self.bump().ok_or(JsonError::UnexpectedEnd)? {
                b',' => continue,
                b']' => return Ok(Json::Array(elements)),
                _ => {
                    return Err(JsonError::Unexpected {
                        offset: self.offset - 1,
                    })
                }
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, JsonError> {
        let inner = self.descend(depth)?;
        self.expect(b'{')?;
        let mut members: Vec<(String, Json)> = Vec::new();

        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.offset += 1;
            return Ok(Json::Object(members));
        }

        loop {
            self.skip_whitespace();
            let key_offset = self.offset;
            if members.len() == MAX_JSON_OBJECT_MEMBERS {
                return Err(JsonError::TooManyMembers { offset: key_offset });
            }
            let key = self.string()?;
            if members.iter().any(|(existing, _)| existing == &key) {
                return Err(JsonError::DuplicateKey {
                    key,
                    offset: key_offset,
                });
            }
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.value(inner)?;
            members.push((key, value));

            self.skip_whitespace();
            match self.bump().ok_or(JsonError::UnexpectedEnd)? {
                b',' => continue,
                b'}' => return Ok(Json::Object(members)),
                _ => {
                    return Err(JsonError::Unexpected {
                        offset: self.offset - 1,
                    })
                }
            }
        }
    }

    fn string(&mut self) -> Result<String, JsonError> {
        let start = self.offset;
        self.expect(b'"')?;
        let mut out = String::new();

        loop {
            if out.len() > MAX_JSON_STRING_BYTES {
                return Err(JsonError::StringTooLong { offset: start });
            }
            match self.bump().ok_or(JsonError::UnexpectedEnd)? {
                b'"' => return Ok(out),
                b'\\' => self.escape(&mut out)?,
                byte if byte < 0x20 => {
                    return Err(JsonError::ControlCharacter {
                        offset: self.offset - 1,
                    })
                }
                byte if byte < 0x80 => out.push(byte as char),
                // A multi-byte UTF-8 sequence. The input was validated as UTF-8
                // up front, so the continuation bytes are already known good;
                // they are copied through without re-decoding.
                byte => {
                    let width = utf8_width(byte).ok_or(JsonError::Unexpected {
                        offset: self.offset - 1,
                    })?;
                    let from = self.offset - 1;
                    let to = from + width;
                    let slice = self.input.get(from..to).ok_or(JsonError::UnexpectedEnd)?;
                    let text = core::str::from_utf8(slice)
                        .map_err(|_| JsonError::Unexpected { offset: from })?;
                    out.push_str(text);
                    self.offset = to;
                }
            }
        }
    }

    fn escape(&mut self, out: &mut String) -> Result<(), JsonError> {
        let start = self.offset - 1;
        let byte = self.bump().ok_or(JsonError::UnexpectedEnd)?;
        let decoded = match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.unicode_escape(out, start),
            _ => return Err(JsonError::MalformedEscape { offset: start }),
        };
        out.push(decoded);
        Ok(())
    }

    /// Decodes `\uXXXX`, including a surrogate pair.
    ///
    /// A lone surrogate is refused rather than replaced. Replacement is how one
    /// system's string stops being another system's string.
    fn unicode_escape(&mut self, out: &mut String, start: usize) -> Result<(), JsonError> {
        let first = self.hex4(start)?;
        let code = match first {
            0xD800..=0xDBFF => {
                self.expect(b'\\')
                    .map_err(|_| JsonError::MalformedEscape { offset: start })?;
                self.expect(b'u')
                    .map_err(|_| JsonError::MalformedEscape { offset: start })?;
                let second = self.hex4(start)?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err(JsonError::MalformedEscape { offset: start });
                }
                0x1_0000 + ((first - 0xD800) << 10) + (second - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(JsonError::MalformedEscape { offset: start }),
            other => other,
        };
        let decoded = char::from_u32(code).ok_or(JsonError::MalformedEscape { offset: start })?;
        out.push(decoded);
        Ok(())
    }

    fn hex4(&mut self, start: usize) -> Result<u32, JsonError> {
        let mut value: u32 = 0;
        for _ in 0..4 {
            let byte = self.bump().ok_or(JsonError::UnexpectedEnd)?;
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                b'A'..=b'F' => u32::from(byte - b'A') + 10,
                _ => return Err(JsonError::MalformedEscape { offset: start }),
            };
            value = value * 16 + digit;
        }
        Ok(value)
    }

    /// Reads a number literal exactly as RFC 8259 defines it.
    ///
    /// No leading `+`, no leading zeros, no bare `.5`, no hex, no `Infinity`,
    /// no `NaN`. The literal is kept as text and flagged integral or not; it is
    /// never converted to a float here, so nothing is rounded on the way in.
    fn number(&mut self) -> Result<Number, JsonError> {
        let start = self.offset;
        let mut integral = true;

        if self.peek() == Some(b'-') {
            self.offset += 1;
        }

        match self.peek().ok_or(JsonError::UnexpectedEnd)? {
            b'0' => {
                self.offset += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(JsonError::MalformedNumber { offset: start });
                }
            }
            b'1'..=b'9' => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.offset += 1;
                }
            }
            _ => return Err(JsonError::MalformedNumber { offset: start }),
        }

        if self.peek() == Some(b'.') {
            integral = false;
            self.offset += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::MalformedNumber { offset: start });
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            integral = false;
            self.offset += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::MalformedNumber { offset: start });
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
        }

        let lexeme = core::str::from_utf8(&self.input[start..self.offset])
            .map_err(|_| JsonError::MalformedNumber { offset: start })?;
        Ok(Number {
            lexeme: String::from(lexeme),
            integral,
        })
    }
}

/// The length in bytes of the UTF-8 sequence a lead byte starts.
fn utf8_width(lead: u8) -> Option<usize> {
    match lead {
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}
