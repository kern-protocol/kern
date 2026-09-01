//! Writing JSON, and reading it back with somebody else's hostile reader.
//!
//! # Reading
//!
//! Scenario files are read with [`kern_ai::json`], the reader written for model
//! output. That is deliberate rather than lazy: a scenario file is experiment
//! configuration that an evaluator author edits by hand, and the failure modes
//! worth catching — a duplicate key silently winning, a float where an integer
//! belongs, a truncated document parsed as far as it goes — are exactly the ones
//! that reader refuses. It also means the evaluation harness adds no
//! dependency of its own to the workspace.
//!
//! Its bounds apply here too, which caps a scenario file at
//! [`MAX_JSON_ARRAY_ELEMENTS`](kern_ai::bounds::MAX_JSON_ARRAY_ELEMENTS)
//! scenarios. Scenario packs are split by category, and the matrix expansion
//! does the multiplying.
//!
//! # Writing
//!
//! A tiny writer, because the records this crate emits have a shape it fully
//! controls and a serialization framework would be a large dependency for a
//! handful of object literals. It escapes what RFC 8259 requires and nothing
//! more.

use std::fmt::Write as _;

/// A JSON object being built, in insertion order.
///
/// Insertion order rather than sorted order because these records are read by
/// people as often as by programs, and a record whose fields wander is harder to
/// diff across runs.
#[derive(Clone, Debug, Default)]
pub struct Obj {
    out: String,
    empty: bool,
}

impl Obj {
    /// An empty object.
    pub fn new() -> Self {
        Self {
            out: String::from("{"),
            empty: true,
        }
    }

    fn comma(&mut self) {
        if self.empty {
            self.empty = false;
        } else {
            self.out.push(',');
        }
    }

    fn key(&mut self, key: &str) {
        self.comma();
        push_str(&mut self.out, key);
        self.out.push(':');
    }

    /// Adds a string member.
    #[must_use]
    pub fn str(mut self, key: &str, value: &str) -> Self {
        self.key(key);
        push_str(&mut self.out, value);
        self
    }

    /// Adds a string member, or `null` when absent.
    #[must_use]
    pub fn opt_str(self, key: &str, value: Option<&str>) -> Self {
        match value {
            Some(value) => self.str(key, value),
            None => self.null(key),
        }
    }

    /// Adds an integer member.
    #[must_use]
    pub fn int(mut self, key: &str, value: i64) -> Self {
        self.key(key);
        let _ = write!(self.out, "{value}");
        self
    }

    /// Adds an unsigned member.
    #[must_use]
    pub fn uint(self, key: &str, value: u64) -> Self {
        self.int(key, value as i64)
    }

    /// Adds an integer member, or `null` when absent.
    #[must_use]
    pub fn opt_int(self, key: &str, value: Option<i64>) -> Self {
        match value {
            Some(value) => self.int(key, value),
            None => self.null(key),
        }
    }

    /// Adds a boolean member.
    #[must_use]
    pub fn bool(mut self, key: &str, value: bool) -> Self {
        self.key(key);
        self.out.push_str(if value { "true" } else { "false" });
        self
    }

    /// Adds a `null` member.
    ///
    /// Explicit rather than omitted. A field that disappears when it has no
    /// value makes "we did not measure this" and "this did not happen"
    /// indistinguishable in the record, and the whole point of these records is
    /// that absence of evidence is recorded as absence of evidence.
    #[must_use]
    pub fn null(mut self, key: &str) -> Self {
        self.key(key);
        self.out.push_str("null");
        self
    }

    /// Adds a nested object.
    #[must_use]
    pub fn obj(mut self, key: &str, value: Obj) -> Self {
        self.key(key);
        self.out.push_str(&value.finish());
        self
    }

    /// Adds an array of strings.
    #[must_use]
    pub fn str_array(mut self, key: &str, values: &[String]) -> Self {
        self.key(key);
        self.out.push('[');
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                self.out.push(',');
            }
            push_str(&mut self.out, value);
        }
        self.out.push(']');
        self
    }

    /// Adds an array of objects.
    #[must_use]
    pub fn obj_array(mut self, key: &str, values: Vec<Obj>) -> Self {
        self.key(key);
        self.out.push('[');
        for (index, value) in values.into_iter().enumerate() {
            if index > 0 {
                self.out.push(',');
            }
            self.out.push_str(&value.finish());
        }
        self.out.push(']');
        self
    }

    /// Renders the object.
    pub fn finish(mut self) -> String {
        self.out.push('}');
        self.out
    }
}

/// Appends `value` as a JSON string literal.
fn push_str(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
