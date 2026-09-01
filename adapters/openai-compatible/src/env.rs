//! Reading configuration, and one deliberately boring `.env` loader.
//!
//! # Why this exists at all
//!
//! So a credential can live in a gitignored file rather than in a shell history
//! or a committed fixture. That is its entire purpose, and it is why the parser
//! is as small as it is: a `.env` file is a list of `KEY=VALUE` lines, and
//! anything cleverer is a way to be surprised by a file that holds a secret.
//!
//! # What it will not do
//!
//! It does not overwrite a variable already set in the environment, so an
//! explicit `export` always wins over a file. It does not expand variables, run
//! commands, or follow includes. It never prints a value, and it never returns
//! one to a caller that did not ask for that exact key.

use std::fs;
use std::path::{Path, PathBuf};

/// Loads `.env` from `dir` or the nearest ancestor that has one.
///
/// Returns the path it loaded, or `None` if there was nothing to load. Values
/// already present in the environment are left alone.
///
/// Malformed lines are skipped in silence rather than reported: a parse error
/// message about a line in a credentials file is a very good way to print a
/// credential.
pub fn load_dotenv(dir: impl AsRef<Path>) -> Option<PathBuf> {
    let mut current = Some(dir.as_ref().to_path_buf());
    while let Some(directory) = current {
        let candidate = directory.join(".env");
        if candidate.is_file() {
            let contents = fs::read_to_string(&candidate).ok()?;
            apply(&contents);
            return Some(candidate);
        }
        current = directory.parent().map(Path::to_path_buf);
    }
    None
}

fn apply(contents: &str) {
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = unquote(value.trim());
        if std::env::var_os(key).is_none() {
            // Safety-relevant only in the sense that a process-wide mutation
            // should happen once, early, before threads exist. The loader is
            // called from `main` before anything else.
            std::env::set_var(key, value);
        }
    }
}

fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        return &value[1..value.len() - 1];
    }
    value
}
