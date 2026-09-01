//! Where the integer boundary is.
//!
//! Kern's semantics are integer: millimetres, millimetres per second. The
//! machine wants metres. The conversion happens here, below every authority
//! decision, and no `f64` is ever an input to policy, a lease, or an
//! enforcement check.

/// Millimetres to metres.
pub fn mm_to_m(mm: i64) -> f64 {
    mm as f64 / 1_000.0
}

/// Millimetres per second to metres per second.
pub fn mm_s_to_m_s(mm_s: i64) -> f64 {
    mm_s as f64 / 1_000.0
}
