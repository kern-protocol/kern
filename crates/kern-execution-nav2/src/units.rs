//! The integer-to-float boundary.
//!
//! Everything above this module is integer and exact, which is what makes
//! authority decisions deterministic and constraint sets orderable. Everything
//! below it is ROS, which speaks metres, radians, and `f64`.
//!
//! Conversion happens here and nowhere else, and only after authority has
//! already been granted.

/// Millimetres to metres.
pub fn mm_to_m(mm: i64) -> f64 {
    mm as f64 / 1000.0
}

/// Millimetres per second to metres per second.
pub fn mm_s_to_m_s(mm_s: i64) -> f64 {
    mm_s as f64 / 1000.0
}

/// Millidegrees to radians.
pub fn mdeg_to_rad(mdeg: i64) -> f64 {
    (mdeg as f64 / 1000.0).to_radians()
}

/// The `z` and `w` components of a yaw-only quaternion.
///
/// A planar goal has no roll or pitch, so `x` and `y` are zero and only these
/// two carry the heading.
pub fn yaw_quaternion(yaw_rad: f64) -> (f64, f64) {
    ((yaw_rad / 2.0).sin(), (yaw_rad / 2.0).cos())
}
