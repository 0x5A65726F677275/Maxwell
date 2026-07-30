//! Static binary analysis for Maxwell — structure parse + light disassembly.
//!
//! This module is intentionally read-only analysis. It does not execute samples.

mod analyze;
mod disasm;

pub use analyze::analyze_path;

/// Crate identity for event `source` fields.
pub const CRATE_NAME: &str = "max-binwalk";
