//! Binary analysis contracts used by max-binwalk and consumers.

use serde::{Deserialize, Serialize};

/// Recognized executable container formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    Unknown,
}

/// Summary of a parsed executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryInfo {
    pub path: String,
    pub format: BinaryFormat,
    pub entry_point: Option<u64>,
    pub architecture: Option<String>,
    #[serde(default)]
    pub functions: Vec<FunctionInfo>,
}

/// Disassembled / recovered function summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionInfo {
    pub name: Option<String>,
    pub address: u64,
    pub size: Option<u64>,
    #[serde(default)]
    pub disasm: Vec<InstructionInfo>,
}

/// One disassembled instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionInfo {
    pub address: u64,
    pub bytes: String,
    pub text: String,
}
