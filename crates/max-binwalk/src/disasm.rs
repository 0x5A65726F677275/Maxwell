//! Disassemble a slice of bytes at a virtual address (x86 / x86_64).

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use max_core::InstructionInfo;

const MAX_INSTRUCTIONS: usize = 32;

pub fn disassemble(code: &[u8], ip: u64, bitness: u32) -> Vec<InstructionInfo> {
    if code.is_empty() || (bitness != 16 && bitness != 32 && bitness != 64) {
        return Vec::new();
    }

    let mut decoder = Decoder::with_ip(bitness, code, ip, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut output = String::new();
    let mut instruction = Instruction::default();
    let mut out = Vec::new();

    while decoder.can_decode() && out.len() < MAX_INSTRUCTIONS {
        decoder.decode_out(&mut instruction);
        output.clear();
        formatter.format(&instruction, &mut output);

        let start = instruction.ip().saturating_sub(ip) as usize;
        let len = instruction.len();
        let end = (start + len).min(code.len());
        let bytes = if start < code.len() {
            code[start..end]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            String::new()
        };

        out.push(InstructionInfo {
            address: instruction.ip(),
            bytes,
            text: output.clone(),
        });

        if instruction.is_invalid() {
            break;
        }
    }

    out
}
