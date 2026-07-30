//! Parse PE/ELF/Mach-O and recover a function listing with light disassembly.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use goblin::Object;
use max_core::{BinaryFormat, BinaryInfo, FunctionInfo};

use crate::disasm::disassemble;

const MAX_FUNCTIONS: usize = 64;

/// Analyze a binary on disk. Read-only — never executes the sample.
pub fn analyze_path(path: impl AsRef<Path>) -> max_core::Result<BinaryInfo> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|e| {
        max_core::Error::InvalidArgument(format!("read {}: {e}", path.display()))
    })?;

    let object = Object::parse(&bytes).map_err(|e| {
        max_core::Error::InvalidArgument(format!("parse {}: {e}", path.display()))
    })?;

    let path_str = path.display().to_string();

    match object {
        Object::Elf(elf) => analyze_elf(path_str, &bytes, &elf),
        Object::PE(pe) => analyze_pe(path_str, &bytes, &pe),
        Object::Mach(mach) => match mach {
            goblin::mach::Mach::Binary(macho) => analyze_macho(path_str, &bytes, &macho),
            goblin::mach::Mach::Fat(_) => Ok(BinaryInfo {
                path: path_str,
                format: BinaryFormat::MachO,
                entry_point: None,
                architecture: Some("fat".into()),
                functions: Vec::new(),
            }),
        },
        _ => Ok(BinaryInfo {
            path: path_str,
            format: BinaryFormat::Unknown,
            entry_point: None,
            architecture: None,
            functions: Vec::new(),
        }),
    }
}

fn analyze_elf(
    path: String,
    bytes: &[u8],
    elf: &goblin::elf::Elf<'_>,
) -> max_core::Result<BinaryInfo> {
    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => Some("x86_64".into()),
        goblin::elf::header::EM_386 => Some("x86".into()),
        goblin::elf::header::EM_AARCH64 => Some("aarch64".into()),
        goblin::elf::header::EM_ARM => Some("arm".into()),
        _ => None,
    };
    let bitness = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => 64,
        goblin::elf::header::EM_386 => 32,
        _ => 0,
    };
    let entry = Some(elf.entry);

    let mut addrs: BTreeMap<u64, Option<String>> = BTreeMap::new();
    addrs.insert(elf.entry, Some("_start".into()));

    for sym in elf.syms.iter() {
        if sym.is_function() && sym.st_value != 0 {
            let name = elf
                .strtab
                .get_at(sym.st_name)
                .map(|s| s.to_string());
            addrs.entry(sym.st_value).or_insert(name);
        }
    }
    for sym in elf.dynsyms.iter() {
        if sym.is_function() && sym.st_value != 0 {
            let name = elf
                .dynstrtab
                .get_at(sym.st_name)
                .map(|s| s.to_string());
            addrs.entry(sym.st_value).or_insert(name);
        }
    }

    let functions = build_functions(bytes, &addrs, bitness, |va| {
        elf_offset_for_va(elf, va)
    });

    Ok(BinaryInfo {
        path,
        format: BinaryFormat::Elf,
        entry_point: entry,
        architecture: arch,
        functions,
    })
}

fn elf_offset_for_va(elf: &goblin::elf::Elf<'_>, va: u64) -> Option<usize> {
    for ph in &elf.program_headers {
        if ph.p_type != goblin::elf::program_header::PT_LOAD {
            continue;
        }
        let start = ph.p_vaddr;
        let end = ph.p_vaddr.saturating_add(ph.p_filesz);
        if va >= start && va < end {
            let delta = va - start;
            return Some((ph.p_offset + delta) as usize);
        }
    }
    None
}

fn analyze_pe(
    path: String,
    bytes: &[u8],
    pe: &goblin::pe::PE<'_>,
) -> max_core::Result<BinaryInfo> {
    let arch = match pe.header.coff_header.machine {
        goblin::pe::header::COFF_MACHINE_X86_64 => Some("x86_64".into()),
        goblin::pe::header::COFF_MACHINE_X86 => Some("x86".into()),
        goblin::pe::header::COFF_MACHINE_ARM64 => Some("aarch64".into()),
        _ => None,
    };
    let bitness = match pe.header.coff_header.machine {
        goblin::pe::header::COFF_MACHINE_X86_64 => 64,
        goblin::pe::header::COFF_MACHINE_X86 => 32,
        _ => 0,
    };

    let image_base = pe.image_base as u64;
    let entry = pe
        .header
        .optional_header
        .as_ref()
        .map(|oh| image_base + oh.standard_fields.address_of_entry_point as u64);

    let mut addrs: BTreeMap<u64, Option<String>> = BTreeMap::new();
    if let Some(ep) = entry {
        addrs.insert(ep, Some("entry".into()));
    }
    for export in &pe.exports {
        if let Some(name) = export.name {
            let rva = export.rva as u64;
            addrs.insert(image_base + rva, Some(name.to_string()));
        }
    }

    let functions = build_functions(bytes, &addrs, bitness, |va| {
        pe_offset_for_va(pe, va, image_base)
    });

    Ok(BinaryInfo {
        path,
        format: BinaryFormat::Pe,
        entry_point: entry,
        architecture: arch,
        functions,
    })
}

fn pe_offset_for_va(pe: &goblin::pe::PE<'_>, va: u64, image_base: u64) -> Option<usize> {
    if va < image_base {
        return None;
    }
    let rva = (va - image_base) as usize;
    for section in &pe.sections {
        let start = section.virtual_address as usize;
        let size = section.virtual_size.max(section.size_of_raw_data) as usize;
        if rva >= start && rva < start + size {
            let delta = rva - start;
            return Some(section.pointer_to_raw_data as usize + delta);
        }
    }
    None
}

fn analyze_macho(
    path: String,
    bytes: &[u8],
    macho: &goblin::mach::MachO<'_>,
) -> max_core::Result<BinaryInfo> {
    let arch = match macho.header.cputype {
        goblin::mach::constants::cputype::CPU_TYPE_X86_64 => Some("x86_64".into()),
        goblin::mach::constants::cputype::CPU_TYPE_X86 => Some("x86".into()),
        goblin::mach::constants::cputype::CPU_TYPE_ARM64 => Some("aarch64".into()),
        _ => None,
    };
    let bitness = match macho.header.cputype {
        goblin::mach::constants::cputype::CPU_TYPE_X86_64 => 64,
        goblin::mach::constants::cputype::CPU_TYPE_X86 => 32,
        _ => 0,
    };

    let entry = macho.entry;
    let mut addrs: BTreeMap<u64, Option<String>> = BTreeMap::new();
    if entry != 0 {
        addrs.insert(entry, Some("_main".into()));
    }
    if let Ok(syms) = macho.symbols() {
        for sym in syms.iter() {
            if let Ok((name, nlist)) = sym {
                let addr = nlist.n_value;
                if addr != 0 && (name.starts_with('_') || nlist.is_global()) {
                    addrs.entry(addr).or_insert(Some(name.to_string()));
                }
            }
        }
    }

    let functions = build_functions(bytes, &addrs, bitness, |va| {
        macho_offset_for_va(macho, va)
    });

    Ok(BinaryInfo {
        path,
        format: BinaryFormat::MachO,
        entry_point: if entry == 0 { None } else { Some(entry) },
        architecture: arch,
        functions,
    })
}

fn macho_offset_for_va(macho: &goblin::mach::MachO<'_>, va: u64) -> Option<usize> {
    for segment in &macho.segments {
        let start = segment.vmaddr;
        let end = segment.vmaddr.saturating_add(segment.filesize);
        if va >= start && va < end {
            let delta = va - start;
            return Some((segment.fileoff + delta) as usize);
        }
    }
    None
}

fn build_functions(
    bytes: &[u8],
    addrs: &BTreeMap<u64, Option<String>>,
    bitness: u32,
    offset_for_va: impl Fn(u64) -> Option<usize>,
) -> Vec<FunctionInfo> {
    let keys: Vec<u64> = addrs.keys().copied().take(MAX_FUNCTIONS).collect();
    let mut functions = Vec::new();

    for (i, &addr) in keys.iter().enumerate() {
        let name = addrs.get(&addr).cloned().flatten();
        let next = keys.get(i + 1).copied();
        let size = next.map(|n| n.saturating_sub(addr));
        let disasm = if bitness == 32 || bitness == 64 {
            if let Some(off) = offset_for_va(addr) {
                let end = next
                    .and_then(|n| offset_for_va(n))
                    .unwrap_or_else(|| (off + 64).min(bytes.len()));
                let end = end.min(bytes.len()).max(off);
                let slice = &bytes[off..end.min(off + 128)];
                disassemble(slice, addr, bitness)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        functions.push(FunctionInfo {
            name,
            address: addr,
            size,
            disasm,
        });
    }

    functions
}
