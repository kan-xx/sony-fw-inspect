"""Linux `ET_REL` `.ko` (`SHT_REL`) ARM32 kernel module inspector and Unicorn relocator.

Supports offline inspection and relocation of Sony kernel modules (`dmm.ko`,
`osal_uipc.ko`, `liro.ko`, `codec_drv.ko`) with zero external C parser dependencies:
- Allocates `SHF_ALLOC` sections (including zero-initialized `SHT_NOBITS` `.bss`).
- Applies `R_ARM_ABS32`, `R_ARM_REL32`, `R_ARM_CALL`, `R_ARM_JUMP24`,
  `R_ARM_MOVW_ABS_NC`, and `R_ARM_MOVT_ABS` relocations.
- Maps unresolved `SHN_UNDEF` kernel symbols to deterministic synthetic intercept
  addresses (`extern_base + 16 * sym_index`) while recording exact call-site hooks.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
from typing import Any

from ..elf_abi.relcount_patcher import EM_ARM, ET_REL, parse_elf32_metadata

SHT_SYMTAB = 2
SHT_NOBITS = 8
SHT_REL = 9
SHF_ALLOC = 0x2

SHN_UNDEF = 0
SHN_ABS = 0xFFF1

R_ARM_ABS32 = 2
R_ARM_REL32 = 3
R_ARM_CALL = 28
R_ARM_JUMP24 = 29
R_ARM_MOVW_ABS_NC = 43
R_ARM_MOVT_ABS = 44


def _read_cstring(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("ascii", errors="replace")


def _patch_arm_branch24(insn: int, pc: int, target: int) -> int:
    """Patch 24-bit signed word displacement in an ARM `B` / `BL` instruction."""
    # On ARM mode, PC reads as instruction_addr + 8; retain original addend if encoded.
    orig_imm24 = insn & 0x00FFFFFF
    if orig_imm24 & 0x00800000:
        orig_imm24 -= 0x01000000
    addend = orig_imm24 << 2
    disp = (target + addend - pc) & 0xFFFFFFFF
    if disp & 0x80000000:
        disp -= 0x100000000
    word_off = disp >> 2
    if not (-0x800000 <= word_off <= 0x7FFFFF):
        raise ValueError(f"ARM branch target {hex(target)} out of +/-32MB range from {hex(pc)}")
    return (insn & 0xFF000000) | (word_off & 0x00FFFFFF)


def _patch_arm_movw_movt(insn: int, value16: int) -> int:
    """Encode a 16-bit immediate into an ARMv7 `MOVW` or `MOVT` instruction (`imm4:16..19 | imm12:0..11`)."""
    imm4 = (value16 >> 12) & 0xF
    imm12 = value16 & 0xFFF
    return (insn & 0xFFF0F000) | (imm4 << 16) | imm12


@dataclass(frozen=True)
class KernelSymbol:
    index: int
    name: str
    value: int
    size: int
    bind: int
    sym_type: int
    shndx: int


@dataclass
class RelocatedKernelModule:
    sha256: str
    section_bases: dict[int, int]
    section_names: dict[int, str]
    section_blobs: dict[int, bytes]
    symbol_addresses: dict[str, int]
    call_sites: dict[int, KernelSymbol]
    unresolved_imports: dict[str, int]


class KernelObjectModule:
    """Parsed 32-bit ARM `ET_REL` Linux kernel module (`.ko` / `.o`)."""

    def __init__(self, raw_bytes: bytes, *, name: str = "module.ko") -> None:
        meta = parse_elf32_metadata(raw_bytes)
        if meta["e_type"] != ET_REL or meta["e_machine"] != EM_ARM:
            raise ValueError(
                f"Expected ARM ET_REL (1, 40), got e_type={meta['e_type']}, e_machine={meta['e_machine']}"
            )
        self.name = name
        self.raw = raw_bytes
        self.sha256 = hashlib.sha256(raw_bytes).hexdigest()
        self.shdrs = meta["shdrs"]

        self.sections: dict[int, dict[str, Any]] = {}
        for s in self.shdrs:
            idx = s["index"]
            data = (
                bytes(s["sh_size"])
                if s["sh_type"] == SHT_NOBITS
                else raw_bytes[s["sh_offset"] : s["sh_offset"] + s["sh_size"]]
            )
            self.sections[idx] = {
                "index": idx,
                "name": s["name"],
                "sh_type": s["sh_type"],
                "sh_flags": s["sh_flags"],
                "sh_size": s["sh_size"],
                "sh_info": s["sh_info"],
                "sh_link": s["sh_link"],
                "data": data,
            }

        self.symbols: list[KernelSymbol] = []
        for s in self.shdrs:
            if s["sh_type"] == SHT_SYMTAB or s["name"] == ".symtab":
                str_sec = self.shdrs[s["sh_link"]]
                str_blob = raw_bytes[str_sec["sh_offset"] : str_sec["sh_offset"] + str_sec["sh_size"]]
                sym_blob = raw_bytes[s["sh_offset"] : s["sh_offset"] + s["sh_size"]]
                for idx, off in enumerate(range(0, len(sym_blob) - (len(sym_blob) % 16), 16)):
                    st_name, st_value, st_size, st_info, _st_other, st_shndx = struct.unpack_from(
                        "<IIIBBH", sym_blob, off
                    )
                    self.symbols.append(
                        KernelSymbol(
                            index=idx,
                            name=_read_cstring(str_blob, st_name),
                            value=st_value,
                            size=st_size,
                            bind=st_info >> 4,
                            sym_type=st_info & 0xF,
                            shndx=st_shndx,
                        )
                    )
                break

        self.named_symbols: dict[str, KernelSymbol] = {
            sym.name: sym for sym in self.symbols if sym.name
        }

        self.relocations: list[dict[str, int]] = []
        for s in self.shdrs:
            if s["sh_type"] == SHT_REL:
                target_sec = s["sh_info"]
                rel_blob = raw_bytes[s["sh_offset"] : s["sh_offset"] + s["sh_size"]]
                for off in range(0, len(rel_blob) - (len(rel_blob) % 8), 8):
                    r_offset, r_info = struct.unpack_from("<II", rel_blob, off)
                    self.relocations.append(
                        {
                            "target_shndx": target_sec,
                            "r_offset": r_offset,
                            "r_sym": r_info >> 8,
                            "r_type": r_info & 0xFF,
                        }
                    )

    @classmethod
    def from_file(cls, path: Path) -> "KernelObjectModule":
        p = path.resolve(strict=True)
        return cls(p.read_bytes(), name=p.name)


def relocate_ko_bytes(
    raw_bytes: bytes,
    *,
    base_origin: int = 0x10000000,
    section_stride: int = 0x00100000,
    extern_base: int = 0x60000000,
    external_overrides: dict[str, int] | None = None,
    patch_local_branches: bool = True,
) -> RelocatedKernelModule:
    """Relocate all `SHF_ALLOC` sections of an ARM `ET_REL` `.ko` image in memory."""
    mod = KernelObjectModule(raw_bytes)
    overrides = dict(external_overrides or {})

    mutable_sections: dict[int, bytearray] = {}
    bases: dict[int, int] = {}
    section_names: dict[int, str] = {}
    for idx, sec in mod.sections.items():
        if (sec["sh_flags"] & SHF_ALLOC) and sec["sh_size"] > 0:
            mutable_sections[idx] = bytearray(sec["data"])
            bases[idx] = base_origin + idx * section_stride
            section_names[idx] = sec["name"]

    unresolved_imports: dict[str, int] = {}

    def resolve_symbol(sym: KernelSymbol) -> int:
        if sym.name in overrides:
            return overrides[sym.name]
        if sym.shndx in bases:
            return (bases[sym.shndx] + sym.value) & 0xFFFFFFFF
        if sym.shndx == SHN_ABS:
            return sym.value & 0xFFFFFFFF
        if sym.shndx == SHN_UNDEF:
            stub_va = (extern_base + 16 * sym.index) & 0xFFFFFFFF
            if sym.name:
                unresolved_imports[sym.name] = stub_va
            return stub_va
        raise ValueError(f"Symbol {sym.name!r} references non-allocated section {sym.shndx}")

    call_sites: dict[int, KernelSymbol] = {}
    for rel in mod.relocations:
        t_idx = rel["target_shndx"]
        if t_idx not in mutable_sections:
            continue
        buf = mutable_sections[t_idx]
        at = rel["r_offset"]
        r_type = rel["r_type"]
        sym = mod.symbols[rel["r_sym"]]
        pc = (bases[t_idx] + at) & 0xFFFFFFFF
        sym_va = resolve_symbol(sym)

        if r_type == R_ARM_ABS32:
            addend = struct.unpack_from("<I", buf, at)[0]
            struct.pack_into("<I", buf, at, (sym_va + addend) & 0xFFFFFFFF)
        elif r_type == R_ARM_REL32:
            addend = struct.unpack_from("<I", buf, at)[0]
            struct.pack_into("<I", buf, at, (sym_va + addend - pc) & 0xFFFFFFFF)
        elif r_type in (R_ARM_CALL, R_ARM_JUMP24):
            call_sites[pc] = sym
            if sym.shndx in bases and patch_local_branches:
                insn = struct.unpack_from("<I", buf, at)[0]
                struct.pack_into("<I", buf, at, _patch_arm_branch24(insn, pc, sym_va))
        elif r_type == R_ARM_MOVW_ABS_NC:
            insn = struct.unpack_from("<I", buf, at)[0]
            orig_imm16 = ((insn >> 4) & 0xF000) | (insn & 0xFFF)
            val = (sym_va + orig_imm16) & 0xFFFF
            struct.pack_into("<I", buf, at, _patch_arm_movw_movt(insn, val))
        elif r_type == R_ARM_MOVT_ABS:
            insn = struct.unpack_from("<I", buf, at)[0]
            orig_imm16 = ((insn >> 4) & 0xF000) | (insn & 0xFFF)
            val = ((sym_va + (orig_imm16 << 16)) >> 16) & 0xFFFF
            struct.pack_into("<I", buf, at, _patch_arm_movw_movt(insn, val))
        else:
            raise ValueError(f"Unsupported ARM ET_REL relocation type {r_type} at {hex(pc)}")

    symbol_addresses: dict[str, int] = {}
    for sym in mod.symbols:
        if sym.name and sym.shndx in bases:
            symbol_addresses[sym.name] = (bases[sym.shndx] + sym.value) & 0xFFFFFFFF

    return RelocatedKernelModule(
        sha256=mod.sha256,
        section_bases=bases,
        section_names=section_names,
        section_blobs={k: bytes(v) for k, v in mutable_sections.items()},
        symbol_addresses=symbol_addresses,
        call_sites=call_sites,
        unresolved_imports=unresolved_imports,
    )


def load_ko_into_unicorn(
    uc: Any,
    raw_bytes: bytes,
    **relocate_kwargs: Any,
) -> RelocatedKernelModule:
    """Relocate an ARM `.ko` module and map all allocated sections into a Unicorn instance."""
    relocated = relocate_ko_bytes(raw_bytes, **relocate_kwargs)
    for sec_idx, blob in relocated.section_blobs.items():
        base = relocated.section_bases[sec_idx]
        aligned = (max(4096, len(blob)) + 4095) & ~4095
        uc.mem_map(base, aligned)
        uc.mem_write(base, blob)
    return relocated
