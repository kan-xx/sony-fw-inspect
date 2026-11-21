"""ARM32 ELF `.dynamic` `DT_RELCOUNT = 0` post-link patcher and `ld-2.11.2.so` relocation model.

Background:
Modern linkers (`lld` / `zig cc`) emit non-contiguous `DT_REL` and `DT_JMPREL` tables alongside
`-Wl,-z,now` (`DT_BIND_NOW` / `DF_BIND_NOW`) and `DT_RELCOUNT > 0`.
Sony's older glibc `/lib/ld-2.11.2.so` (`0x866e..0x8fc2`) splits non-contiguous `DT_REL` and
`DT_JMPREL` into two eager ranges, re-reads `DT_RELCOUNT` on the second (`DT_JMPREL`) range,
and blindly applies `R_ARM_RELATIVE` (`*slot += load_base`) without checking the relocation type!
Zeroing `DT_RELCOUNT` in `.dynamic` post-link forces `ld-2.11.2.so` through its type-aware
relocation loop for both ranges while keeping `-Wl,-z,now` eager binding intact.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any

EM_ARM = 40
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

SHT_DYNSYM = 11
SHT_DYNAMIC = 6

DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_STRTAB = 5
DT_SYMTAB = 6
DT_INIT = 12
DT_FINI = 13
DT_REL = 17
DT_RELSZ = 18
DT_JMPREL = 23
DT_BIND_NOW = 24
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_FLAGS = 30
DT_RELCOUNT = 0x6FFFFFFA

DF_BIND_NOW = 0x8

R_ARM_JUMP_SLOT = 22
R_ARM_RELATIVE = 23


def _read_cstring(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("ascii", errors="replace")


def parse_elf32_metadata(elf_bytes: bytes) -> dict[str, Any]:
    """Parse 32-bit little-endian ELF headers, program headers, sections, `.dynamic`, and `.dynsym`."""
    if len(elf_bytes) < 52 or elf_bytes[:4] != b"\x7fELF":
        raise ValueError("Not a valid ELF binary")
    if elf_bytes[4] != 1 or elf_bytes[5] != 1:
        raise ValueError("Expected 32-bit little-endian ELF (ELFCLASS32 / ELFDATA2LSB)")

    (
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        _e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from("<HHIIIIIHHHHHH", elf_bytes, 16)

    phdrs: list[dict[str, int]] = []
    if e_phoff and e_phnum:
        if e_phentsize < 32 or e_phoff + e_phnum * e_phentsize > len(elf_bytes):
            raise ValueError("Truncated ELF32 program header table")
        for idx in range(e_phnum):
            off = e_phoff + idx * e_phentsize
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
                "<8I", elf_bytes, off
            )
            phdrs.append(
                {
                    "index": idx,
                    "p_type": p_type,
                    "p_offset": p_offset,
                    "p_vaddr": p_vaddr,
                    "p_paddr": p_paddr,
                    "p_filesz": p_filesz,
                    "p_memsz": p_memsz,
                    "p_flags": p_flags,
                    "p_align": p_align,
                }
            )

    shdrs: list[dict[str, Any]] = []
    if e_shoff and e_shnum:
        if e_shentsize < 40 or e_shoff + e_shnum * e_shentsize > len(elf_bytes):
            raise ValueError("Truncated ELF32 section header table")
        for idx in range(e_shnum):
            off = e_shoff + idx * e_shentsize
            (
                sh_name,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                sh_link,
                sh_info,
                sh_addralign,
                sh_entsize,
            ) = struct.unpack_from("<10I", elf_bytes, off)
            shdrs.append(
                {
                    "index": idx,
                    "sh_name_off": sh_name,
                    "name": "",
                    "sh_type": sh_type,
                    "sh_flags": sh_flags,
                    "sh_addr": sh_addr,
                    "sh_offset": sh_offset,
                    "sh_size": sh_size,
                    "sh_link": sh_link,
                    "sh_info": sh_info,
                    "sh_addralign": sh_addralign,
                    "sh_entsize": sh_entsize,
                }
            )
        if 0 <= e_shstrndx < len(shdrs):
            str_sec = shdrs[e_shstrndx]
            str_blob = elf_bytes[str_sec["sh_offset"] : str_sec["sh_offset"] + str_sec["sh_size"]]
            for s in shdrs:
                s["name"] = _read_cstring(str_blob, s["sh_name_off"])

    dyn_offset: int | None = None
    dyn_size: int = 0
    for s in shdrs:
        if s["sh_type"] == SHT_DYNAMIC or s["name"] == ".dynamic":
            dyn_offset = s["sh_offset"]
            dyn_size = s["sh_size"]
            break
    if dyn_offset is None:
        for p in phdrs:
            if p["p_type"] == PT_DYNAMIC:
                dyn_offset = p["p_offset"]
                dyn_size = p["p_filesz"]
                break

    dynamic_entries: list[dict[str, int]] = []
    if dyn_offset is not None and dyn_size >= 8:
        if dyn_offset + dyn_size > len(elf_bytes):
            raise ValueError("Truncated .dynamic section")
        for i in range(0, dyn_size - (dyn_size % 8), 8):
            file_off = dyn_offset + i
            d_tag, d_val = struct.unpack_from("<II", elf_bytes, file_off)
            dynamic_entries.append({"file_offset": file_off, "d_tag": d_tag, "d_val": d_val})
            if d_tag == DT_NULL:
                break

    # Resolve .dynstr and .dynsym if present
    dynstr_blob = b""
    for s in shdrs:
        if s["name"] == ".dynstr":
            dynstr_blob = elf_bytes[s["sh_offset"] : s["sh_offset"] + s["sh_size"]]
            break

    dynsyms: list[dict[str, Any]] = []
    for s in shdrs:
        if s["sh_type"] == SHT_DYNSYM or s["name"] == ".dynsym":
            if not dynstr_blob and 0 <= s["sh_link"] < len(shdrs):
                ls = shdrs[s["sh_link"]]
                dynstr_blob = elf_bytes[ls["sh_offset"] : ls["sh_offset"] + ls["sh_size"]]
            sec_data = elf_bytes[s["sh_offset"] : s["sh_offset"] + s["sh_size"]]
            for off in range(0, len(sec_data) - (len(sec_data) % 16), 16):
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                    "<IIIBBH", sec_data, off
                )
                dynsyms.append(
                    {
                        "name": _read_cstring(dynstr_blob, st_name),
                        "st_value": st_value,
                        "st_size": st_size,
                        "st_bind": st_info >> 4,
                        "st_type": st_info & 0xF,
                        "st_other": st_other,
                        "st_shndx": st_shndx,
                    }
                )
            break

    needed = [
        _read_cstring(dynstr_blob, e["d_val"])
        for e in dynamic_entries
        if e["d_tag"] == DT_NEEDED and dynstr_blob
    ]

    return {
        "e_type": e_type,
        "e_machine": e_machine,
        "e_version": e_version,
        "e_entry": e_entry,
        "e_flags": e_flags,
        "phdrs": phdrs,
        "shdrs": shdrs,
        "dynamic_offset": dyn_offset,
        "dynamic_entries": dynamic_entries,
        "dynsyms": dynsyms,
        "needed": needed,
    }


def patch_dt_relcount_zero(elf_bytes: bytes) -> tuple[bytes, dict[str, Any]]:
    """Zero every `DT_RELCOUNT` (`0x6ffffffa`) tag value in `.dynamic` without shifting offsets."""
    meta = parse_elf32_metadata(elf_bytes)
    if meta["e_machine"] != EM_ARM:
        raise ValueError(f"Expected ARM ELF (EM_ARM=40), got e_machine={meta['e_machine']}")
    if meta["dynamic_offset"] is None:
        raise ValueError("ELF binary has no .dynamic section or PT_DYNAMIC segment")

    patched = bytearray(elf_bytes)
    previous_values: list[int] = []
    offsets_patched: list[int] = []

    for entry in meta["dynamic_entries"]:
        if entry["d_tag"] == DT_RELCOUNT:
            previous_values.append(entry["d_val"])
            struct.pack_into("<I", patched, entry["file_offset"] + 4, 0)
            offsets_patched.append(entry["file_offset"])

    out_bytes = bytes(patched)
    return out_bytes, {
        "patched_entries": len(offsets_patched),
        "previous_relcount_values": previous_values,
        "file_offsets": offsets_patched,
        "sha256_before": hashlib.sha256(elf_bytes).hexdigest(),
        "sha256_after": hashlib.sha256(out_bytes).hexdigest(),
    }


def simulate_sony_ld_2_11_2_relocations(
    elf_bytes: bytes,
    *,
    base_addr: int = 0x0410F000,
    mock_resolved_va: int = 0x0509DD30,
) -> dict[str, Any]:
    """Model Sony's `/lib/ld-2.11.2.so` (`0x866e..0x8fc2`) eager relocation bug.

    Demonstrates why non-contiguous `DT_REL` + `DT_JMPREL` with `DT_RELCOUNT > 0`
    corrupts `R_ARM_JUMP_SLOT` entries in `.got.plt`, and proves `DT_RELCOUNT == 0`
    resolves every `R_ARM_JUMP_SLOT` via normal symbol lookup.
    """
    meta = parse_elf32_metadata(elf_bytes)
    load_segs = [p for p in meta["phdrs"] if p["p_type"] == PT_LOAD]
    dt = {e["d_tag"]: e["d_val"] for e in meta["dynamic_entries"]}

    def read_va(va: int, n: int = 4) -> bytes:
        for s in load_segs:
            if s["p_vaddr"] <= va and va + n <= s["p_vaddr"] + s["p_filesz"]:
                off = va - s["p_vaddr"] + s["p_offset"]
                return elf_bytes[off : off + n]
        raise ValueError(f"Virtual address {hex(va)} not backed by PT_LOAD file bytes")

    ranges: list[tuple[int, int]] = []
    if dt.get(DT_RELSZ, 0):
        ranges.append((dt[DT_REL], dt[DT_RELSZ]))
    if dt.get(DT_PLTRELSZ, 0):
        if ranges and ranges[0][0] + ranges[0][1] == dt[DT_JMPREL]:
            ranges[0] = (ranges[0][0], ranges[0][1] + dt[DT_PLTRELSZ])
        else:
            ranges.append((dt[DT_JMPREL], dt[DT_PLTRELSZ]))

    mem: dict[int, int] = {}
    events: list[dict[str, Any]] = []
    corrupted_jump_slots: list[str] = []
    relcount = dt.get(DT_RELCOUNT, 0)

    for start_va, size in ranges:
        fast_count = min(relcount, size // 8)
        for index, rel_va in enumerate(range(start_va, start_va + size, 8)):
            r_offset, r_info = struct.unpack("<II", read_va(rel_va, 8))
            r_type = r_info & 0xFF
            before = mem.get(r_offset, int.from_bytes(read_va(r_offset, 4), "little"))
            if index < fast_count:
                after = (before + base_addr) & 0xFFFFFFFF
                action = "RELCOUNT_fast_relative_type_ignored"
                if r_type != R_ARM_RELATIVE:
                    corrupted_jump_slots.append(hex(r_offset))
            elif r_type == R_ARM_RELATIVE:
                after = (before + base_addr) & 0xFFFFFFFF
                action = "normal_R_ARM_RELATIVE"
            elif r_type == R_ARM_JUMP_SLOT:
                after = mock_resolved_va
                action = "normal_R_ARM_JUMP_SLOT_symbol_lookup"
            else:
                raise ValueError(f"Unsupported relocation type {r_type} at {hex(rel_va)}")
            mem[r_offset] = after
            events.append(
                {
                    "range_start": hex(start_va),
                    "relocation_va": hex(rel_va),
                    "r_type": r_type,
                    "target_va": hex(r_offset),
                    "before": hex(before),
                    "after": hex(after),
                    "action": action,
                }
            )

    return {
        "relcount": relcount,
        "ranges": [{"start": hex(a), "bytes": z} for a, z in ranges],
        "non_contiguous_pltrel": len(ranges) > 1,
        "corrupted_jump_slots": corrupted_jump_slots,
        "safe_under_ld_2_11_2": len(corrupted_jump_slots) == 0,
        "memory_after": {hex(k): hex(v) for k, v in mem.items()},
        "events": events,
    }
