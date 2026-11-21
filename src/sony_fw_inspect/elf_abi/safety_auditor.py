"""ARMv7 Sony camera ELF safety & ABI auditor.

Enforces project-wide binary hygiene rules:
1. 32-bit little-endian ARM (`EM_ARM == 40`).
2. Zero `RWX` (`PF_W | PF_X`) `PT_LOAD` segments.
3. Non-executable `PT_GNU_STACK` (`!(p_flags & PF_X)`).
4. Deterministic `DT_RELCOUNT == 0` (or absent) for `ET_DYN` shared libraries.
5. Zero unintended `DT_INIT` / `DT_INIT_ARRAY` / `DT_FINI` / `DT_FINI_ARRAY` sections
   unless explicitly allowlisted by the build specification.
6. Optional strict exported `.dynsym` symbol allowlist check.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .relcount_patcher import (
    DT_FINI,
    DT_FINI_ARRAY,
    DT_INIT,
    DT_INIT_ARRAY,
    DT_RELCOUNT,
    EM_ARM,
    ET_DYN,
    PF_W,
    PF_X,
    PT_GNU_STACK,
    PT_LOAD,
    parse_elf32_metadata,
)


class ElfSafetyViolation(RuntimeError):
    """Raised when an ARM ELF binary violates one or more Sony ABI / W^X safety rules."""


def audit_arm_elf(
    elf_bytes: bytes,
    *,
    allowed_exports: set[str] | None = None,
    allow_init: bool = False,
    allow_fini: bool = False,
    require_gnu_stack: bool = True,
    require_relcount_zero: bool = True,
    raise_on_violation: bool = True,
) -> dict[str, Any]:
    """Audit an ARM32 ELF binary and return a structured safety compliance report."""
    meta = parse_elf32_metadata(elf_bytes)
    violations: list[str] = []

    if meta["e_machine"] != EM_ARM:
        violations.append(f"Expected EM_ARM (40), found e_machine={meta['e_machine']}")

    rwx_segments: list[int] = []
    gnu_stack_segments = [p for p in meta["phdrs"] if p["p_type"] == PT_GNU_STACK]
    for p in meta["phdrs"]:
        if p["p_type"] == PT_LOAD and (p["p_flags"] & PF_W) and (p["p_flags"] & PF_X):
            rwx_segments.append(p["index"])
            violations.append(f"RWX PT_LOAD segment forbidden (phdr index {p['index']})")

    if require_gnu_stack:
        if not gnu_stack_segments:
            violations.append("Missing PT_GNU_STACK program header")
        elif any(p["p_flags"] & PF_X for p in gnu_stack_segments):
            violations.append("Executable PT_GNU_STACK is forbidden")

    dyn_tags = [e["d_tag"] for e in meta["dynamic_entries"]]
    relcounts = [e["d_val"] for e in meta["dynamic_entries"] if e["d_tag"] == DT_RELCOUNT]
    if require_relcount_zero and meta["e_type"] == ET_DYN:
        if any(v != 0 for v in relcounts):
            violations.append(f"Non-zero DT_RELCOUNT forbidden for ld-2.11.2.so: {relcounts}")

    has_init = DT_INIT in dyn_tags or DT_INIT_ARRAY in dyn_tags
    has_fini = DT_FINI in dyn_tags or DT_FINI_ARRAY in dyn_tags
    if has_init and not allow_init:
        violations.append("Unintended DT_INIT / DT_INIT_ARRAY constructor present")
    if has_fini and not allow_fini:
        violations.append("Unintended DT_FINI / DT_FINI_ARRAY destructor present")

    exports = sorted(
        {
            s["name"]
            for s in meta["dynsyms"]
            if s["name"] and s["st_shndx"] != 0 and s["st_bind"] in (1, 2)
        }
    )
    if allowed_exports is not None and set(exports) != set(allowed_exports):
        unexpected = sorted(set(exports) - set(allowed_exports))
        missing = sorted(set(allowed_exports) - set(exports))
        if unexpected:
            violations.append(f"Unexpected exported symbols: {unexpected}")
        if missing:
            violations.append(f"Missing required exported symbols: {missing}")

    report = {
        "passed": len(violations) == 0,
        "bytes": len(elf_bytes),
        "sha256": hashlib.sha256(elf_bytes).hexdigest(),
        "e_type": meta["e_type"],
        "e_machine": meta["e_machine"],
        "rwx_segment_indices": rwx_segments,
        "gnu_stack_non_executable": bool(gnu_stack_segments)
        and all(not (p["p_flags"] & PF_X) for p in gnu_stack_segments),
        "dt_relcount_values": relcounts,
        "has_init": has_init,
        "has_fini": has_fini,
        "needed": meta["needed"],
        "exports": exports,
        "violations": violations,
    }
    if violations and raise_on_violation:
        raise ElfSafetyViolation("; ".join(violations))
    return report
