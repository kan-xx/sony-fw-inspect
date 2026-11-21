"""Sony ARMv7 `ld-2.11.2.so` `DT_RELCOUNT = 0` post-link patcher, ELF safety auditor,
and `zig cc` cross-compilation helper.
"""

from .relcount_patcher import (
    DT_BIND_NOW,
    DT_FLAGS,
    DT_FINI,
    DT_FINI_ARRAY,
    DT_INIT,
    DT_INIT_ARRAY,
    DT_JMPREL,
    DT_NEEDED,
    DT_PLTRELSZ,
    DT_REL,
    DT_RELCOUNT,
    DT_RELSZ,
    DF_BIND_NOW,
    parse_elf32_metadata,
    patch_dt_relcount_zero,
    simulate_sony_ld_2_11_2_relocations,
)
from .safety_auditor import ElfSafetyViolation, audit_arm_elf
from .zig_builder import (
    SONY_ARM_DSO_CFLAGS,
    SONY_ARM_STATIC_CFLAGS,
    build_sony_arm_dso,
    build_sony_arm_static_elf,
    resolve_zig_cc,
)

__all__ = [
    "DT_NEEDED",
    "DT_PLTRELSZ",
    "DT_INIT",
    "DT_FINI",
    "DT_REL",
    "DT_RELSZ",
    "DT_JMPREL",
    "DT_BIND_NOW",
    "DT_INIT_ARRAY",
    "DT_FINI_ARRAY",
    "DT_FLAGS",
    "DT_RELCOUNT",
    "DF_BIND_NOW",
    "parse_elf32_metadata",
    "patch_dt_relcount_zero",
    "simulate_sony_ld_2_11_2_relocations",
    "ElfSafetyViolation",
    "audit_arm_elf",
    "SONY_ARM_DSO_CFLAGS",
    "SONY_ARM_STATIC_CFLAGS",
    "resolve_zig_cc",
    "build_sony_arm_dso",
    "build_sony_arm_static_elf",
]
