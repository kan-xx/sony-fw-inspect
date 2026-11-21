"""Unicorn stub-free execution toolkit: ARMv7/Thumb runner, Linux `ET_REL` `.ko` relocator,
and MIPS32 LE (`vcd_firmware.bin`) xref scanner / `MADD` normalizer.
"""

from .arm_stubfree import (
    StubFreeArmRunner,
    TripwireHitError,
    WriteViolationError,
)
from .ko_relocator import (
    R_ARM_ABS32,
    R_ARM_CALL,
    R_ARM_JUMP24,
    R_ARM_MOVT_ABS,
    R_ARM_MOVW_ABS_NC,
    R_ARM_REL32,
    KernelObjectModule,
    RelocatedKernelModule,
    load_ko_into_unicorn,
    relocate_ko_bytes,
)
from .mips_vcd import (
    DEFAULT_VCD_BASE,
    DEFAULT_VCD_GP,
    MipsVcdRunner,
    normalize_legacy_mips_madd,
    scan_mips_lui_xrefs,
)

__all__ = [
    "StubFreeArmRunner",
    "TripwireHitError",
    "WriteViolationError",
    "R_ARM_ABS32",
    "R_ARM_REL32",
    "R_ARM_CALL",
    "R_ARM_JUMP24",
    "R_ARM_MOVW_ABS_NC",
    "R_ARM_MOVT_ABS",
    "KernelObjectModule",
    "RelocatedKernelModule",
    "relocate_ko_bytes",
    "load_ko_into_unicorn",
    "DEFAULT_VCD_BASE",
    "DEFAULT_VCD_GP",
    "scan_mips_lui_xrefs",
    "normalize_legacy_mips_madd",
    "MipsVcdRunner",
]
