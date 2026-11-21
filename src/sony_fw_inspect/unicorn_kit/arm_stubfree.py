"""Stub-free ARMv7 / Thumb (`av-cam.bin`, `libObj.so`) Unicorn execution harness.

Key capabilities:
- SHA-256 verification of user-supplied firmware binaries before mapping.
- Automatic VFPv3 coprocessor enablement (`C1_C0_2 = 0x00f00000`, `FPEXC = 0x40000000`)
  required by RTOS floating-point timing/ratio helpers.
- Strict allowed memory write-range enforcement (`WriteViolationError`).
- OS / debug-logger / MMIO PC tripwires (`TripwireHitError`) guaranteeing zero accidental
  side-effect stubs or unmodeled hardware register walks.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable, Iterable

# Standard Unicorn ARM constants (mirrored as integers so mock/offline tests work
# without requiring the C `unicorn` extension to be installed).
UC_ARCH_ARM_CONST = 1
UC_MODE_ARM_CONST = 0
UC_MODE_THUMB_CONST = 16
UC_HOOK_CODE_CONST = 4
UC_HOOK_MEM_WRITE_CONST = 2048

UC_ARM_REG_SP_CONST = 12
UC_ARM_REG_LR_CONST = 10
UC_ARM_REG_PC_CONST = 11
UC_ARM_REG_R0_CONST = 66
UC_ARM_REG_R1_CONST = 67
UC_ARM_REG_R2_CONST = 68
UC_ARM_REG_R3_CONST = 69
UC_ARM_REG_C1_C0_2_CONST = 95
UC_ARM_REG_FPEXC_CONST = 94

VFP_CPACR_ENABLE = 0x00F00000
VFP_FPEXC_ENABLE = 0x40000000
DEFAULT_MMIO_TRIPWIRE_RANGE = (0xF0000000, 0x100000000)


class TripwireHitError(AssertionError):
    """Raised when stub-free execution reaches a forbidden OS, logging, or MMIO PC."""


class WriteViolationError(AssertionError):
    """Raised when stub-free execution attempts to write outside allowed RAM ranges."""


def _align_up_4k(size: int) -> int:
    return (max(4096, size) + 4095) & ~4095


def _load_unicorn_symbols() -> dict[str, Any]:
    try:
        import unicorn as u_mod
        import unicorn.arm_const as arm_c

        return {
            "Uc": u_mod.Uc,
            "UC_ARCH_ARM": u_mod.UC_ARCH_ARM,
            "UC_MODE_ARM": u_mod.UC_MODE_ARM,
            "UC_MODE_THUMB": u_mod.UC_MODE_THUMB,
            "UC_HOOK_CODE": u_mod.UC_HOOK_CODE,
            "UC_HOOK_MEM_WRITE": u_mod.UC_HOOK_MEM_WRITE,
            "R0": arm_c.UC_ARM_REG_R0,
            "R1": arm_c.UC_ARM_REG_R1,
            "R2": arm_c.UC_ARM_REG_R2,
            "R3": arm_c.UC_ARM_REG_R3,
            "SP": arm_c.UC_ARM_REG_SP,
            "LR": arm_c.UC_ARM_REG_LR,
            "PC": arm_c.UC_ARM_REG_PC,
            "C1_C0_2": arm_c.UC_ARM_REG_C1_C0_2,
            "FPEXC": arm_c.UC_ARM_REG_FPEXC,
        }
    except ImportError:
        return {
            "Uc": None,
            "UC_ARCH_ARM": UC_ARCH_ARM_CONST,
            "UC_MODE_ARM": UC_MODE_ARM_CONST,
            "UC_MODE_THUMB": UC_MODE_THUMB_CONST,
            "UC_HOOK_CODE": UC_HOOK_CODE_CONST,
            "UC_HOOK_MEM_WRITE": UC_HOOK_MEM_WRITE_CONST,
            "R0": UC_ARM_REG_R0_CONST,
            "R1": UC_ARM_REG_R1_CONST,
            "R2": UC_ARM_REG_R2_CONST,
            "R3": UC_ARM_REG_R3_CONST,
            "SP": UC_ARM_REG_SP_CONST,
            "LR": UC_ARM_REG_LR_CONST,
            "PC": UC_ARM_REG_PC_CONST,
            "C1_C0_2": UC_ARM_REG_C1_C0_2_CONST,
            "FPEXC": UC_ARM_REG_FPEXC_CONST,
        }


class StubFreeArmRunner:
    """Bounded, stub-free ARMv7 / Thumb function runner over Unicorn."""

    def __init__(
        self,
        image_bytes: bytes,
        load_base: int = 0x635C6000,
        *,
        thumb: bool = True,
        enable_vfp: bool = True,
        expected_sha256: str | None = None,
        scratch_ram_base: int = 0x70000000,
        scratch_ram_size: int = 0x10000,
        return_fence_addr: int = 0x71000000,
        allowed_write_ranges: Iterable[tuple[int, int]] = (),
        tripwire_pcs: Iterable[int] = (),
        mmio_tripwire_ranges: Iterable[tuple[int, int]] = (DEFAULT_MMIO_TRIPWIRE_RANGE,),
        uc_factory: Callable[[int, int], Any] | None = None,
    ) -> None:
        actual_sha = hashlib.sha256(image_bytes).hexdigest()
        if expected_sha256 and actual_sha != expected_sha256.lower():
            raise ValueError(f"Firmware image SHA-256 mismatch: expected {expected_sha256}, got {actual_sha}")

        self.image_bytes = image_bytes
        self.image_sha256 = actual_sha
        self.load_base = load_base
        self.thumb = thumb
        self.enable_vfp = enable_vfp
        self.scratch_ram_base = scratch_ram_base
        self.scratch_ram_size = _align_up_4k(scratch_ram_size)
        self.return_fence_addr = return_fence_addr & ~0xFFF

        self._syms = _load_unicorn_symbols()
        factory = uc_factory or self._syms["Uc"]
        if factory is None:
            raise RuntimeError("Unicorn is not installed; install `unicorn` or pass `uc_factory`")

        mode = self._syms["UC_MODE_THUMB"] if thumb else self._syms["UC_MODE_ARM"]
        self.uc = factory(self._syms["UC_ARCH_ARM"], mode)

        self.uc.mem_map(self.load_base, _align_up_4k(len(image_bytes)))
        self.uc.mem_write(self.load_base, image_bytes)
        self.uc.mem_map(self.scratch_ram_base, self.scratch_ram_size)
        self.uc.mem_map(self.return_fence_addr, 0x1000)

        if self.enable_vfp:
            self.uc.reg_write(self._syms["C1_C0_2"], VFP_CPACR_ENABLE)
            self.uc.reg_write(self._syms["FPEXC"], VFP_FPEXC_ENABLE)

        self.allowed_write_ranges: list[tuple[int, int]] = [
            (self.scratch_ram_base, self.scratch_ram_base + self.scratch_ram_size),
            *allowed_write_ranges,
        ]
        self.tripwire_pcs: set[int] = {pc & ~1 for pc in tripwire_pcs}
        self.mmio_tripwire_ranges: list[tuple[int, int]] = list(mmio_tripwire_ranges)

        self.executed_pcs: set[int] = set()
        self.external_writes: list[dict[str, Any]] = []

        def _on_code(uc: Any, address: int, _size: int, _user_data: Any) -> None:
            clean_pc = address & ~1
            self.executed_pcs.add(clean_pc)
            if clean_pc in self.tripwire_pcs or any(
                lo <= clean_pc < hi for lo, hi in self.mmio_tripwire_ranges
            ):
                raise TripwireHitError(f"Stub-free execution hit forbidden PC tripwire: {hex(address)}")

        def _on_write(
            uc: Any, _access: int, address: int, size: int, value: int, _user_data: Any
        ) -> None:
            if not any(lo <= address and address + size <= hi for lo, hi in self.allowed_write_ranges):
                pc = uc.reg_read(self._syms["PC"])
                raise WriteViolationError(
                    f"Unauthorized write at {hex(address)} ({size}B) from PC={hex(pc)}"
                )
            if not (self.scratch_ram_base <= address < self.scratch_ram_base + self.scratch_ram_size):
                self.external_writes.append(
                    {"address": hex(address), "size": size, "value": value & 0xFFFFFFFF}
                )

        self.uc.hook_add(self._syms["UC_HOOK_CODE"], _on_code)
        self.uc.hook_add(self._syms["UC_HOOK_MEM_WRITE"], _on_write)

    @classmethod
    def from_file(
        cls,
        path: Path,
        load_base: int = 0x635C6000,
        **kwargs: Any,
    ) -> "StubFreeArmRunner":
        raw = path.resolve(strict=True).read_bytes()
        return cls(raw, load_base=load_base, **kwargs)

    def call(
        self,
        entry_va: int,
        args: tuple[int, ...] = (),
        *,
        thumb_entry: bool | None = None,
        max_instructions: int = 50000,
        sp: int | None = None,
    ) -> dict[str, Any]:
        """Invoke an ARM/Thumb routine with up to 4 register arguments (`R0..R3`)."""
        if len(args) > 4:
            raise ValueError("StubFreeArmRunner.call supports up to 4 register arguments (R0..R3)")
        reg_ids = (self._syms["R0"], self._syms["R1"], self._syms["R2"], self._syms["R3"])
        for reg_id, val in zip(reg_ids, args):
            self.uc.reg_write(reg_id, val & 0xFFFFFFFF)

        stack_top = sp if sp is not None else (self.scratch_ram_base + self.scratch_ram_size - 0x1000)
        is_thumb = self.thumb if thumb_entry is None else thumb_entry
        start_pc = (entry_va | 1) if is_thumb else (entry_va & ~3)
        lr_val = (self.return_fence_addr | 1) if is_thumb else self.return_fence_addr

        self.uc.reg_write(self._syms["SP"], stack_top)
        self.uc.reg_write(self._syms["LR"], lr_val)

        self.executed_pcs.clear()
        self.external_writes.clear()

        self.uc.emu_start(start_pc, self.return_fence_addr, count=max_instructions)
        final_pc = self.uc.reg_read(self._syms["PC"]) & ~1
        if final_pc != self.return_fence_addr:
            raise RuntimeError(
                f"Execution stopped at {hex(final_pc)} before reaching return fence {hex(self.return_fence_addr)}"
            )
        r0 = self.uc.reg_read(self._syms["R0"]) & 0xFFFFFFFF
        return {
            "r0": r0,
            "unique_instructions": len(self.executed_pcs),
            "external_writes": list(self.external_writes),
        }
