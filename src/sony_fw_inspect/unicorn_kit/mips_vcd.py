"""MIPS32 little-endian (`vcd_firmware.bin`) xref scanner, Ghidra legacy `MADD`/`MADDU`
instruction normalizer, and Unicorn MIPS32 LE execution helper.
"""

from __future__ import annotations

import hashlib
import re
import struct
from typing import Any, Callable

DEFAULT_VCD_BASE = 0x80000000
DEFAULT_VCD_GP = 0x802F2920  # Observed at native startup LUI/ADDIU pair 0x80004314


def scan_mips_lui_xrefs(
    blob: bytes,
    targets: dict[int, str] | None = None,
    *,
    base: int = DEFAULT_VCD_BASE,
    text_limit: int | None = None,
    window_bytes: int = 64,
) -> list[dict[str, Any]]:
    """Scan MIPS32 LE code for `LUI` + `ADDIU`/`ORI` address-pair references.

    Applies conservative register-clobber stopping so intermediate ALU or load
    instructions overwriting `rt`/`rd` do not produce false-positive xrefs.
    """
    if targets is None:
        targets = {
            base + m.start(): m[0].decode("ascii")
            for m in re.finditer(rb"[\x20-\x7e]{6,}", blob)
        }
    end_off = min(len(blob) - 3, text_limit if text_limit is not None else len(blob) - 3)
    hits: list[dict[str, Any]] = []

    for off in range(0, max(0, end_off), 4):
        q = struct.unpack_from("<I", blob, off)[0]
        if (q >> 26) != 15:  # LUI opcode == 15 (0x0f)
            continue
        reg = (q >> 16) & 31
        if reg == 0:
            continue
        upper = (q & 0xFFFF) << 16

        scan_end = min(off + window_bytes, len(blob) - 3)
        for at in range(off + 4, scan_end, 4):
            ins = struct.unpack_from("<I", blob, at)[0]
            op = ins >> 26
            rs = (ins >> 21) & 31
            rt = (ins >> 16) & 31

            if op in (9, 13) and rs == reg:  # 9=ADDIU, 13=ORI
                low = ins & 0xFFFF
                if op == 9 and (low & 0x8000):
                    low -= 0x10000
                target = ((upper + low) & 0xFFFFFFFF) if op == 9 else (upper | low)
                if target in targets:
                    hits.append(
                        {
                            "lui": hex(base + off),
                            "combine": hex(base + at),
                            "combine_op": "addiu" if op == 9 else "ori",
                            "register": reg,
                            "target": hex(target),
                            "text": targets[target],
                        }
                    )

            # Stop scanning if `reg` is overwritten by I-type ALU/load or R-type `rd`
            if op in (8, 9, 10, 11, 12, 13, 14, 15, 32, 33, 34, 35, 36, 37, 38) and rt == reg:
                break
            if op == 0 and ((ins >> 11) & 31) == reg and (ins & 63) not in (
                8, 12, 13, 17, 19, 24, 25, 26, 27
            ):
                break
    return hits


def normalize_legacy_mips_madd(
    blob: bytes,
    *,
    start_offset: int = 0x4000,
    end_offset: int | None = None,
    base: int = DEFAULT_VCD_BASE,
) -> tuple[bytes, dict[str, Any]]:
    """Translate legacy `SPECIAL` (`0x00`) `MADD`/`MADDU` encodings into MIPS32 `SPECIAL2` (`0x1c`).

    Produces an analysis-only binary (`deployable=False`) so stock MIPS32 disassemblers
    and Ghidra's SLEIGH CFG builder do not truncate functions at legacy `0x00 .. 0x1c/0x1d`
    multiply-accumulate instructions. Raw unmodified bytes must still be used in Unicorn.
    """
    stop = min(len(blob) - (len(blob) % 4), end_offset if end_offset is not None else len(blob))
    if start_offset < 0 or start_offset > stop or (start_offset % 4) != 0:
        raise ValueError("start_offset must be 4-byte aligned and within image bounds")

    out = bytearray(blob)
    changes: list[dict[str, str]] = []
    for off in range(start_offset, stop, 4):
        old = struct.unpack_from("<I", blob, off)[0]
        if (old & 0xFC00FFFF) in (0x1C, 0x1D):
            new = (old & 0x03FF0000) | 0x70000000 | (old & 1)
            struct.pack_into("<I", out, off, new)
            changes.append(
                {
                    "address": hex(base + off),
                    "original": f"{old:08x}",
                    "analysis": f"{new:08x}",
                    "operation": "maddu" if (old & 1) else "madd",
                }
            )

    normalized_bytes = bytes(out)
    report = {
        "source_sha256": hashlib.sha256(blob).hexdigest(),
        "analysis_sha256": hashlib.sha256(normalized_bytes).hexdigest(),
        "change_count": len(changes),
        "changes": changes,
        "camera_written": False,
        "deployable": False,
    }
    return normalized_bytes, report


class MipsVcdRunner:
    """Bounded MIPS32 little-endian Unicorn harness for `vcd_firmware.bin` analysis."""

    def __init__(
        self,
        image_bytes: bytes,
        *,
        base: int = DEFAULT_VCD_BASE,
        gp: int = DEFAULT_VCD_GP,
        scratch_base: int = 0x81000000,
        scratch_size: int = 0x10000,
        return_fence: int = 0x81FF0000,
        uc_factory: Callable[[int, int], Any] | None = None,
    ) -> None:
        self.base = base
        self.gp = gp
        self.scratch_base = scratch_base
        self.scratch_size = (max(4096, scratch_size) + 4095) & ~4095
        self.return_fence = return_fence & ~0xFFF

        try:
            import unicorn as u_mod
            import unicorn.mips_const as mips_c

            factory = uc_factory or u_mod.Uc
            arch = u_mod.UC_ARCH_MIPS
            mode = u_mod.UC_MODE_MIPS32 | u_mod.UC_MODE_LITTLE_ENDIAN
            self._regs = {
                "A0": mips_c.UC_MIPS_REG_A0,
                "A1": mips_c.UC_MIPS_REG_A1,
                "A2": mips_c.UC_MIPS_REG_A2,
                "A3": mips_c.UC_MIPS_REG_A3,
                "V0": mips_c.UC_MIPS_REG_V0,
                "GP": mips_c.UC_MIPS_REG_GP,
                "SP": mips_c.UC_MIPS_REG_SP,
                "RA": mips_c.UC_MIPS_REG_RA,
                "PC": mips_c.UC_MIPS_REG_PC,
            }
        except ImportError as exc:
            if uc_factory is None:
                raise RuntimeError("Unicorn is not installed; install `unicorn` or pass `uc_factory`") from exc
            factory = uc_factory
            arch, mode = 5, 4
            self._regs = {"A0": 5, "A1": 6, "A2": 7, "A3": 8, "V0": 3, "GP": 29, "SP": 30, "RA": 32, "PC": 34}

        self.uc = factory(arch, mode)
        aligned_img = (max(4096, len(image_bytes)) + 4095) & ~4095
        self.uc.mem_map(self.base, aligned_img)
        self.uc.mem_write(self.base, image_bytes)
        self.uc.mem_map(self.scratch_base, self.scratch_size)
        self.uc.mem_map(self.return_fence, 0x1000)

    def call(
        self,
        entry_va: int,
        args: tuple[int, ...] = (),
        *,
        max_instructions: int = 50000,
    ) -> int:
        if len(args) > 4:
            raise ValueError("MipsVcdRunner.call supports up to 4 register arguments ($a0..$a3)")
        for reg_name, val in zip(("A0", "A1", "A2", "A3"), args):
            self.uc.reg_write(self._regs[reg_name], val & 0xFFFFFFFF)
        self.uc.reg_write(self._regs["GP"], self.gp)
        self.uc.reg_write(self._regs["SP"], self.scratch_base + self.scratch_size - 0x1000)
        self.uc.reg_write(self._regs["RA"], self.return_fence)
        self.uc.emu_start(entry_va, self.return_fence, count=max_instructions)
        return int(self.uc.reg_read(self._regs["V0"]) & 0xFFFFFFFF)
