"""Self-contained synthetic unit tests for `unicorn_kit`:
1. Linux `ET_REL` `.ko` (`SHT_REL`) relocator (`R_ARM_ABS32`, `R_ARM_CALL`, `MOVW`/`MOVT`, `.bss`).
2. MIPS32 LE legacy `MADD`/`MADDU` normalizer & `LUI`+`ADDIU`/`ORI` xref scanner.
3. `StubFreeArmRunner` VFPv3 enablement, write-range enforcement, and PC tripwires.
"""

from __future__ import annotations

import struct
import unittest

from sony_fw_inspect.unicorn_kit import (
    R_ARM_ABS32,
    R_ARM_CALL,
    R_ARM_MOVT_ABS,
    R_ARM_MOVW_ABS_NC,
    KernelObjectModule,
    StubFreeArmRunner,
    TripwireHitError,
    WriteViolationError,
    load_ko_into_unicorn,
    normalize_legacy_mips_madd,
    relocate_ko_bytes,
    scan_mips_lui_xrefs,
)
from sony_fw_inspect.unicorn_kit.arm_stubfree import (
    UC_ARM_REG_C1_C0_2_CONST,
    UC_ARM_REG_FPEXC_CONST,
    UC_ARM_REG_LR_CONST,
    UC_ARM_REG_PC_CONST,
    UC_ARM_REG_R0_CONST,
    UC_HOOK_CODE_CONST,
    UC_HOOK_MEM_WRITE_CONST,
    VFP_CPACR_ENABLE,
    VFP_FPEXC_ENABLE,
)


def _build_synthetic_arm_ko() -> bytes:
    """Build a synthetic 32-bit ARM `ET_REL` `.ko` with `.text`, `.data`, `.bss`, `.symtab`, and `.rel.text`."""
    img = bytearray(0x1000)

    # .text at 0x0100 (32 bytes = 8 ARM instructions):
    #   +0x00: 0xebfffffe  bl local_callee      (R_ARM_CALL -> sym 1 at .text+0x18)
    #   +0x04: 0xebfffffe  bl ext_printk        (R_ARM_CALL -> sym 4 SHN_UNDEF)
    #   +0x08: 0xe3000000  movw r0, #0          (R_ARM_MOVW_ABS_NC -> sym 2 state_var in .data+4)
    #   +0x0c: 0xe3400000  movt r0, #0          (R_ARM_MOVT_ABS -> sym 2 state_var in .data+4)
    #   +0x10: 0x00000008  .word bss_sym + 8    (R_ARM_ABS32 -> sym 3 in .bss+0, addend=8)
    #   +0x14: 0xe12fff1e  bx lr
    #   +0x18: 0xe3a0002a  mov r0, #42          (local_callee)
    #   +0x1c: 0xe12fff1e  bx lr
    text_words = [
        0xEBFFFFFE,
        0xEBFFFFFE,
        0xE3000000,
        0xE3400000,
        0x00000008,
        0xE12FFF1E,
        0xE3A0002A,
        0xE12FFF1E,
    ]
    struct.pack_into("<8I", img, 0x0100, *text_words)

    # .data at 0x0200 (16 bytes)
    struct.pack_into("<4I", img, 0x0200, 0x11111111, 0x22222222, 0, 0)

    # .strtab at 0x0300
    strtab = b"\x00local_callee\x00state_var\x00bss_table\x00printk\x00entry_fn\x00"
    img[0x0300 : 0x0300 + len(strtab)] = strtab

    # .symtab at 0x0400 (6 symbols x 16B):
    # [0] NULL
    # [1] local_callee: .text (shndx=1), st_value=0x18
    # [2] state_var:    .data (shndx=2), st_value=0x04
    # [3] bss_table:    .bss  (shndx=3), st_value=0x00
    # [4] printk:       SHN_UNDEF (shndx=0)
    # [5] entry_fn:     .text (shndx=1), st_value=0x00
    syms = [
        (0, 0, 0, 0, 0, 0),
        (1, 0x18, 8, (1 << 4) | 2, 0, 1),
        (14, 0x04, 4, (1 << 4) | 1, 0, 2),
        (24, 0x00, 64, (1 << 4) | 1, 0, 3),
        (34, 0x00, 0, (1 << 4) | 2, 0, 0),
        (41, 0x00, 24, (1 << 4) | 2, 0, 1),
    ]
    for i, sym in enumerate(syms):
        struct.pack_into("<IIIBBH", img, 0x0400 + 16 * i, *sym)

    # .rel.text at 0x0500 (5 relocations x 8B targeting sh_info=1 .text)
    rels = [
        (0x00, (1 << 8) | R_ARM_CALL),
        (0x04, (4 << 8) | R_ARM_CALL),
        (0x08, (2 << 8) | R_ARM_MOVW_ABS_NC),
        (0x0C, (2 << 8) | R_ARM_MOVT_ABS),
        (0x10, (3 << 8) | R_ARM_ABS32),
    ]
    for i, (r_off, r_info) in enumerate(rels):
        struct.pack_into("<II", img, 0x0500 + 8 * i, r_off, r_info)

    # .shstrtab at 0x0600
    shstr = b"\x00.text\x00.data\x00.bss\x00.strtab\x00.symtab\x00.rel.text\x00.shstrtab\x00"
    img[0x0600 : 0x0600 + len(shstr)] = shstr

    # Section headers at 0x0700:
    # [0] NULL, [1] .text, [2] .data, [3] .bss (SHT_NOBITS=8), [4] .strtab, [5] .symtab, [6] .rel.text, [7] .shstrtab
    shdrs = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 6, 0, 0x0100, 32, 0, 0, 4, 0),
        (7, 1, 3, 0, 0x0200, 16, 0, 0, 4, 0),
        (13, 8, 3, 0, 0x0210, 64, 0, 0, 4, 0),
        (18, 3, 0, 0, 0x0300, len(strtab), 0, 0, 1, 0),
        (26, 2, 0, 0, 0x0400, 16 * len(syms), 4, 1, 4, 16),
        (34, 9, 0, 0, 0x0500, 8 * len(rels), 5, 1, 4, 8),
        (44, 3, 0, 0, 0x0600, len(shstr), 0, 0, 1, 0),
    ]
    for i, sh in enumerate(shdrs):
        struct.pack_into("<10I", img, 0x0700 + 40 * i, *sh)

    # ELF32 ET_REL (1) EM_ARM (40) header
    img[0:16] = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
    struct.pack_into("<HHIIIIIHHHHHH", img, 16, 1, 40, 1, 0, 0, 0x0700, 0x05000000, 52, 0, 0, 40, len(shdrs), 7)
    return bytes(img)


class _MockUnicorn:
    """Deterministic mock Unicorn instance exercising StubFreeArmRunner & ko_relocator."""

    def __init__(self, arch: int, mode: int) -> None:
        self.arch = arch
        self.mode = mode
        self.mapped: dict[int, bytearray] = {}
        self.regs: dict[int, int] = {}
        self.code_hooks: list[object] = []
        self.write_hooks: list[object] = []
        self.scripted_steps: list[tuple[str, int, int, int]] = []

    def mem_map(self, addr: int, size: int) -> None:
        self.mapped[addr] = bytearray(size)

    def mem_write(self, addr: int, data: bytes) -> None:
        for base, buf in self.mapped.items():
            if base <= addr and addr + len(data) <= base + len(buf):
                off = addr - base
                buf[off : off + len(data)] = data
                return
        raise ValueError(f"Unmapped address {hex(addr)}")

    def reg_write(self, reg: int, val: int) -> None:
        self.regs[reg] = val & 0xFFFFFFFF

    def reg_read(self, reg: int) -> int:
        return self.regs.get(reg, 0)

    def hook_add(self, htype: int, callback: object) -> None:
        if htype == UC_HOOK_CODE_CONST:
            self.code_hooks.append(callback)
        elif htype == UC_HOOK_MEM_WRITE_CONST:
            self.write_hooks.append(callback)

    def emu_start(self, begin: int, _until: int, count: int = 0) -> None:
        assert count > 0
        self.regs[UC_ARM_REG_PC_CONST] = begin & ~1
        for kind, a, size, val in self.scripted_steps:
            if kind == "code":
                self.regs[UC_ARM_REG_PC_CONST] = a & ~1
                for cb in self.code_hooks:
                    cb(self, a, size, None)  # type: ignore[operator]
            elif kind == "write":
                for cb in self.write_hooks:
                    cb(self, 0, a, size, val, None)  # type: ignore[operator]
        self.regs[UC_ARM_REG_R0_CONST] = 0x1234
        self.regs[UC_ARM_REG_PC_CONST] = self.regs[UC_ARM_REG_LR_CONST] & ~1


class UnicornKitTests(unittest.TestCase):
    def test_ko_relocator_abs32_call_movw_movt_and_bss(self) -> None:
        ko_bytes = _build_synthetic_arm_ko()
        mod = KernelObjectModule(ko_bytes)
        self.assertIn("entry_fn", mod.named_symbols)
        self.assertEqual(len(mod.relocations), 5)

        mock_uc = _MockUnicorn(1, 0)
        rel = load_ko_into_unicorn(
            mock_uc,
            ko_bytes,
            base_origin=0x10000000,
            section_stride=0x00100000,
            extern_base=0x60000000,
        )
        text_base = rel.section_bases[1]  # 0x10100000
        data_base = rel.section_bases[2]  # 0x10200000
        bss_base = rel.section_bases[3]   # 0x10300000
        text_blob = rel.section_blobs[1]

        # 1. .bss allocated as 64 zero bytes
        self.assertEqual(rel.section_blobs[3], bytes(64))

        # 2. Local R_ARM_CALL at +0x00 patched to jump to local_callee (+0x18):
        #    PC = +0x00, target = +0x18, original imm24 = -2 (-8B) => disp = 0x18 - 8 - 0 = 0x10 (4 words)
        bl_local = struct.unpack_from("<I", text_blob, 0x00)[0]
        self.assertEqual(bl_local, 0xEB000004)

        # 3. External R_ARM_CALL (`printk`) recorded in call_sites and unresolved_imports
        self.assertEqual(rel.call_sites[text_base + 0x04].name, "printk")
        self.assertEqual(rel.unresolved_imports["printk"], 0x60000040)

        # 4. MOVW / MOVT pair encodes state_var = data_base + 4 = 0x10200004
        movw, movt = struct.unpack_from("<2I", text_blob, 0x08)
        dec_lo = ((movw >> 4) & 0xF000) | (movw & 0xFFF)
        dec_hi = ((movt >> 4) & 0xF000) | (movt & 0xFFF)
        self.assertEqual((dec_hi << 16) | dec_lo, data_base + 4)

        # 5. R_ARM_ABS32 at +0x10 = bss_base + addend(8)
        abs_ptr = struct.unpack_from("<I", text_blob, 0x10)[0]
        self.assertEqual(abs_ptr, bss_base + 8)

    def test_mips_vcd_madd_normalizer_and_lui_xref_scanner(self) -> None:
        # Build a synthetic MIPS32 LE image (size 0x4100)
        blob = bytearray(0x4100)
        # Put string at offset 0x0100 -> VA 0x80000100, and at 0x9000? Let's put one at 0x80018020 (negative low16!)
        blob = bytearray(0x20000)
        str1 = b"venc_param_avc.cxx\x00"
        blob[0x0120 : 0x0120 + len(str1)] = str1
        str2 = b"venc_hrd_avc.cxx\x00"
        # 0x00018020 has low16 = 0x8020 (-0x7fe0), so LUI loads 0x8002 and ADDIU adds -0x7fe0!
        blob[0x18020 : 0x18020 + len(str2)] = str2

        # At 0x4000:
        #   lui $a0 (4), 0x8000       -> (15<<26)|(4<<16)|0x8000
        #   ori $a0 (4), $a0 (4), 0x0120 -> (13<<26)|(4<<21)|(4<<16)|0x0120
        #   lui $a1 (5), 0x8002       -> (15<<26)|(5<<16)|0x8002
        #   addiu $a1 (5), $a1 (5), 0x8020 -> (9<<26)|(5<<21)|(5<<16)|0x8020
        #   lui $a2 (6), 0x8000       -> clobbered before addiu!
        #   lw  $a2 (6), 0($sp)       -> (35<<26)|(29<<21)|(6<<16)|0
        #   addiu $a2 (6), $a2 (6), 0x0120 (must NOT match due to clobber!)
        #   legacy madd $v0(2), $v1(3): (2<<21)|(3<<16)|0x1c = 0x0043001c
        #   legacy maddu $a0(4), $a1(5): (4<<21)|(5<<16)|0x1d = 0x0085001d
        insns = [
            (15 << 26) | (4 << 16) | 0x8000,
            (13 << 26) | (4 << 21) | (4 << 16) | 0x0120,
            (15 << 26) | (5 << 16) | 0x8002,
            (9 << 26) | (5 << 21) | (5 << 16) | 0x8020,
            (15 << 26) | (6 << 16) | 0x8000,
            (35 << 26) | (29 << 21) | (6 << 16) | 0,
            (9 << 26) | (6 << 21) | (6 << 16) | 0x0120,
            0x0043001C,
            0x0085001D,
        ]
        struct.pack_into(f"<{len(insns)}I", blob, 0x4000, *insns)

        hits = scan_mips_lui_xrefs(bytes(blob), text_limit=0x5000)
        self.assertEqual(len(hits), 2)
        self.assertEqual(hits[0]["text"], "venc_param_avc.cxx")
        self.assertEqual(hits[0]["combine_op"], "ori")
        self.assertEqual(hits[1]["text"], "venc_hrd_avc.cxx")
        self.assertEqual(hits[1]["combine_op"], "addiu")

        norm, rep = normalize_legacy_mips_madd(bytes(blob), start_offset=0x4000, end_offset=0x4100)
        self.assertFalse(rep["deployable"])
        self.assertEqual(rep["change_count"], 2)
        w_madd, w_maddu = struct.unpack_from("<2I", norm, 0x4000 + 7 * 4)
        self.assertEqual(w_madd, 0x70430000)
        self.assertEqual(w_maddu, 0x70850001)
        self.assertEqual([c["operation"] for c in rep["changes"]], ["madd", "maddu"])

    def test_stub_free_arm_runner_vfp_write_bounds_and_tripwires(self) -> None:
        holder: dict[str, _MockUnicorn] = {}

        def factory(arch: int, mode: int) -> _MockUnicorn:
            m = _MockUnicorn(arch, mode)
            holder["uc"] = m
            return m

        runner = StubFreeArmRunner(
            b"\x00" * 4096,
            load_base=0x635C6000,
            thumb=True,
            allowed_write_ranges=[(0x64000000, 0x64000100)],
            tripwire_pcs=[0x6395B314],
            uc_factory=factory,
        )
        uc = holder["uc"]

        # VFPv3 enabled automatically
        self.assertEqual(uc.regs[UC_ARM_REG_C1_C0_2_CONST], VFP_CPACR_ENABLE)
        self.assertEqual(uc.regs[UC_ARM_REG_FPEXC_CONST], VFP_FPEXC_ENABLE)

        # Allowed scratch + whitelisted table write succeeds
        uc.scripted_steps = [
            ("code", 0x637A6540, 2, 0),
            ("write", 0x70000100, 4, 0xAA),
            ("write", 0x64000010, 4, 0xBB),
        ]
        res = runner.call(0x637A6540, (1, 2))
        self.assertEqual(res["r0"], 0x1234)
        self.assertEqual(res["unique_instructions"], 1)
        self.assertEqual(len(res["external_writes"]), 1)

        # Unauthorized write outside whitelist triggers WriteViolationError
        uc.scripted_steps = [("write", 0x64000200, 4, 1)]
        with self.assertRaises(WriteViolationError):
            runner.call(0x637A6540)

        # OS/Logger tripwire PC triggers TripwireHitError
        uc.scripted_steps = [("code", 0x6395B315, 2, 0)]
        with self.assertRaises(TripwireHitError):
            runner.call(0x637A6540)

        # MMIO address range (0xf3120000) triggers TripwireHitError
        uc.scripted_steps = [("code", 0xF3120000, 4, 0)]
        with self.assertRaises(TripwireHitError):
            runner.call(0x637A6540)


if __name__ == "__main__":
    unittest.main()
