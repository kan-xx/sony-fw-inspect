"""Synthetic unit tests for ARMv7 Sony `ld-2.11.2.so` `DT_RELCOUNT = 0` `.dynamic` patcher,
non-contiguous `DT_REL`/`DT_JMPREL` relocation corruption model, and `audit_arm_elf`.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import struct
import tempfile
import unittest

from sony_fw_inspect.elf_abi import (
    DF_BIND_NOW,
    DT_BIND_NOW,
    DT_FLAGS,
    DT_INIT_ARRAY,
    DT_JMPREL,
    DT_NEEDED,
    DT_PLTRELSZ,
    DT_REL,
    DT_RELCOUNT,
    DT_RELSZ,
    ElfSafetyViolation,
    audit_arm_elf,
    build_sony_arm_dso,
    patch_dt_relcount_zero,
    simulate_sony_ld_2_11_2_relocations,
)


def _build_synthetic_arm_dso(
    *,
    relcount: int = 3,
    rwx_load: bool = False,
    exec_stack: bool = False,
    include_init_array: bool = False,
    export_names: tuple[str, ...] = ("commandFA00",),
) -> bytes:
    """Construct a synthetic 32-bit ARM `ET_DYN` ELF matching `lld` non-contiguous layout."""
    # Virtual layout:
    # Segment 0 (RX, p_vaddr=0x0000, p_offset=0x0000, size=0x1000):
    #   0x0100: .dynstr
    #   0x0200: .dynsym
    #   0x0300: .rel.dyn (3 x R_ARM_RELATIVE = 24B)
    #   0x0340: gap (non-contiguous!)
    #   0x0380: .rel.plt (1 x R_ARM_JUMP_SLOT = 8B targeting 0x140c)
    #   0x0400: .plt (PLT0 at 0x0400)
    # Segment 1 (RW, p_vaddr=0x1000, p_offset=0x1000, size=0x1000):
    #   0x1000: .dynamic
    #   0x1400: .got.plt (4 words; word[3] at 0x140c = 0x0400 PLT0)
    img = bytearray(0x2800)

    # Strtab (.dynstr at 0x0100, .shstrtab at 0x2000)
    dynstr = bytearray(b"\x00")
    libc_off = len(dynstr)
    dynstr += b"libc.so.6\x00"
    syscall_off = len(dynstr)
    dynstr += b"syscall\x00"
    exp_offs = []
    for name in export_names:
        exp_offs.append(len(dynstr))
        dynstr += name.encode("ascii") + b"\x00"
    img[0x0100 : 0x0100 + len(dynstr)] = dynstr

    # .dynsym at 0x0200: [0]=NULL, [1]=UND syscall, [2..]=FUNC exports in section 1
    dynsym = bytearray(16)  # STN_UNDEF
    dynsym += struct.pack("<IIIBBH", syscall_off, 0, 0, (1 << 4) | 2, 0, 0)
    for off in exp_offs:
        dynsym += struct.pack("<IIIBBH", off, 0x0500, 16, (1 << 4) | 2, 0, 1)
    img[0x0200 : 0x0200 + len(dynsym)] = dynsym

    # .rel.dyn at 0x0300: 3 x R_ARM_RELATIVE (type 23) targeting 0x1500, 0x1504, 0x1508
    for i in range(3):
        target = 0x1500 + 4 * i
        struct.pack_into("<II", img, 0x0300 + 8 * i, target, 23)
        struct.pack_into("<I", img, target, 0x0500 + 4 * i)

    # Non-contiguous .rel.plt at 0x0380: 1 x R_ARM_JUMP_SLOT (type 22, sym 1) targeting .got.plt+12 (0x140c)
    struct.pack_into("<II", img, 0x0380, 0x140C, (1 << 8) | 22)
    # .got.plt at 0x1400: word[3] pre-linked to PLT0 (0x0400)
    struct.pack_into("<4I", img, 0x1400, 0x1000, 0, 0, 0x0400)

    # .dynamic at 0x1000
    dyn_tags = [
        (DT_NEEDED, libc_off),
        (DT_REL, 0x0300),
        (DT_RELSZ, 24),
        (DT_JMPREL, 0x0380),
        (DT_PLTRELSZ, 8),
        (DT_BIND_NOW, 0),
        (DT_FLAGS, DF_BIND_NOW),
        (DT_RELCOUNT, relcount),
    ]
    if include_init_array:
        dyn_tags.append((DT_INIT_ARRAY, 0x1600))
    dyn_tags.append((0, 0))
    for idx, (tag, val) in enumerate(dyn_tags):
        struct.pack_into("<II", img, 0x1000 + 8 * idx, tag, val)
    dyn_bytes = 8 * len(dyn_tags)

    # Program headers at 0x0034 (4 entries: RX, RW, PT_DYNAMIC, PT_GNU_STACK)
    pf_r, pf_w, pf_x = 4, 2, 1
    seg0_flags = (pf_r | pf_w | pf_x) if rwx_load else (pf_r | pf_x)
    stack_flags = (pf_r | pf_w | pf_x) if exec_stack else (pf_r | pf_w)
    phdrs = [
        (1, 0x0000, 0x0000, 0x0000, 0x1000, 0x1000, seg0_flags, 0x1000),  # PT_LOAD RX
        (1, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, pf_r | pf_w, 0x1000),  # PT_LOAD RW
        (2, 0x1000, 0x1000, 0x1000, dyn_bytes, dyn_bytes, pf_r | pf_w, 4),  # PT_DYNAMIC
        (0x6474E551, 0, 0, 0, 0, 0, stack_flags, 4),  # PT_GNU_STACK
    ]
    for idx, ph in enumerate(phdrs):
        struct.pack_into("<8I", img, 0x34 + 32 * idx, *ph)

    # Section headers at 0x2200: [0]=NULL, [1]=.text, [2]=.dynstr, [3]=.dynsym, [4]=.dynamic, [5]=.shstrtab
    shstr = b"\x00.text\x00.dynstr\x00.dynsym\x00.dynamic\x00.shstrtab\x00"
    img[0x2000 : 0x2000 + len(shstr)] = shstr
    shdrs = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 6, 0x0400, 0x0400, 0x0200, 0, 0, 4, 0),
        (7, 3, 2, 0x0100, 0x0100, len(dynstr), 0, 0, 1, 0),
        (15, 11, 2, 0x0200, 0x0200, len(dynsym), 2, 1, 4, 16),
        (23, 6, 3, 0x1000, 0x1000, dyn_bytes, 2, 0, 4, 8),
        (32, 3, 0, 0, 0x2000, len(shstr), 0, 0, 1, 0),
    ]
    for idx, sh in enumerate(shdrs):
        struct.pack_into("<10I", img, 0x2200 + 40 * idx, *sh)

    # ELF32 header at 0x0000
    img[0:16] = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
    struct.pack_into(
        "<HHIIIIIHHHHHH",
        img,
        16,
        3,       # ET_DYN
        40,      # EM_ARM
        1,
        0,
        0x34,    # e_phoff
        0x2200,  # e_shoff
        0x05000200,
        52,
        32,
        len(phdrs),
        40,
        len(shdrs),
        5,       # e_shstrndx
    )
    return bytes(img)


class ElfAbiPatcherAndAuditorTests(unittest.TestCase):
    def test_dt_relcount_bug_reproduction_and_postlink_patch(self) -> None:
        base = 0x0410F000
        unpatched = _build_synthetic_arm_dso(relcount=3)

        # 1. Under Sony ld-2.11.2.so, DT_RELCOUNT=3 corrupts .got.plt+12 (0x140c) into base + PLT0 (0x400)!
        bad_sim = simulate_sony_ld_2_11_2_relocations(unpatched, base_addr=base, mock_resolved_va=0x0509DD30)
        self.assertTrue(bad_sim["non_contiguous_pltrel"])
        self.assertFalse(bad_sim["safe_under_ld_2_11_2"])
        self.assertEqual(bad_sim["corrupted_jump_slots"], ["0x140c"])
        self.assertEqual(bad_sim["memory_after"]["0x140c"], hex(base + 0x0400))

        # 2. Patch DT_RELCOUNT -> 0
        patched, info = patch_dt_relcount_zero(unpatched)
        self.assertEqual(info["patched_entries"], 1)
        self.assertEqual(info["previous_relcount_values"], [3])

        # 3. Patched DSO resolves R_ARM_JUMP_SLOT cleanly via symbol lookup!
        good_sim = simulate_sony_ld_2_11_2_relocations(patched, base_addr=base, mock_resolved_va=0x0509DD30)
        self.assertTrue(good_sim["safe_under_ld_2_11_2"])
        self.assertEqual(good_sim["corrupted_jump_slots"], [])
        self.assertEqual(good_sim["memory_after"]["0x140c"], "0x509dd30")
        # And R_ARM_RELATIVE slots still receive base + addend!
        self.assertEqual(good_sim["memory_after"]["0x1500"], hex(base + 0x0500))

        # 4. Auditor accepts patched DSO with exact export allowlist
        audit = audit_arm_elf(patched, allowed_exports={"commandFA00"})
        self.assertTrue(audit["passed"])
        self.assertEqual(audit["dt_relcount_values"], [0])
        self.assertEqual(audit["needed"], ["libc.so.6"])

    def test_safety_auditor_rejects_rwx_execstack_relcount_init_and_extra_exports(self) -> None:
        # Non-zero DT_RELCOUNT rejected
        with self.assertRaises(ElfSafetyViolation) as ctx:
            audit_arm_elf(_build_synthetic_arm_dso(relcount=2))
        self.assertIn("DT_RELCOUNT", str(ctx.exception))

        # RWX PT_LOAD rejected
        rwx_patched, _ = patch_dt_relcount_zero(_build_synthetic_arm_dso(relcount=1, rwx_load=True))
        with self.assertRaises(ElfSafetyViolation) as ctx:
            audit_arm_elf(rwx_patched)
        self.assertIn("RWX", str(ctx.exception))

        # Executable PT_GNU_STACK rejected
        execstack_patched, _ = patch_dt_relcount_zero(_build_synthetic_arm_dso(relcount=1, exec_stack=True))
        with self.assertRaises(ElfSafetyViolation) as ctx:
            audit_arm_elf(execstack_patched)
        self.assertIn("PT_GNU_STACK", str(ctx.exception))

        # Unintended DT_INIT_ARRAY constructor rejected unless allow_init=True
        ctor_patched, _ = patch_dt_relcount_zero(_build_synthetic_arm_dso(relcount=1, include_init_array=True))
        with self.assertRaises(ElfSafetyViolation) as ctx:
            audit_arm_elf(ctor_patched)
        self.assertIn("DT_INIT", str(ctx.exception))
        self.assertTrue(audit_arm_elf(ctor_patched, allow_init=True)["passed"])

        # Unexpected exported symbol rejected
        extra_patched, _ = patch_dt_relcount_zero(
            _build_synthetic_arm_dso(relcount=1, export_names=("commandFA00", "leaked_helper"))
        )
        with self.assertRaises(ElfSafetyViolation) as ctx:
            audit_arm_elf(extra_patched, allowed_exports={"commandFA00"})
        self.assertIn("leaked_helper", str(ctx.exception))

    @unittest.skipUnless(shutil.which("zig"), "zig compiler not installed")
    def test_zig_builder_compiles_patches_and_audits_real_arm_dso(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            src_c = root / "plugin.c"
            src_c.write_text(
                '__attribute__((visibility("default"))) int commandFA00(void *pkt) {\n'
                "    return pkt != 0 ? 1 : 0;\n"
                "}\n",
                encoding="utf-8",
            )
            out_so = root / "libproFA.so"
            res = build_sony_arm_dso(
                [src_c],
                out_so,
                allowed_exports={"commandFA00"},
            )
            self.assertTrue(res["audit"]["passed"])
            self.assertTrue(all(v == 0 for v in res["audit"]["dt_relcount_values"]))
            self.assertEqual(res["audit"]["exports"], ["commandFA00"])


if __name__ == "__main__":
    unittest.main()
