"""Command-line interface for `sony-fw-inspect`."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .acquisition.backup_verifier import verify_backup_directory
from .elf_abi.relcount_patcher import patch_dt_relcount_zero
from .elf_abi.safety_auditor import audit_arm_elf
from .unicorn_kit.ko_relocator import KernelObjectModule
from .unicorn_kit.mips_vcd import normalize_legacy_mips_madd, scan_mips_lui_xrefs
from .unpacker.boot_components import unpack_cramfs_image, unpack_wbi_image
from .unpacker.partition_carver import carve_firmware_image


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sony-fw-inspect",
        description="Sony firmware forensics, read-only unpacker, ld-2.11.2.so ELF ABI patcher, and static/Unicorn analyzer",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify-backups", help="Verify saved acquisition manifest and SHA-256 digests")
    p_verify.add_argument("directory", type=Path, help="Acquisition directory containing manifest.json")

    p_carve = sub.add_parser("carve-firmware", help="Carve verified logical NAND image and export filesystems")
    p_carve.add_argument("--image", type=Path, required=True)
    p_carve.add_argument("--manifest", type=Path, required=True)
    p_carve.add_argument("--geometry", type=Path, required=True)
    p_carve.add_argument("--output", type=Path, required=True)
    p_carve.add_argument("--debugfs", type=Path, help="Optional e2fsprogs debugfs binary path")

    p_wbi = sub.add_parser("unpack-wbi", help="Bounds-checked Sony WBI1 warmboot section decompressor")
    p_wbi.add_argument("--input", type=Path, required=True, help="Raw WBI1 partition slice (e.g. nflasha5.bin)")
    p_wbi.add_argument("--output", type=Path, required=True, help="New output directory")

    p_cram = sub.add_parser("unpack-cramfs", help="CRC32-verified Linux CramFS extractor (initrd.img)")
    p_cram.add_argument("--input", type=Path, required=True, help="Input CramFS image")
    p_cram.add_argument("--output", type=Path, required=True, help="New output directory")

    p_patch = sub.add_parser("patch-relcount", help="Zero DT_RELCOUNT in ARM32 .dynamic for Sony ld-2.11.2.so")
    p_patch.add_argument("elf", type=Path, help="Input ARM32 ELF shared object")
    p_patch.add_argument("-o", "--output", type=Path, help="Output path (defaults to in-place update)")

    p_audit = sub.add_parser("audit-elf", help="Audit ARM32 ELF for W^X, PT_GNU_STACK, DT_RELCOUNT=0, and constructors")
    p_audit.add_argument("elf", type=Path, help="ARM32 ELF binary to audit")
    p_audit.add_argument("--allow-init", action="store_true")
    p_audit.add_argument("--allow-fini", action="store_true")

    p_madd = sub.add_parser("normalize-mips-madd", help="Produce analysis-only MIPS32 binary with normalized MADD/MADDU")
    p_madd.add_argument("--input", type=Path, required=True, help="Raw vcd_firmware.bin")
    p_madd.add_argument("--output", type=Path, required=True, help="Output analysis-only binary path")
    p_madd.add_argument("--report", type=Path, help="Optional JSON normalization report")

    p_xref = sub.add_parser("scan-mips-xrefs", help="Scan MIPS32 LE image for LUI+ADDIU/ORI string xrefs")
    p_xref.add_argument("image", type=Path, help="Raw MIPS32 LE firmware image")
    p_xref.add_argument("--filter", default="", help="Optional substring filter on ASCII strings")

    p_ko = sub.add_parser("inspect-ko", help="Inspect symbols and SHT_REL relocations of an ARM ET_REL .ko module")
    p_ko.add_argument("ko", type=Path, help="Path to .ko kernel object")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "verify-backups":
        res = verify_backup_directory(args.directory)
        print(json.dumps(res, indent=2))
        return 0 if res["saved_file_integrity_ok"] else 1
    if args.command == "carve-firmware":
        rc, report = carve_firmware_image(
            image_path=args.image,
            manifest_path=args.manifest,
            geometry_path=args.geometry,
            output_dir=args.output,
            debugfs_binary=args.debugfs,
        )
        print(json.dumps({"status": report["status"], "partitions": len(report["partitions"])}, indent=2))
        return rc
    if args.command == "unpack-wbi":
        print(json.dumps(unpack_wbi_image(args.input, args.output), indent=2))
        return 0
    if args.command == "unpack-cramfs":
        print(json.dumps(unpack_cramfs_image(args.input, args.output), indent=2))
        return 0
    if args.command == "patch-relcount":
        patched, info = patch_dt_relcount_zero(args.elf.read_bytes())
        dst = args.output or args.elf
        dst.write_bytes(patched)
        print(json.dumps(info, indent=2))
        return 0
    if args.command == "audit-elf":
        res = audit_arm_elf(
            args.elf.read_bytes(),
            allow_init=args.allow_init,
            allow_fini=args.allow_fini,
            raise_on_violation=False,
        )
        print(json.dumps(res, indent=2))
        return 0 if res["passed"] else 1
    if args.command == "normalize-mips-madd":
        out_bytes, rep = normalize_legacy_mips_madd(args.input.read_bytes())
        args.output.write_bytes(out_bytes)
        if args.report:
            args.report.write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"change_count": rep["change_count"], "analysis_sha256": rep["analysis_sha256"]}, indent=2))
        return 0
    if args.command == "scan-mips-xrefs":
        blob = args.image.read_bytes()
        hits = scan_mips_lui_xrefs(blob)
        if args.filter:
            hits = [h for h in hits if args.filter in h["text"]]
        print(json.dumps(hits, indent=2))
        return 0
    if args.command == "inspect-ko":
        mod = KernelObjectModule.from_file(args.ko)
        summary = {
            "name": mod.name,
            "sha256": mod.sha256,
            "sections": [
                {"index": i, "name": s["name"], "size": s["sh_size"]}
                for i, s in mod.sections.items()
                if s["sh_size"] > 0
            ],
            "defined_symbols": sorted(
                sym.name for sym in mod.symbols if sym.name and sym.shndx != 0
            ),
            "relocation_count": len(mod.relocations),
        }
        print(json.dumps(summary, indent=2))
        return 0
    return 64


if __name__ == "__main__":
    sys.exit(main())
