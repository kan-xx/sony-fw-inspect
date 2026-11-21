"""Static forensic analyzer for Sony `/lib/ld-2.11.2.so` (`DT_RELCOUNT` replay bug)
and candidate ARM32 DSOs.

Parameterized via `--fw-root` / `A7R3_FW_ROOT`; contains zero hardcoded user paths
and zero bundled firmware binaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from sony_fw_inspect.elf_abi.relcount_patcher import simulate_sony_ld_2_11_2_relocations

LOADER_RANGES: list[tuple[int, int, str]] = [
    (0x502E, 0x5084, "dynamic-tag-index"),
    (0x5122, 0x515E, "FLAGS/NOW recognized"),
    (0x881A, 0x882A, "NOW clears lazy flag"),
    (0x866E, 0x8708, "REL/PLT range setup"),
    (0x87CE, 0x881A, "lazy GOT resolver setup only if lazy"),
    (0x8708, 0x8718, "each range eager branch"),
    (0x8ED2, 0x8EF4, "separate ranges unless contiguous"),
    (0x94D0, 0x94DC, "contiguous NOW merge"),
    (0x8AAE, 0x8AD6, "RELCOUNT re-read per range"),
    (0x8EF4, 0x8F46, "relative fast path ignores type"),
    (0x8AD6, 0x8AE8, "end check skips type-aware loop"),
    (0x8862, 0x886C, "range completion"),
    (0x8FB4, 0x8FC2, "next range repeats same loop"),
    (0x8AFE, 0x8B64, "normal versioned type decoder and lookup classification"),
    (0x9566, 0x957A, "normal versioned RELATIVE store"),
    (0x8850, 0x8862, "resolved JUMP_SLOT store"),
    (0x9020, 0x9044, "normal unversioned type decoder"),
    (0x977A, 0x9784, "normal unversioned RELATIVE store"),
]


def disassemble_loader_proof(loader_path: Path) -> str:
    from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

    raw = loader_path.resolve(strict=True).read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    lines = [
        f"Static stock ld-2.11.2.so native VA == file offset in inspected ranges; SHA256={sha}"
    ]
    for lo, hi, label in LOADER_RANGES:
        lines.append(f"\n{label}:")
        for ins in cs.disasm(raw[lo:hi], lo):
            lines.append(f"{ins.address:08x} {ins.bytes.hex():12s} {ins.mnemonic} {ins.op_str}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fw-root",
        type=Path,
        default=Path(os.environ["A7R3_FW_ROOT"]) if "A7R3_FW_ROOT" in os.environ else None,
        help="Extracted firmware root (or set A7R3_FW_ROOT)",
    )
    parser.add_argument("--dso", type=Path, nargs="*", default=[], help="Candidate DSOs to model")
    parser.add_argument("--output-dir", type=Path, help="Optional directory to write proof files")
    args = parser.parse_args()

    result: dict[str, object] = {"models": []}
    if args.fw_root is not None:
        ld_path = args.fw_root / "filesystems/nflasha7/export/lib/ld-2.11.2.so"
        if ld_path.is_file():
            proof = disassemble_loader_proof(ld_path)
            result["loader_sha256"] = hashlib.sha256(ld_path.read_bytes()).hexdigest()
            if args.output_dir:
                args.output_dir.mkdir(parents=True, exist_ok=True)
                (args.output_dir / "loader-byte-proof.txt").write_text(proof, encoding="utf-8")

    models = []
    for dso in args.dso:
        m = simulate_sony_ld_2_11_2_relocations(dso.read_bytes())
        m["file"] = dso.name
        models.append(m)
    result["models"] = models
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "relocation-model.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
