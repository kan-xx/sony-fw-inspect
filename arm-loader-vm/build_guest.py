"""Build an isolated QEMU ARM guest `initramfs.cpio.gz` reproducing the `ld-2.11.2.so`
`DT_RELCOUNT` crash (`original-V1`) and verifying both `fixed-RELCOUNT0` and `raw-SVC`.

All binary inputs (`ld-2.11.2.so`, `libc-2.11.2.so`) are read externally from
`--fw-root` / `A7R3_FW_ROOT`, and all outputs are written into an untracked `--work-dir`.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from sony_fw_inspect.elf_abi.relcount_patcher import patch_dt_relcount_zero
from sony_fw_inspect.elf_abi.zig_builder import SONY_ARM_DSO_CFLAGS, resolve_zig_cc


def pack_newc_cpio(entries: dict[str, tuple[int, bytes, int, int]]) -> bytes:
    out = bytearray()
    all_items = list(entries.items()) + [("TRAILER!!!", (0, b"", 0, 0))]
    for ino, (name, (mode, blob, maj, minor)) in enumerate(all_items, 1):
        encoded_name = name.encode("ascii") + b"\x00"
        nlink = 2 if stat.S_ISDIR(mode) else 1
        words = [ino, mode, 0, 0, nlink, 0, len(blob), 0, 0, maj, minor, len(encoded_name), 0]
        out += b"070701" + "".join(f"{v:08x}" for v in words).encode("ascii") + encoded_name
        out += b"\x00" * ((-len(out)) % 4)
        out += blob
        out += b"\x00" * ((-len(out)) % 4)
    return gzip.compress(bytes(out), mtime=0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fw-root",
        type=Path,
        default=Path(os.environ["A7R3_FW_ROOT"]) if "A7R3_FW_ROOT" in os.environ else None,
        required="A7R3_FW_ROOT" not in os.environ,
        help="Extracted firmware root containing filesystems/nflasha7/export/lib",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=HERE / "work",
        help="Untracked build directory for guest ELFs and initramfs.cpio.gz",
    )
    parser.add_argument("--zig-cc", default=os.environ.get("ZIG_CC"))
    args = parser.parse_args()

    zig_cc = resolve_zig_cc(args.zig_cc)
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    lib_dir = args.fw_root.resolve(strict=True) / "filesystems/nflasha7/export/lib"

    init_elf = work / "init.elf"
    im_stub = work / "im.elf"
    orig_v1 = work / "original-v1.so"
    fixed_v1 = work / "fixed-relcount0.so"
    raw_svc = work / "raw-svc.so"

    subprocess.run(
        [*zig_cc, "-target", "arm-linux-musleabi", "-mcpu=cortex_a9", "-Os", "-static", str(HERE / "init.c"), "-o", str(init_elf)],
        check=True,
    )
    subprocess.run(
        [*zig_cc, "-target", "arm-linux-gnueabi", "-mcpu=cortex_a9", "-marm", "-Os", "-nostdlib", str(HERE / "inert_im_stub.c"), str(lib_dir / "libc-2.11.2.so"), "-Wl,--dynamic-linker,/lib/ld-linux.so.3", "-o", str(im_stub)],
        check=True,
    )
    subprocess.run(
        [*zig_cc, *SONY_ARM_DSO_CFLAGS, str(HERE / "canary.c"), str(lib_dir / "libc-2.11.2.so"), "-o", str(orig_v1)],
        check=True,
    )
    patched, _ = patch_dt_relcount_zero(orig_v1.read_bytes())
    fixed_v1.write_bytes(patched)

    subprocess.run(
        [*zig_cc, *SONY_ARM_DSO_CFLAGS, "-DUSE_RAW_SVC", str(HERE / "canary.c"), "-o", str(raw_svc)],
        check=True,
    )
    patched_svc, _ = patch_dt_relcount_zero(raw_svc.read_bytes())
    raw_svc.write_bytes(patched_svc)

    entries: dict[str, tuple[int, bytes, int, int]] = {}
    for d in ("dev", "proc", "sys", "tmp", "lib", "probe", "setting", "setting/custom_sound_test"):
        entries[d] = (stat.S_IFDIR | 0o755, b"", 0, 0)
    entries["dev/console"] = (stat.S_IFCHR | 0o600, b"", 5, 1)
    entries["init"] = (stat.S_IFREG | 0o755, init_elf.read_bytes(), 0, 0)
    entries["lib/ld-2.11.2.so"] = (stat.S_IFREG | 0o755, (lib_dir / "ld-2.11.2.so").read_bytes(), 0, 0)
    entries["lib/libc-2.11.2.so"] = (stat.S_IFREG | 0o755, (lib_dir / "libc-2.11.2.so").read_bytes(), 0, 0)
    entries["lib/ld-linux.so.3"] = (stat.S_IFLNK | 0o777, b"ld-2.11.2.so", 0, 0)
    entries["lib/libc.so.6"] = (stat.S_IFLNK | 0o777, b"libc-2.11.2.so", 0, 0)
    entries["probe/im.elf"] = (stat.S_IFREG | 0o755, im_stub.read_bytes(), 0, 0)
    entries["probe/original-v1.so"] = (stat.S_IFREG | 0o755, orig_v1.read_bytes(), 0, 0)
    entries["probe/fixed-relcount0.so"] = (stat.S_IFREG | 0o755, fixed_v1.read_bytes(), 0, 0)
    entries["probe/raw-svc.so"] = (stat.S_IFREG | 0o755, raw_svc.read_bytes(), 0, 0)

    cpio_gz = pack_newc_cpio(entries)
    initrd_path = work / "initramfs.cpio.gz"
    initrd_path.write_bytes(cpio_gz)

    manifest = {
        "initramfs": str(initrd_path),
        "gzip_bytes": len(cpio_gz),
        "sha256": hashlib.sha256(cpio_gz).hexdigest(),
        "guest_disk_network_USB_devices": False,
    }
    (work / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
