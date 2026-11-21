"""Boot the isolated ARM loader qualification guest in `qemu-system-arm` with zero
network, block disk, or USB passthrough attachments.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--kernel",
        type=Path,
        default=Path(os.environ["DEBIAN_ARM_VMLINUZ"]) if "DEBIAN_ARM_VMLINUZ" in os.environ else None,
        required="DEBIAN_ARM_VMLINUZ" not in os.environ,
        help="Path to generic ARMv7 Linux kernel (vmlinuz) or set DEBIAN_ARM_VMLINUZ",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=HERE / "work",
        help="Work directory containing initramfs.cpio.gz",
    )
    parser.add_argument(
        "--qemu",
        default=os.environ.get("QEMU_ARM") or shutil.which("qemu-system-arm") or "qemu-system-arm",
        help="qemu-system-arm binary (or set QEMU_ARM)",
    )
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args()

    work = args.work_dir.resolve(strict=True)
    initrd = (work / "initramfs.cpio.gz").resolve(strict=True)
    kernel = args.kernel.resolve(strict=True)
    serial = work / "serial-trial.log"
    stderr_log = work / "qemu-trial.stderr"
    if serial.exists():
        serial.unlink()

    cmd = [
        str(args.qemu),
        "-machine",
        "virt",
        "-cpu",
        "cortex-a15",
        "-accel",
        "tcg",
        "-m",
        "256M",
        "-nodefaults",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        f"file:{serial}",
        "-no-reboot",
        "-kernel",
        str(kernel),
        "-initrd",
        str(initrd),
        "-append",
        "console=ttyAMA0 rdinit=/init panic=-1 loglevel=4",
    ]

    report: dict[str, object] = {
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "command": cmd,
        "physical_camera_access": False,
        "guest_disk_network_USB_attached": False,
        "timeout_seconds": args.timeout,
    }

    with stderr_log.open("wb") as err_f:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err_f)
        try:
            report["exit_status"] = proc.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            report["timed_out"] = True
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
            report["exit_status"] = proc.returncode

    data = serial.read_bytes() if serial.exists() else b""
    text = data.decode("utf-8", errors="replace")
    report["serial_sha256"] = hashlib.sha256(data).hexdigest()
    report["serial_bytes"] = len(data)
    report["test_lines"] = [line for line in text.splitlines() if "CXVM_" in line]
    report["suite_passed"] = "CXVM_COMPLETE failures=0" in text and report["exit_status"] == 0

    (work / "trial-result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["suite_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
