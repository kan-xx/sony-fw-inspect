"""Complete a partial ext2 partition export (such as `nflasha7` case-collision recovery)
while preserving first-attempt reports and inventories.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
from typing import Any

from .partition_carver import (
    ext_export,
    hashes,
    inventory_export,
    require,
    sanitize_export_permissions,
    write_json,
)


def complete_failed_ext_partition(
    run_dir: Path,
    partition_name: str = "nflasha7",
    *,
    debugfs_binary: Path | None = None,
    timeout: int = 900,
) -> dict[str, Any]:
    """Export a previously failed ext2 partition using per-inode host filename aliasing."""
    out = run_dir.resolve(strict=True)
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    require(report.get("status") == "partial-export", "Expected partial-export run directory")
    item = next(x for x in report["partitions"] if x["name"] == partition_name)
    require(str(item.get("export_status", "")).startswith("failed"), f"{partition_name} did not fail export")

    raw = out / item["raw_path"]
    require(hashes(raw) == {"sha256": item["sha256"], "sha1": item["sha1"]}, "Partition slice hash mismatch")

    manifest = json.loads((out / "source-manifest.json").read_text(encoding="utf-8"))
    require(manifest.get("exposed_internal_storage_acquisition_complete") is True, "Acquisition incomplete")
    if partition_name in manifest.get("post_acquisition_readonly_partition_sha1", {}):
        require(
            item["sha1"] == manifest["post_acquisition_readonly_partition_sha1"][partition_name].lower(),
            "Readonly partition SHA-1 mismatch",
        )

    for name in ("report.json", "file-inventory.jsonl", "elf-inventory.jsonl"):
        p = out / name
        backup = out / f"first-attempt-{name}"
        if not backup.exists():
            with p.open("rb") as src, backup.open("xb") as dst:
                shutil.copyfileobj(src, dst)

    folder = out / "filesystems" / partition_name
    require(not (folder / "export").exists(), "Export directory already exists")
    logs = folder / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    for stale in ("ext-directory-inventory.json", "host-path-mapping.json"):
        if (logs / stale).exists():
            (logs / stale).replace(logs / f"first-attempt-{stale}")

    try:
        item["export"] = ext_export(
            raw, folder / "export", logs, debugfs_binary=debugfs_binary, timeout=timeout
        )
        source_map = {
            e["host_path"]: e["path"]
            for e in json.loads((logs / "ext-directory-inventory.json").read_text(encoding="utf-8"))
        }
        with (
            (out / "file-inventory.jsonl").open("a", encoding="utf-8") as files,
            (out / "elf-inventory.jsonl").open("a", encoding="utf-8") as elfs,
        ):
            item["inventory"] = inventory_export(
                folder / "export", partition_name, files, elfs, source_map
            )
        item["previous_export_error"] = item.pop("export_error", None)
        item["export_status"] = "complete with explicit host filename mapping"
        if all(not str(p.get("export_status", "")).startswith("failed") for p in report["partitions"]):
            report["status"] = "complete"
        for name in ("file-inventory.jsonl", "elf-inventory.jsonl"):
            report[name] = hashes(out / name)
        write_json(out / "report.completed.json", report)
        (out / "report.completed.json").replace(out / "report.json")
    finally:
        sanitize_export_permissions(folder / "export")

    return {"status": report["status"], "partition": partition_name, "export": item["export"], "inventory": item["inventory"]}
