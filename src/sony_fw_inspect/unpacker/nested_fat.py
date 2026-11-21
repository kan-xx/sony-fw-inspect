"""Validate and carve nested MBR/FAT volumes (such as `nflasha23`) read-only."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import struct
from typing import Any

from .partition_carver import (
    CHUNK,
    fat_export,
    format_header,
    hashes,
    inventory_export,
    require,
    write_json,
)


def extract_nested_mbr_fat(
    run_dir: Path,
    partition_name: str = "nflasha23",
) -> dict[str, Any]:
    """Carve an inner MBR FAT child volume from a carved partition and export its files."""
    out = run_dir.resolve(strict=True)
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    part = next(p for p in report["partitions"] if p["name"] == partition_name)
    raw = out / part["raw_path"]
    before = hashes(raw)
    require(before == {"sha256": part["sha256"], "sha1": part["sha1"]}, "Parent partition hash mismatch")

    with raw.open("rb") as f:
        header = f.read(512)
    require(len(header) == 512 and header[510:512] == b"\x55\xaa", "Missing 0x55aa MBR signature")

    entries: list[dict[str, Any]] = []
    for i in range(4):
        e = header[446 + 16 * i : 462 + 16 * i]
        start, sectors = struct.unpack_from("<II", e, 8)
        require(e[0] in (0, 0x80), "Invalid MBR boot indicator")
        if e[4] == 0:
            require(start == 0 and sectors == 0, "Non-zero geometry in empty MBR slot")
            continue
        require(
            start > 0 and sectors > 0 and (start + sectors) * 512 <= part["bytes"],
            "Nested MBR partition exceeds parent slice bounds",
        )
        entries.append(
            {
                "mbr_slot": i + 1,
                "type": e[4],
                "start_sector": start,
                "sectors": sectors,
                "offset_bytes": start * 512,
                "bytes": sectors * 512,
            }
        )
    require(len(entries) == 1, f"Expected 1 active nested MBR partition, found {len(entries)}")
    e0 = entries[0]

    volume_dir = out / "volumes" / partition_name
    volume_dir.mkdir(parents=True)
    volume = volume_dir / f"mbr{e0['mbr_slot']}.fat.bin"
    with raw.open("rb") as src, volume.open("xb") as dst:
        src.seek(e0["offset_bytes"])
        remaining = int(e0["bytes"])
        while remaining:
            b = src.read(min(remaining, CHUNK))
            require(b, "Short read carving nested MBR volume")
            dst.write(b)
            remaining -= len(b)
    volume.chmod(0o400)
    volume_hash = hashes(volume)

    with volume.open("rb") as f:
        fmt = format_header(f.read(4096))
    require(fmt.get("family") == "fat", f"Nested MBR partition is not FAT: {fmt}")

    child_label = f"{partition_name}-mbr{e0['mbr_slot']}"
    folder = out / "filesystems" / child_label
    folder.mkdir()
    (folder / "logs").mkdir()
    export_res = fat_export(volume, folder / "export")
    require(hashes(volume) == volume_hash and hashes(raw) == before, "Source hash changed during FAT export")

    for name in ("report.json", "file-inventory.jsonl", "elf-inventory.jsonl"):
        backup = out / f"pre-nested-fat-{name}"
        if not backup.exists():
            with (out / name).open("rb") as src, backup.open("xb") as dst:
                shutil.copyfileobj(src, dst)

    with (
        (out / "file-inventory.jsonl").open("a", encoding="utf-8") as files,
        (out / "elf-inventory.jsonl").open("a", encoding="utf-8") as elfs,
    ):
        counts = inventory_export(folder / "export", child_label, files, elfs)

    mapping = {
        "parent_partition": partition_name,
        "parent_raw_path": part["raw_path"],
        "parent_sha256": part["sha256"],
        "parent_bytes": part["bytes"],
        "logical_sector_bytes": 512,
        "mbr_signature": "55aa",
        "entries": entries,
        "nested_volume": {
            **e0,
            **volume_hash,
            "raw_path": str(volume.relative_to(out)),
            "identification": fmt,
            "source_main_image_offset_bytes": part["offset_bytes"] + e0["offset_bytes"],
            "export_directory": str((folder / "export").relative_to(out)),
            "export": export_res,
            "inventory": counts,
        },
        "bounds_verified": True,
        "source_hash_unchanged": True,
        "source_execution": False,
        "os_mount": False,
    }
    write_json(volume_dir / "layer-mapping.json", mapping)
    write_json(folder / "logs/fat-export.json", mapping)

    part.update(
        identification={"format": "mbr", "family": "partition-table", "nested_format": fmt["format"]},
        export_status=f"complete nested {fmt['format']} export",
        nested_volumes=[mapping["nested_volume"]],
        inventory=counts,
    )
    for name in ("file-inventory.jsonl", "elf-inventory.jsonl"):
        report[name] = hashes(out / name)
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return mapping
