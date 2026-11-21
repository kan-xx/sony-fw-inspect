"""Offline SHA-256 and byte-length verifier for saved acquisition manifests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def verify_backup_directory(directory: Path) -> dict[str, Any]:
    """Verify every `storage_images` and `files` entry in `manifest.json` offline.

    Enforces strict path confinement (`is_relative_to`) and never claims physical
    raw NAND/OOB completeness (`complete_physical_firmware_backup_verified=False`).
    """
    root = directory.resolve(strict=True)
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Missing manifest.json in {root}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    results: list[dict[str, Any]] = []
    records = list(manifest.get("storage_images", [])) + list(manifest.get("files", []))
    for record in records:
        rel = record.get("path", "")
        raw_target = root / rel
        if raw_target.is_symlink():
            raise ValueError(f"Symlink forbidden in backup verification: {rel}")
        path = raw_target.resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(f"Invalid or escaping manifest path: {rel!r}")
        with path.open("rb") as f:
            actual_sha256 = hashlib.file_digest(f, "sha256").hexdigest()
        actual_size = path.stat().st_size
        results.append(
            {
                "path": rel,
                "bytes": actual_size,
                "sha256": actual_sha256,
                "match": actual_sha256 == str(record.get("sha256", "")).lower()
                and actual_size == record.get("bytes"),
            }
        )

    ok = bool(results) and all(item["match"] for item in results)
    return {
        "saved_file_integrity_ok": ok,
        "exposed_internal_storage_acquisition_complete": bool(
            manifest.get("exposed_internal_storage_acquisition_complete", False)
        ),
        "complete_physical_firmware_backup_verified": False,
        "restorability_verified": bool(manifest.get("restorability_verified", False)),
        "results": results,
    }
