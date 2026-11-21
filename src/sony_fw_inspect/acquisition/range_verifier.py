"""Independent bounded 128-chunk camera-side MD5 range verifier for logical NAND dumps."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shlex
from typing import Any, Callable

from .nand_dumper import CHUNK_BYTES


def verify_image_ranges(
    image_path: Path,
    term_read_fn: Callable[[str], bytes],
    *,
    device_path: str = "/dev/nflasha",
    chunk_bytes: int = CHUNK_BYTES,
    range_chunks: int = 128,
    output_json: Path | None = None,
) -> list[dict[str, Any]]:
    """Compare a saved logical image against live camera `dd | md5sum` across 128-chunk windows."""
    image_path = image_path.resolve(strict=True)
    total_bytes = image_path.stat().st_size
    if total_bytes % chunk_bytes != 0:
        raise ValueError("Image size is not an exact multiple of chunk_bytes")
    total_chunks = total_bytes // chunk_bytes

    results: list[dict[str, Any]] = []
    with image_path.open("rb") as image:
        for start in range(0, total_chunks, range_chunks):
            count = min(range_chunks, total_chunks - start)
            image.seek(start * chunk_bytes)
            data = image.read(count * chunk_bytes)
            if len(data) != count * chunk_bytes:
                raise RuntimeError("Short host read during range verification")
            host_md5 = hashlib.md5(data).hexdigest()

            cmd = (
                f"I={start}; C={count}; echo ACQ_RANGE=$I,$C; "
                f"busybox dd if={shlex.quote(device_path)} bs={chunk_bytes} skip=$I count=$C | busybox md5sum"
            )
            raw_text = term_read_fn(cmd).replace(b"\r", b"")
            expected_echo = f"\nACQ_RANGE={start},{count}\n".encode("ascii")
            if expected_echo not in raw_text:
                raise RuntimeError(f"Missing range echo for start_chunk={start}")
            for direction in ("in", "out"):
                rec = f"\n{count}+0 records {direction}\n".encode("ascii")
                if rec not in raw_text:
                    raise RuntimeError(f"Missing dd record count ({direction}) for start_chunk={start}")

            digests = re.findall(rb"\n([0-9a-f]{32})\s+-\n", raw_text)
            if len(digests) != 1:
                raise RuntimeError(f"Expected exactly 1 MD5 digest for start_chunk={start}")
            camera_md5 = digests[0].decode("ascii")

            row = {
                "start_chunk": start,
                "chunks": count,
                "offset_bytes": start * chunk_bytes,
                "bytes": count * chunk_bytes,
                "host_md5": host_md5,
                "camera_md5": camera_md5,
                "match": host_md5 == camera_md5,
            }
            results.append(row)
            if output_json is not None:
                output_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return results
