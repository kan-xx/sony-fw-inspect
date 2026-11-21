"""Quiescent live-partition diff reconciler.

Preserves the original `nflasha-full.bin` untouched, narrows mismatched 128-chunk
ranges to exact differing 512 KiB chunks (e.g., live-mounted VFAT `nflasha2` chunks 16..55),
verifies consecutive camera MD5 stability, and selectively updates a separate
`nflasha-reconciled.bin` candidate via volatile `/tmp_bt`.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
from typing import Any, Callable
import uuid

from .nand_dumper import CHUNK_BYTES, ExactSizeBuffer


def reconcile_differing_chunks(
    original_image: Path,
    candidate_image: Path,
    range_results: list[dict[str, Any]],
    cam: Any,
    term_read_fn: Callable[[str], bytes],
    *,
    device_path: str = "/dev/nflasha",
    chunk_bytes: int = CHUNK_BYTES,
    stage_prefix: str = "fw-reconcile",
) -> dict[str, Any]:
    """Locate differing chunks within mismatched ranges and re-acquire them when quiescent."""
    original_image = original_image.resolve(strict=True)
    candidate_image = candidate_image.resolve()
    if candidate_image.exists():
        raise FileExistsError(f"Refusing to overwrite existing candidate: {candidate_image}")

    def checked_camera_md5(index: int) -> str:
        cmd = (
            f"I={index}; B={chunk_bytes}; C=1; echo ACQ_RANGE=$I,$C,$B; "
            f"busybox dd if={shlex.quote(device_path)} bs=$B skip=$I count=$C | busybox md5sum"
        )
        text = term_read_fn(cmd).replace(b"\r", b"")
        if f"\nACQ_RANGE={index},1,{chunk_bytes}\n".encode("ascii") not in text:
            raise RuntimeError(f"Missing echo during chunk {index} MD5 check")
        if b"\n1+0 records in\n" not in text or b"\n1+0 records out\n" not in text:
            raise RuntimeError(f"Incomplete dd records during chunk {index} MD5 check")
        digests = re.findall(rb"\n([0-9a-f]{32})\s+-\n", text)
        if len(digests) != 1:
            raise RuntimeError(f"Missing MD5 output for chunk {index}")
        return digests[0].decode("ascii")

    changed_chunks: list[dict[str, Any]] = []
    with original_image.open("rb") as source:
        for region in range_results:
            if region.get("match"):
                continue
            start_idx = int(region["start_chunk"])
            count = int(region["chunks"])
            for index in range(start_idx, start_idx + count):
                source.seek(index * chunk_bytes)
                data = source.read(chunk_bytes)
                if len(data) != chunk_bytes:
                    raise RuntimeError(f"Short read on original image chunk {index}")
                orig_md5 = hashlib.md5(data).hexdigest()
                obs_md5 = checked_camera_md5(index)
                if orig_md5 != obs_md5:
                    repeat_md5 = checked_camera_md5(index)
                    if repeat_md5 != obs_md5:
                        raise RuntimeError(f"Live chunk {index} is still mutating; wait for quiescence")
                    changed_chunks.append(
                        {
                            "index": index,
                            "offset_bytes": index * chunk_bytes,
                            "original_md5": orig_md5,
                            "camera_md5": obs_md5,
                            "camera_md5_repeat": repeat_md5,
                            "source_repeat_stable": True,
                        }
                    )

    if not changed_chunks:
        raise RuntimeError("No differing chunks located in mismatched ranges")

    shutil.copyfile(original_image, candidate_image)
    recon_dir = f"/tmp_bt/{stage_prefix}-{uuid.uuid4().hex[:12]}"
    recon_chunk = f"{recon_dir}/chunk.bin"

    create_reply = term_read_fn(
        "busybox grep '^none /tmp_bt tmpfs ' /proc/mounts >/dev/null && "
        f"test ! -e {shlex.quote(recon_dir)} && mkdir {shlex.quote(recon_dir)} && echo RECON_STAGE_READY"
    ).replace(b"\r", b"")
    if b"\nRECON_STAGE_READY\n" not in create_reply:
        raise RuntimeError("Failed to create /tmp_bt reconciliation staging directory")

    replacements: list[dict[str, Any]] = []
    stage_removed = False
    try:
        with candidate_image.open("r+b") as target:
            for diff in changed_chunks:
                idx = int(diff["index"])
                cmd = (
                    f"I={idx}; B={chunk_bytes}; C=1; T={shlex.quote(recon_chunk)}; "
                    f"echo ACQ_RANGE=$I,$C,$B; busybox dd if={shlex.quote(device_path)} of=$T bs=$B skip=$I count=$C && "
                    "busybox sha1sum $T && busybox wc -c $T"
                )
                text = term_read_fn(cmd).replace(b"\r", b"")
                escaped = re.escape(recon_chunk.encode("ascii"))
                sha1s = re.findall(rb"\n([0-9a-f]{40})\s+" + escaped + rb"\n", text)
                sizes = re.findall(rb"\n\s*([0-9]+)\s+" + escaped + rb"\n", text)
                if len(sha1s) != 1 or len(sizes) != 1 or int(sizes[0]) != chunk_bytes:
                    raise RuntimeError(f"Chunk {idx} re-acquisition digest/size check failed")
                buf = ExactSizeBuffer(chunk_bytes)
                cam.readFile(recon_chunk, buf)
                data = buf.getvalue()
                if len(data) != chunk_bytes or hashlib.sha1(data).hexdigest() != sha1s[0].decode("ascii"):
                    raise RuntimeError(f"Chunk {idx} camera/host SHA-1 mismatch during reconciliation")
                target.seek(idx * chunk_bytes)
                target.write(data)
                replacements.append(
                    {
                        **diff,
                        "replacement_sha256": hashlib.sha256(data).hexdigest(),
                        "replacement_md5": hashlib.md5(data).hexdigest(),
                        "replacement_camera_sha1": sha1s[0].decode("ascii"),
                        "camera_host_sha1_match": True,
                    }
                )
            target.flush()
            os.fsync(target.fileno())
    finally:
        rm_reply = term_read_fn(
            f"rm -f {shlex.quote(recon_chunk)} && rmdir {shlex.quote(recon_dir)} && echo RECON_STAGE_REMOVED"
        ).replace(b"\r", b"")
        stage_removed = b"\nRECON_STAGE_REMOVED\n" in rm_reply

    if not stage_removed:
        raise RuntimeError("Failed to confirm cleanup of /tmp_bt reconciliation stage")

    with candidate_image.open("rb") as handle:
        cand_sha256 = hashlib.file_digest(handle, "sha256").hexdigest()
    with candidate_image.open("rb") as handle:
        cand_md5 = hashlib.file_digest(handle, "md5").hexdigest()

    return {
        "original_retained": original_image.name,
        "candidate": candidate_image.name,
        "replacements": replacements,
        "replaced_chunk_count": len(replacements),
        "sha256": cand_sha256,
        "md5": cand_md5,
        "ram_stage_removed": stage_removed,
    }
