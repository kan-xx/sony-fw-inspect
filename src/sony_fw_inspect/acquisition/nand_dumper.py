"""Non-destructive `/tmp_bt` 512 KiB windowed logical NAND dumper.

On Sony ILCE-7RM3, `/tmp` is persistent VFAT flash (`/dev/nflasha2`) and is NEVER used.
All read windows are staged exclusively in a unique directory inside volatile `/tmp_bt` (`tmpfs`),
pulled via SENSER `readFile`, SHA-1 cross-checked against camera `busybox sha1sum`,
and fsync-verified on disk with resumable JSONL chunk ledgers.
"""

from __future__ import annotations

import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import time
from typing import Any, Callable
import uuid

CHUNK_BYTES = 512 * 1024
DEFAULT_DEVICE_BYTES: dict[str, int] = {
    "nflasha": 3817472 * 512,   # 1,954,545,664 B (3728 x 512 KiB)
    "nflashaB0": 8192 * 512,    # 4,194,304 B
    "nflashaB1": 8192 * 512,    # 4,194,304 B
}


class ExactSizeBuffer(io.BytesIO):
    """BytesIO sink that rejects transfers exceeding the expected chunk ceiling."""

    def __init__(self, maximum: int) -> None:
        super().__init__()
        self.maximum = maximum

    def write(self, data: bytes | bytearray | memoryview) -> int:  # type: ignore[override]
        if self.tell() + len(data) > self.maximum:
            raise RuntimeError("Camera returned more bytes than the selected chunk ceiling")
        return super().write(data)


class LogicalNandDumper:
    """Windowed logical NAND image collector operating over an authenticated SENSER session."""

    def __init__(
        self,
        cam: Any,
        term_read_fn: Callable[..., bytes],
        output_dir: Path,
        *,
        recover_terminal_fn: Callable[[], None] | None = None,
        device_bytes: dict[str, int] | None = None,
        chunk_bytes: int = CHUNK_BYTES,
        stage_prefix: str = "fw-acq",
    ) -> None:
        self.cam = cam
        self.term_read = term_read_fn
        self.output_dir = output_dir.resolve()
        self.recover_terminal = recover_terminal_fn
        self.device_bytes = dict(device_bytes or DEFAULT_DEVICE_BYTES)
        self.chunk_bytes = chunk_bytes
        nonce = uuid.uuid4().hex[:12]
        self.ram_dir = f"/tmp_bt/{stage_prefix}-{nonce}"
        self.ram_chunk = f"{self.ram_dir}/chunk.bin"
        if not re.fullmatch(r"/tmp_bt/[a-z0-9-]+-[0-9a-f]{12}/chunk\.bin", self.ram_chunk):
            raise ValueError(f"Unsafe RAM chunk staging path: {self.ram_chunk}")
        self.stage_created = False
        self.stage_removed = False

    def create_ram_stage(self) -> None:
        cmd = (
            "cat /proc/mounts; busybox grep '^none /tmp_bt tmpfs ' /proc/mounts >/dev/null && "
            f"test ! -e {shlex.quote(self.ram_dir)} && mkdir {shlex.quote(self.ram_dir)} && echo ACQ_STAGE_READY"
        )
        result = self.term_read(cmd).replace(b"\r", b"")
        if b"none /tmp_bt tmpfs " not in result:
            raise RuntimeError("Refusing to stage: /tmp_bt is not mounted as volatile tmpfs")
        if b"\nACQ_STAGE_READY\n" not in result:
            raise RuntimeError("Unique /tmp_bt RAM staging directory was not created")
        self.stage_created = True

    def remove_ram_stage(self) -> bool:
        if self.stage_removed or not self.stage_created:
            return self.stage_removed
        cmd = f"rm -f {shlex.quote(self.ram_chunk)} && rmdir {shlex.quote(self.ram_dir)} && echo ACQ_STAGE_REMOVED"
        result = self.term_read(cmd).replace(b"\r", b"")
        self.stage_removed = b"\nACQ_STAGE_REMOVED\n" in result
        return self.stage_removed

    def dump_image(self, device_name: str, label: str, *, resume: bool = False) -> dict[str, Any]:
        if device_name not in self.device_bytes:
            raise ValueError(f"Device {device_name!r} outside internal-storage whitelist")
        total = self.device_bytes[device_name]
        if total % self.chunk_bytes != 0:
            raise ValueError("Device byte length must be an exact multiple of chunk_bytes")
        if not self.stage_created:
            self.create_ram_stage()

        self.output_dir.mkdir(parents=True, exist_ok=True)
        source = f"/dev/{device_name}"
        destination = self.output_dir / f"{label}.bin"
        partial = self.output_dir / f"{label}.partial"
        ledger_path = self.output_dir / f"{label}-chunks.jsonl"
        digest = hashlib.sha256()
        started = time.monotonic()
        chunks = total // self.chunk_bytes
        resume_index = 0

        if resume:
            records = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
            if partial.stat().st_size != len(records) * self.chunk_bytes:
                raise RuntimeError("Partial image and chunk ledger lengths disagree")
            with partial.open("rb") as previous:
                for index, record in enumerate(records):
                    data = previous.read(self.chunk_bytes)
                    if (
                        record["index"] != index
                        or record["offset"] != index * self.chunk_bytes
                        or len(data) != self.chunk_bytes
                        or record["bytes"] != self.chunk_bytes
                        or hashlib.sha256(data).hexdigest() != record["host_sha256"]
                    ):
                        raise RuntimeError(f"Retained chunk {index} failed resume validation")
                    digest.update(data)
            resume_index = len(records)

        with (
            partial.open("ab" if resume else "xb") as output,
            ledger_path.open("a" if resume else "x", encoding="utf-8") as ledger,
        ):
            for index in range(resume_index, chunks):
                cmd = (
                    f"T={shlex.quote(self.ram_chunk)}; "
                    f"busybox dd if={shlex.quote(source)} of=$T bs={self.chunk_bytes} skip={index} count=1 && "
                    "busybox sha1sum $T && busybox wc -c $T && echo ACQ_COPY_OK"
                )
                transcript: bytes | None = None
                for attempt in range(3):
                    try:
                        transcript = self.term_read(cmd)
                        break
                    except TimeoutError:
                        if attempt == 2 or self.recover_terminal is None:
                            raise
                        self.recover_terminal()
                assert transcript is not None
                normalized = transcript.replace(b"\r", b"")
                if b"\nACQ_COPY_OK\n" not in normalized:
                    raise RuntimeError(f"Camera dd or checksum failed on chunk {index}")

                escaped = re.escape(self.ram_chunk.encode("ascii"))
                sha1_match = re.search(rb"\n([0-9a-f]{40})\s+" + escaped + rb"\n", normalized)
                len_match = re.search(rb"\n\s*([0-9]+)\s+" + escaped + rb"\n", normalized)
                if not sha1_match or not len_match or int(len_match[1]) != self.chunk_bytes:
                    raise RuntimeError(f"Camera chunk digest/length missing on chunk {index}")

                buf = ExactSizeBuffer(self.chunk_bytes)
                self.cam.readFile(self.ram_chunk, buf)
                data = buf.getvalue()
                if len(data) != self.chunk_bytes:
                    raise RuntimeError(f"Short chunk read from camera on chunk {index}")
                host_sha1 = hashlib.sha1(data).hexdigest()
                if host_sha1 != sha1_match[1].decode("ascii"):
                    raise RuntimeError(f"Camera/host SHA1 mismatch on chunk {index}")

                output.write(data)
                digest.update(data)
                ledger.write(
                    json.dumps(
                        {
                            "index": index,
                            "offset": index * self.chunk_bytes,
                            "bytes": len(data),
                            "camera_sha1": host_sha1,
                            "host_sha256": hashlib.sha256(data).hexdigest(),
                        }
                    )
                    + "\n"
                )
                if (index + 1) % 32 == 0 or index + 1 == chunks:
                    output.flush()
                    ledger.flush()
                    os.fsync(output.fileno())

        if partial.stat().st_size != total:
            raise RuntimeError("Completed partial image has unexpected byte length")

        readback = hashlib.sha256()
        with partial.open("rb") as handle:
            for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                readback.update(block)
        if readback.digest() != digest.digest():
            raise RuntimeError("Saved host image readback SHA-256 mismatch")
        if destination.exists():
            raise RuntimeError(f"Refusing to overwrite existing image: {destination}")
        os.link(partial, destination)
        partial.unlink()

        return {
            "path": destination.name,
            "source": source,
            "bytes": total,
            "sha256": digest.hexdigest(),
            "chunk_bytes": self.chunk_bytes,
            "chunks": chunks,
            "resumed_from_chunk": resume_index,
            "all_chunk_camera_host_sha1_match": True,
            "host_readback_sha256_match": True,
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "chunk_ledger": ledger_path.name,
            "completed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "snapshot_consistency": "live mounted storage; not an atomic snapshot",
        }
