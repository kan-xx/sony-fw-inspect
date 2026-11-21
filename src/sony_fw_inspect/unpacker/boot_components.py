"""Bounds-checked Sony `WBI1` warmboot LZ77 decompressor and CRC-verified CramFS extractor.

Zero third-party `fwtool.py` code is vendored; binary headers (`WBI1` and Linux `cramfs`)
are unpacked directly with strict seek/read bounds and output size ceilings.
"""

from __future__ import annotations

import collections
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import time
from typing import Any, BinaryIO
import zlib

from .partition_carver import clean_component, collision_key, hashes, inventory_export, write_json

DEFAULT_MAX_OUTPUT = 1024**3  # 1 GiB ceiling
WBI_MAGIC = b"WBI1"
WBI_VERSION = 0x20060224
WBI_FLAG_COMPRESSED = 0x1

CRAMFS_MAGIC = b"\x45\x3d\xcd\x28"
CRAMFS_SIGNATURE = b"Compressed ROMFS"
CRAMFS_BLOCK_SIZE = 4096


def _check(ok: object, message: str, deadline: float | None = None) -> None:
    if not ok:
        raise RuntimeError(message)
    if deadline is not None and time.monotonic() > deadline:
        raise RuntimeError("Extraction deadline exceeded")


class BoundedFile:
    """Read-only file wrapper enforcing strict seek/read bounds within the source file."""

    def __init__(self, path: Path) -> None:
        self.file = path.open("rb")
        self.size = path.stat().st_size

    def tell(self) -> int:
        return self.file.tell()

    def seek(self, offset: int, whence: int = 0) -> int:
        pos = (
            offset
            if whence == 0
            else self.tell() + offset
            if whence == 1
            else self.size + offset
        )
        _check(0 <= pos <= self.size, "Seek outside source image bounds")
        return self.file.seek(pos)

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = self.size - self.tell()
        _check(0 <= n <= self.size - self.tell(), "Read outside source image bounds")
        b = self.file.read(n)
        _check(len(b) == n, "Short source read")
        return b

    def close(self) -> None:
        self.file.close()

    def __enter__(self) -> "BoundedFile":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def inflate_bounded(stream: BinaryIO, limit: int, *, deadline: float | None = None) -> bytes:
    """Bounds-checked Sony LZ77 block decompressor (`0x0f` raw and `0xf0` backreference)."""

    def read_exact(n: int) -> bytes:
        _check(n >= 0, "Negative LZ77 read", deadline)
        b = stream.read(n)
        _check(len(b) == n, "Truncated LZ77 block", deadline)
        return b

    kind = read_exact(1)[0]
    if kind == 0x0F:
        read_exact(1)
        length = int.from_bytes(read_exact(2), "little")
        _check(0 < length <= limit, "Raw LZ77 block exceeds declared output", deadline)
        return read_exact(length)

    _check(kind == 0xF0, f"Unsupported LZ77 block type: 0x{kind:02x}", deadline)
    output = bytearray()
    lengths = list(range(3, 17)) + [32, 64]
    while True:
        flags = read_exact(1)[0]
        if flags == 0:
            _check(len(output) + 8 <= limit, "LZ77 output exceeds declared output", deadline)
            output.extend(read_exact(8))
            continue
        for i in range(8):
            if (flags >> i) & 1:
                a, b = read_exact(2)
                length = lengths[a >> 4]
                distance = ((a & 15) << 8) | b
                if distance == 0:
                    _check(len(output) > 0, "Empty LZ77 decoded block", deadline)
                    return bytes(output)
                _check(0 < distance <= len(output), "Invalid LZ77 back reference", deadline)
                _check(len(output) + length <= limit, "LZ77 match exceeds declared output", deadline)
                window = output[-distance:]
                output.extend((window * (length // len(window) + 1))[:length])
            else:
                _check(len(output) < limit, "LZ77 literal exceeds declared output", deadline)
                output.extend(read_exact(1))


@dataclass(frozen=True)
class WbiHeader:
    magic: bytes
    num_sections: int
    flag: int
    resume_vector: int
    version: int
    sector_size: int
    data_size: int
    kernel_start: int
    kernel_size: int
    kernel_checksum: int
    odata_size: int

    STRUCT = struct.Struct("<4s10I")

    @classmethod
    def unpack_from_file(cls, f: BoundedFile, offset: int = 0) -> "WbiHeader":
        f.seek(offset)
        return cls(*cls.STRUCT.unpack(f.read(cls.STRUCT.size)))


@dataclass(frozen=True)
class WbiSectionHeader:
    addr: int
    size: int
    checksum: int
    flag: int
    osize: int
    virt: int
    pad: int
    meta_checksum: int

    STRUCT = struct.Struct("<8I")

    @classmethod
    def unpack_from_file(cls, f: BoundedFile, offset: int) -> "WbiSectionHeader":
        f.seek(offset)
        return cls(*cls.STRUCT.unpack(f.read(cls.STRUCT.size)))


def unpack_wbi_image(
    source_path: Path,
    output_dir: Path,
    *,
    max_output: int = DEFAULT_MAX_OUTPUT,
    timeout_sec: float = 300.0,
) -> dict[str, Any]:
    """Validate and decompress all sections of a Sony `WBI1` warmboot partition (`nflasha5`)."""
    deadline = time.monotonic() + timeout_sec
    source_path = source_path.resolve(strict=True)
    source_hashes = hashes(source_path)
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    sections_dir = output_dir / "sections"
    sections_dir.mkdir()

    with BoundedFile(source_path) as f:
        h = WbiHeader.unpack_from_file(f, 0)
        _check(
            h.magic == WBI_MAGIC and h.version == WBI_VERSION and (h.flag & WBI_FLAG_COMPRESSED),
            "Unsupported WBI header/version/compression",
            deadline,
        )
        _check(h.sector_size == 512 and 0 < h.num_sections <= 10000, "Invalid WBI geometry", deadline)
        _check(
            0 < h.odata_size <= max_output and 0 < h.data_size <= f.size,
            "WBI declared sizes exceed bounds",
            deadline,
        )

        header_bytes = h.sector_size
        while header_bytes + h.sector_size <= f.size:
            f.seek(header_bytes)
            sec_probe = f.read(h.sector_size)
            if sec_probe not in (bytes(h.sector_size), b"\xff" * h.sector_size):
                break
            header_bytes += h.sector_size

        table_offset = header_bytes + h.data_size
        _check(
            table_offset + h.num_sections * WbiSectionHeader.STRUCT.size <= f.size,
            "WBI section table exceeds source image",
            deadline,
        )
        sections = [
            WbiSectionHeader.unpack_from_file(f, table_offset + i * WbiSectionHeader.STRUCT.size)
            for i in range(h.num_sections)
        ]
        _check(
            all(s.flag == 0 and s.size > 0 and s.osize > 0 for s in sections),
            "Unsupported/invalid WBI section flags or sizes",
            deadline,
        )
        _check(
            sum(s.size for s in sections) == h.data_size
            and sum(s.osize for s in sections) == h.odata_size,
            "WBI section totals mismatch header",
            deadline,
        )
        _check(
            all(s.addr + s.osize <= 2**32 and s.virt + s.osize <= 2**32 for s in sections),
            "WBI address arithmetic overflow",
            deadline,
        )

        header_doc = {
            "magic": h.magic.decode("ascii"),
            "num_sections": h.num_sections,
            "flag": h.flag,
            "resume_vector": hex(h.resume_vector),
            "version": hex(h.version),
            "sector_size": h.sector_size,
            "data_size": h.data_size,
            "odata_size": h.odata_size,
            "header_bytes": header_bytes,
            "section_table_offset": table_offset,
            "checksums_validated": False,
        }
        write_json(output_dir / "header.json", header_doc)

        rows: list[dict[str, Any]] = []
        comp_offset = header_bytes
        total_decoded = 0
        for idx, sec in enumerate(sections):
            f.seek(comp_offset)
            comp_stream = io.BytesIO(f.read(sec.size))
            remaining = sec.osize
            lz_blocks = 0
            target = sections_dir / f"section-{idx:04d}-phys-{sec.addr:08x}.bin"
            with target.open("xb") as out_f:
                while remaining > 0:
                    dec = inflate_bounded(comp_stream, remaining, deadline=deadline)
                    out_f.write(dec)
                    remaining -= len(dec)
                    lz_blocks += 1
            target.chmod(0o600)
            _check(remaining == 0 and target.stat().st_size == sec.osize, "WBI decoded section size mismatch", deadline)
            total_decoded += sec.osize
            _check(total_decoded <= max_output, "WBI output budget exceeded", deadline)
            rows.append(
                {
                    "section": idx,
                    "source_compressed_offset_bytes": comp_offset,
                    "compressed_bytes": sec.size,
                    "physical_address": hex(sec.addr),
                    "virtual_address": hex(sec.virt),
                    "bytes": sec.osize,
                    "path": str(target.relative_to(output_dir)),
                    **hashes(target),
                    "lz77_blocks": lz_blocks,
                    "declared_section_checksum": sec.checksum,
                    "declared_meta_checksum": sec.meta_checksum,
                }
            )
            comp_offset += sec.size

    _check(len(rows) == h.num_sections and total_decoded == h.odata_size, "Incomplete WBI export", deadline)
    with (output_dir / "warmboot-inventory.jsonl").open("x", encoding="utf-8") as inv:
        for row in rows:
            inv.write(json.dumps(row) + "\n")
    _check(hashes(source_path) == source_hashes, "WBI source image mutated during extraction", deadline)
    return {
        "status": "complete",
        "sections": len(rows),
        "decompressed_bytes": total_decoded,
        "source_sha256_unchanged": True,
    }


@dataclass(frozen=True)
class CramfsSuper:
    magic: bytes
    size: int
    flags: int
    future: int
    signature: bytes
    crc: int
    edition: int
    blocks: int
    files: int
    name: bytes

    STRUCT = struct.Struct("<4s3I16s4I16s")

    @classmethod
    def unpack_from_file(cls, f: BoundedFile) -> "CramfsSuper":
        f.seek(0)
        return cls(*cls.STRUCT.unpack(f.read(cls.STRUCT.size)))


def _bounded_zlib_block(data: bytes, deadline: float | None = None) -> bytes:
    obj = zlib.decompressobj()
    out = obj.decompress(data, CRAMFS_BLOCK_SIZE + 1)
    _check(
        len(out) <= CRAMFS_BLOCK_SIZE and obj.eof and not obj.unconsumed_tail,
        "CramFS zlib block exceeds 4096 bytes or has unconsumed/truncated stream",
        deadline,
    )
    return out


def unpack_cramfs_image(
    source_path: Path,
    output_dir: Path,
    *,
    max_output: int = DEFAULT_MAX_OUTPUT,
    timeout_sec: float = 300.0,
) -> dict[str, Any]:
    """Verify full-image CRC32 and extract a Linux `cramfs` image (`initrd.img`) read-only."""
    deadline = time.monotonic() + timeout_sec
    source_path = source_path.resolve(strict=True)
    source_hash = hashes(source_path)
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    export_dir = output_dir / "export"
    export_dir.mkdir(mode=0o700)

    with BoundedFile(source_path) as f:
        sup = CramfsSuper.unpack_from_file(f)
        _check(
            sup.magic == CRAMFS_MAGIC and sup.signature == CRAMFS_SIGNATURE,
            "Invalid CramFS magic or signature",
            deadline,
        )
        _check(sup.size == f.size and 0 < sup.files <= 100000, "CramFS declared geometry mismatch", deadline)
        _check(not (sup.flags & 0x10000000), "LZO CramFS is unsupported", deadline)
        use_lz77 = bool((sup.flags & 0x20000000) or (sup.flags & 0x800))

        # Full-image IEEE CRC32 check with bytes 32..36 zeroed
        f.seek(0)
        head32 = f.read(32)
        f.seek(36)
        crc = zlib.crc32(head32)
        crc = zlib.crc32(b"\x00\x00\x00\x00", crc)
        rem_crc = f.size - 36
        while rem_crc > 0:
            chunk = f.read(min(1024 * 1024, rem_crc))
            crc = zlib.crc32(chunk, crc)
            rem_crc -= len(chunk)
        _check((crc & 0xFFFFFFFF) == sup.crc, "CramFS superblock CRC32 mismatch", deadline)

        inode_struct = struct.Struct("<HHII")
        entries: list[tuple[str, int, int, int, int, int]] = []

        def walk_inodes(inode_off: int, prefix: str, depth: int = 0) -> int:
            _check(depth < 128 and len(entries) < sup.files + 1, "CramFS tree exceeds header count", deadline)
            f.seek(inode_off)
            mode, uid, size_gid, namelen_offset = inode_struct.unpack(f.read(inode_struct.size))
            size = size_gid & 0xFFFFFF
            gid = size_gid >> 24
            namelen = (namelen_offset & 0x3F) * 4
            data_offset = (namelen_offset >> 6) * 4
            name_raw = f.read(namelen)
            next_entry_off = f.tell()
            name = name_raw.rstrip(b"\x00").decode("ascii")
            full_path = (prefix + "/" + name).lstrip("/") if prefix or name else ""
            entries.append((full_path, mode, uid, gid, size, data_offset))
            if stat.S_ISDIR(mode) and size > 0:
                child_off = data_offset
                dir_end = data_offset + size
                _check(dir_end <= f.size, "CramFS directory table exceeds image", deadline)
                while child_off < dir_end:
                    child_off = walk_inodes(child_off, full_path, depth + 1)
                _check(child_off == dir_end, "Misaligned CramFS directory boundary", deadline)
            return next_entry_off

        walk_inodes(CramfsSuper.STRUCT.size, "")
        _check(len(entries) == sup.files, "CramFS inode count disagrees with superblock", deadline)

        def decode_inode_data(data_offset: int, byte_size: int) -> bytes:
            if byte_size == 0:
                return b""
            n_blocks = (byte_size - 1) // CRAMFS_BLOCK_SIZE + 1
            f.seek(data_offset)
            ptrs = [data_offset + n_blocks * 4] + [
                struct.unpack("<I", f.read(4))[0] for _ in range(n_blocks)
            ]
            out = bytearray()
            for idx in range(n_blocks):
                lo, hi = ptrs[idx], ptrs[idx + 1]
                _check(0 <= lo <= hi <= f.size, "Invalid CramFS block pointer", deadline)
                f.seek(lo)
                comp = f.read(hi - lo)
                expected_block = min(CRAMFS_BLOCK_SIZE, byte_size - len(out))
                if use_lz77:
                    dec = inflate_bounded(io.BytesIO(comp), expected_block, deadline=deadline)
                else:
                    dec = _bounded_zlib_block(comp, deadline=deadline)
                _check(len(dec) == expected_block, "CramFS decompressed block size mismatch", deadline)
                out.extend(dec)
            return bytes(out)

        pathmap: dict[str, str] = {"": ""}
        sibling_names: dict[str, set[str]] = collections.defaultdict(set)
        rows: list[dict[str, Any]] = []
        links: list[tuple[Path, str]] = []
        written = 0

        for idx, (source_rel, mode, uid, gid, size, data_offset) in enumerate(entries):
            if source_rel == "":
                _check(stat.S_ISDIR(mode), "CramFS root is not a directory", deadline)
                rows.append(
                    {"path": ".", "host_path": ".", "type": "directory", "mode": oct(mode), "uid": uid, "gid": gid, "bytes": 0}
                )
                continue
            components = PurePosixPath(source_rel).parts
            _check(all(p not in (".", "..") for p in components), "Unsafe CramFS path", deadline)
            _check(source_rel not in pathmap, "Duplicate CramFS path", deadline)
            parent = str(PurePosixPath(source_rel).parent)
            if parent == ".":
                parent = ""
            _check(parent in pathmap, "CramFS parent missing", deadline)
            leaf = components[-1]
            clean_component(leaf)
            alias = leaf
            if collision_key(alias) in sibling_names[parent]:
                alias = f"__node_{idx}_{hashlib.sha256(leaf.encode('utf-8')).hexdigest()[:12]}"
            sibling_names[parent].add(collision_key(alias))
            host_rel = str(PurePosixPath(pathmap[parent]) / alias) if pathmap[parent] else alias
            pathmap[source_rel] = host_rel
            target = export_dir / host_rel

            kind = (
                "directory"
                if stat.S_ISDIR(mode)
                else "file"
                if stat.S_ISREG(mode)
                else "symlink"
                if stat.S_ISLNK(mode)
                else "special"
            )
            row: dict[str, Any] = {
                "path": source_rel,
                "host_path": host_rel,
                "type": kind,
                "mode": oct(mode),
                "uid": uid,
                "gid": gid,
                "bytes": 0 if kind == "directory" else size,
            }
            rows.append(row)

            if kind == "directory":
                target.mkdir(mode=0o700)
            elif kind == "file":
                _check(written + size <= max_output, "CramFS written output exceeds budget", deadline)
                payload = decode_inode_data(data_offset, size)
                with target.open("xb") as out_f:
                    out_f.write(payload)
                target.chmod(0o600)
                written += size
            elif kind == "symlink":
                _check(size <= 65536, "Oversize CramFS symlink", deadline)
                link_bytes = decode_inode_data(data_offset, size)
                _check(b"\x00" not in link_bytes, "NUL byte in CramFS symlink target", deadline)
                link_target = os.fsdecode(link_bytes)
                row["link_target"] = link_target
                links.append((target, link_target))

        for target, link_target in links:
            os.symlink(link_target, target)

    write_json(output_dir / "source-directory-inventory.json", rows)
    with (
        (output_dir / "file-inventory.jsonl").open("x", encoding="utf-8") as files_log,
        (output_dir / "elf-inventory.jsonl").open("x", encoding="utf-8") as elfs_log,
    ):
        counts = inventory_export(export_dir, "initrd-cramfs", files_log, elfs_log, {v: k for k, v in pathmap.items() if v})

    _check(hashes(source_path) == source_hash, "CramFS source changed during extraction", deadline)
    result = {
        "status": "complete",
        "source_bytes": source_path.stat().st_size,
        **source_hash,
        "header_files": sup.files,
        "header_flags": sup.flags,
        "source_crc_verified": True,
        "inventory": counts,
        "written_bytes": written,
        "source_hash_unchanged": True,
        "source_execution": False,
        "os_mount": False,
    }
    write_json(output_dir / "report.json", result)
    return result
