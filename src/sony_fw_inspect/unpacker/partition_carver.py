"""Carve a verified logical storage acquisition and export filesystems read-only.

Never mounts an image via the host OS kernel and never executes extracted binaries.
Resolves macOS APFS case-insensitive filename collisions (such as Linux netfilter
`libxt_DSCP.so` vs `libxt_dscp.so`) via deterministic `__inode_<ino>_<sha12>` aliases
recorded in `host-path-mapping.json`.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
from typing import Any
import unicodedata
import uuid

CHUNK = 4 * 1024 * 1024
LIMITATIONS = [
    "Logical exposed internal block devices only; physical NAND/OOB/OTP/RPMB/hidden storage coverage is unverified.",
    "Source was acquired from live mounted storage and is not an atomic filesystem snapshot.",
    "complete_firmware_backup remains false; restorability_verified remains false.",
    "Raw partition slices are authoritative. Filesystem exports omit device nodes, sockets and FIFOs, do not preserve hardlink identity, and may omit filesystem metadata.",
    "No source or exported binary is executed or mounted. Exported regular files have execute permission removed; symlinks are inventoried without following them.",
]


def require(condition: object, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as f:
        json.dump(value, f, indent=2, ensure_ascii=True)
        f.write("\n")


def hashes(path: Path) -> dict[str, str]:
    sha256, sha1 = hashlib.sha256(), hashlib.sha1()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(CHUNK), b""):
            sha256.update(b)
            sha1.update(b)
    return {"sha256": sha256.hexdigest(), "sha1": sha1.hexdigest()}


def regular_input(path: Path) -> Path:
    path = path.resolve(strict=True)
    require(stat.S_ISREG(path.stat().st_mode), f"Not a regular input file: {path}")
    return path


def no_symlink_ancestors(path: Path) -> None:
    for p in [path, *path.parents]:
        require(not p.is_symlink(), f"Symlink output ancestor is forbidden: {p}")


def integer(value: Any, label: str, minimum: int = 0) -> int:
    require(type(value) is int and value >= minimum, f"Invalid integer {label}")
    return value


def clean_component(name: str) -> str:
    require(isinstance(name, str) and name not in ("", ".", ".."), "Invalid filesystem name")
    require("/" not in name and "\0" not in name, f"Unsafe filesystem name: {name!r}")
    return name


def collision_key(name: str) -> str:
    return unicodedata.normalize("NFD", name).casefold()


def format_header(data: bytes) -> dict[str, Any]:
    if len(data) >= 2048 and data[1080:1082] == b"\x53\xef":
        compat, incompat, rocompat = struct.unpack_from("<III", data, 1116)
        kind = (
            "ext4"
            if incompat & (0x40 | 0x80 | 0x4000 | 0x8000)
            else "ext3"
            if compat & 4
            else "ext2"
        )
        return {
            "format": kind,
            "family": "ext",
            "feature_compat": compat,
            "feature_incompat": incompat,
            "feature_ro_compat": rocompat,
        }
    if data.startswith(b"WBI1"):
        return {"format": "sony-wbi1", "family": "warm-boot"}
    if len(data) >= 64 and data[:4] == b"\x45\x3d\xcd\x28" and data[16:32] == b"Compressed ROMFS":
        return {"format": "cramfs", "family": "cramfs"}
    signatures = [
        (b"\x7fELF", "elf"),
        (b"\x1f\x8b", "gzip"),
        (b"\xfd7zXZ\0", "xz"),
        (b"hsqs", "squashfs"),
        (b"sqsh", "squashfs-big-endian"),
        (b"UBI#", "ubi"),
        (b"\x31\x18\x10\x06", "ubifs"),
        (b"\x27\x05\x19\x56", "u-boot-uimage"),
        (b"ANDROID!", "android-boot"),
        (b"\x3a\xff\x26\xed", "android-sparse"),
        (b"PK\x03\x04", "zip"),
    ]
    for magic, name in signatures:
        if data.startswith(magic):
            return {"format": name}
    if len(data) >= 512 and data[510:512] == b"\x55\xaa":
        bps = struct.unpack_from("<H", data, 11)[0]
        spc = data[13]
        reserved = struct.unpack_from("<H", data, 14)[0]
        fats = data[16]
        roots = struct.unpack_from("<H", data, 17)[0]
        if (
            bps in (512, 1024, 2048, 4096)
            and spc
            and not (spc & (spc - 1))
            and reserved
            and fats
        ):
            total = struct.unpack_from("<H", data, 19)[0] or struct.unpack_from("<I", data, 32)[0]
            fatsecs = struct.unpack_from("<H", data, 22)[0] or struct.unpack_from("<I", data, 36)[0]
            clusters = (total - reserved - fats * fatsecs - (roots * 32 + bps - 1) // bps) // spc
            if total and fatsecs and clusters > 0:
                kind = "fat12" if clusters < 4085 else "fat16" if clusters < 65525 else "fat32"
                return {"format": kind, "family": "fat", "bytes_per_sector": bps, "clusters": clusters}
        # Check for MBR partition table with non-BPB sector 0
        entries = []
        for idx in range(4):
            entry = data[446 + 16 * idx : 462 + 16 * idx]
            if entry[4] != 0:
                start_lba, sectors = struct.unpack_from("<II", entry, 8)
                if start_lba > 0 and sectors > 0:
                    entries.append(idx)
        if entries:
            return {"format": "mbr", "family": "partition-table"}
    return {"format": "unknown"}


class ExtPreflight:
    """Read-only classic ext2/3 block-map parser, collision detector, and content reader."""

    def __init__(self, path: Path) -> None:
        self.f = path.open("rb")
        self.size = path.stat().st_size
        s = self.read(1024, 1024)
        require(s[56:58] == b"\x53\xef", "Not an ext filesystem")
        self.bs = 1024 << struct.unpack_from("<I", s, 24)[0]
        require(self.bs in (1024, 2048, 4096), "Unsupported ext block size")
        self.inodes = struct.unpack_from("<I", s, 0)[0]
        self.ipg = struct.unpack_from("<I", s, 40)[0]
        self.isize = struct.unpack_from("<H", s, 88)[0] or 128
        self.incompat = struct.unpack_from("<I", s, 96)[0]
        require(
            not (self.incompat & ~0x2),
            "Ext preflight only admits classic ext2/3 block maps (filetype flag only)",
        )
        require(self.ipg > 0 and 128 <= self.isize <= self.bs, "Invalid ext inode geometry")
        first = struct.unpack_from("<I", s, 20)[0]
        self.gdt = (first + 1) * self.bs
        self.seen_dirs: set[int] = set()
        self.entries: list[dict[str, Any]] = []
        self.aliases: list[dict[str, Any]] = []

    def close(self) -> None:
        self.f.close()

    def read(self, offset: int, count: int) -> bytes:
        require(0 <= offset <= self.size and 0 <= count <= self.size - offset, "Ext read exceeds partition")
        self.f.seek(offset)
        b = self.f.read(count)
        require(len(b) == count, "Short ext metadata read")
        return b

    def inode(self, ino: int) -> dict[str, Any]:
        require(1 <= ino <= self.inodes, "Ext inode outside filesystem")
        group, index = divmod(ino - 1, self.ipg)
        desc = self.read(self.gdt + group * 32, 32)
        table = struct.unpack_from("<I", desc, 8)[0]
        b = self.read(table * self.bs + index * self.isize, self.isize)
        mode = struct.unpack_from("<H", b)[0]
        size = struct.unpack_from("<I", b, 4)[0]
        if stat.S_ISREG(mode):
            size |= struct.unpack_from("<I", b, 108)[0] << 32
        require(size <= self.size, "Ext inode size exceeds partition")
        require(not (struct.unpack_from("<I", b, 32)[0] & 0x80000), "Extents inode unsupported")
        return {"inode": ino, "mode": mode, "size": size, "raw": b}

    def indirect(self, block: int, level: int, count: int):
        capacity = (self.bs // 4) ** level
        count = min(count, capacity)
        if not block:
            yield from [0] * count
            return
        ptrs = struct.unpack("<" + "I" * (self.bs // 4), self.read(block * self.bs, self.bs))
        remaining = count
        for child in ptrs:
            if not remaining:
                break
            take = min(remaining, (self.bs // 4) ** (level - 1))
            if level == 1:
                yield child
            else:
                yield from self.indirect(child, level - 1, take)
            remaining -= take

    def contents(self, inode_rec: dict[str, Any]) -> bytes:
        count = (inode_rec["size"] + self.bs - 1) // self.bs
        require(count <= 1048576, "Inode block count exceeds safety limit")
        ptrs = struct.unpack_from("<15I", inode_rec["raw"], 40)
        blocks = list(ptrs[: min(12, count)])
        for level in (1, 2, 3):
            need = count - len(blocks)
            if need > 0:
                blocks.extend(self.indirect(ptrs[11 + level], level, need))
        require(len(blocks) == count, "Incomplete ext block mapping")
        return b"".join(
            self.read(b * self.bs, self.bs) if b else bytes(self.bs) for b in blocks
        )[: inode_rec["size"]]

    def walk(self, ino: int = 2, rel: str = "", depth: int = 0, hostrel: str = "") -> None:
        require(depth < 128 and len(self.entries) < 1000000, "Ext tree exceeds safety bounds")
        node = self.inode(ino)
        mode = node["mode"]
        kind = (
            "directory"
            if stat.S_ISDIR(mode)
            else "file"
            if stat.S_ISREG(mode)
            else "symlink"
            if stat.S_ISLNK(mode)
            else "special"
        )
        item: dict[str, Any] = {
            "path": rel or ".",
            "host_path": hostrel or ".",
            "inode": ino,
            "type": kind,
            "mode": oct(mode),
            "bytes": node["size"],
        }
        self.entries.append(item)
        if kind == "symlink":
            data = (
                node["raw"][40 : 40 + node["size"]]
                if node["size"] <= 60 and struct.unpack_from("<I", node["raw"], 28)[0] == 0
                else self.contents(node)
            )
            require(b"\0" not in data, "Invalid NUL in symlink target")
            item["link_target"] = os.fsdecode(data)
        if kind != "directory":
            return
        require(ino not in self.seen_dirs, "Directory cycle or directory hardlink detected")
        self.seen_dirs.add(ino)
        data = self.contents(node)
        offset = 0
        names: set[str] = set()
        hostnames: set[str] = set()
        while offset < len(data):
            require(offset + 8 <= len(data), "Truncated ext directory entry")
            child, length = struct.unpack_from("<IH", data, offset)
            namelen = (
                data[offset + 6]
                if self.incompat & 2
                else struct.unpack_from("<H", data, offset + 6)[0]
            )
            require(
                length >= 8
                and length % 4 == 0
                and offset + length <= len(data)
                and namelen <= length - 8
                and namelen <= 255,
                "Invalid ext directory record",
            )
            if child:
                name = os.fsdecode(data[offset + 8 : offset + 8 + namelen])
                if name not in (".", ".."):
                    clean_component(name)
                    require(name not in names, f"Duplicate exact ext filename in {rel}: {name!r}")
                    names.add(name)
                    host_name = name
                    if collision_key(host_name) in hostnames or any(
                        ord(c) < 32 or c in '\\"' for c in host_name
                    ):
                        digest = hashlib.sha256(os.fsencode(name)).hexdigest()[:12]
                        host_name = f"__inode_{child}_{digest}"
                        index = 0
                        while collision_key(host_name) in hostnames:
                            index += 1
                            host_name = f"__inode_{child}_{digest}_{index}"
                        self.aliases.append(
                            {
                                "original_path": f"{rel}/{name}" if rel else name,
                                "host_path": f"{hostrel}/{host_name}" if hostrel else host_name,
                                "inode": child,
                                "reason": "host filename collision or debugfs command quoting",
                            }
                        )
                    hostnames.add(collision_key(host_name))
                    self.walk(
                        child,
                        f"{rel}/{name}" if rel else name,
                        depth + 1,
                        f"{hostrel}/{host_name}" if hostrel else host_name,
                    )
            offset += length


def _ext_python_export(
    preflight: ExtPreflight,
    dest: Path,
    logs: Path,
    expected: list[dict[str, Any]],
    aliases: list[dict[str, Any]],
) -> dict[str, Any]:
    """Pure-Python read-only ext2 exporter preserving APFS case-collision inode aliases."""
    dest.mkdir(mode=0o700)
    for e in sorted(expected, key=lambda x: str(x["host_path"]).count("/")):
        if e["type"] == "directory" and e["host_path"] != ".":
            (dest / e["host_path"]).mkdir(mode=0o700)
    for e in expected:
        if e["type"] == "file":
            node = preflight.inode(int(e["inode"]))
            blob = preflight.contents(node)
            target = dest / e["host_path"]
            with target.open("xb") as dst:
                dst.write(blob)
            target.chmod(0o600)
            s = target.lstat()
            require(stat.S_ISREG(s.st_mode) and s.st_size == e["bytes"], f"Short file export: {e['path']}")
    for e in expected:
        if e["type"] == "symlink":
            os.symlink(e["link_target"], dest / e["host_path"])
    return {
        "method": "pure-python read-only ext2 block/inode exporter",
        "expected_entries": len(expected),
        "size_and_type_verification": True,
        "host_alias_count": len(aliases),
        "path_mapping_log": str((logs / "host-path-mapping.json").relative_to(dest.parent)),
    }


def ext_export(
    image: Path,
    dest: Path,
    logs: Path,
    *,
    debugfs_binary: Path | None = None,
    timeout: int = 900,
) -> dict[str, Any]:
    """Export an ext2/3 image read-only via `debugfs` (if provided) or built-in pure-Python reader."""
    preflight = ExtPreflight(image)
    try:
        preflight.walk()
        expected = preflight.entries
        aliases = preflight.aliases
        write_json(logs / "ext-directory-inventory.json", expected)
        write_json(logs / "host-path-mapping.json", aliases)
        if debugfs_binary is None:
            return _ext_python_export(preflight, dest, logs, expected, aliases)
    finally:
        preflight.close()

    if aliases:
        return _debugfs_inode_export(debugfs_binary, image, dest, logs, timeout, expected, aliases)

    dest.mkdir(mode=0o700)
    requests = {"stats": "stats", "root-listing": "ls -l -p /", "rdump": "rdump / export"}
    commands = []
    for label, request in requests.items():
        argv = [str(debugfs_binary), "-R", request, str(image)]
        with (logs / f"debugfs-{label}.log").open("xb") as f:
            result = subprocess.run(
                argv,
                cwd=dest.parent,
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            )
        commands.append({"label": label, "argv": argv, "returncode": result.returncode, "cwd": str(dest.parent)})
        require(result.returncode == 0, f"debugfs {label} returned {result.returncode}")
    write_json(logs / "debugfs-commands.json", commands)
    diagnostics = [
        line
        for line in (logs / "debugfs-rdump.log").read_text(errors="replace").splitlines()
        if line.strip() and not line.startswith("debugfs ")
    ]
    metadata_warnings = [line for line in diagnostics if "while changing ownership" in line]
    errors = [line for line in diagnostics if "while changing ownership" not in line]
    require(not errors, f"debugfs rdump reported errors: {errors[:3]}")
    for e in sorted(expected, key=lambda x: str(x["path"]).count("/")):
        p = dest if e["path"] == "." else dest / e["path"]
        if e["type"] == "special":
            continue
        s = p.lstat()
        if e["type"] == "directory":
            require(stat.S_ISDIR(s.st_mode), f"Missing/wrong exported directory {e['path']}")
            p.chmod(0o700)
        elif e["type"] == "file":
            require(stat.S_ISREG(s.st_mode) and s.st_size == e["bytes"], f"Missing/short exported file {e['path']}")
            p.chmod(0o600)
        else:
            require(stat.S_ISLNK(s.st_mode), f"Missing exported symlink {e['path']}")
    return {
        "method": "read-only debugfs rdump",
        "expected_entries": len(expected),
        "size_and_type_verification": True,
        "host_alias_count": 0,
        "metadata_warning_count": len(metadata_warnings),
    }


def _debugfs_inode_export(
    binary: Path,
    image: Path,
    dest: Path,
    logs: Path,
    timeout: int,
    expected: list[dict[str, Any]],
    aliases: list[dict[str, Any]],
) -> dict[str, Any]:
    dest.mkdir(mode=0o700)
    for e in sorted(expected, key=lambda x: str(x["host_path"]).count("/")):
        if e["type"] == "directory" and e["host_path"] != ".":
            (dest / e["host_path"]).mkdir(mode=0o700)
    commands = []
    for e in expected:
        if e["type"] == "file":
            path = "export/" + str(e["host_path"])
            require(not any(c in path for c in '\n\r\0\\"'), "Unsafe inode export command path")
            commands.append(f'dump <{e["inode"]}> "{path}"')
    command_file = logs / "debugfs-inode-dump.commands"
    command_file.write_text("\n".join(commands) + "\n", encoding="utf-8")
    argv = [str(binary), "-f", str(command_file), str(image)]
    with (logs / "debugfs-inode-dump.log").open("xb") as f:
        result = subprocess.run(
            argv,
            cwd=dest.parent,
            stdout=f,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C"},
        )
    write_json(
        logs / "debugfs-commands.json",
        [{"argv": argv, "returncode": result.returncode, "read_only": True, "cwd": str(dest.parent)}],
    )
    require(result.returncode == 0, f"debugfs inode export exited {result.returncode}")
    for e in expected:
        target = dest / e["host_path"]
        if e["type"] == "file":
            s = target.lstat()
            require(stat.S_ISREG(s.st_mode) and s.st_size == e["bytes"], f"Inode export missing/short: {e['path']}")
            target.chmod(0o600)
    for e in expected:
        if e["type"] == "symlink":
            os.symlink(e["link_target"], dest / e["host_path"])
    return {
        "method": "read-only debugfs per-inode dump with explicit host filename mapping",
        "expected_entries": len(expected),
        "size_and_type_verification": True,
        "host_alias_count": len(aliases),
        "path_mapping_log": str((logs / "host-path-mapping.json").relative_to(dest.parent)),
    }


def _fat12_16_python_export(image: Path, dest: Path) -> dict[str, Any]:
    """Minimal read-only pure-Python FAT12/FAT16 exporter (supports VFAT LFN + 8.3 names)."""
    raw = image.read_bytes()
    require(len(raw) >= 512 and raw[510:512] == b"\x55\xaa", "Invalid FAT boot sector")
    bps = struct.unpack_from("<H", raw, 11)[0]
    spc = raw[13]
    reserved = struct.unpack_from("<H", raw, 14)[0]
    fats = raw[16]
    roots = struct.unpack_from("<H", raw, 17)[0]
    total = struct.unpack_from("<H", raw, 19)[0] or struct.unpack_from("<I", raw, 32)[0]
    fatsecs = struct.unpack_from("<H", raw, 22)[0]
    require(roots > 0 and fatsecs > 0, "Pure-Python fallback supports FAT12/FAT16 only")
    root_dir_sectors = (roots * 32 + bps - 1) // bps
    clusters = (total - reserved - fats * fatsecs - root_dir_sectors) // spc
    is_fat12 = clusters < 4085
    fat_off = reserved * bps
    root_off = (reserved + fats * fatsecs) * bps
    data_off = root_off + root_dir_sectors * bps
    cluster_bytes = bps * spc

    def next_cluster(c: int) -> int | None:
        if is_fat12:
            pos = fat_off + c + (c // 2)
            val = struct.unpack_from("<H", raw, pos)[0]
            val = (val >> 4) if (c & 1) else (val & 0xFFF)
            return None if val >= 0xFF8 or val < 2 else val
        pos = fat_off + c * 2
        val = struct.unpack_from("<H", raw, pos)[0]
        return None if val >= 0xFFF8 or val < 2 else val

    def read_chain(start_cluster: int, byte_len: int | None = None) -> bytes:
        if start_cluster < 2:
            return b""
        out = bytearray()
        cur: int | None = start_cluster
        seen: set[int] = set()
        while cur is not None:
            require(cur not in seen and 2 <= cur < clusters + 2, "FAT cluster loop or out-of-bounds")
            seen.add(cur)
            off = data_off + (cur - 2) * cluster_bytes
            out.extend(raw[off : off + cluster_bytes])
            if byte_len is not None and len(out) >= byte_len:
                return bytes(out[:byte_len])
            cur = next_cluster(cur)
        return bytes(out[:byte_len] if byte_len is not None else out)

    dest.mkdir(mode=0o700)
    count = 0

    def parse_dir(dir_bytes: bytes, out_dir: Path, depth: int = 0) -> None:
        nonlocal count
        require(depth < 128 and count < 1000000, "FAT tree exceeds safety bounds")
        lfn_parts: list[str] = []
        names_seen: set[str] = set()
        for off in range(0, len(dir_bytes), 32):
            rec = dir_bytes[off : off + 32]
            if len(rec) < 32 or rec[0] == 0x00:
                break
            if rec[0] == 0xE5:
                lfn_parts.clear()
                continue
            attr = rec[11]
            if attr == 0x0F:
                raw_chars = rec[1:11] + rec[14:26] + rec[28:32]
                chars = []
                for idx in range(0, len(raw_chars), 2):
                    code = struct.unpack_from("<H", raw_chars, idx)[0]
                    if code in (0x0000, 0xFFFF):
                        break
                    chars.append(chr(code))
                if rec[0] & 0x40:
                    lfn_parts = ["".join(chars)]
                else:
                    lfn_parts.insert(0, "".join(chars))
                continue
            if attr & 0x08:  # Volume label
                lfn_parts.clear()
                continue
            if lfn_parts:
                name = "".join(lfn_parts)
                lfn_parts.clear()
            else:
                stem = rec[0:8].rstrip(b" ").decode("ascii", errors="replace")
                ext = rec[8:11].rstrip(b" ").decode("ascii", errors="replace")
                nt_res = rec[12]
                if nt_res & 0x08:
                    stem = stem.lower()
                if nt_res & 0x10:
                    ext = ext.lower()
                name = f"{stem}.{ext}" if ext else stem
            if name in (".", ".."):
                continue
            clean_component(name)
            key = collision_key(name)
            require(key not in names_seen, f"FAT host filename collision: {name!r}")
            names_seen.add(key)
            first_cluster = struct.unpack_from("<H", rec, 26)[0]
            file_size = struct.unpack_from("<I", rec, 28)[0]
            target = out_dir / name
            count += 1
            if attr & 0x10:
                target.mkdir(mode=0o700)
                parse_dir(read_chain(first_cluster), target, depth + 1)
            else:
                payload = read_chain(first_cluster, file_size) if file_size > 0 else b""
                require(len(payload) == file_size, f"FAT short cluster chain for {name}")
                with target.open("xb") as f:
                    f.write(payload)
                target.chmod(0o600)

    parse_dir(raw[root_off : root_off + root_dir_sectors * bps], dest)
    return {"method": "pure-python FAT12/16 read-only exporter", "entries": count, "size_verification": True}


def fat_export(image: Path, dest: Path) -> dict[str, Any]:
    """Export a FAT12/16/32 filesystem image read-only without OS mounting."""
    try:
        from pyfatfs.PyFatFS import PyFatFS
    except ImportError:
        return _fat12_16_python_export(image, dest)

    dest.mkdir(mode=0o700)
    count = 0
    with PyFatFS(str(image), read_only=True, preserve_case=True) as fs:
        def walk(src: str, out: Path, depth: int = 0) -> None:
            nonlocal count
            require(depth < 128 and count < 1000000, "FAT tree exceeds safety bounds")
            names: set[str] = set()
            for name in fs.listdir(src):
                clean_component(name)
                key = collision_key(name)
                require(key not in names, f"FAT host filename collision: {name!r}")
                names.add(key)
                child = src.rstrip("/") + "/" + name
                target = out / name
                count += 1
                if fs.isdir(child):
                    target.mkdir(mode=0o700)
                    walk(child, target, depth + 1)
                else:
                    with fs.openbin(child, "r") as inp, target.open("xb") as dst:
                        for data in iter(lambda: inp.read(CHUNK), b""):
                            dst.write(data)
                    target.chmod(0o600)
                    require(target.stat().st_size == fs.getsize(child), f"FAT export size mismatch: {child}")

        walk("/", dest)
    return {"method": "PyFatFS read_only=True", "entries": count, "size_verification": True}


def elf_header(data: bytes) -> dict[str, Any] | None:
    if not data.startswith(b"\x7fELF"):
        return None
    if len(data) < 52 or data[4] not in (1, 2) or data[5] not in (1, 2):
        return {"valid_header": False}
    endian = "<" if data[5] == 1 else ">"
    bits = 32 if data[4] == 1 else 64
    if len(data) < (52 if bits == 32 else 64):
        return {"valid_header": False}
    kind, machine = struct.unpack_from(endian + "HH", data, 16)
    entry = struct.unpack_from(endian + ("I" if bits == 32 else "Q"), data, 24)[0]
    arch_map = {3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 62: "x86_64", 183: "AArch64"}
    return {
        "valid_header": True,
        "bits": bits,
        "endianness": "little" if endian == "<" else "big",
        "elf_type": kind,
        "machine": machine,
        "architecture": arch_map.get(machine, "unknown"),
        "entry": hex(entry),
    }


def inventory_export(
    root: Path,
    label: str,
    filelog: Any,
    elflog: Any,
    source_map: dict[str, str] | None = None,
) -> dict[str, int]:
    counts = {"files": 0, "directories": 0, "symlinks": 0, "elf": 0}

    def walk(folder: Path) -> None:
        with os.scandir(folder) as it:
            entries = sorted(it, key=lambda e: e.name)
        for e in entries:
            p = Path(e.path)
            s = e.stat(follow_symlinks=False)
            item: dict[str, Any] = {
                "partition": label,
                "path": str(p.relative_to(root)),
                "mode": oct(stat.S_IMODE(s.st_mode)),
            }
            if source_map and item["path"] in source_map:
                item["source_path"] = source_map[item["path"]]
            if stat.S_ISLNK(s.st_mode):
                item.update(type="symlink", target=os.readlink(p))
                counts["symlinks"] += 1
            elif stat.S_ISDIR(s.st_mode):
                item["type"] = "directory"
                counts["directories"] += 1
            elif stat.S_ISREG(s.st_mode):
                item.update(type="file", bytes=s.st_size, **hashes(p))
                counts["files"] += 1
                with p.open("rb") as f:
                    elf = elf_header(f.read(64))
                if elf is not None:
                    counts["elf"] += 1
                    elflog.write(json.dumps({**item, **elf}) + "\n")
            else:
                item["type"] = "special"
            filelog.write(json.dumps(item, ensure_ascii=True) + "\n")
            if stat.S_ISDIR(s.st_mode):
                walk(p)

    walk(root)
    return counts


def sanitize_export_permissions(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        return
    root.chmod(0o700)
    for folder, dirs, files in os.walk(root, topdown=True, followlinks=False):
        for name in dirs:
            p = Path(folder) / name
            if not p.is_symlink():
                p.chmod(0o700)
        for name in files:
            p = Path(folder) / name
            if stat.S_ISREG(p.lstat().st_mode):
                p.chmod(0o600)


def carve_firmware_image(
    *,
    image_path: Path,
    manifest_path: Path,
    geometry_path: Path,
    output_dir: Path,
    offline_root: Path | None = None,
    debugfs_binary: Path | None = None,
    debugfs_timeout: int = 900,
) -> tuple[int, dict[str, Any]]:
    """Verify acquisition gates and carve/export partitions into `output_dir`."""
    manifest_path = regular_input(manifest_path)
    geometry_path = regular_input(geometry_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    geometry = json.loads(geometry_path.read_text(encoding="utf-8"))

    require(
        manifest.get("exposed_internal_storage_acquisition_complete") is True,
        "Acquisition gate closed: exposed_internal_storage_acquisition_complete is not true",
    )
    require(
        manifest.get("complete_firmware_backup") is False,
        "Physical firmware completeness must remain explicitly false",
    )
    require(
        manifest.get("restorability_verified") is False,
        "Restorability must remain explicitly false",
    )

    image = regular_input(image_path)
    matches = []
    for entry in manifest.get("storage_images", []):
        rel = Path(entry.get("path", ""))
        require(not rel.is_absolute() and ".." not in rel.parts, "Unsafe image path in manifest")
        if (manifest_path.parent / rel).resolve() == image:
            matches.append(entry)
    require(len(matches) == 1, "Image must match exactly one storage_images record")
    entry = matches[0]
    require(entry.get("host_readback_sha256_match") is True, "Host readback gate failed")
    require(entry.get("all_chunk_camera_host_sha1_match") is True, "Camera/host chunk hash gate failed")
    require(
        re.fullmatch(r"[0-9a-fA-F]{64}", entry.get("sha256", "")) is not None,
        "Manifest SHA256 missing/invalid",
    )

    total = integer(entry.get("bytes"), "storage image bytes", 1)
    require(geometry.get("main_bytes") == total, "Geometry main_bytes disagrees with manifest")
    require(
        geometry.get("main_device") == entry.get("source") == "/dev/nflasha",
        "Geometry/manifest main device mismatch",
    )
    sector = integer(geometry.get("logical_sector_bytes"), "logical_sector_bytes", 1)
    require(sector in (512, 1024, 2048, 4096), "Unsupported logical sector size")

    parts = geometry.get("partitions")
    require(isinstance(parts, list) and parts, "Partition geometry is empty")
    names: set[str] = set()
    ranges: list[tuple[int, int, str]] = []
    for part in parts:
        name = part.get("name")
        require(
            isinstance(name, str)
            and re.fullmatch(r"nflasha[0-9]+", name) is not None
            and name not in names,
            "Invalid/duplicate partition name",
        )
        names.add(name)
        start = integer(part.get("start_sector"), f"{name}.start_sector")
        sectors = integer(part.get("sectors"), f"{name}.sectors", 1)
        offset = integer(part.get("offset_bytes"), f"{name}.offset_bytes")
        size = integer(part.get("bytes"), f"{name}.bytes", 1)
        require(
            offset == start * sector and size == sectors * sector and offset + size <= total,
            f"Inconsistent/out-of-bounds geometry: {name}",
        )
        ranges.append((offset, offset + size, name))
    ranges.sort()
    require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "Partition ranges overlap")

    post = manifest.get("post_acquisition_readonly_partition_sha1", {})
    require(
        isinstance(post, dict) and {"nflasha7", "nflasha15"}.issubset(post),
        "Post-acquisition root/usr camera SHA1 missing",
    )
    for name, digest in post.items():
        require(
            name in names and isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{40}", digest) is not None,
            "Invalid post-acquisition SHA1 entry",
        )
    require(debugfs_timeout > 0, "Invalid timeout")

    output = output_dir.absolute()
    no_symlink_ancestors(output)
    output = output.resolve(strict=False)
    if offline_root is not None:
        resolved_root = offline_root.resolve(strict=False)
        require(
            output != resolved_root and output.is_relative_to(resolved_root),
            f"Output must be a new child of {resolved_root}",
        )
    require(not output.exists(), "Output already exists; use a new run directory")

    env_debugfs = os.environ.get("E2FSPROGS_DEBUGFS")
    if debugfs_binary is None and env_debugfs:
        debugfs_binary = Path(env_debugfs).resolve(strict=True)

    fd = os.open(image, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    report: dict[str, Any] = {
        "status": "running",
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "run_id": uuid.uuid4().hex[:8],
        "source_image": str(image),
        "complete_firmware_backup": False,
        "restorability_verified": False,
        "limitations": LIMITATIONS,
        "partitions": [],
    }
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode) and before.st_size == total,
            "Image length does not match completed manifest",
        )
        sha = hashlib.sha256()
        while b := os.read(fd, CHUNK):
            sha.update(b)
        require(sha.hexdigest() == entry["sha256"].lower(), "Image SHA256 does not match manifest")
        report["source_verification"] = {
            "bytes": total,
            "sha256": sha.hexdigest(),
            "readback_flags": True,
            "acquisition_complete": True,
            "snapshot_consistency": entry.get("snapshot_consistency"),
        }

        output.mkdir(parents=True, mode=0o700)
        write_json(output / "source-manifest.json", manifest)
        write_json(output / "partition-geometry.json", geometry)
        (output / "partitions").mkdir()

        for part in parts:
            target = output / "partitions" / (part["name"] + ".bin")
            os.lseek(fd, part["offset_bytes"], os.SEEK_SET)
            h256, h1 = hashlib.sha256(), hashlib.sha1()
            remaining = part["bytes"]
            with target.open("xb") as dst:
                while remaining:
                    b = os.read(fd, min(CHUNK, remaining))
                    require(b, "Short partition read")
                    dst.write(b)
                    h256.update(b)
                    h1.update(b)
                    remaining -= len(b)
            target.chmod(0o400)
            item: dict[str, Any] = {
                **part,
                "raw_path": str(target.relative_to(output)),
                "sha256": h256.hexdigest(),
                "sha1": h1.hexdigest(),
            }
            report["partitions"].append(item)
            require(
                hashes(target) == {"sha256": item["sha256"], "sha1": item["sha1"]},
                f"Partition host readback mismatch: {part['name']}",
            )
            item["host_slice_readback_match"] = True
            if part["name"] in post:
                item["post_acquisition_camera_sha1_match"] = h1.hexdigest() == post[part["name"]].lower()
                require(
                    item["post_acquisition_camera_sha1_match"],
                    f"Camera readonly partition reread mismatch: {part['name']}",
                )

        after = os.fstat(fd)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "Source image changed during processing",
        )
        report["source_verification"]["unchanged_during_carve"] = True

        (output / "filesystems").mkdir()
        failed = False
        with (
            (output / "file-inventory.jsonl").open("x", encoding="utf-8") as files,
            (output / "elf-inventory.jsonl").open("x", encoding="utf-8") as elfs,
        ):
            for item in report["partitions"]:
                raw = output / item["raw_path"]
                with raw.open("rb") as f:
                    item["identification"] = format_header(f.read(4096))
                family = item["identification"].get("family")
                if family not in ("ext", "fat"):
                    item["export_status"] = "raw retained; no supported filesystem detected"
                    continue
                folder = output / "filesystems" / item["name"]
                folder.mkdir()
                logs = folder / "logs"
                logs.mkdir()
                try:
                    if family == "ext":
                        item["export"] = ext_export(
                            raw,
                            folder / "export",
                            logs,
                            debugfs_binary=debugfs_binary,
                            timeout=debugfs_timeout,
                        )
                    else:
                        item["export"] = fat_export(raw, folder / "export")
                    source_map = {}
                    if family == "ext":
                        source_map = {
                            e["host_path"]: e["path"]
                            for e in json.loads((logs / "ext-directory-inventory.json").read_text(encoding="utf-8"))
                        }
                    item["inventory"] = inventory_export(
                        folder / "export", item["name"], files, elfs, source_map
                    )
                    item["export_status"] = "complete"
                except Exception as error:
                    failed = True
                    item["export_status"] = "failed; raw partition retained"
                    item["export_error"] = str(error)
                finally:
                    sanitize_export_permissions(folder / "export")

        report["status"] = "partial-export" if failed else "complete"
        for inv_name in ("file-inventory.jsonl", "elf-inventory.jsonl"):
            report[inv_name] = hashes(output / inv_name)
        write_json(output / "report.json", report)
        return (2 if failed else 0), report
    except Exception as error:
        if output.is_dir() and not (output / "report.json").exists():
            report.update(status="failed", error=str(error))
            write_json(output / "report.json", report)
        raise
    finally:
        os.close(fd)
