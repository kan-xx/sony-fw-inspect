"""Self-contained synthetic unit tests for `partition_carver`, APFS case-collision
inode aliasing, `complete_failed_ext_partition`, and `extract_nested_mbr_fat`.

Builds minimal spec-compliant ext2 and MBR+FAT12 images purely in Python —
requires ZERO external `mke2fs`/`debugfs` binaries and ZERO proprietary files.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import struct
import tempfile
import unittest

from sony_fw_inspect.unpacker import (
    carve_firmware_image,
    complete_failed_ext_partition,
    ext_export,
    extract_nested_mbr_fat,
    fat_export,
    format_header,
    hashes,
)


def _build_synthetic_ext2(
    files_spec: list[tuple[str, int, bytes]],
    *,
    include_subdir_and_symlink: bool = True,
) -> bytes:
    """Construct a minimal valid 1024-byte-block classic ext2 filesystem image in memory."""
    bs = 1024
    num_blocks = 64
    num_inodes = 32
    img = bytearray(num_blocks * bs)

    # Superblock at offset 1024 (block 1)
    # s_inodes_count=32, s_blocks_count=64, s_first_data_block=1 (at +20),
    # s_log_block_size=0 (1024B, at +24), s_blocks_per_group=64 (+32), s_inodes_per_group=32 (+40),
    # s_magic=0xEF53 (+56), s_rev_level=1 (+76), s_inode_size=128 (+88), s_feature_incompat=0x2 (filetype, +96)
    sb = bytearray(1024)
    struct.pack_into("<I", sb, 0, num_inodes)
    struct.pack_into("<I", sb, 4, num_blocks)
    struct.pack_into("<I", sb, 20, 1)
    struct.pack_into("<I", sb, 24, 0)
    struct.pack_into("<I", sb, 32, num_blocks)
    struct.pack_into("<I", sb, 40, num_inodes)
    struct.pack_into("<H", sb, 56, 0xEF53)
    struct.pack_into("<I", sb, 76, 1)
    struct.pack_into("<H", sb, 88, 128)
    struct.pack_into("<I", sb, 96, 0x2)
    img[1024:2048] = sb

    # Block Group Descriptor Table at block 2 (offset 2048): inode_table = block 5
    inode_table_blk = 5
    struct.pack_into("<III", img, 2048, 3, 4, inode_table_blk)

    # Inode table occupies blocks 5..8 (32 * 128 = 4096 bytes); data blocks start at block 10
    next_blk = 10
    next_ino = 11

    def write_inode(ino: int, mode: int, size: int, blocks_list: list[int], inline_bytes: bytes = b"") -> None:
        raw = bytearray(128)
        struct.pack_into("<HHI", raw, 0, mode, 0, size)
        i_blocks_512 = len(blocks_list) * (bs // 512)
        struct.pack_into("<I", raw, 28, i_blocks_512)
        if inline_bytes:
            raw[40 : 40 + len(inline_bytes)] = inline_bytes
        else:
            for idx, bno in enumerate(blocks_list[:12]):
                struct.pack_into("<I", raw, 40 + idx * 4, bno)
        off = inode_table_blk * bs + (ino - 1) * 128
        img[off : off + 128] = raw

    def alloc_data(payload: bytes) -> list[int]:
        nonlocal next_blk
        if not payload:
            return []
        blks = []
        for pos in range(0, len(payload), bs):
            b = next_blk
            next_blk += 1
            chunk = payload[pos : pos + bs]
            img[b * bs : b * bs + len(chunk)] = chunk
            blks.append(b)
        return blks

    def pack_dirents(entries: list[tuple[int, int, str]]) -> bytes:
        buf = bytearray()
        for idx, (ino, ftype, name) in enumerate(entries):
            nb = name.encode("utf-8")
            rec_len = ((8 + len(nb) + 3) // 4) * 4
            if idx == len(entries) - 1:
                rem = bs - (len(buf) % bs)
                if rem >= rec_len:
                    rec_len = rem
            entry = bytearray(rec_len)
            struct.pack_into("<IHBB", entry, 0, ino, rec_len, len(nb), ftype)
            entry[8 : 8 + len(nb)] = nb
            buf.extend(entry)
        return bytes(buf)

    root_entries: list[tuple[int, int, str]] = [(2, 2, "."), (2, 2, "..")]

    if include_subdir_and_symlink:
        etc_ino = next_ino
        next_ino += 1
        etc_dir_bytes = pack_dirents([(etc_ino, 2, "."), (2, 2, "..")])
        etc_blks = alloc_data(etc_dir_bytes)
        write_inode(etc_ino, stat.S_IFDIR | 0o755, len(etc_dir_bytes), etc_blks)
        root_entries.append((etc_ino, 2, "etc"))

        sym_ino = next_ino
        next_ino += 1
        target_bytes = b"/etc"
        write_inode(sym_ino, stat.S_IFLNK | 0o777, len(target_bytes), [], inline_bytes=target_bytes)
        root_entries.append((sym_ino, 7, "absolute"))

    for name, mode, data in files_spec:
        f_ino = next_ino
        next_ino += 1
        f_blks = alloc_data(data)
        write_inode(f_ino, mode, len(data), f_blks)
        root_entries.append((f_ino, 1, name))

    root_bytes = pack_dirents(root_entries)
    root_blks = alloc_data(root_bytes)
    write_inode(2, stat.S_IFDIR | 0o755, len(root_bytes), root_blks)
    return bytes(img)


def _lfn_checksum(short11: bytes) -> int:
    s = 0
    for c in short11:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


def _build_synthetic_fat12(long_filename: str, payload: bytes) -> bytes:
    """Construct a valid synthetic FAT12 volume containing a subdirectory and VFAT LFN file."""
    bps = 512
    total_sectors = 64  # 32 KiB FAT12 volume
    spc = 1
    reserved = 1
    fats = 2
    fat_sectors = 1
    root_entries = 16  # 1 sector (512B)
    img = bytearray(total_sectors * bps)

    # Boot sector BPB
    img[0:3] = b"\xeb\x3c\x90"
    img[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBHHBHHHII", img, 11, bps, spc, reserved, fats, root_entries, total_sectors, 0xF8, fat_sectors, 18, 2, 0, 0)
    img[510:512] = b"\x55\xaa"

    # FAT1 at sector 1, FAT2 at sector 2:
    # Cluster 2 = /folder directory (EOF 0xFFF)
    # Cluster 3 = file payload (EOF 0xFFF)
    # Entries: [0]=0xFF8, [1]=0xFFF, [2]=0xFFF, [3]=0xFFF -> 6 bytes: f8 ff ff ff ff 0f
    fat_bytes = bytes([0xF8, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F])
    img[512 : 512 + len(fat_bytes)] = fat_bytes
    img[1024 : 1024 + len(fat_bytes)] = fat_bytes

    # Root directory at sector 3 (offset 1536): 8.3 entry "FOLDER" (attr 0x10, cluster 2)
    folder_ent = bytearray(32)
    folder_ent[0:11] = b"FOLDER     "
    folder_ent[11] = 0x10
    folder_ent[12] = 0x08  # lowercase stem -> "folder"
    struct.pack_into("<H", folder_ent, 26, 2)
    img[1536 : 1536 + 32] = folder_ent

    # Data area starts at sector 4 (offset 2048 -> cluster 2)
    # Cluster 2 (/folder): LFN entry + short entry for `long_filename` (<=13 chars or 2 LFN entries)
    short11 = b"MIXED~1 TXT"
    chk = _lfn_checksum(short11)
    utf16_units = [ord(c) for c in long_filename] + [0x0000]
    while len(utf16_units) % 13 != 0:
        utf16_units.append(0xFFFF)
    n_lfn = len(utf16_units) // 13
    sub_buf = bytearray()
    for seq in range(n_lfn, 0, -1):
        chunk13 = utf16_units[(seq - 1) * 13 : seq * 13]
        lfn = bytearray(32)
        lfn[0] = seq | (0x40 if seq == n_lfn else 0)
        lfn[11] = 0x0F
        lfn[13] = chk
        packed26 = struct.pack("<13H", *chunk13)
        lfn[1:11] = packed26[0:10]
        lfn[14:26] = packed26[10:22]
        lfn[28:32] = packed26[22:26]
        sub_buf.extend(lfn)

    sfn = bytearray(32)
    sfn[0:11] = short11
    sfn[11] = 0x20
    struct.pack_into("<HI", sfn, 26, 3, len(payload))
    sub_buf.extend(sfn)
    img[2048 : 2048 + len(sub_buf)] = sub_buf

    # Cluster 3 at offset 2560: file payload
    assert len(payload) <= 512
    img[2560 : 2560 + len(payload)] = payload
    return bytes(img)


class FirmwareUnpackerTests(unittest.TestCase):
    def test_gates_ext2_export_case_collision_and_nested_mbr_fat(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # Resolve macOS /var -> /private/var symlink on temp root
            t = Path(td).resolve()
            offline_root = t / "offline"

            # 1. Incomplete acquisition gate rejected before opening image
            manifest_path = t / "manifest.json"
            geometry_path = t / "geometry.json"
            manifest_path.write_text(
                json.dumps({"exposed_internal_storage_acquisition_complete": False}),
                encoding="utf-8",
            )
            geometry_path.write_text("{}", encoding="utf-8")
            with self.assertRaises(RuntimeError) as ctx:
                carve_firmware_image(
                    image_path=t / "nonexistent.bin",
                    manifest_path=manifest_path,
                    geometry_path=geometry_path,
                    output_dir=offline_root / "run1",
                    offline_root=offline_root,
                )
            self.assertIn("Acquisition gate closed", str(ctx.exception))

            # 2. Build synthetic ext2 root (with ARM ELF + symlink) and nested MBR+FAT12 partition
            hello_bytes = b"Synthetic fixture; not camera data.\n"
            elf_hdr = bytearray(64)
            elf_hdr[:7] = b"\x7fELF\x01\x01\x01"
            struct.pack_into("<HH", elf_hdr, 16, 2, 40)

            ext2_raw = _build_synthetic_ext2(
                [
                    ("hello.txt", stat.S_IFREG | 0o755, hello_bytes),
                    ("mock.elf", stat.S_IFREG | 0o755, bytes(elf_hdr)),
                ]
            )
            fat12_raw = _build_synthetic_fat12("Mixed Name.txt", b"synthetic FAT payload")
            mbr_sector = bytearray(512)
            struct.pack_into("<BBBBBBBBII", mbr_sector, 446, 0x00, 0, 0, 0, 0x01, 0, 0, 0, 1, len(fat12_raw) // 512)
            mbr_sector[510:512] = b"\x55\xaa"
            nested_part_raw = bytes(mbr_sector) + fat12_raw
            usr_stub = b"synthetic-usr-slice".ljust(512, b"\x00")

            main_img = t / "synthetic-main.bin"
            main_bytes = ext2_raw + usr_stub + nested_part_raw
            main_img.write_bytes(main_bytes)

            record = {
                "path": main_img.name,
                "source": "/dev/nflasha",
                "bytes": len(main_bytes),
                "sha256": hashlib.sha256(main_bytes).hexdigest(),
                "host_readback_sha256_match": True,
                "all_chunk_camera_host_sha1_match": True,
            }
            doc = {
                "exposed_internal_storage_acquisition_complete": True,
                "complete_firmware_backup": False,
                "restorability_verified": False,
                "storage_images": [record],
                "post_acquisition_readonly_partition_sha1": {
                    "nflasha7": hashlib.sha1(ext2_raw).hexdigest(),
                    "nflasha15": hashlib.sha1(usr_stub).hexdigest(),
                },
            }
            off_7 = 0
            off_15 = len(ext2_raw)
            off_23 = off_15 + len(usr_stub)
            geo = {
                "logical_sector_bytes": 512,
                "main_device": "/dev/nflasha",
                "main_bytes": len(main_bytes),
                "partitions": [
                    {"name": "nflasha7", "start_sector": off_7 // 512, "sectors": len(ext2_raw) // 512, "offset_bytes": off_7, "bytes": len(ext2_raw)},
                    {"name": "nflasha15", "start_sector": off_15 // 512, "sectors": len(usr_stub) // 512, "offset_bytes": off_15, "bytes": len(usr_stub)},
                    {"name": "nflasha23", "start_sector": off_23 // 512, "sectors": len(nested_part_raw) // 512, "offset_bytes": off_23, "bytes": len(nested_part_raw)},
                ],
            }
            geometry_path.write_text(json.dumps(geo), encoding="utf-8")

            # 3. Bad SHA256 rejected before creating output
            record["sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(RuntimeError) as ctx:
                carve_firmware_image(
                    image_path=main_img,
                    manifest_path=manifest_path,
                    geometry_path=geometry_path,
                    output_dir=offline_root / "bad-hash",
                    offline_root=offline_root,
                )
            self.assertIn("Image SHA256", str(ctx.exception))
            self.assertFalse((offline_root / "bad-hash").exists())

            # 4. Path escape rejected
            record["sha256"] = hashlib.sha256(main_bytes).hexdigest()
            manifest_path.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(RuntimeError):
                carve_firmware_image(
                    image_path=main_img,
                    manifest_path=manifest_path,
                    geometry_path=geometry_path,
                    output_dir=offline_root / "run/../../escape",
                    offline_root=offline_root,
                )

            # 5. Full successful carve & export
            good_out = offline_root / "good"
            rc, report = carve_firmware_image(
                image_path=main_img,
                manifest_path=manifest_path,
                geometry_path=geometry_path,
                output_dir=good_out,
                offline_root=offline_root,
            )
            self.assertEqual(rc, 0)
            self.assertEqual(report["status"], "complete")

            exported = good_out / "filesystems/nflasha7/export"
            self.assertEqual((exported / "hello.txt").read_bytes(), hello_bytes)
            self.assertTrue((exported / "absolute").is_symlink())
            # Execute permissions stripped (0600)
            self.assertFalse((exported / "hello.txt").stat().st_mode & 0o111)
            self.assertFalse((exported / "mock.elf").stat().st_mode & 0o111)
            self.assertEqual(
                len((good_out / "elf-inventory.jsonl").read_text(encoding="utf-8").splitlines()), 1
            )

            # 6. Nested MBR + FAT12 extraction on nflasha23
            nested_res = extract_nested_mbr_fat(good_out, "nflasha23")
            self.assertTrue(nested_res["bounds_verified"])
            self.assertEqual(
                (good_out / "filesystems/nflasha23-mbr1/export/folder/Mixed Name.txt").read_bytes(),
                b"synthetic FAT payload",
            )

            # 7. Readonly partition SHA1 mismatch prevents filesystem export
            doc["post_acquisition_readonly_partition_sha1"]["nflasha7"] = "0" * 40
            manifest_path.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(RuntimeError):
                carve_firmware_image(
                    image_path=main_img,
                    manifest_path=manifest_path,
                    geometry_path=geometry_path,
                    output_dir=offline_root / "bad-reread",
                    offline_root=offline_root,
                )
            self.assertFalse((offline_root / "bad-reread/filesystems").exists())

            # 8. Linux case-collision ext2 image (`Case.so` vs `case.so`) -> reversible inode alias
            collision_ext2 = t / "collision-ext2.bin"
            collision_ext2.write_bytes(
                _build_synthetic_ext2(
                    [
                        ("Case.so", stat.S_IFREG | 0o644, b"UPPERCASE_LIB"),
                        ("case.so", stat.S_IFREG | 0o644, b"lowercase_lib"),
                    ],
                    include_subdir_and_symlink=False,
                )
            )
            col_dir = t / "collision-out"
            col_dir.mkdir()
            (col_dir / "logs").mkdir()
            col_res = ext_export(collision_ext2, col_dir / "export", col_dir / "logs")
            self.assertEqual(col_res["host_alias_count"], 1)
            mapping = json.loads((col_dir / "logs/host-path-mapping.json").read_text(encoding="utf-8"))
            self.assertEqual(len(mapping), 1)
            self.assertEqual((col_dir / "export/Case.so").read_bytes(), b"UPPERCASE_LIB")
            self.assertEqual(
                (col_dir / "export" / mapping[0]["host_path"]).read_bytes(), b"lowercase_lib"
            )

            # 9. Standalone FAT12 format detection & source immutability
            fat_file = t / "standalone-fat12.bin"
            fat_file.write_bytes(fat12_raw)
            before_fat = hashes(fat_file)
            self.assertEqual(format_header(fat12_raw)["format"], "fat12")
            fat_export(fat_file, t / "standalone-fat-out")
            self.assertEqual(hashes(fat_file), before_fat)

            # 10. `complete_failed_ext_partition` recovery test
            partial_dir = offline_root / "partial-sim"
            partial_dir.mkdir(parents=True)
            (partial_dir / "partitions").mkdir()
            p7 = partial_dir / "partitions/nflasha7.bin"
            p7.write_bytes(collision_ext2.read_bytes())
            p7_h = hashes(p7)
            (partial_dir / "filesystems/nflasha7/logs").mkdir(parents=True)
            (partial_dir / "file-inventory.jsonl").write_text("", encoding="utf-8")
            (partial_dir / "elf-inventory.jsonl").write_text("", encoding="utf-8")
            (partial_dir / "source-manifest.json").write_text(
                json.dumps(
                    {
                        "exposed_internal_storage_acquisition_complete": True,
                        "post_acquisition_readonly_partition_sha1": {"nflasha7": p7_h["sha1"]},
                    }
                ),
                encoding="utf-8",
            )
            (partial_dir / "report.json").write_text(
                json.dumps(
                    {
                        "status": "partial-export",
                        "partitions": [
                            {
                                "name": "nflasha7",
                                "raw_path": "partitions/nflasha7.bin",
                                **p7_h,
                                "export_status": "failed; raw partition retained",
                                "export_error": "Simulated initial rdump collision",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            completed = complete_failed_ext_partition(partial_dir, "nflasha7")
            self.assertEqual(completed["status"], "complete")
            self.assertEqual(completed["export"]["host_alias_count"], 1)


if __name__ == "__main__":
    unittest.main()
