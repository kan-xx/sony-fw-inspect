"""Synthetic unit tests for `inflate_bounded()` LZ77 decompression,
`WBI1` warmboot container unpacking, and CRC32-verified `CramFS` extraction.
Zero proprietary files or external tools required.
"""

from __future__ import annotations

import io
from pathlib import Path
import stat
import struct
import tempfile
import unittest
import zlib

from sony_fw_inspect.unpacker import (
    CramfsSuper,
    WbiHeader,
    WbiSectionHeader,
    inflate_bounded,
    unpack_cramfs_image,
    unpack_wbi_image,
)


def _build_synthetic_wbi(sections_spec: list[tuple[int, int, bytes, bytes]]) -> bytes:
    """Build a valid synthetic `WBI1` warmboot partition from `(phys, virt, raw_data, lz77_stream)`."""
    comp_blob = b"".join(s[3] for s in sections_spec)
    total_osize = sum(len(s[2]) for s in sections_spec)
    sec_headers = b"".join(
        WbiSectionHeader.STRUCT.pack(phys, len(comp), 0, 0, len(orig), virt, 0, 0)
        for phys, virt, orig, comp in sections_spec
    )
    hdr = WbiHeader.STRUCT.pack(
        b"WBI1",
        len(sections_spec),
        0x9,  # Compressed flag 0x1 + observed uninterpreted bit 0x8
        0x80001000,
        0x20060224,
        512,
        len(comp_blob),
        0,
        0,
        0,
        total_osize,
    )
    sector0 = hdr.ljust(512, b"\x00")
    sector1_pad = b"\xff" * 512  # Exercise empty/0xFF header padding sector skip
    return sector0 + sector1_pad + comp_blob + sec_headers


def _pack_cramfs_inode(mode: int, uid: int, gid: int, size: int, name: str, data_offset: int) -> bytes:
    name_bytes = name.encode("ascii")
    if name_bytes:
        padded_len = ((len(name_bytes) + 3) // 4) * 4
        name_padded = name_bytes.ljust(padded_len, b"\x00")
    else:
        padded_len = 0
        name_padded = b""
    assert data_offset % 4 == 0
    size_gid = (size & 0xFFFFFF) | ((gid & 0xFF) << 24)
    namelen_offset = ((padded_len // 4) & 0x3F) | ((data_offset // 4) << 6)
    return struct.pack("<HHII", mode, uid, size_gid, namelen_offset) + name_padded


def _build_synthetic_cramfs() -> bytes:
    """Build a valid CRC32-signed CramFS image with a regular file, case-colliding sibling, and symlink."""
    file_a_data = b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 2, 40) + b"\x00" * 40
    file_b_data = b"Case-colliding sibling payload\n"
    sym_data = b"/bin/busybox"

    def pack_blocks(payload: bytes, start_off: int) -> bytes:
        comp = zlib.compress(payload)
        end_ptr = start_off + 4 + len(comp)
        out = struct.pack("<I", end_ptr) + comp
        out += b"\x00" * ((-len(out)) % 4)
        return out

    # Layout:
    # 0..64: superblock
    # 64..76: root inode (12B, name="") -> children at offset 76
    # Children inodes at 76:
    #   1) "App.so" (12 + 8 = 20B)
    #   2) "app.so" (12 + 8 = 20B)  -> triggers APFS case collision alias!
    #   3) "sh" symlink (12 + 4 = 16B)
    # Total children dir size = 56B -> data starts at 76 + 56 = 132
    data_cursor = 76 + 20 + 20 + 16
    blk_a = pack_blocks(file_a_data, data_cursor)
    off_a = data_cursor
    data_cursor += len(blk_a)

    blk_b = pack_blocks(file_b_data, data_cursor)
    off_b = data_cursor
    data_cursor += len(blk_b)

    blk_sym = pack_blocks(sym_data, data_cursor)
    off_sym = data_cursor
    data_cursor += len(blk_sym)

    child1 = _pack_cramfs_inode(stat.S_IFREG | 0o755, 0, 0, len(file_a_data), "App.so", off_a)
    child2 = _pack_cramfs_inode(stat.S_IFREG | 0o644, 0, 0, len(file_b_data), "app.so", off_b)
    child3 = _pack_cramfs_inode(stat.S_IFLNK | 0o777, 0, 0, len(sym_data), "sh", off_sym)
    children = child1 + child2 + child3
    assert len(children) == 56

    root_inode = _pack_cramfs_inode(stat.S_IFDIR | 0o755, 0, 0, len(children), "", 76)
    body = root_inode + children + blk_a + blk_b + blk_sym
    total_size = 64 + len(body)

    sup_zero_crc = CramfsSuper.STRUCT.pack(
        b"\x45\x3d\xcd\x28",
        total_size,
        0x00000003,
        0,
        b"Compressed ROMFS",
        0,
        1,
        3,
        4,  # root + 3 children
        b"SYNTHETIC\x00\x00\x00\x00\x00\x00\x00",
    )
    draft = bytearray(sup_zero_crc + body)
    crc = zlib.crc32(draft) & 0xFFFFFFFF
    struct.pack_into("<I", draft, 32, crc)
    return bytes(draft)


class BootComponentsTests(unittest.TestCase):
    def test_inflate_bounded_lz77_forms_and_limits(self) -> None:
        fixtures = [
            (b"\x0f\x00\x03\x00abc", b"abc"),
            (b"\xf0\x00ABCDEFGH\x01\x00\x00", b"ABCDEFGH"),
            (b"\xf0\x00ABCDEFGH\x03\x00\x08\x00\x00", b"ABCDEFGHABC"),
            # Overlapping run-length backreference (literal 'Z', match len=6 dist=1, EOF)
            (b"\xf0\x06Z\x30\x01\x00\x00", b"ZZZZZZZ"),
        ]
        for encoded, expected in fixtures:
            with self.subTest(expected=expected):
                self.assertEqual(inflate_bounded(io.BytesIO(encoded), len(expected)), expected)
                with self.assertRaises(RuntimeError):
                    inflate_bounded(io.BytesIO(encoded), len(expected) - 1)

        for corrupt in (b"", b"\xf0\x00AB", b"\xff", b"\xf0\x01\x00\x01"):
            with self.subTest(corrupt=corrupt.hex()), self.assertRaises(RuntimeError):
                inflate_bounded(io.BytesIO(corrupt), 4096)

    def test_wbi1_warmboot_unpacker(self) -> None:
        sec0_raw = b"KERNEL_RESUME_VECTOR_DATA"
        sec0_lz = b"\x0f\x00" + struct.pack("<H", len(sec0_raw)) + sec0_raw
        sec1_raw = b"ABCDEFGHABC"
        sec1_lz = b"\xf0\x00ABCDEFGH\x03\x00\x08\x00\x00"

        wbi_bytes = _build_synthetic_wbi(
            [
                (0x03000000, 0xC3000000, sec0_raw, sec0_lz),
                (0x03001000, 0xC3001000, sec1_raw, sec1_lz),
            ]
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "nflasha5.bin"
            src.write_bytes(wbi_bytes)
            out = root / "wbi-out"
            res = unpack_wbi_image(src, out)
            self.assertEqual(res["status"], "complete")
            self.assertEqual(res["sections"], 2)
            self.assertEqual(res["decompressed_bytes"], len(sec0_raw) + len(sec1_raw))
            self.assertEqual(
                (out / "sections/section-0000-phys-03000000.bin").read_bytes(), sec0_raw
            )
            self.assertEqual(
                (out / "sections/section-0001-phys-03001000.bin").read_bytes(), sec1_raw
            )

    def test_cramfs_crc_verified_extractor_and_tamper_rejection(self) -> None:
        cram_bytes = _build_synthetic_cramfs()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "initrd.img"
            src.write_bytes(cram_bytes)
            out = root / "cramfs-out"
            res = unpack_cramfs_image(src, out)
            self.assertEqual(res["status"], "complete")
            self.assertTrue(res["source_crc_verified"])
            self.assertEqual(res["inventory"]["files"], 2)
            self.assertEqual(res["inventory"]["symlinks"], 1)
            self.assertEqual(res["inventory"]["elf"], 1)
            self.assertTrue((out / "export/sh").is_symlink())
            self.assertEqual((out / "export/sh").readlink(), Path("/bin/busybox"))

            # Flip 1 bit in payload and verify CRC32 gate rejects before writing files
            tampered = bytearray(cram_bytes)
            tampered[-1] ^= 0x01
            bad_src = root / "tampered.img"
            bad_src.write_bytes(bytes(tampered))
            with self.assertRaises(RuntimeError):
                unpack_cramfs_image(bad_src, root / "bad-out")


if __name__ == "__main__":
    unittest.main()
