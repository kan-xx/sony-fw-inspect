"""Synthetic unit tests for offline backup verification, `/tmp_bt` windowed NAND dumping,
128-range MD5 verification, and quiescent live-chunk reconciliation.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from sony_fw_inspect.acquisition import (
    ExactSizeBuffer,
    LogicalNandDumper,
    reconcile_differing_chunks,
    verify_backup_directory,
    verify_image_ranges,
)


class BackupVerifierAndBufferTests(unittest.TestCase):
    def test_exact_size_buffer_enforces_ceiling(self) -> None:
        buf = ExactSizeBuffer(8)
        buf.write(b"1234")
        buf.write(b"5678")
        self.assertEqual(buf.getvalue(), b"12345678")
        with self.assertRaises(RuntimeError):
            buf.write(b"!")

    def test_verify_backup_directory_and_path_confinement(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            img = b"SYNTHETIC_STORAGE_SLICE_DATA" * 64
            cfg = b"SYNTHETIC_SETTINGS_BACKUP"
            (root / "slice.bin").write_bytes(img)
            (root / "settings.bin").write_bytes(cfg)

            manifest = {
                "exposed_internal_storage_acquisition_complete": True,
                "restorability_verified": False,
                "storage_images": [
                    {
                        "path": "slice.bin",
                        "bytes": len(img),
                        "sha256": hashlib.sha256(img).hexdigest(),
                    }
                ],
                "files": [
                    {
                        "path": "settings.bin",
                        "bytes": len(cfg),
                        "sha256": hashlib.sha256(cfg).hexdigest(),
                    }
                ],
            }
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

            res = verify_backup_directory(root)
            self.assertTrue(res["saved_file_integrity_ok"])
            self.assertTrue(res["exposed_internal_storage_acquisition_complete"])
            self.assertFalse(res["complete_physical_firmware_backup_verified"])

            # Corrupt one byte and verify detection
            (root / "settings.bin").write_bytes(cfg[:-1] + b"X")
            res_bad = verify_backup_directory(root)
            self.assertFalse(res_bad["saved_file_integrity_ok"])

            # Escaping path rejected
            manifest["files"][0]["path"] = "../outside.bin"
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises((ValueError, FileNotFoundError)):
                verify_backup_directory(root)


class DumperRangeAndReconcileTests(unittest.TestCase):
    def test_windowed_nand_dump_range_check_and_reconcile(self) -> None:
        chunk_size = 1024
        # 6 synthetic chunks on simulated camera
        initial_chunks = [bytes([i + 1]) * chunk_size for i in range(6)]
        live_chunks = list(initial_chunks)
        staged_files: dict[str, bytes] = {}

        class _MockCam:
            def readFile(self, remote_path: str, buf: ExactSizeBuffer) -> None:
                buf.write(staged_files[remote_path])

        def term_read(cmd: str) -> bytes:
            if "ACQ_STAGE_READY" in cmd:
                return b"\nnone /tmp_bt tmpfs rw 0 0\nACQ_STAGE_READY\n"
            if "ACQ_STAGE_REMOVED" in cmd:
                staged_files.clear()
                return b"\nACQ_STAGE_REMOVED\n"
            if "RECON_STAGE_READY" in cmd:
                return b"\nRECON_STAGE_READY\n"
            if "RECON_STAGE_REMOVED" in cmd:
                staged_files.clear()
                return b"\nRECON_STAGE_REMOVED\n"
            if "ACQ_COPY_OK" in cmd:
                target = cmd.split("T=", 1)[1].split(";", 1)[0].strip("'")
                skip = int(cmd.split("skip=", 1)[1].split()[0])
                blob = initial_chunks[skip]
                staged_files[target] = blob
                sha1 = hashlib.sha1(blob).hexdigest().encode("ascii")
                return (
                    b"\n"
                    + sha1
                    + b"  "
                    + target.encode("ascii")
                    + b"\n  "
                    + str(len(blob)).encode("ascii")
                    + b" "
                    + target.encode("ascii")
                    + b"\nACQ_COPY_OK\n"
                )
            if "| busybox md5sum" in cmd:
                # Range or single-chunk MD5 query against live_chunks
                i_val = int(cmd.split("I=", 1)[1].split(";", 1)[0])
                c_val = int(cmd.split("C=", 1)[1].split(";", 1)[0])
                window = b"".join(live_chunks[i_val : i_val + c_val])
                md5 = hashlib.md5(window).hexdigest().encode("ascii")
                if "B=" in cmd:
                    echo = f"ACQ_RANGE={i_val},{c_val},{chunk_size}".encode("ascii")
                else:
                    echo = f"ACQ_RANGE={i_val},{c_val}".encode("ascii")
                return (
                    b"\n"
                    + echo
                    + f"\n{c_val}+0 records in\n{c_val}+0 records out\n".encode("ascii")
                    + md5
                    + b"  -\n"
                )
            if "of=$T" in cmd:
                idx = int(cmd.split("I=", 1)[1].split(";", 1)[0])
                target = cmd.split("T=", 1)[1].split(";", 1)[0].strip("'")
                blob = live_chunks[idx]
                staged_files[target] = blob
                sha1 = hashlib.sha1(blob).hexdigest().encode("ascii")
                return (
                    f"\nACQ_RANGE={idx},1,{chunk_size}\n1+0 records in\n1+0 records out\n".encode("ascii")
                    + sha1
                    + b"  "
                    + target.encode("ascii")
                    + b"\n  "
                    + str(len(blob)).encode("ascii")
                    + b" "
                    + target.encode("ascii")
                    + b"\n"
                )
            raise AssertionError(f"Unhandled command: {cmd}")

        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            dumper = LogicalNandDumper(
                _MockCam(),
                term_read,
                out_dir,
                device_bytes={"nflasha": 6 * chunk_size},
                chunk_bytes=chunk_size,
            )
            dump_res = dumper.dump_image("nflasha", "nflasha-full")
            self.assertTrue(dumper.remove_ram_stage())

            full_path = out_dir / "nflasha-full.bin"
            self.assertEqual(full_path.read_bytes(), b"".join(initial_chunks))
            self.assertEqual(dump_res["chunks"], 6)

            # Mutate chunk 2 on live camera (simulating live VFAT nflasha2 write during dump)
            live_chunks[2] = b"\xfe" * chunk_size

            ranges = verify_image_ranges(
                full_path,
                term_read,
                chunk_bytes=chunk_size,
                range_chunks=2,
            )
            self.assertEqual([r["match"] for r in ranges], [True, False, True])

            reconciled_path = out_dir / "nflasha-reconciled.bin"
            recon_res = reconcile_differing_chunks(
                full_path,
                reconciled_path,
                ranges,
                _MockCam(),
                term_read,
                chunk_bytes=chunk_size,
            )
            self.assertEqual(recon_res["replaced_chunk_count"], 1)
            self.assertEqual(recon_res["replacements"][0]["index"], 2)
            # Original image untouched, reconciled image matches live camera!
            self.assertEqual(full_path.read_bytes(), b"".join(initial_chunks))
            self.assertEqual(reconciled_path.read_bytes(), b"".join(live_chunks))


if __name__ == "__main__":
    unittest.main()
