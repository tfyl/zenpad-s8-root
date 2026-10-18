"""Reject unverified patch inputs before extracting executable APK contents."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BootPatchTest(unittest.TestCase):
    def test_bad_apk_or_stock_hash_stops_before_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "firmware").mkdir()
            (root / "mocks").mkdir()
            script = root / "scripts/patch-magisk-boot.sh"
            shutil.copy2(ROOT / "scripts/patch-magisk-boot.sh", script)
            apk, stock = root / "input-apk", root / "input-stock"
            apk.write_bytes(b"fixture APK input")
            stock.write_bytes(b"fixture stock input")
            marker = root / "extracted"
            unzip = root / "mocks/unzip"
            unzip.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 92\n")
            unzip.chmod(0o755)
            env = os.environ | {"PATH": str(root / "mocks") + os.pathsep + os.environ["PATH"]}
            good = [hashlib.sha256(p.read_bytes()).hexdigest() for p in (apk, stock)]
            for bad_index in (0, 1):
                with self.subTest(input=bad_index):
                    hashes = good.copy()
                    hashes[bad_index] = "0" * 64
                    (root / "firmware/SHA256SUMS").write_text(
                        hashes[0] + "  firmware/Magisk-v30.7.apk\n" +
                        hashes[1] + "  firmware/boot-stock-WW-5.5.1.img\n")
                    result = subprocess.run(
                        ["bash", str(script), str(apk), str(stock), str(root / "work"), str(root / "out")],
                        env=env, text=True, capture_output=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("checksum mismatch", result.stderr)
                    self.assertFalse(marker.exists())
                    self.assertFalse((root / "work").exists())


if __name__ == "__main__":
    unittest.main()
