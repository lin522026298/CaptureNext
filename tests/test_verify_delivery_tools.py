from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest
import zipfile

from tools.verify_weixin4_database import PAGE_SIZE, page_hmac_matches
from tools.verify_zip_jsonl_manifest import verify


class VerifyDeliveryToolsTests(unittest.TestCase):
    def test_weixin4_page_hmac(self) -> None:
        raw_key = bytes(range(32))
        salt = bytes(range(32, 48))
        page = bytearray(PAGE_SIZE)
        page[:16] = salt
        for index in range(16, PAGE_SIZE - 64):
            page[index] = (index * 29 + 7) & 0xFF
        mac_salt = bytes(value ^ 0x3A for value in salt)
        mac_key = hashlib.pbkdf2_hmac("sha512", raw_key, mac_salt, 2, dklen=32)
        digest = hmac.new(mac_key, bytes(page[16 : PAGE_SIZE - 64]), hashlib.sha512)
        digest.update(struct.pack("<I", 1))
        page[PAGE_SIZE - 64 :] = digest.digest()
        self.assertTrue(page_hmac_matches(bytes(page), 1, raw_key, salt))
        page[100] ^= 1
        self.assertFalse(page_hmac_matches(bytes(page), 1, raw_key, salt))

    def test_embedded_zip_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            zip_path = root / "sample.zip"
            payload = b"payload"
            record = {
                "relative_path": "data/value.bin",
                "length": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            manifest = (json.dumps(record, separators=(",", ":")) + "\n").encode()
            sidecar = f"{hashlib.sha256(manifest).hexdigest()} *FINAL_CONTENT_MANIFEST.jsonl\n"
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("ROOT/data/value.bin", payload)
                archive.writestr("ROOT/20_MANIFESTS/FINAL_CONTENT_MANIFEST.jsonl", manifest)
                archive.writestr("ROOT/20_MANIFESTS/FINAL_CONTENT_MANIFEST.sha256", sidecar)
            result = verify(
                zip_path,
                "/20_MANIFESTS/FINAL_CONTENT_MANIFEST.jsonl",
                "/20_MANIFESTS/FINAL_CONTENT_MANIFEST.sha256",
            )
            self.assertTrue(result["pass"])
            self.assertEqual(result["verified_file_count"], 1)
            self.assertEqual(len(result["archive_files_excluded_from_manifest"]), 2)


if __name__ == "__main__":
    unittest.main()
