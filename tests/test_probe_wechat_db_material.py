from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest

from tools.probe_wechat_db_material import (
    PAGE_SIZE,
    RESERVED_SIZE,
    candidate_stream,
    first_page_hmac_matches,
    inspect_sqlite,
)


def make_hmac_page(key: bytes) -> bytes:
    page = bytearray(PAGE_SIZE)
    page[:16] = bytes(range(16, 32))
    for index in range(16, PAGE_SIZE - RESERVED_SIZE):
        page[index] = (index * 17 + 31) & 0xFF
    salt = bytes(page[:16])
    encryption_key = hashlib.pbkdf2_hmac("sha1", key, salt, 64_000, 32)
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha1", encryption_key, mac_salt, 2, 32)
    digest = hmac.new(
        mac_key,
        bytes(page[16 : PAGE_SIZE - RESERVED_SIZE]),
        hashlib.sha1,
    )
    digest.update(struct.pack("<I", 1))
    page[PAGE_SIZE - RESERVED_SIZE : PAGE_SIZE - RESERVED_SIZE + 20] = digest.digest()
    return bytes(page)


class ProbeWechatDbMaterialTests(unittest.TestCase):
    def test_first_page_hmac_accepts_only_the_matching_key(self) -> None:
        key = bytes(range(32))
        page = make_hmac_page(key)
        self.assertTrue(first_page_hmac_matches(key, page))
        self.assertFalse(first_page_hmac_matches(bytes(reversed(key)), page))

    def test_candidate_stream_finds_hex_and_raw_windows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.bin"
            key = bytes(range(32))
            path.write_bytes(b"prefix " + key.hex().encode("ascii") + b" suffix")
            candidates = list(candidate_stream(path, all_windows=True))
            self.assertIn(("hex-text@7", key), candidates)
            self.assertGreater(len(candidates), 1)

    def test_inspect_sqlite_is_read_only_and_reports_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.sqlite"
            connection = sqlite3.connect(path)
            try:
                connection.execute("CREATE TABLE sample (id INTEGER, value TEXT)")
                connection.execute("INSERT INTO sample VALUES (1, 'hello')")
                connection.commit()
            finally:
                connection.close()
            before = path.read_bytes()
            report = inspect_sqlite(path)
            after = path.read_bytes()
            self.assertEqual(before, after)
            self.assertEqual(report["quick_check"], ["ok"])
            self.assertEqual(report["tables"][0]["row_count"], 1)


if __name__ == "__main__":
    unittest.main()
