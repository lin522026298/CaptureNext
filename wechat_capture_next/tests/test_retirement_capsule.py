import hashlib
import json
import sqlite3
import struct
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path

from tools.wechat_retirement_capsule import Capsule, decode_value, encode_value, table_lines, verify


class CapsuleTests(unittest.TestCase):
    def test_values_and_table_roundtrip(self):
        values = (None, -9223372036854775808, 0.125, "a\0中文", b"\0\xff")
        self.assertEqual(values, tuple(decode_value(encode_value(v)) for v in values))
        self.assertEqual(struct.pack(">d", -0.0), struct.pack(">d", decode_value(encode_value(-0.0))))
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute("CREATE TABLE example(a,b,c,d,e)")
            db.execute("INSERT INTO example VALUES(?,?,?,?,?)", values)
            db.execute("INSERT INTO example VALUES(?,?,?,?,?)", values)
            lines = list(table_lines(db, "example"))
            self.assertEqual(3, len(lines))
            self.assertEqual(values, tuple(decode_value(v) for v in json.loads(lines[1])))
            self.assertEqual(lines[1], lines[2])
            self.assertEqual("example", json.loads(lines[0])["table"])

    def test_readback_and_corruption(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.zip"
            raw = b"preserve" * 8000
            capsule = Capsule(path)
            capsule.add("cache/hash.sqlite", [raw[:4], raw[4:]], dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
            capsule.finish(dict(source="synthetic"))
            self.assertEqual(len(raw), verify(path)["members"][0]["bytes"])
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr("unexpected", b"value")
            with self.assertRaisesRegex(ValueError, "member set"):
                verify(path)

    def test_reject_unsafe_and_wrong_source(self):
        with tempfile.TemporaryDirectory() as temp:
            capsule = Capsule(Path(temp) / "evidence.zip")
            try:
                for name in ("../a", "C:/a", "/root", "a\\b", "a//b", "a/\0b"):
                    with self.assertRaises(ValueError):
                        capsule.add(name, [b"x"])
                with self.assertRaisesRegex(ValueError, "source digest"):
                    capsule.add("cache/data", [b"x"], dict(bytes=1, sha256="0" * 64))
            finally:
                capsule.close()
