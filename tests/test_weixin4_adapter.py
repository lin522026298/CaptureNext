import hashlib
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from wua import ArchiveStore
from wua.weixin4 import Weixin4Database, decode_text


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "fixture.db"
        self.peer = "synthetic_custom_name"
        self.table = "Msg_" + hashlib.md5(self.peer.encode()).hexdigest()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY,is_session INTEGER)")
            db.executemany("INSERT INTO Name2Id(rowid,user_name) VALUES (?,?)",
                           [(7, self.peer), (19, "wxid_synthetic_self")])
            db.execute(f'CREATE TABLE "{self.table}" (local_id INTEGER PRIMARY KEY, server_id INTEGER, '
                       'local_type INTEGER,real_sender_id INTEGER,create_time INTEGER,message_content BLOB,'
                       'WCDB_CT_message_content INTEGER,packed_info_data BLOB)')
            db.execute(f'INSERT INTO "{self.table}" VALUES (?,?,?,?,?,?,?,?)',
                       (-1, -9001, 1, 7, 0, "合成文本", None, b"\x00\xff"))

    def tearDown(self):
        self.temp.cleanup()

    def adapter(self, **kwargs):
        return Weixin4Database(self.path, db_relative_path="message/fixture.db",
                               account_alias="fixture", **kwargs)

    def test_native_mapping_raw_preservation_and_epoch(self):
        before = self.path.read_bytes()
        with self.adapter(self_username="wxid_synthetic_self") as adapter:
            rows = list(adapter.observations())
            self.assertEqual(rows[0]["conversation_id"], self.peer)
            self.assertTrue(rows[0]["conversation_id_is_stable"])
            self.assertEqual(rows[0]["sender_id"], self.peer)
            self.assertEqual(rows[0]["direction"], "incoming")
            self.assertEqual(rows[0]["event_time"], "1970-01-01T00:00:00+00:00")
            self.assertEqual(rows[0]["raw_record"]["packed_info_data"], b"\x00\xff")
            self.assertEqual(rows[0]["native_locator"]["local_id"], -1)
            self.assertEqual(adapter.report()["counts"]["rows"], 1)
        self.assertEqual(before, self.path.read_bytes())

    def test_unknown_direction_and_missing_sender_never_guessed(self):
        with self.adapter() as adapter:
            self.assertEqual(list(adapter.observations())[0]["direction"], "unknown")
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("DELETE FROM Name2Id")
        with self.adapter() as adapter:
            row = list(adapter.observations())[0]
            self.assertIsNone(row["conversation_id"])
            self.assertIsNone(row["sender_id"])
            self.assertFalse(row["conversation_id_is_stable"])

    def test_shard_local_id_map_not_global(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE Name2Id SET user_name='wxid_other_synthetic' WHERE rowid=7")
        with self.adapter(self_username="wxid_other_synthetic") as adapter:
            row = list(adapter.observations())[0]
            self.assertEqual(row["sender_id"], "wxid_other_synthetic")
            self.assertEqual(row["direction"], "outgoing")
            self.assertIsNone(row["conversation_id"])

    def test_sidecar_and_encrypted_input_fail_closed(self):
        sidecar = Path(str(self.path) + "-wal")
        sidecar.write_bytes(b"incomplete")
        with self.assertRaisesRegex(ValueError, "sidecar"):
            self.adapter()
        sidecar.unlink()
        encrypted = self.root / "encrypted.db"
        encrypted.write_bytes(b"not SQLite")
        with self.assertRaisesRegex(ValueError, "decrypted"):
            Weixin4Database(encrypted, db_relative_path="x.db", account_alias="fixture")

    def test_import_replay_is_byte_identical(self):
        target = self.root / "archive.sqlite"
        with ArchiveStore(target) as store:
            for index in range(2):
                with self.adapter(self_username="wxid_synthetic_self") as adapter:
                    result = store.import_observations({"source_id": "fixture"},
                        {"snapshot_id": "snapshot", "database": adapter.profile}, adapter.observations())
                current = target.read_bytes()
                if index:
                    self.assertTrue(result["idempotent_replay"])
                    self.assertEqual(previous, current)
                previous = current

    def test_strict_decoding_no_lossy_heuristics(self):
        self.assertEqual(decode_text(b"\xff"), (None, "unparsed-binary"))
        self.assertEqual(decode_text(b"abc", 8), (None, "unsupported-wcdb-compression"))
        self.assertEqual(decode_text(" x\n\x00"), (" x\n\x00", "sqlite-text"))
        import zstandard
        blob = zstandard.ZstdCompressor().compress("合成Zstd".encode())
        self.assertEqual(decode_text(blob, 4), ("合成Zstd", "zstd-utf8"))
        self.assertEqual(decode_text(blob + b"junk", 4)[0], None)
        self.assertEqual(decode_text(b"invalid", 4)[0], None)


if __name__ == "__main__":
    unittest.main()
