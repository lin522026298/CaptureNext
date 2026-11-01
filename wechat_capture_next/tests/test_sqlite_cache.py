"""Connection-local cache budgets; synthetic files only, no format changes."""
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tests.test_wua_store import observation
from wechat_capture_next.compact_archive import CompactArchive, HEAVY_CACHE_KIB
from wechat_capture_next.union_archive import cold_input, cold_reader


class ConnectionCacheTests(unittest.TestCase):
    def test_owned_writer_budget_is_local_and_does_not_persist_or_expand_file(self):
        with tempfile.TemporaryDirectory(prefix='next-cache-test-') as root:
            path = Path(root)/'archive.sqlite'
            with CompactArchive(path, create=True) as archive:
                self.assertEqual(archive._db.execute('PRAGMA cache_size').fetchone()[0], -131072)
                self.assertEqual(HEAVY_CACHE_KIB, 131072)
                archive.import_observations({'source_id': 'synthetic'}, {'snapshot_id': 'synthetic'},
                    [observation(body_text='synthetic cache test searchable body')])
                semantic = archive.semantic_digest()
            before = path.read_bytes()
            with closing(sqlite3.connect(path)) as ordinary:
                baseline_cache = ordinary.execute('PRAGMA cache_size').fetchone()[0]
                default_cache = ordinary.execute('PRAGMA default_cache_size').fetchone()[0]
                self.assertNotEqual(baseline_cache, -HEAVY_CACHE_KIB)
            with CompactArchive(path) as archive:
                self.assertEqual(archive._db.execute('PRAGMA cache_size').fetchone()[0], -HEAVY_CACHE_KIB)
                self.assertEqual(archive._db.execute('PRAGMA default_cache_size').fetchone()[0], default_cache)
                self.assertEqual(archive.semantic_digest(), semantic)
            self.assertEqual(path.read_bytes(), before)
            # Lightweight viewers retain SQLite's ordinary connection budget.
            with CompactArchive(path, readonly=True) as archive:
                self.assertEqual(archive._db.execute('PRAGMA cache_size').fetchone()[0], baseline_cache)

    def test_cold_reader_budget_keeps_input_readonly_immutable_and_bytes_unchanged(self):
        with tempfile.TemporaryDirectory(prefix='next-cache-test-') as root:
            path = Path(root)/'archive.sqlite'
            with CompactArchive(path, create=True) as archive:
                archive.import_observations({'source_id': 'synthetic'}, {'snapshot_id': 'synthetic'},
                    [observation(body_text='synthetic immutable input')])
            before = path.read_bytes()
            with cold_input(path), closing(cold_reader(path)) as reader:
                self.assertEqual(reader.execute('PRAGMA cache_size').fetchone()[0], -HEAVY_CACHE_KIB)
                self.assertEqual(reader.execute('PRAGMA query_only').fetchone()[0], 1)
                self.assertEqual(reader.execute('SELECT count(*) FROM message_observation').fetchone()[0], 1)
                with self.assertRaises(sqlite3.OperationalError):
                    reader.execute("INSERT INTO archive_meta VALUES('forbidden','write')")
            self.assertEqual(path.read_bytes(), before)
            for suffix in ('-wal', '-shm', '-journal'):
                self.assertFalse(Path(str(path)+suffix).exists())


if __name__ == '__main__':
    unittest.main()
