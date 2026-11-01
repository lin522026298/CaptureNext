"""Synthetic maintenance pager-cache scope and explicit session-release tests."""
import random
import sqlite3
import unittest

from wechat_capture_v2.common import digest_file
from wechat_capture_next import pair_repository as repo
from wechat_capture_next.tests import test_pair_repository as fixtures


class FailingConnection:
    def __init__(self, db, exception, *, at='incremental_vacuum'):
        self.db, self.exception, self.at = db, exception, at
    def __getattr__(self, name):
        return getattr(self.db, name)
    def execute(self, query, parameters=()):
        if self.at in query:
            raise self.exception
        return self.db.execute(query, parameters)


class ReclaimCacheTests(unittest.TestCase):
    setUp = fixtures.PairedTreeTests.setUp

    def prepared(self, *, free=True):
        self.snapshot = repo.publish(self.repository, self.owner, self.files, {})['snapshot_id']
        with repo.session(self.repository) as (db, owner):
            self.default_cache = db.execute('PRAGMA cache_size').fetchone()[0]
            self.literal = db.execute('SELECT manifest FROM snapshot WHERE id=?', (self.snapshot,)).fetchone()[0]
            self.block_count = db.execute('SELECT count(*) FROM block').fetchone()[0]
            self.generations = [tuple(r) for r in db.execute('SELECT * FROM generation ORDER BY seq')]
            if free:
                rng = random.Random(20261022)
                keys = [repo._put(db, 'D', rng.randbytes(256*1024))[0] for _ in range(16)]
                db.commit()
                db.executemany('DELETE FROM block WHERE hash=?', ((key,) for key in keys))
                db.commit()
                self.assertGreater(db.execute('PRAGMA freelist_count').fetchone()[0], 0)
            else:
                self.assertEqual(db.execute('PRAGMA freelist_count').fetchone()[0], 0)

    def assert_preserved(self):
        with repo.session(self.repository) as (db, owner):
            self.assertEqual(db.execute('PRAGMA cache_size').fetchone()[0], self.default_cache)
            self.assertEqual(db.execute('SELECT manifest FROM snapshot WHERE id=?', (self.snapshot,)).fetchone()[0], self.literal)
            self.assertEqual(db.execute('SELECT count(*) FROM block').fetchone()[0], self.block_count)
            self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM generation ORDER BY seq')], self.generations)
            self.assertEqual([r[0] for r in db.execute('PRAGMA integrity_check')], ['ok'])
            self.assertFalse(list(db.execute('PRAGMA foreign_key_check')))
            self.assertTrue(repo.verify_files(db, repo.manifest(db, self.snapshot, owner))['verified'])

    def assert_explicitly_closed(self, db):
        # Hold a strong reference: this MUST be session.close, not destructor GC.
        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute('SELECT 1')

    def test_free_pages_raise_only_maintenance_connection_and_close_releases(self):
        self.prepared()
        with repo.session(self.repository) as (db, _):
            result = repo._reclaim(db, self.repository)
            self.assertGreater(result['file_bytes_reclaimed'], 0)
            self.assertFalse(result['cleanup_pending'])
            self.assertEqual(db.execute('PRAGMA cache_size').fetchone()[0], -131072)
        self.assert_explicitly_closed(db)
        self.assert_preserved()

    def test_no_free_pages_do_not_change_hint_or_persistent_database_bytes(self):
        self.prepared(free=False)
        before = digest_file(self.repository/repo.DATABASE)
        with repo.session(self.repository) as (db, _):
            db.execute('PRAGMA cache_size=-8192')
            statements = []; db.set_trace_callback(statements.append)
            result = repo._reclaim(db, self.repository)
            db.set_trace_callback(None)
            self.assertEqual(db.execute('PRAGMA cache_size').fetchone()[0], -8192)
            self.assertFalse(any('cache_size' in sql.casefold() for sql in statements))
            self.assertEqual(result['file_bytes_reclaimed'], 0)
            self.assertFalse(result['cleanup_pending'])
        self.assert_explicitly_closed(db)
        self.assertEqual(before, digest_file(self.repository/repo.DATABASE))
        self.assert_preserved()

    def test_caught_sqlite_failure_rolls_back_and_session_close_releases_hint(self):
        self.prepared(); before = digest_file(self.repository/repo.DATABASE)
        with repo.session(self.repository) as (db, _):
            result = repo._reclaim(FailingConnection(db, sqlite3.OperationalError('synthetic reclaim failure')), self.repository)
            self.assertEqual(result['cleanup_error'], 'OperationalError')
            self.assertTrue(result['cleanup_pending'])
            self.assertFalse(db.in_transaction)
            self.assertEqual(db.execute('PRAGMA cache_size').fetchone()[0], -131072)
        self.assert_explicitly_closed(db)
        self.assertEqual(before, digest_file(self.repository/repo.DATABASE))
        self.assert_preserved()

    def test_uncaught_interruption_also_explicitly_closes_and_rolls_back(self):
        self.prepared(); before = digest_file(self.repository/repo.DATABASE); db = None
        with self.assertRaisesRegex(RuntimeError, 'synthetic interruption'):
            with repo.session(self.repository) as (db, _):
                repo._reclaim(FailingConnection(db, RuntimeError('synthetic interruption')), self.repository)
        self.assert_explicitly_closed(db)
        self.assertEqual(before, digest_file(self.repository/repo.DATABASE))
        self.assert_preserved()

    def test_hint_configuration_error_is_pending_without_persistent_mutation(self):
        self.prepared(); before = digest_file(self.repository/repo.DATABASE)
        with repo.session(self.repository) as (db, _):
            result = repo._reclaim(FailingConnection(db, sqlite3.OperationalError('synthetic hint failure'), at='cache_size=-'), self.repository)
            self.assertEqual(result['cleanup_error'], 'OperationalError')
            self.assertFalse(db.in_transaction)
            self.assertEqual(db.execute('PRAGMA cache_size').fetchone()[0], self.default_cache)
        self.assert_explicitly_closed(db)
        self.assertEqual(before, digest_file(self.repository/repo.DATABASE))
        self.assert_preserved()


if __name__ == '__main__':
    unittest.main()
