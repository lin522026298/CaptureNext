from copy import deepcopy
from pathlib import Path
import subprocess
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests.test_wua_store import observation
from wua.store import ArchiveStore
from wechat_capture_next.merge import LeanArchiveStore


def import_rows(store, snapshot, rows):
    return store.import_observations({'source_id': 'synthetic'},
        {'source_id': 'synthetic', 'snapshot_id': snapshot}, rows)


def assert_equal(test, old, new):
    test.assertEqual(old.semantic_digest(), new.semantic_digest())
    test.assertEqual([tuple(r) for r in old._db.execute('SELECT logical_id,body_text FROM message_fts ORDER BY logical_id')],
                     [tuple(r) for r in new._db.execute('SELECT logical_id,body_text FROM message_fts ORDER BY logical_id')])
    test.assertFalse(list(new._db.execute('PRAGMA foreign_key_check')))


class DeltaMergeTests(unittest.TestCase):
    def test_single_add_leaves_unrelated_parents_links_and_fts_rowids_untouched(self):
        with ArchiveStore(':memory:') as old, LeanArchiveStore(':memory:') as new:
            rows = [observation(native_locator=i, server_id=1000+i, body_text='body '+str(i)) for i in range(100)]
            for store in (old, new):
                import_rows(store, 'base', rows)
            rowids = dict(new._db.execute('SELECT logical_id,rowid FROM message_fts'))
            sentinel = next(iter(rowids))
            new._db.execute("CREATE TRIGGER protect_unrelated BEFORE DELETE ON logical_message WHEN old.logical_id='"+
                            sentinel+"' BEGIN SELECT RAISE(ABORT,'unrelated deletion'); END")
            extra = [observation(native_locator=1001, server_id=99999, body_text='one new message')]
            for store in (old, new):
                import_rows(store, 'additional', extra)
            assert_equal(self, old, new)
            self.assertEqual(new.last_rebuild_writes['logical_message'], {'insert': 1, 'update': 0, 'delete': 0})
            self.assertEqual(new.last_rebuild_writes['message_fts'], {'insert': 1, 'update': 0, 'delete': 0})
            self.assertTrue(all(dict(new._db.execute('SELECT logical_id,rowid FROM message_fts'))[key] == value
                                for key, value in rowids.items()))
            before = new._db.total_changes
            new.rebuild_logical()
            self.assertEqual(before, new._db.total_changes)

    def test_representative_conflict_and_candidate_witness_updates_match_reference(self):
        with ArchiveStore(':memory:') as old, LeanArchiveStore(':memory:') as new:
            rows = [observation(native_locator=1, server_id=500, sender_id='wxid_sender_a', body_text='repeat'),
                    observation(native_locator=2, server_id=500, sender_id='wxid_sender_b', body_text='repeat')]
            for store in (old, new):
                import_rows(store, 'base', rows)
            candidate = tuple(new._db.execute('SELECT candidate_id,evidence_json FROM dedupe_candidate').fetchone())
            minimum = min(r[0] for r in new._db.execute('SELECT observation_id FROM message_observation'))
            extra = observation(native_locator=1, server_id=500, sender_id='wxid_sender_a', body_text='repeat')
            snapshot = next('next-'+str(i) for i in range(1000)
                            if new._prepare_row('next-'+str(i), extra)['observation_id'] < minimum)
            for store in (old, new):
                import_rows(store, snapshot, [extra])
            assert_equal(self, old, new)
            updated = tuple(new._db.execute('SELECT candidate_id,evidence_json FROM dedupe_candidate').fetchone())
            self.assertEqual(candidate[0], updated[0])
            self.assertNotEqual(candidate[1], updated[1])
            self.assertEqual(new.last_rebuild_writes['dedupe_candidate']['update'], 1)
            revised = observation(native_locator=3, server_id=500, sender_id='wxid_sender_a', body_text='new conflict text')
            for store in (old, new):
                import_rows(store, 'conflict', [revised])
            assert_equal(self, old, new)
            self.assertTrue(new.last_rebuild_writes['message_fts']['update'])

    def test_logical_key_migration_inserts_new_parent_before_rehoming_children(self):
        with ArchiveStore(':memory:') as old, LeanArchiveStore(':memory:') as new:
            for store in (old, new):
                import_rows(store, 'base', [observation(native_locator=1, server_id=500, body_text='alpha')])
            desired = new._desired_state()
            old_key = desired['logical_message'][0][0]
            migrated = 'msg_migrated_synthetic'
            desired['logical_message'] = [(migrated,)+row[1:] for row in desired['logical_message']]
            desired['message_link'] = [(row[0], migrated)+row[2:] for row in desired['message_link']]
            for store in (old, new):
                with patch.object(store, '_desired_state', return_value=deepcopy(desired)):
                    store.rebuild_logical()
            assert_equal(self, old, new)
            self.assertIsNone(new._db.execute('SELECT 1 FROM logical_message WHERE logical_id=?', (old_key,)).fetchone())
            self.assertEqual(new.last_rebuild_writes['logical_message']['delete'], 1)

    def test_every_derived_phase_failure_rolls_back_original_import_and_results(self):
        for phase in ('logical_message', 'message_link', 'conflict', 'dedupe_candidate'):
            with self.subTest(phase=phase), LeanArchiveStore(':memory:') as store:
                import_rows(store, 'base', [observation(native_locator=1, server_id=500, body_text='alpha')])
                digest = store.semantic_digest()
                real = store._apply_rows

                def fail(table, delta, *, delete=False):
                    real(table, delta, delete=delete)
                    if table == phase and not delete:
                        raise RuntimeError('synthetic stage failure')

                with patch.object(store, '_apply_rows', side_effect=fail):
                    with self.assertRaises(RuntimeError):
                        import_rows(store, 'changed', [observation(native_locator=2, server_id=501, body_text='beta')])
                self.assertEqual(digest, store.semantic_digest())
                self.assertFalse(list(store._db.execute('PRAGMA foreign_key_check')))

    def test_process_exit_mid_transaction_recovers_only_own_new_archive(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'owned.sqlite'
            with LeanArchiveStore(path) as store:
                import_rows(store, 'base', [observation(native_locator=1, server_id=500, body_text='alpha')])
                digest = store.semantic_digest()
            code = '''import os,sys
from wechat_capture_next.merge import LeanArchiveStore
from tests.test_wua_store import observation
with LeanArchiveStore(sys.argv[1]) as store:
 real=store._apply_rows
 def fail(table,delta,*,delete=False):
  real(table,delta,delete=delete)
  if table=='logical_message' and not delete: os._exit(71)
 store._apply_rows=fail
 store.import_observations({'source_id':'synthetic'},{'source_id':'synthetic','snapshot_id':'crash'},[observation(native_locator=2,server_id=501,body_text='beta')])
'''
            run = subprocess.run([sys.executable, '-c', code, str(path)], capture_output=True)
            self.assertEqual(run.returncode, 71, run.stderr)
            with LeanArchiveStore(path) as store:
                self.assertEqual(digest, store.semantic_digest())
                self.assertEqual(store.integrity_check()['quick_check'], ['ok'])

    def test_fts_failure_rolls_back_raw_and_all_derived_changes(self):
        with LeanArchiveStore(':memory:') as store:
            import_rows(store, 'base', [observation(native_locator=1, server_id=500, body_text='alpha')])
            digest = store.semantic_digest()
            fts = list(map(tuple, store._db.execute('SELECT logical_id,body_text FROM message_fts')))
            store._db.set_authorizer(lambda action, arg1, arg2, database, caller:
                sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT and arg1 == 'message_fts' else sqlite3.SQLITE_OK)
            with self.assertRaises(sqlite3.DatabaseError):
                import_rows(store, 'changed', [observation(native_locator=2, server_id=501, body_text='beta')])
            store._db.set_authorizer(None)
            self.assertEqual(digest, store.semantic_digest())
            self.assertEqual(fts, list(map(tuple, store._db.execute('SELECT logical_id,body_text FROM message_fts'))))


if __name__ == '__main__':
    unittest.main()
