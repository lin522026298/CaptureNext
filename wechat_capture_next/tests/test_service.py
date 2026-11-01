from contextlib import closing
import hashlib
import json
import sqlite3
import unittest
from unittest.mock import patch

from wechat_capture_next.service import CaptureService, initialize
from wechat_capture_next.merge import LeanArchiveStore
from wechat_capture_v2.common import canonical
from wechat_capture_v2.compare import compare_native
from wechat_capture_v2.service import CaptureService as OldService, initialize as old_initialize
from wechat_capture_v2.tests.test_backend import TABLE, KEY
from wechat_capture_next.tests import test_materialize as materialize_tests
from wua.store import ArchiveStore


class ServiceTests(unittest.TestCase):
    # Reuse fixture helpers, without accidentally discovering/running the
    # materializer's entire test class a second and third time.
    setUp = materialize_tests.ChangedWriteTests.setUp
    tearDown = materialize_tests.ChangedWriteTests.tearDown
    pages = materialize_tests.ChangedWriteTests.pages
    publish = materialize_tests.ChangedWriteTests.publish
    def init_service(self):
        self.keys = self.root/'keys.json'
        self.keys.write_text(canonical({'databases': [{'relative_path': self.source.name,
            'verified': True, 'raw_encryption_key_hex': KEY.hex()}]}), encoding='utf-8')
        # Only the encrypted DB is placed inside this isolated source tree.
        live = self.root/'account'/'db_storage'
        live.mkdir(parents=True)
        self.source = self.source.replace(live/self.source.name)
        self.wal = self.source.with_name(self.source.name+'-wal')
        state = self.root/'state'
        initialize(state, live, self.keys, source_id='fixture', account_alias='fixture', self_username='self')
        return CaptureService(state)

    def test_capture_restart_backlog_edits_delete_and_no_old_state_upgrade(self):
        service = self.init_service()
        state = service.state
        try:
            report = service.capture(force=True)
            self.assertEqual(report['status'], 'local_complete')
            self.assertEqual(report['summary']['active_messages'], 40)
        finally:
            service.close()
        with closing(sqlite3.connect(self.plain)) as db, db:
            db.execute(f'UPDATE "{TABLE}" SET message_content=? WHERE local_id=1', ('revision',))
            db.execute(f'DELETE FROM "{TABLE}" WHERE local_id=2')
            db.execute(f'INSERT INTO "{TABLE}" VALUES(-99,777,1,7,1,?,NULL,NULL,-999)', ('old backlog',))
        self.publish()
        with closing(CaptureService(state)) as service:
            report = service.capture(force=True)
            self.assertEqual(report['status'], 'local_complete')
            self.assertEqual(report['databases'][0]['new_versions'], 2)
            self.assertTrue(compare_native(service.catalog, 'fixture', self.source.name, self.plain)['pass'])
            self.assertTrue(service.verify_state()['pass'])
            self.assertEqual(service.objects.db.execute('SELECT count(*) FROM file').fetchone()[0], 0)
            self.assertEqual(service.capture()['status'], 'idle')
        old = self.root/'old-state'
        old_initialize(old, self.source.parent, self.keys, source_id='fixture', account_alias='fixture')
        with self.assertRaises(FileNotFoundError):
            CaptureService(old)

    def test_failed_capture_does_not_advance_checkpoint(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            previous = service.catalog.checkpoint('fixture', self.source.name)['capture_id']
            blob = bytearray(self.source.read_bytes())
            blob[-1] ^= 1
            self.source.write_bytes(blob)
            report = service.capture(force=True, retries=1)
            self.assertEqual(report['status'], 'partial')
            self.assertEqual(previous, service.catalog.checkpoint('fixture', self.source.name)['capture_id'])

    def test_dirty_missing_view_and_binding_change_bypass_metadata_idle(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            view = service.view_path(self.source.name)
            view.with_suffix('.dirty').write_text('interrupted', encoding='utf-8')
            self.assertEqual(service.capture()['status'], 'local_complete')
            view.unlink()
            self.assertEqual(service.capture()['status'], 'local_complete')
            service.interpretation_binding += '-new-reader'
            rebound = service.capture()
            self.assertEqual(rebound['status'], 'local_complete')
            self.assertEqual(rebound['databases'][0]['changed_plain_pages'], 0)
            self.assertEqual(rebound['databases'][0]['rows'], 40)
            self.assertEqual(service.capture()['status'], 'idle')

    def test_missing_source_is_partial_not_crash_or_checkpoint_advance(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            self.source.unlink()
            self.assertEqual(service.capture()['status'], 'partial')

    def test_ingest_failure_after_view_ready_is_retried_without_source_change(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            previous = service.catalog.checkpoint('fixture', self.source.name)['capture_id']
            with patch.object(service.catalog, 'ingest', side_effect=RuntimeError('synthetic ingest failure')):
                self.assertEqual(service.capture(force=True, retries=1)['status'], 'partial')
            view = service.view_path(self.source.name)
            self.assertTrue(view.with_suffix('.pending').exists())
            self.assertEqual(previous, service.catalog.checkpoint('fixture', self.source.name)['capture_id'])
            self.assertEqual(service.capture()['status'], 'local_complete')
            self.assertFalse(view.with_suffix('.pending').exists())

    def test_wua_export_equals_baseline_from_identical_catalog(self):
        from wechat_capture_v2.export import export_wua as previous_export
        from wechat_capture_next.exports import export_wua
        from wechat_capture_next.catalog import Catalog
        # Frozen v2 exporter requires table rowid; compare before/after the
        # explicit next-only extension rather than silently modifying v2.
        with patch.object(Catalog, 'enable_compact', return_value=False):
            service = self.init_service()
        with closing(service):
            service.capture(force=True)
            old = previous_export(service, self.root/'old.wua.sqlite')
            service.catalog.enable_compact()
            new = export_wua(service, self.root/'new.wua.sqlite')
            self.assertEqual(old, new)

    def test_identical_authenticated_view_reuses_rows_but_explicit_full_still_scans(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            with patch.object(service.catalog, 'ingest', side_effect=RuntimeError('must not scan')):
                report = service.capture(force=True, reuse_identical=True)
                self.assertEqual(report['status'], 'local_complete')
                self.assertTrue(report['databases'][0]['verified_identical_decoded_rows_reused'])
            report = service.capture(force=True)
            self.assertEqual(report['databases'][0]['rows'], 40)

    def test_independent_native_and_same_cut_validation(self):
        from wechat_capture_next.validate_current import validate
        with closing(self.init_service()) as service:
            service.capture(force=True)
            result = validate(service, self.root/'comparison')
            self.assertTrue(result['pass_all'])
            self.assertEqual(result['matched_native_rows'], 40)
            self.assertEqual(result['same_cut_matches_accepted_views'], 1)

    def test_partial_restore_fails_before_any_startup_writes(self):
        from wechat_capture_v2.common import digest_file
        with closing(self.init_service()) as service:
            service.capture(force=True)
            state = service.state
        before = digest_file(state/'catalog.sqlite')
        (state/'RESTORE.partial.private.json').write_text('{}',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'incomplete restored'):
            CaptureService(state)
        self.assertEqual(digest_file(state/'catalog.sqlite'), before)


class MergeProjectionTests(unittest.TestCase):
    def test_all_rules_conflicts_fts_and_candidate_witnesses_unchanged(self):
        from tests.test_wua_store import observation
        with ArchiveStore(':memory:') as old, LeanArchiveStore(':memory:') as new:
            for snapshot, source in [('one', 'pc1'), ('two', 'pc2')]:
                rows = [observation(native_locator=i, server_id=100+i//3,
                    body_text=['alpha beta', 'alpha revision', 'repeated'][i%3],
                    raw_record={'id': i, 'blob': b'large-opaque'*4000}) for i in range(12)]
                rows.extend([observation(native_locator=100+i, server_id=None,
                    conversation_id='unknown', body_text='same repeated', event_time=1700000000+i*.1)
                    for i in range(8)])
                for store in (old, new):
                    store.import_observations({'source_id': source}, {'source_id': source, 'snapshot_id': snapshot}, rows)
            self.assertEqual(old.semantic_digest(), new.semantic_digest())
            self.assertEqual(old._desired_state(), new._desired_state())
            self.assertEqual([tuple(r) for r in old._db.execute('SELECT * FROM message_fts ORDER BY logical_id')],
                [tuple(r) for r in new._db.execute('SELECT * FROM message_fts ORDER BY logical_id')])
            self.assertFalse(new.rebuild_logical()['rebuild_changed'])


if __name__ == '__main__':
    unittest.main()
