from contextlib import closing
from pathlib import Path
import hashlib
import os
import sqlite3
import unittest
from unittest.mock import patch

from wechat_capture_next.tests import test_service as fixtures
from wechat_capture_next.sync_wua import sync_wua
from wechat_capture_next.exports import export_wua
from wechat_capture_next.merge import LeanArchiveStore
from wechat_capture_v2.tests.test_backend import TABLE


class SyncTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    tearDown = fixtures.ServiceTests.tearDown
    pages = fixtures.ServiceTests.pages
    publish = fixtures.ServiceTests.publish
    init_service = fixtures.ServiceTests.init_service

    def digest(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def change(self):
        with closing(sqlite3.connect(self.plain)) as db, db:
            db.execute(f'UPDATE "{TABLE}" SET message_content=? WHERE local_id=1', ('revision',))
            db.execute(f'INSERT INTO "{TABLE}" VALUES(-99,777,1,7,1,?,NULL,NULL,-999)', ('old backlog',))
        self.publish()

    def test_fresh_incremental_and_noop_equal_full_export(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            target = self.root/'managed'
            first = sync_wua(service, target, verify=True)
            self.assertEqual(first['added_observations'], 40)
            self.assertEqual(first['semantic_digest'], export_wua(service, self.root/'first.sqlite')['semantic_digest'])
            path = target/'archive.wua.sqlite'
            before = self.digest(path)
            self.assertEqual(sync_wua(service, target)['added_observations'], 0)
            self.assertEqual(before, self.digest(path))
            self.change()
            service.capture(force=True)
            result = sync_wua(service, target, verify=True)
            self.assertEqual(result['added_versions'], 2)
            self.assertEqual(result['semantic_digest'], export_wua(service, self.root/'second.sqlite')['semantic_digest'])
            self.assertEqual(result['integrity']['quick_check'], ['ok'])
            self.assertFalse(result['integrity']['foreign_key_check'])

    def test_failure_rolls_back_import_tracking_and_can_retry(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            target = self.root/'managed'
            first = sync_wua(service, target, verify=True)
            self.change()
            service.capture(force=True)
            real = LeanArchiveStore._apply_rows

            def fail(store, table, delta, *, delete=False):
                real(store, table, delta, delete=delete)
                if table == 'message_link' and not delete:
                    raise RuntimeError('synthetic interruption')

            with patch.object(LeanArchiveStore, '_apply_rows', fail):
                with self.assertRaises(RuntimeError):
                    sync_wua(service, target)
            with LeanArchiveStore(target/'archive.wua.sqlite') as archive:
                self.assertEqual(first['semantic_digest'], archive.semantic_digest())
                self.assertEqual(archive._db.execute('SELECT count(*) FROM next_imported_version').fetchone()[0], 40)
            retried = sync_wua(service, target, verify=True)
            self.assertEqual(retried['added_versions'], 2)
            self.assertEqual(retried['semantic_digest'], export_wua(service, self.root/'fresh.sqlite')['semantic_digest'])

    def test_foreign_directory_and_source_overlap_refused_without_touching_files(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            foreign = self.root/'old-output'
            foreign.mkdir()
            path = foreign/'archive.wua.sqlite'
            path.write_bytes(b'protected historical file')
            before = self.digest(path)
            with self.assertRaises(FileNotFoundError):
                sync_wua(service, foreign)
            self.assertEqual(before, self.digest(path))
            with self.assertRaises(ValueError):
                sync_wua(service, service.root/'new-output')

    def test_tracking_failure_after_fts_update_rolls_everything_back(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            target = self.root/'managed'
            first = sync_wua(service, target, verify=True)
            self.change()
            service.capture(force=True)
            with closing(sqlite3.connect(target/'archive.wua.sqlite')) as db:
                db.execute('''CREATE TRIGGER fail_tracking AFTER INSERT ON next_imported_version
                    BEGIN SELECT RAISE(ABORT,'synthetic tracking failure'); END''')
            with self.assertRaises(sqlite3.IntegrityError):
                sync_wua(service, target)
            with LeanArchiveStore(target/'archive.wua.sqlite') as archive:
                self.assertEqual(archive.semantic_digest(), first['semantic_digest'])
                self.assertEqual(archive._db.execute('SELECT count(*) FROM next_imported_version').fetchone()[0], 40)
                archive._db.execute('DROP TRIGGER fail_tracking')
            result = sync_wua(service, target, verify=True)
            self.assertEqual(result['semantic_digest'], export_wua(service, self.root/'retried.sqlite')['semantic_digest'])

    def test_attached_source_is_readonly(self):
        with closing(self.init_service()) as service, closing(sqlite3.connect(':memory:', uri=True)) as db:
            db.execute('ATTACH DATABASE ? AS source', ((service.state/'catalog.sqlite').as_uri()+'?mode=ro',))
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("INSERT INTO source.meta VALUES('forbidden','write')")

    def test_dangling_output_and_sidecar_links_refused(self):
        from wechat_capture_next.sync_wua import catalog_identity, owned_directory
        with closing(self.init_service()) as service:
            target = self.root/'managed'
            path = owned_directory(service, target, catalog_identity(service))
            path.unlink()  # Own empty synthetic output only.
            outside = self.root/'must-not-be-created.sqlite'
            try:
                path.symlink_to(outside)
            except OSError as exc:
                self.skipTest('local account cannot create symlinks: '+str(exc))
            with self.assertRaises(ValueError):
                sync_wua(service, target)
            self.assertFalse(outside.exists())
            path.unlink()
            journal = path.with_name(path.name+'-journal')
            journal.symlink_to(outside)
            with self.assertRaises(ValueError):
                sync_wua(service, target)
            self.assertFalse(outside.exists())

    def test_hardlinked_output_refused(self):
        from wechat_capture_next.sync_wua import catalog_identity, owned_directory
        with closing(self.init_service()) as service:
            target = self.root/'managed'
            path = owned_directory(service, target, catalog_identity(service))
            os.link(path, self.root/'protected-file')
            with self.assertRaises(ValueError):
                sync_wua(service, target)

    def test_reinterpretation_and_source_regression_are_not_silently_skipped(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            target = self.root/'managed'
            sync_wua(service, target)
            with service.catalog.db:
                row = service.catalog.db.execute('SELECT id,normalized_json,first_capture FROM version LIMIT 1').fetchone()
                import json
                normalized = json.loads(row['normalized_json'])
                normalized['body_text'] = 'explicit revised interpretation'
                from wechat_capture_v2.common import canonical
                text = canonical(normalized)
                service.catalog.db.execute('''INSERT INTO db_capture SELECT 'new-interpretation-capture',cycle_id,
                    source_id,relative_path,signature,evidence_json,message_count,accepted FROM db_capture WHERE id=?''',
                    (row['first_capture'],))
                service.catalog.db.execute('INSERT INTO interpretation VALUES(?,?,?,?)',
                    (row['id'], hashlib.sha256(text.encode()).hexdigest(), text, 'new-interpretation-capture'))
            revised = sync_wua(service, target, verify=True)
            self.assertEqual(revised['added_interpretations'], 1)
            self.assertEqual(revised['semantic_digest'], export_wua(service, self.root/'interpreted.sqlite')['semantic_digest'])
            # Simulate a target imported from a later source generation. Do
            # not bypass the catalog's immutable-record protection triggers.
            with closing(sqlite3.connect(target/'archive.wua.sqlite')) as db, db:
                db.execute("INSERT INTO next_imported_version VALUES('absent-from-restored-source')")
            before = self.digest(target/'archive.wua.sqlite')
            with self.assertRaisesRegex(ValueError, 'regressed'):
                sync_wua(service, target)
            self.assertEqual(before, self.digest(target/'archive.wua.sqlite'))


if __name__ == '__main__':
    unittest.main()
