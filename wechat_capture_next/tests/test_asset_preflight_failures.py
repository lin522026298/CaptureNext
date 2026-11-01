"""Source preflight failures through real synthetic service/product paths."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from wechat_capture_next import assets, service as service_module
from wechat_capture_next.asset_notifications import NotificationLedger
from wechat_capture_next.service import CaptureService
from wechat_capture_next.tests import test_assets as asset_fixtures
from wechat_capture_next.tests import test_product as product_fixtures
from wechat_capture_v2.common import digest_file
from wechat_capture_v2.objects import CHUNK_BYTES, PendingImport


class AssetPreflightTests(unittest.TestCase):
    setUp = asset_fixtures.AssetTests.setUp
    tearDown = asset_fixtures.AssetTests.tearDown
    add_media = asset_fixtures.AssetTests.add_media
    capture = asset_fixtures.AssetTests.capture

    def arm(self):
        self.ledger = NotificationLedger()
        observer = SimpleNamespace(root=self.media, poll=self.ledger.poll,
            begin=self.ledger.begin, complete=self.ledger.complete,
            require_full_bytes=self.ledger.invalidate, close=lambda: None)
        self.service._asset_notifications = observer
        return observer

    def test_preflight_failure_preserves_published_and_pending_cas_and_forces_bytes_without_observer_ack(self):
        original = self.add_media(data=b'original')
        observer = self.arm()
        self.assertTrue(self.capture()['complete'])
        self.assertFalse(assets.assets_need_scan(self.service))
        published = list(self.service.catalog.db.execute('SELECT * FROM asset_history'))
        pending_path = self.add_media('pending.dat', b'p' * (CHUNK_BYTES * 3))
        pending = PendingImport(self.service.objects, pending_path)
        self.assertIsNone(pending.advance(0))
        self.service._pending_asset = ('pending.dat', pending_path, pending)
        self.service._asset_iterator = iter([('pending.dat', pending_path)])
        chunks = list(self.service.objects.db.execute('SELECT hash,bytes,data FROM chunk ORDER BY hash'))
        observer.complete = Mock(wraps=self.ledger.complete)
        observer.require_full_bytes = Mock(side_effect=RuntimeError('secondary-private-observer-failure'))
        with patch.object(assets, '_parents', side_effect=PermissionError('private-source-failure')):
            failed = self.capture()
        self.assertEqual(failed['errors'], [dict(error_type='PermissionError', phase='asset_preflight')])
        self.assertFalse(failed['complete'])
        self.assertNotIn('private-', str(failed))
        self.assertIsNone(self.service._pending_asset)
        self.assertIsNone(self.service._asset_iterator)
        observer.complete.assert_not_called()
        self.assertEqual(published, list(self.service.catalog.db.execute('SELECT * FROM asset_history')))
        self.assertEqual(chunks, list(self.service.objects.db.execute('SELECT hash,bytes,data FROM chunk ORDER BY hash')))
        self.assertFalse(self.ledger.poll()['full_required'])
        self.assertTrue(assets.assets_need_scan(self.service))
        before = original.stat()
        original.write_bytes(b'revision')
        os.utime(original, ns=(before.st_atime_ns, before.st_mtime_ns))
        retried = self.capture()
        self.assertTrue(retried['complete'])
        self.assertEqual(retried['byte_verification'], 'full_sweep')
        self.assertEqual(retried['new_versions'], 2)
        current = dict(self.service.catalog.db.execute('SELECT relative_path,file_sha FROM asset'))
        self.assertEqual(current['a.dat'], digest_file(original))
        self.assertFalse(self.service._asset_preflight_retry)
        self.assertFalse(assets.assets_need_scan(self.service))

    def test_programming_and_configuration_checks_remain_exceptions_and_disabled_remains_disabled(self):
        for budget in (0, -1):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                self.capture(budget_seconds=budget)
        with self.assertRaises(TypeError):
            self.capture(budget_seconds='invalid')
        with patch.object(assets.os.path, 'lexists', return_value=True):
            with self.assertRaisesRegex(ValueError, 'configuration recovery'):
                self.capture()
        saved = self.service.config.pop('asset_root')
        try:
            self.assertFalse(self.capture(budget_seconds=0)['enabled'])
        finally:
            self.service.config['asset_root'] = saved

    def test_baseexceptions_and_post_preflight_exceptions_are_not_reclassified(self):
        for error in (KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(error=type(error).__name__), \
                    patch.object(assets, '_notifications', side_effect=error):
                with self.assertRaises(type(error)):
                    self.capture()
        self.arm()
        with patch.object(assets.time, 'monotonic', side_effect=RuntimeError('after-preflight')):
            with self.assertRaisesRegex(RuntimeError, 'after-preflight'):
                self.capture()

    def test_reopened_service_still_requires_bytes_after_preflight_failure(self):
        self.add_media()
        self.assertTrue(self.capture()['complete'])
        with patch.object(assets, '_notifications', side_effect=PermissionError('source-unavailable')):
            self.assertFalse(self.capture()['complete'])
        self.service.close()
        self.service = CaptureService(self.state)
        self.assertTrue(assets.assets_need_scan(self.service))
        self.assertEqual(self.capture()['byte_verification'], 'full_sweep')


class ProductAssetPreflightTests(unittest.TestCase):
    setUp = product_fixtures.ProductTests.setUp
    tearDown = product_fixtures.ProductTests.tearDown
    pages = product_fixtures.ProductTests.pages
    publish = product_fixtures.ProductTests.publish
    init_service = product_fixtures.ProductTests.init_service
    prepared = product_fixtures.ProductTests.prepared
    core = product_fixtures.ProductTests.core
    wait = product_fixtures.ProductTests.wait

    def prepare(self):
        self.service_source_sha = digest_file(Path(service_module.__file__))
        core = self.core()
        root = Path(core.config['database_root']).parent / 'synthetic-assets'
        root.mkdir()
        (root/'one.dat').write_bytes(b'accepted original attachment')
        self.wait(core, core.submit(dict(action='configure_assets', root=str(root))))
        self.wait(core, core.submit(dict(action='capture', full=True, assets=True)))
        self.assertEqual(core.journal.pipelines['assets']['outcome'], 'completed')
        return core, root, dict(core.journal.pipelines['assets']), core.service.interpretation_binding

    def failed(self, core, success, error_type):
        current = core.journal.pipelines['assets']
        self.assertEqual(current['outcome'], 'failed')
        self.assertTrue(current['pending'])
        self.assertEqual(current['error_type'], error_type)
        self.assertEqual(current['last_success'], success['last_success'])
        self.assertEqual(current['last_success_details'], success['details'])
        self.assertNotIn('private-source-failure', core.journal.path.read_text(encoding='utf-8'))

    def retry(self, core, success, binding):
        job = self.wait(core, core.submit(dict(action='capture', full=False, assets=True)))
        current = core.journal.pipelines['assets']
        self.assertEqual(current['outcome'], 'completed')
        self.assertFalse(current['pending'])
        self.assertIsNone(current['error_type'])
        self.assertNotEqual(current['last_success'], success['last_success'])
        with closing(sqlite3.connect((core.state/'catalog.sqlite').as_uri()+'?mode=ro', uri=True)) as database:
            report = json.loads(database.execute('SELECT report_json FROM cycle WHERE id=?',
                (job['result']['cycle_id'],)).fetchone()[0])
            self.assertEqual(database.execute('SELECT count(*) FROM asset_history').fetchone()[0], 2)
        self.assertEqual(report['assets']['byte_verification'], 'full_sweep')
        self.assertEqual(core.service.interpretation_binding, binding)
        self.assertEqual(digest_file(Path(service_module.__file__)), self.service_source_sha)

    def test_full_capture_real_nondirectory_source_then_full_byte_retry(self):
        core, root, success, binding = self.prepare()
        observer = getattr(core.service, '_asset_notifications', None)
        if observer is not None:
            observer.close()
            core.service._asset_notifications = None
        offline = root.with_name(root.name+'-offline')
        root.rename(offline)
        root.write_bytes(b'synthetic nondirectory unavailable source')
        self.wait(core, core.submit(dict(action='capture', full=True, assets=True)), status='warning')
        self.failed(core, success, 'ValueError')
        root.unlink()
        offline.rename(root)
        self.assertEqual((root/'one.dat').read_bytes(), b'accepted original attachment')
        (root/'two.dat').write_bytes(b'new attachment after recovery')
        self.retry(core, success, binding)

    def test_asset_only_capture_observer_failure_then_full_byte_retry(self):
        core, root, success, binding = self.prepare()
        with patch.object(assets, '_notifications', side_effect=PermissionError('private-source-failure')):
            self.wait(core, core.submit(dict(action='capture', full=False, assets=True)), status='warning')
        self.failed(core, success, 'PermissionError')
        (root/'two.dat').write_bytes(b'new attachment after recovery')
        self.retry(core, success, binding)

    def test_background_watch_observer_failure_then_full_byte_retry(self):
        core, root, success, binding = self.prepare()
        with patch.object(assets, '_notifications', side_effect=PermissionError('private-source-failure')):
            self.wait(core, core.submit(dict(action='start_watch')))
            end = time.monotonic()+5
            while time.monotonic() < end:
                if core.journal.pipelines['assets']['outcome'] == 'failed' and core.watch_error == 'partial':
                    break
                time.sleep(.01)
            else:
                self.fail('synthetic watch failed to publish the asset source failure')
            self.wait(core, core.submit(dict(action='stop_watch')))
        self.failed(core, success, 'PermissionError')
        (root/'two.dat').write_bytes(b'new attachment after recovery')
        self.retry(core, success, binding)


if __name__ == '__main__':
    unittest.main()
