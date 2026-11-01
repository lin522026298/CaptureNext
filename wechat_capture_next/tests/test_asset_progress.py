from itertools import count
from contextlib import closing
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from wechat_capture_next import assets
from wechat_capture_next.assets import configure_asset_root
from wechat_capture_next.service import CaptureService
from wechat_capture_next.tests import test_service as fixtures


class AssetProgressTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    tearDown = fixtures.ServiceTests.tearDown
    pages = fixtures.ServiceTests.pages
    publish = fixtures.ServiceTests.publish
    init_service = fixtures.ServiceTests.init_service

    def prepare(self):
        service = self.init_service()
        root = service.root.parent/'msg'
        root.mkdir()
        (root/'a.dat').write_bytes(b'a'*(assets.CHUNK_BYTES*5))
        (root/'b.dat').write_bytes(b'b'*(assets.CHUNK_BYTES*5))
        configure_asset_root(service,root)
        service.close()
        service = CaptureService(service.state)
        self.addCleanup(service.close)
        with patch.object(assets.time,'monotonic',side_effect=count().__next__):
            first = service.capture(force=True,assets=True,asset_budget_seconds=.5)
        self.assertFalse(first['assets']['complete'])
        return service

    def tearDown(self):
        self.doCleanups()
        fixtures.ServiceTests.tearDown(self)

    def step(self, service):
        with patch.object(assets.time,'monotonic',side_effect=count().__next__):
            return service.capture(assets=True,asset_budget_seconds=.5)

    def test_many_slices_persist_one_continuation_report_and_all_history(self):
        service = self.prepare()
        identifiers = set()
        for _ in range(100):
            result = self.step(service)
            identifiers.add(result['cycle_id'])
            if result.get('assets',{}).get('complete'):
                break
        else:
            self.fail('synthetic assets failed to complete')
        self.assertEqual(len(identifiers),1)
        self.assertEqual(service.catalog.db.execute('SELECT count(*) FROM cycle').fetchone()[0],2)
        report = json.loads(service.catalog.report(identifiers.pop()))
        self.assertEqual(report['status'],'local_complete')
        self.assertGreater(report['rounds'],2)
        self.assertTrue(report['assets']['complete'])
        self.assertEqual(service.catalog.db.execute('SELECT count(*) FROM asset_history').fetchone()[0],2)
        self.assertEqual(service.catalog.db.execute('SELECT count(*) FROM version').fetchone()[0],40)
        self.assertTrue(service.verify_state()['pass'])

    def test_normal_full_completion_closes_prior_batch_with_true_completion(self):
        service = self.prepare()
        first = self.step(service)
        result = service.capture(force=True,assets=True)
        self.assertTrue(result['assets']['complete'])
        report = json.loads(service.catalog.report(first['cycle_id']))
        self.assertEqual(report['status'],'local_complete')
        self.assertTrue(report['assets']['complete'])
        self.assertEqual(report['completion_cycle'],result['cycle_id'])
        self.assertIsNone(service._asset_batch)

    def test_failed_slice_tail_never_completes_until_whole_pass_retries(self):
        service = self.prepare()
        with patch.object(assets.PendingImport,'advance',
                          side_effect=RuntimeError('synthetic source read failure')):
            failed = self.step(service)
        self.assertEqual(failed['status'],'partial')
        self.assertFalse(failed['assets']['complete'])
        self.assertTrue(failed['errors'])
        self.assertTrue(service._asset_pass_failed)
        self.assertIsNotNone(service._asset_iterator)

        # The remaining tail may still land useful observations, but it cannot
        # turn a pass with an unverified prefix into a completed local archive.
        for _ in range(100):
            if service._asset_iterator is None:
                break
            tail = self.step(service)
            self.assertEqual(tail['status'],'partial')
            self.assertFalse(tail['assets']['complete'])
            self.assertIn('previous_asset_slice_failed',
                          {error['error_type'] for error in tail['errors']})
            stored = json.loads(service.catalog.report(tail['cycle_id']))
            self.assertEqual(stored['status'],'partial')
            self.assertFalse(stored['assets']['complete'])
        else:
            self.fail('failed pass tail did not terminate')
        self.assertEqual([row[0] for row in service.catalog.db.execute(
            'SELECT relative_path FROM asset')],['b.dat'])
        self.assertTrue(service._asset_notifications.poll()['full_required'])
        self.assertTrue(assets.assets_need_scan(service))

        for _ in range(100):
            retry = self.step(service)
            self.assertFalse(retry['errors'])
            if retry['assets']['complete']:
                break
            self.assertEqual(retry['status'],'local_complete_assets_pending')
        else:
            self.fail('complete retry did not finish')
        self.assertEqual(retry['status'],'local_complete')
        self.assertEqual({row[0] for row in service.catalog.db.execute(
            'SELECT relative_path FROM asset')},{'a.dat','b.dat'})
        self.assertEqual(service.catalog.db.execute(
            'SELECT count(*) FROM asset_history').fetchone()[0],2)
        self.assertFalse(assets.assets_need_scan(service))
        self.assertTrue(service.verify_state()['pass'])

    def test_safe_close_marks_one_partial_batch_interrupted_without_losing_files(self):
        service = self.prepare()
        pending = self.step(service)
        state = service.state
        service.close()
        with closing(CaptureService(state)) as reopened:
            report = json.loads(reopened.catalog.report(pending['cycle_id']))
            self.assertEqual(report['status'],'interrupted')
            self.assertTrue(reopened.capture(force=True,assets=True)['assets']['complete'])
            self.assertTrue(reopened.verify_state()['pass'])
