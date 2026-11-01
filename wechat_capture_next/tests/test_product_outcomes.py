import unittest
from unittest.mock import patch
from wechat_capture_next.tests import test_product as live
from wechat_capture_next.tests import test_recovery_core as offline
from wechat_capture_next.tests import test_product_auto_pipelines as automatic
from wechat_capture_next.tests import test_asset_progress as progress
from wechat_capture_next.product import _asset_outcome


class ActualAssetReportTests(unittest.TestCase):
    setUp=progress.AssetProgressTests.setUp
    tearDown=progress.AssetProgressTests.tearDown
    pages=progress.AssetProgressTests.pages
    publish=progress.AssetProgressTests.publish
    init_service=progress.AssetProgressTests.init_service
    prepare=progress.AssetProgressTests.prepare
    step=progress.AssetProgressTests.step

    def test_actual_continuation_then_full_completion(self):
        service=self.prepare()
        pending=self.step(service)['assets']
        self.assertFalse(pending['complete']);self.assertNotIn('status',pending)
        self.assertEqual(_asset_outcome(pending)['status'],'warning')
        completed=service.capture(force=True,assets=True)['assets']
        result=_asset_outcome(completed)
        self.assertEqual(result['status'],'completed')
        self.assertEqual(result['details']['files_seen'],completed['files_seen'])
        self.assertEqual(result['details']['new_versions'],completed['new_versions'])

    def test_actual_source_read_failure_is_failed_not_a_partial_success(self):
        service=self.prepare()
        with patch('wechat_capture_next.assets.PendingImport.advance',side_effect=FileNotFoundError('private-source')):
            report=self.step(service)['assets']
        result=_asset_outcome(report)
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['error_type'],'FileNotFoundError')
        self.assertEqual(result['details']['errors_count'],len(report['errors']))
        self.assertNotIn('private-source',str(result))


class AssetOutcomeTests(unittest.TestCase):
    setUp=automatic.AutomaticPipelineTests.setUp
    core=automatic.AutomaticPipelineTests.core
    saved=automatic.AutomaticPipelineTests.saved

    def project(self,assets,mode='changed_shards'):
        core=self.core();core._sync_pending=False;core.identity_status=dict(status='ready')
        core._after_capture(dict(mode=mode,databases=[],assets=assets,errors=assets.get('errors',[])))
        return core,self.saved('assets')

    def test_real_complete_shape_is_success_with_counts_and_scope(self):
        core,result=self.project(dict(enabled=True,complete=True,errors=[],files_seen=7,new_versions=2,
            bytes_seen=900,verified_unchanged_files=3,verified_unchanged_bytes=400))
        self.assertEqual(result['outcome'],'completed');self.assertFalse(result['pending'])
        self.assertEqual(result['reason'],'configured_local_asset_tree_only')
        self.assertEqual(result['details']['files_seen'],7)
        self.assertEqual(result['details']['new_versions'],2)
        self.assertEqual(result['details']['verified_unchanged_bytes'],400)
        self.assertEqual(result['details']['errors_count'],0)
        self.assertIsNotNone(result['last_success'])
        self.assertEqual(self.core().journal.pipelines['assets'],result)

    def test_partial_scan_and_pending_file_are_not_successes(self):
        for extra,reason in (({},'asset_scan_pending'),
            (dict(pending_phase='verify',pending_bytes=200,pending_processed_bytes=80),'asset_import_pending')):
            with self.subTest(reason=reason):
                _,result=self.project(dict(enabled=True,complete=False,errors=[],files_seen=1,new_versions=1,**extra),
                                      mode='asset_continuation')
                self.assertEqual(result['outcome'],'warning');self.assertTrue(result['pending'])
                self.assertEqual(result['reason'],reason);self.assertTrue(result['next_step'])
                self.assertNotIn('last_success',result)
                if extra:self.assertEqual(result['details']['pending_processed_bytes'],80)

    def test_errors_and_failed_pass_tail_preserve_previous_success_without_private_text(self):
        core,success=self.project(dict(enabled=True,complete=True,errors=[],files_seen=2,new_versions=1))
        for error_type in ('FileNotFoundError','previous_asset_slice_failed'):
            with self.subTest(error_type=error_type):
                errors=[dict(error_type=error_type,path='private-path',detail_private='private-detail')]
                core._after_capture(dict(mode='asset_continuation',databases=[],errors=errors,
                    assets=dict(enabled=True,complete=True,files_seen=1,new_versions=1,errors=errors)))
                result=self.saved('assets')
                self.assertEqual(result['outcome'],'failed');self.assertTrue(result['pending'])
                self.assertEqual(result['reason'],'asset_source_errors')
                self.assertEqual(result['error_type'],error_type)
                self.assertEqual(result['details']['errors_count'],1)
                self.assertEqual(result['details']['new_versions'],1)
                self.assertEqual(result['last_success'],success['last_success'])
                self.assertNotIn('private-path',self.path.read_text(encoding='utf-8'))
                self.assertNotIn('private-detail',self.path.read_text(encoding='utf-8'))

    def test_disabled_unknown_or_contradictory_completion_never_turns_green(self):
        for assets,reason in ((dict(enabled=False,complete=True,errors=[]),'asset_source_not_configured'),
            (dict(status='completed',errors=[]),'asset_completion_unconfirmed'),
            (dict(enabled=True,complete=True,errors=[],pending_phase='store'),'asset_import_pending')):
            with self.subTest(reason=reason):
                _,result=self.project(assets)
                self.assertEqual(result['outcome'],'warning');self.assertEqual(result['reason'],reason)
                self.assertNotIn('last_success',result)

    def test_metadata_poll_does_not_rewrite_asset_health(self):
        core,_=self.project(dict(enabled=True,complete=True,errors=[],files_seen=0,new_versions=0))
        before=self.path.read_bytes()
        core._after_capture(dict(mode='metadata_poll',databases=[],assets=dict(enabled=False,complete=True,errors=[])))
        self.assertEqual(self.path.read_bytes(),before)


class LiveOutcomeTests(unittest.TestCase):
    setUp=live.ProductTests.setUp
    tearDown=live.ProductTests.tearDown
    pages=live.ProductTests.pages
    publish=live.ProductTests.publish
    init_service=live.ProductTests.init_service
    prepared=live.ProductTests.prepared
    core=live.ProductTests.core
    wait=live.ProductTests.wait

    def test_saved_unsupported_never_overwrites_durable_warning_with_completed(self):
        core=self.core()
        with patch.object(core,'_perform',return_value=dict(status='saved_unsupported',raw_preserved=True)):
            job=core.submit(dict(action='index_media'));result=self.wait(core,job,status='warning')
        self.assertEqual(core.journal.records[job['id']]['job']['status'],result['status'])


class RecoveryOutcomeTests(unittest.TestCase):
    setUp=offline.RecoveryTests.setUp
    tearDown=offline.RecoveryTests.tearDown
    pages=offline.RecoveryTests.pages
    publish=offline.RecoveryTests.publish
    init_service=offline.RecoveryTests.init_service
    prepared=offline.RecoveryTests.prepared
    setup_copy=offline.RecoveryTests.setup_copy
    core=offline.RecoveryTests.core
    wait=offline.RecoveryTests.wait

    def test_no_key_queue_preserves_warning_outcome(self):
        self.setup_copy();core=self.core()
        with patch.object(core,'_execute',return_value=dict(status='saved_unsupported',raw_preserved=True)):
            job=core.submit(dict(action='load_image_keys',path=str(self.root/'unused.json')))
            self.wait(core,job,expected='warning')
        self.assertEqual(core.journal.records[job['id']]['job']['status'],'warning')

if __name__=='__main__':unittest.main()
