import unittest
from unittest.mock import patch

from wechat_capture_next.product import ProductCore
from wechat_capture_next.product_settings import DEFAULTS
from wechat_capture_next.tests import test_product as fixtures


class ProductCollectionTests(unittest.TestCase):
    setUp=fixtures.ProductTests.setUp
    tearDown=fixtures.ProductTests.tearDown
    pages=fixtures.ProductTests.pages
    publish=fixtures.ProductTests.publish
    init_service=fixtures.ProductTests.init_service
    prepared=fixtures.ProductTests.prepared
    wait=fixtures.ProductTests.wait

    def core(self):
        self.prepared()
        with patch('wechat_capture_next.product.preferences.load',return_value=dict(DEFAULTS,auto_capture=False)):
            core=ProductCore(self.state,self.root/'product',union_root=self.formal,repository_root=self.state_repo,
                union_repository=self.union_repo,paired_repository=self.root/'paired')
        self.addCleanup(core.close);self.wait(core)
        return core

    def test_cleanup_pending_is_durable_warning_and_batch_events_are_coalesced(self):
        core=self.core()
        def cleanup(repo,seconds,fault):
            for _ in range(200):
                for phase in ('after_batch_edges','after_edge_commit','after_batch_delete','before_batch_commit','after_batch_commit'):
                    fault(phase,None)
            return dict(cleanup_pending=True,retention_committed=True)
        with patch('wechat_capture_next.pair_repository.govern',side_effect=cleanup),\
             patch.object(core.journal,'save',wraps=core.journal.save) as saves:
            result=self.wait(core,core.submit(dict(action='backup_cleanup')),status='warning')
        self.assertLess(saves.call_count,20)
        self.assertTrue(result['result']['accepted_restore_points_preserved'])
        health=core.control_snapshot()['product']['pipelines']['backup_cleanup']
        self.assertEqual(health['outcome'],'warning')
        self.assertEqual(health['reason'],'backup_cleanup_pending')
        self.assertEqual(health['retry'],dict(action='backup_cleanup'))
        self.assertTrue(health['next_step'])
        self.assertEqual(core.journal.pipelines['backup_cleanup'],health)
        self.assertFalse(core.watching)
        self.assertTrue(core.thread.is_alive())

    def test_cleanup_success_is_distinct_from_a_new_backup(self):
        core=self.core()
        with patch('wechat_capture_next.pair_repository.govern',return_value=dict(cleanup_pending=False)):
            result=self.wait(core,core.submit(dict(action='backup_cleanup')))
        self.assertEqual(result['result']['status'],'completed')
        health=core.control_snapshot()['product']['pipelines']
        self.assertEqual(health['backup_cleanup']['outcome'],'completed')
        self.assertEqual(health['backup_cleanup']['reason'],'backup_cleanup_complete')
        self.assertIsNone(health['backup_cleanup']['retry'])
        self.assertFalse(health['backup_cleanup']['pending'])
        self.assertNotIn('backup',health)


    def test_cleanup_exception_keeps_failed_reason_and_retry(self):
        core=self.core()
        with patch('wechat_capture_next.pair_repository.govern',side_effect=OSError('private path')):
            self.wait(core,core.submit(dict(action='backup_cleanup')),status='failed')
        health=core.control_snapshot()['product']['pipelines']['backup_cleanup']
        self.assertEqual(health['outcome'],'failed')
        self.assertEqual(health['reason'],'backup_cleanup_unconfirmed')
        self.assertEqual(health['error_type'],'OSError')
        self.assertEqual(health['retry'],dict(action='backup_cleanup'))
        self.assertNotIn('private path',str(health))


    def test_actual_committed_cleanup_failure_resets_memo_and_next_backup_authenticates(self):
        import os
        if os.name!='nt':self.skipTest('requires enforceable cold guards')
        from wechat_capture_next import pair_repository,rolling_delivery
        core=self.core()
        first=self.wait(core,core.submit(dict(action='backup_pair')))
        self.wait(core,core.submit(dict(action='backup_pair')))
        with pair_repository.session(core.paired_repository) as (db,_):
            pair_repository._put(db,'D',b'synthetic dead bytes after successful memo')
            db.commit()
        original=core._backup_phase
        def fail_after_commit(ident,phase):
            original(ident,phase)
            if phase=='after_batch_commit':raise RuntimeError('synthetic post-mutation error')
        with patch.object(core,'_backup_phase',side_effect=fail_after_commit):
            result=self.wait(core,core.submit(dict(action='backup_cleanup')),status='warning')
        self.assertGreater(result['result']['deleted_blocks'],0)
        self.assertEqual(result['result']['cleanup_error'],'RuntimeError')
        next_backup=self.wait(core,core.submit(dict(action='backup_pair')))
        self.assertTrue(next_backup['result']['repository_block_authentication_executed_now'])
        restored=rolling_delivery.restore(core.paired_repository,first['result']['snapshot_id'],self.root/'after-mutation-error')
        self.assertTrue(restored['attachments_closed'])
        self.assertTrue(core.thread.is_alive())


    def test_real_product_compact_receipt_reaches_one_scheduled_cleanup(self):
        from wechat_capture_next import pair_repository
        core=self.core()
        self.wait(core,core.submit(dict(action='backup_pair')))
        with pair_repository.session(core.paired_repository) as (db,_):
            pair_repository._put(db,'D',b'synthetic scheduled orphan')
            db.commit()
        core.settings=dict(core.settings,heavy_start=0,heavy_end=0,verify_enabled=False)
        core._schedule_last['backup_pair']=0
        core._schedule_tick()
        ident=core._schedule_jobs['backup_pair']
        completed=self.wait(core,core.jobs[ident])
        # Actual DurableJobs + Coordinator compaction, not a mocked rich job.
        self.assertNotIn('governance',completed['result'])
        self.assertIs(completed['result']['cleanup_pending'],True)
        health=core.journal.pipelines['backup_cleanup']
        self.assertEqual(health['details']['backup_job_id'],ident)
        core._schedule_tick()
        request='scheduled-cleanup-'+ident
        cleanup_ident=core.receipts[request][1]
        self.assertEqual(core.jobs[cleanup_ident]['action'],'backup_cleanup')
        self.wait(core,core.jobs[cleanup_ident])
        core._schedule_tick()
        self.assertIsNone(core._cleanup_schedule_candidate)
        self.assertEqual(sum(key==request for key in core.receipts),1)
        self.assertFalse(core.journal.pipelines['backup_cleanup']['pending'])


if __name__=='__main__':unittest.main()
