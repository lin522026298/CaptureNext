"""Policy regressions: synthetic fixtures only, no real product state."""
import hashlib
import os
import unittest
from unittest.mock import patch
from wechat_capture_next import pair_repository as repository, pair_readback_memo as memory
from wechat_capture_next import rolling_delivery as delivery
from wechat_capture_next.product import _cleanup_outcome
from wechat_capture_next.tests import test_rolling_delivery as fixture


class CleanupOutcomeProjectionTests(unittest.TestCase):
    def test_pending_hint_error_stall_and_unknown_are_actionable_not_green(self):
        for result,reason in (
            ({'cleanup_pending':True,'maintenance_deferred':True},'authenticated_noop_cleanup_deferred'),
            ({'cleanup_pending':True,'cleanup_error':'OperationalError'},'backup_cleanup_error'),
            ({'cleanup_pending':True,'reclaim_progress_stalled':True},'backup_cleanup_reclaim_stalled'),
            ({},'backup_cleanup_pending'),
            ({'cleanup_pending':False,'dead_blocks_remaining':3},'backup_cleanup_pending'),
            ({'cleanup_pending':False,'extra_generations':1},'backup_cleanup_pending'),
            ({'cleanup_pending':False,'orphan_root_found':True},'backup_cleanup_pending')):
            with self.subTest(reason=reason):
                projected=_cleanup_outcome(result)
                self.assertEqual(projected['status'],'warning')
                self.assertEqual(projected['reason'],reason)
                self.assertEqual(projected['retry'],{'action':'backup_cleanup'})
                self.assertTrue(projected['next_step'])
        complete=_cleanup_outcome({'cleanup_pending':False})
        self.assertEqual(complete['status'],'completed')
        self.assertIsNone(complete['retry'])


@unittest.skipUnless(os.name=='nt','requires enforceable cold guards')
class CleanupNoopMemoTests(unittest.TestCase):
    setUp=fixture.RollingDeliveryTests.setUp
    tearDown=fixture.RollingDeliveryTests.tearDown
    pages=fixture.RollingDeliveryTests.pages
    publish=fixture.RollingDeliveryTests.publish
    init_service=fixture.RollingDeliveryTests.init_service
    prepared=fixture.RollingDeliveryTests.prepared

    def test_pending_noop_keeps_memo_without_second_verify_govern_or_repo_write(self):
        self.prepared();target=self.root/'rolling'
        first=delivery.backup(self.state,self.formal,target)
        with repository.session(target) as (db,_):
            repository._put(db,'D',b'synthetic orphan')
            db.commit()
        memo=memory.PairReadbackMemo();phases=[]
        before=hashlib.sha256((target/repository.DATABASE).read_bytes()).hexdigest()
        with patch.object(repository,'verify_files',wraps=repository.verify_files) as verified, \
             patch.object(repository,'govern',side_effect=AssertionError('second readback forbidden')), \
             patch.object(memory.PairReadbackMemo,'reset',side_effect=AssertionError('no mutation, no reset')):
            cold=delivery.backup(self.state,self.formal,target,_memo=memo,fault=lambda phase,db:phases.append(phase))
            warm=delivery.backup(self.state,self.formal,target,_memo=memo,fault=lambda phase,db:phases.append(phase))
        self.assertNotIn('collection_start',phases)
        self.assertNotIn('before_retention',phases)
        self.assertEqual(verified.call_count,1)
        self.assertTrue(cold['repository_block_authentication_executed_now'])
        self.assertTrue(warm['reused_same_process_authenticated_repository_cut'])
        self.assertFalse(warm['repository_block_authentication_executed_now'])
        self.assertTrue(warm['governance']['cleanup_pending'])
        self.assertEqual(first['snapshot_id'],warm['snapshot_id'])
        self.assertEqual(before,hashlib.sha256((target/repository.DATABASE).read_bytes()).hexdigest())
        self.assertEqual(len(repository.snapshots(target)),1)
