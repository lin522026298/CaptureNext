"""Synthetic scheduler/health boundaries; no GUI, source or repository access."""
import json
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from wechat_capture_next.product import ProductCore
from wechat_capture_next.console import _compact_result
from wechat_capture_next.product_journal import Journal,SCHEMA
from wechat_capture_next.product_settings import DEFAULTS

IDENT='a'*32


def fake_core(candidate=IDENT):
    core=ProductCore.__new__(ProductCore)
    core.condition=threading.Condition();core.closing=False
    core.settings=dict(DEFAULTS,heavy_start=0,heavy_end=0,verify_enabled=False)
    core.output_root=Path('UNUSED-SYNTHETIC-OUTPUT')
    core._schedule_last=dict(backup_pair=1000,deep_verify=1000)
    core._schedule_jobs={};core._schedule_dirty=False
    core._cleanup_schedule_candidate=candidate
    job=dict(id=IDENT,action='backup_pair',status='completed',result=_compact_result(dict(governance=dict(cleanup_pending=True),cleanup_pending=True)))
    core.jobs={IDENT:job};core.receipts={}
    journal=Journal.__new__(Journal)
    journal.records={IDENT:dict(job=job,params={})}
    journal.pipelines=dict(backup_cleanup=dict(outcome='warning',pending=True,details=dict(backup_job_id=IDENT)))
    journal.save=Mock();core.journal=journal
    core.submit=Mock(return_value=dict(id='b'*32,status='queued'))
    core.job_phase=Mock()
    core._run_durable=lambda action,params,ident,perform:perform(action,params,ident)
    return core


class ScheduleCleanupBoundaryTests(unittest.TestCase):
    def test_failed_ledger_write_keeps_candidate_until_next_tick_persists_once(self):
        core=fake_core(None)
        core._schedule_jobs={'backup_pair':IDENT}
        events=[]
        def persist(*args):
            events.append('persist')
            if events.count('persist')==1:raise PermissionError('synthetic ledger failure')
            return True
        core.submit.side_effect=lambda request:(events.append('submit') or dict(id='b'*32,status='queued'))
        with patch('wechat_capture_next.product.preferences.atomic_json',side_effect=persist) as saved, \
             patch('wechat_capture_next.product.time.time',return_value=1000):
            with self.assertRaises(PermissionError):core._schedule_tick()
            self.assertTrue(core._schedule_dirty)
            self.assertEqual(core._cleanup_schedule_candidate,IDENT)
            self.assertEqual(core._schedule_last['backup_pair'],1000)
            self.assertFalse(core._schedule_jobs)
            core.submit.assert_not_called()
            core._schedule_tick()
            self.assertFalse(core._schedule_dirty)
            self.assertIsNone(core._cleanup_schedule_candidate)
            core.submit.assert_called_once_with(dict(action='backup_cleanup',request_id='scheduled-cleanup-'+IDENT))
            core._schedule_tick()
            self.assertEqual(saved.call_count,2)
            self.assertEqual(core.submit.call_count,1)
        self.assertEqual(events,['persist','persist','submit'])

    def test_once_per_successful_planned_period_not_health_timestamp(self):
        core=fake_core();core._cleanup_schedule_candidate=None
        self.assertNotIn('governance',core.jobs[IDENT]['result'])
        self.assertIs(core.jobs[IDENT]['result']['cleanup_pending'],True)
        core._schedule_jobs={'backup_pair':IDENT}
        events=[]
        core.submit.side_effect=lambda request:(events.append(('submit',request)) or dict(id='b'*32,status='queued'))
        with patch('wechat_capture_next.product.preferences.atomic_json',side_effect=lambda *a:events.append(('persist',None))), \
             patch('wechat_capture_next.product.time.time',return_value=1000):
            core._schedule_tick()
            core.journal.pipelines['backup_cleanup']['last_attempt']='arbitrary-new-health-time'
            core._schedule_tick()
        self.assertEqual([x[0] for x in events],['persist','submit'])
        self.assertEqual(events[1][1],dict(action='backup_cleanup',request_id='scheduled-cleanup-'+IDENT))
        self.assertIsNone(core._cleanup_schedule_candidate)

    def test_real_product_perform_and_durable_compaction_reach_scheduler(self):
        from contextlib import nullcontext
        from types import MethodType
        from wechat_capture_next.product_journal import DurableJobs
        core=fake_core(None)
        core.capture_capable=True
        core.state=Path('UNUSED-STATE');core.union_root=Path('UNUSED-UNION')
        core.paired_repository=Path('UNUSED-REPO');core.provenance_root=None
        core._paired_backup_reuse=Mock();core._sync=Mock();core._cold=lambda:nullcontext()
        core._run_durable=MethodType(DurableJobs._run_durable,core)
        raw=dict(snapshot_id='d'*64,noop=True,new_blocks=0,governance=dict(cleanup_pending=True))
        # Actual proposed ProductCore._perform + real DurableJobs, with only
        # the repository operation stubbed. No service/thread/root is opened.
        with patch('wechat_capture_next.rolling_delivery.backup_owned',return_value=raw):
            result=core._execute('backup_pair',{},IDENT)
        receipt=core.journal.records[IDENT]['job']['result']
        self.assertNotIn('governance',receipt)
        self.assertIs(receipt['cleanup_pending'],True)
        self.assertEqual(core.journal.pipelines['backup_cleanup']['details']['backup_job_id'],IDENT)
        # Real Coordinator's second compaction must retain the same bool.
        core.jobs[IDENT].update(status='completed',result=_compact_result(result))
        core._schedule_jobs={'backup_pair':IDENT}
        with patch('wechat_capture_next.product.preferences.atomic_json'), \
             patch('wechat_capture_next.product.time.time',return_value=1000):
            core._schedule_tick()
        core.submit.assert_called_once_with(dict(action='backup_cleanup',request_id='scheduled-cleanup-'+IDENT))

    def test_disabled_outside_window_or_busy_wait_without_submission(self):
        for mode in ('disabled','window','busy','closing'):
            core=fake_core()
            if mode=='disabled':core.settings['backup_enabled']=False
            if mode=='busy':core.jobs['b'*32]=dict(id='b'*32,action='capture',status='running')
            if mode=='closing':core.closing=True
            with patch('wechat_capture_next.product.preferences.in_window',return_value=mode!='window'):
                core._maybe_schedule_cleanup()
            core.submit.assert_not_called()
            self.assertEqual(core._cleanup_schedule_candidate,IDENT)

    def test_submission_failure_is_consumed_not_retried_each_tick(self):
        core=fake_core();core.submit.side_effect=RuntimeError('synthetic submission failure')
        core._maybe_schedule_cleanup();core._maybe_schedule_cleanup()
        self.assertEqual(core.submit.call_count,1)
        self.assertIsNone(core._cleanup_schedule_candidate)
        health=core.journal.pipelines['backup_cleanup']
        self.assertEqual(health['reason'],'scheduled_cleanup_submission_unconfirmed')
        self.assertEqual(health['retry'],dict(action='backup_cleanup'))

    def test_restart_does_not_reconstruct_candidate_and_next_period_can_continue(self):
        core=fake_core(None)
        core.receipts['scheduled-cleanup-'+IDENT]=('0'*64,'b'*32)
        core.journal.pipelines['backup_cleanup'].update(outcome='interrupted_unconfirmed')
        core._maybe_schedule_cleanup();core.submit.assert_not_called()
        next_ident='c'*32
        job=dict(id=next_ident,action='backup_pair',status='completed',result=_compact_result(dict(governance=dict(cleanup_pending=True),cleanup_pending=True)))
        core.jobs[next_ident]=job;core.journal.records[next_ident]=dict(job=job,params={})
        core._cleanup_schedule_candidate=next_ident
        core.journal.pipelines['backup_cleanup']['details']=dict(backup_job_id=next_ident)
        core._maybe_schedule_cleanup()
        core.submit.assert_called_once_with(dict(action='backup_cleanup',request_id='scheduled-cleanup-'+next_ident))

    def test_health_from_another_backup_does_not_authorize_old_candidate(self):
        core=fake_core()
        core.journal.pipelines['backup_cleanup']['details']['backup_job_id']='c'*32
        core._maybe_schedule_cleanup()
        core.submit.assert_not_called()
        self.assertIsNone(core._cleanup_schedule_candidate)

    def test_failed_manual_or_clean_backup_cannot_offer_cleanup(self):
        for mode in ('failed','manual','clean'):
            core=fake_core(None)
            if mode=='failed':core.jobs[IDENT]['status']='failed'
            if mode=='clean':core.jobs[IDENT]['result']['cleanup_pending']=False
            if mode!='manual':core._schedule_jobs={'backup_pair':IDENT}
            with patch('wechat_capture_next.product.preferences.atomic_json'), \
                 patch('wechat_capture_next.product.time.time',return_value=1000):
                core._schedule_tick()
            core.submit.assert_not_called()


class PiggybackCleanupBoundaryTests(unittest.TestCase):
    def green(self,core):
        core.journal.health(core,'backup_cleanup','completed',reason='backup_cleanup_complete')
        return core.journal.pipelines['backup_cleanup']['last_success']

    def test_pre_acceptance_failure_does_not_start_collection(self):
        core=fake_core();self.green(core)
        core._perform=Mock(side_effect=RuntimeError('before verify'))
        with self.assertRaises(RuntimeError):core._execute('backup_pair',{},IDENT)
        self.assertEqual(core.journal.pipelines['backup_cleanup']['outcome'],'completed')

    def test_post_acceptance_hook_and_collection_failures_close_running_health(self):
        for phase in ('after_commit','before_retention','after_retention_commit','after_batch_commit'):
            core=fake_core();last_success=self.green(core)
            def perform(action,params,ident):
                core._backup_phase(ident,'collection_start')
                self.assertEqual(core.journal.pipelines['backup_cleanup']['outcome'],'running')
                core._backup_phase(ident,phase)
                raise RuntimeError('synthetic interrupted completion')
            core._perform=perform
            with self.assertRaises(RuntimeError):core._execute('backup_pair',{},IDENT)
            health=core.journal.pipelines['backup_cleanup']
            self.assertEqual(health['outcome'],'failed')
            self.assertTrue(health['pending'])
            self.assertEqual(health['reason'],'piggyback_cleanup_completion_unconfirmed')
            self.assertEqual(health['retry'],dict(action='backup_cleanup'))
            self.assertEqual(health['last_success'],last_success)

    def test_real_journal_restart_demotes_running_cleanup_without_replay(self):
        core=fake_core();last_success=self.green(core)
        core._backup_phase(IDENT,'collection_start')
        value=dict(schema=SCHEMA,jobs=[],receipts=[],pipelines=core.journal.pipelines)
        path=SimpleNamespace(exists=lambda:True,read_text=lambda **kwargs:json.dumps(value))
        restarted=fake_core(None)
        with patch('wechat_capture_next.product_journal._file'), \
             patch('wechat_capture_next.product_journal.atomic_json'):
            restarted.journal=Journal(path,restarted)
        health=restarted.journal.pipelines['backup_cleanup']
        self.assertEqual(health['outcome'],'interrupted_unconfirmed')
        self.assertTrue(health['pending'])
        self.assertEqual(health['retry'],dict(action='backup_cleanup'))
        self.assertTrue(health['next_step'])
        self.assertEqual(health['last_success'],last_success)
        restarted._maybe_schedule_cleanup()
        restarted.submit.assert_not_called()


if __name__=='__main__':unittest.main()
