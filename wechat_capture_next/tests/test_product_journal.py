from collections import OrderedDict,deque
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from wechat_capture_next.product_journal import DurableJobs,Journal


class Fixture(DurableJobs):
    def __init__(self,path):
        self.condition=threading.Condition();self.jobs=OrderedDict();self.receipts=OrderedDict();self.pending=deque()
        self.closing=False;self.queue_size=8;self.journal=Journal(path,self)
    def _validate(self,payload):
        if payload.get('action')!='restore_pair':raise ValueError('synthetic action only')
        return payload['action'],{k:v for k,v in payload.items() if k!='action'}


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'operations.json'
    def test_acceptance_is_durable_and_restart_does_not_replay(self):
        core=Fixture(self.path);payload=dict(action='restore_pair',name='synthetic',request_id='synthetic-request-01')
        job=core.submit(payload)
        persisted=json.loads(self.path.read_text(encoding='utf-8'))
        self.assertEqual(persisted['jobs'][0]['job']['id'],job['id'])
        restarted=Fixture(self.path)
        self.assertEqual(restarted.jobs[job['id']]['status'],'interrupted_unconfirmed')
        self.assertFalse(restarted.pending)
        self.assertEqual(restarted.submit(payload)['id'],job['id'])
        self.assertFalse(restarted.pending)
        self.assertEqual(restarted.jobs_snapshot()['jobs'][0]['retry']['name'],'synthetic')
    def test_persistence_failure_rejects_before_execution(self):
        core=Fixture(self.path)
        with patch('wechat_capture_next.product_journal.atomic_json',side_effect=PermissionError('synthetic')):
            with self.assertRaises(PermissionError):core.submit(dict(action='restore_pair',request_id='synthetic-request-02'))
        self.assertFalse(core.jobs);self.assertFalse(core.pending);self.assertFalse(core.receipts)
        self.assertFalse(self.path.exists())
    def test_failure_preserves_previous_stage_success(self):
        core=Fixture(self.path);core.journal.health(core,'backup','completed')
        succeeded=core.journal.pipelines['backup']['last_success']
        core.journal.health(core,'backup','failed',reason='synthetic')
        self.assertEqual(core.journal.pipelines['backup']['last_success'],succeeded)
        self.assertEqual(core.journal.pipelines['backup']['outcome'],'failed')
    def test_phases_persist_only_transitions_and_recovery_never_blocks_capture(self):
        core=Fixture(self.path);core.capture_capable=False
        job=core.submit(dict(action='restore_pair',name='synthetic'))
        def perform(*args):
            core.job_phase(job['id'],'before_verify')
            before=self.path.read_bytes()
            core.job_phase(job['id'],'before_verify')
            self.assertEqual(self.path.read_bytes(),before)
            saved=json.loads(before)['jobs'][0]['job']
            self.assertEqual(saved['phase'],'before_verify')
            self.assertFalse(saved['blocks_capture'])
            return dict(pass_all=True)
        core._run_durable('restore_pair',{},job['id'],perform)
    def test_running_failure_and_restart_update_stage_without_erasing_success(self):
        core=Fixture(self.path);job=core.submit(dict(action='restore_pair',name='first'))
        core._run_durable('restore_pair',dict(name='first'),job['id'],lambda *args:dict(pass_all=True))
        success=core.journal.pipelines['restore']['last_success']
        failed=core.submit(dict(action='restore_pair',name='second'))
        def perform(*args):raise ValueError('synthetic failure')
        with self.assertRaises(ValueError):core._run_durable('restore_pair',dict(name='second'),failed['id'],perform)
        self.assertEqual(core.journal.pipelines['restore']['outcome'],'failed')
        self.assertEqual(core.journal.pipelines['restore']['last_success'],success)
        restarted=Fixture(self.path)
        self.assertEqual(restarted.journal.pipelines['restore']['last_success'],success)


if __name__=='__main__':unittest.main()
