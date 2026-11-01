"""Synthetic Journal startup uncertainty, never a repository/GC operation."""
from collections import OrderedDict,deque
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from wechat_capture_next.product_journal import DurableJobs,Journal,SCHEMA


class BackupFixture(DurableJobs):
    def __init__(self,path):
        self.condition=threading.Condition()
        self.jobs=OrderedDict();self.receipts=OrderedDict();self.pending=deque()
        self.closing=False;self.queue_size=8
        self.journal=Journal(path,self)

    def _validate(self,payload):
        if payload.get('action')!='backup_pair':raise ValueError('synthetic backup only')
        return payload['action'],{k:v for k,v in payload.items() if k!='action'}


def assert_uncertain(test,health,ident):
    test.assertEqual(health['outcome'],'interrupted_unconfirmed')
    test.assertTrue(health['pending'])
    test.assertEqual(health['reason'],'backup_or_cleanup_completion_unconfirmed')
    test.assertEqual(health['retry'],dict(action='backup_cleanup'))
    test.assertTrue(health['next_step'])
    test.assertEqual(health['details'],dict(backup_job_id=ident,
        backup_completion_unconfirmed=True,cleanup_completion_unconfirmed=True))
    test.assertNotIn('accepted',health['details'])
    test.assertNotIn('collection_started',health['details'])
    test.assertNotIn('deleted_blocks',health['details'])


class RamJournalUncertaintyTests(unittest.TestCase):
    def test_queued_or_running_backup_with_old_green_cleanup_is_unconfirmed(self):
        for status in ('queued','running'):
            ident='a'*32
            value=dict(schema=SCHEMA,jobs=[dict(job=dict(id=ident,action='backup_pair',status=status),params={})],
                receipts=[],pipelines=dict(backup_cleanup=dict(outcome='completed',pending=False,
                    last_success='2026-01-01T00:00:00+00:00',details=dict(deleted_blocks=7))))
            path=SimpleNamespace(exists=lambda:True,read_text=lambda **kwargs:json.dumps(value))
            core=SimpleNamespace(jobs=OrderedDict(),receipts=OrderedDict())
            with patch('wechat_capture_next.product_journal._file'), \
                 patch('wechat_capture_next.product_journal.atomic_json') as saved:
                journal=Journal(path,core)
            health=journal.pipelines['backup_cleanup']
            assert_uncertain(self,health,ident)
            self.assertEqual(health['last_success'],'2026-01-01T00:00:00+00:00')
            self.assertEqual(health['last_success_details'],dict(deleted_blocks=7))
            self.assertEqual(core.jobs[ident]['status'],'interrupted_unconfirmed')
            saved.assert_called_once()


class DiskJournalUncertaintyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='synthetic-journal-addendum-')
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'operations.json'

    def prepare(self):
        core=BackupFixture(self.path)
        core.journal.health(core,'backup_cleanup','completed',reason='backup_cleanup_complete',
                            details=dict(deleted_blocks=7,cleanup_pending=False))
        return core

    def test_real_submit_accept_failure_rolls_back_queue_job_and_receipt(self):
        core=self.prepare();before=self.path.read_bytes()
        payload=dict(action='backup_pair',request_id='synthetic-accept-persistence-failure')
        with patch.object(core.journal,'accept',wraps=core.journal.accept) as accepted, \
             patch('wechat_capture_next.product_journal.atomic_json',side_effect=PermissionError('synthetic journal failure')):
            with self.assertRaises(PermissionError):core.submit(payload)
        accepted.assert_called_once()
        self.assertFalse(core.pending)
        self.assertFalse(core.jobs)
        self.assertFalse(core.receipts)
        self.assertFalse(core.journal.records)
        self.assertEqual(self.path.read_bytes(),before)
        self.assertFalse(self.path.with_name(self.path.name+'.pending').exists())
        reopened=BackupFixture(self.path)
        self.assertFalse(reopened.pending)
        self.assertFalse(reopened.jobs)
        self.assertFalse(reopened.receipts)
        # A later explicit request is not poisoned by a failed fingerprint.
        job=reopened.submit(payload)
        saved=json.loads(self.path.read_text(encoding='utf-8'))
        self.assertEqual(len(saved['jobs']),1)
        self.assertEqual(saved['jobs'][0]['job']['id'],job['id'])
        self.assertEqual(reopened.receipts[payload['request_id']][1],job['id'])

    def test_real_running_backup_and_bound_running_cleanup_reopen_without_replay(self):
        from wechat_capture_next.product import ProductCore
        core=self.prepare();previous=dict(core.journal.pipelines['backup_cleanup'])
        payload=dict(action='backup_pair',request_id='synthetic-running-backup-and-cleanup')
        job=core.submit(payload)
        core.journal.transition(core,job['id'],status='running',phase='repository_tree_publish')
        core.journal.health(core,'backup','running')
        # Real Product phase hook + Journal atomic persistence, without a
        # ProductCore constructor, worker, backup, collector or repository.
        ProductCore._backup_phase(core,job['id'],'collection_start')
        saved=json.loads(self.path.read_text(encoding='utf-8'))
        self.assertEqual(saved['jobs'][0]['job']['status'],'running')
        self.assertEqual(saved['pipelines']['backup_cleanup']['outcome'],'running')
        self.assertEqual(saved['pipelines']['backup_cleanup']['details']['backup_job_id'],job['id'])
        reopened=BackupFixture(self.path)
        self.assertEqual(reopened.jobs[job['id']]['status'],'interrupted_unconfirmed')
        self.assertEqual(reopened.journal.pipelines['backup']['outcome'],'interrupted_unconfirmed')
        health=reopened.journal.pipelines['backup_cleanup']
        assert_uncertain(self,health,job['id'])
        self.assertEqual(health['last_success'],previous['last_success'])
        self.assertEqual(health['last_success_details'],previous['last_success_details'])
        self.assertFalse(reopened.pending)
        self.assertEqual(reopened.submit(payload)['id'],job['id'])
        self.assertFalse(reopened.pending)
        persisted=json.loads(self.path.read_text(encoding='utf-8'))
        self.assertEqual(persisted['jobs'][0]['job']['status'],'interrupted_unconfirmed')
        self.assertTrue(persisted['pipelines']['backup_cleanup']['pending'])

    def test_real_receipt_queued_running_reopen_and_no_replay(self):
        for number,status in enumerate(('queued','running')):
            self.path=Path(self.temp.name)/('operations-'+str(number)+'.json')
            core=self.prepare()
            previous=dict(core.journal.pipelines['backup_cleanup'])
            payload=dict(action='backup_pair',request_id='synthetic-backup-'+str(number))
            job=core.submit(payload)
            if status=='running':
                core.journal.transition(core,job['id'],status='running',phase='repository_tree_publish')
            reopened=BackupFixture(self.path)
            health=reopened.journal.pipelines['backup_cleanup']
            assert_uncertain(self,health,job['id'])
            self.assertEqual(health['last_success'],previous['last_success'])
            self.assertEqual(health['last_success_details'],previous['last_success_details'])
            self.assertEqual(reopened.journal.pipelines['backup']['outcome'],'interrupted_unconfirmed')
            self.assertFalse(reopened.pending)
            self.assertEqual(reopened.submit(payload)['id'],job['id'])
            self.assertFalse(reopened.pending)
            saved=self.path.read_bytes()
            again=BackupFixture(self.path)
            self.assertEqual(again.journal.pipelines['backup_cleanup'],health)
            self.assertEqual(self.path.read_bytes(),saved)
            self.assertFalse(again.pending)

    def test_known_failed_preverify_is_not_projected_as_collection_started(self):
        core=self.prepare();old=dict(core.journal.pipelines['backup_cleanup'])
        job=core.submit(dict(action='backup_pair',request_id='synthetic-preverify-failed'))
        def fail(*args):raise ValueError('synthetic verification rejected before acceptance')
        with self.assertRaises(ValueError):
            core._run_durable('backup_pair',{},job['id'],fail)
        reopened=BackupFixture(self.path)
        self.assertEqual(reopened.jobs[job['id']]['status'],'failed')
        self.assertEqual(reopened.journal.pipelines['backup_cleanup'],old)
        self.assertFalse(reopened.pending)

    def test_completed_job_leaves_real_cleanup_success_unchanged(self):
        core=self.prepare();old=dict(core.journal.pipelines['backup_cleanup'])
        job=core.submit(dict(action='backup_pair',request_id='synthetic-known-complete'))
        core._run_durable('backup_pair',{},job['id'],lambda *args:dict(cleanup_pending=False))
        reopened=BackupFixture(self.path)
        self.assertEqual(reopened.jobs[job['id']]['status'],'completed')
        self.assertEqual(reopened.journal.pipelines['backup_cleanup'],old)

    def test_absent_cleanup_success_is_not_fabricated(self):
        core=BackupFixture(self.path)
        job=core.submit(dict(action='backup_pair',request_id='synthetic-no-previous-success'))
        reopened=BackupFixture(self.path)
        health=reopened.journal.pipelines['backup_cleanup']
        assert_uncertain(self,health,job['id'])
        self.assertNotIn('last_success',health)
        self.assertNotIn('last_success_details',health)

    def test_old_success_details_are_preserved_if_legacy_record_omits_snapshot(self):
        core=self.prepare()
        core.journal.pipelines['backup_cleanup'].pop('last_success_details')
        core.journal.save(core)
        job=core.submit(dict(action='backup_pair',request_id='synthetic-legacy-success-details'))
        reopened=BackupFixture(self.path)
        health=reopened.journal.pipelines['backup_cleanup']
        assert_uncertain(self,health,job['id'])
        self.assertEqual(health['last_success_details'],dict(deleted_blocks=7,cleanup_pending=False))


if __name__=='__main__':unittest.main()
