"""Local API boundary, real synthetic jobs and read-only status regressions."""
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid
from fastapi.testclient import TestClient
from wechat_capture_v2.dashboard import Coordinator,Projection,checked_runtime,create_app,atomic_json
from wechat_capture_v2.qa_fixture import create
from wechat_capture_v2.common import writer_lock


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.state=create(self.root/'fixture',count=8)
        self.coordinator=Coordinator(self.state,self.root/'console')
        self.shutdown_event=threading.Event()
        def shutdown():self.coordinator.thread.join();self.shutdown_event.set()
        self.client=TestClient(create_app(self.coordinator,8765,shutdown),base_url='http://127.0.0.1:8765')
        response=self.client.get('/api/session',headers={'X-Capture-Bootstrap':'1'})
        self.headers={'X-Capture-Token':response.json()['token'],'Origin':'http://127.0.0.1:8765'}

    def tearDown(self):
        self.client.close();self.coordinator.close();self.temp.cleanup()

    def post(self,path,payload):return self.client.post(path,json=payload,headers=self.headers)

    def completed(self,job):
        until=time.monotonic()+40
        while time.monotonic()<until:
            value=next(j for j in self.coordinator.status()['jobs'] if j['id']==job['id'])
            if value['status'] not in ('queued','running'):break
            time.sleep(0.05)
        self.assertEqual(value['status'],'completed',value)
        return value

    def enqueue(self,kind,**values):
        response=self.post('/api/jobs',{'kind':kind,'acknowledge':True,**values})
        self.assertEqual(response.status_code,200,response.text)
        return response.json()

    def test_boundary_rejects_cross_origin_host_missing_token_and_large_body(self):
        self.assertEqual(self.client.get('/health',headers={'Host':'evil.test'}).status_code,400)
        self.assertEqual(self.client.get('/api/session').status_code,403)
        self.assertEqual(self.client.get('/api/status').status_code,403)
        self.assertEqual(self.client.get('/api/status',headers={**self.headers,'Origin':'http://evil.test'}).status_code,403)
        self.assertEqual(self.client.post('/api/watch',json={'enabled':True},headers={'X-Capture-Token':self.headers['X-Capture-Token']}).status_code,403)
        self.assertEqual(self.client.post('/api/jobs',content='x'*17000,headers={**self.headers,'Content-Type':'application/json'}).status_code,413)
        self.assertEqual(self.post('/api/jobs',{'kind':'verify','acknowledge':False}).status_code,400)
        self.assertEqual(self.post('/api/jobs',['invalid']).status_code,400)
        self.assertEqual(self.post('/api/jobs',{'kind':'verify','acknowledge':True,'out':'arbitrary'}).status_code,400)
        self.assertEqual(self.client.get('/config.private.json').status_code,404)
        self.assertEqual(self.client.get('/').headers['content-security-policy'].count("'self'")>0,True)

    def test_status_never_constructs_writer_or_changes_cycles(self):
        db=sqlite3.connect(self.state/'catalog.sqlite')
        before=db.execute('SELECT id,status FROM cycle ORDER BY id').fetchall()
        with writer_lock(self.state),patch('wechat_capture_v2.service.CaptureService',side_effect=AssertionError('writer constructed')):
            for _ in range(5):
                response=self.client.get('/api/status',headers=self.headers)
                self.assertEqual(response.status_code,200)
                self.assertEqual(response.json()['catalog']['active_observations'],8)
                self.assertNotIn('raw_encryption_key',response.text)
                self.assertNotIn('synthetic 1',response.text)
        self.assertEqual(before,db.execute('SELECT id,status FROM cycle ORDER BY id').fetchall());db.close()

    def test_real_job_workflow_backup_restore_compare_verify_exports_media(self):
        self.completed(self.enqueue('reconcile',assets=True))
        backup=self.completed(self.enqueue('backup'))
        restored=self.completed(self.enqueue('restore',input_job=backup['id']))
        self.assertTrue(restored['result']['readback_verified'])
        self.completed(self.enqueue('compare'))
        self.completed(self.enqueue('verify'))
        self.assertEqual(self.completed(self.enqueue('jsonl'))['result']['rows'],8)
        self.assertEqual(self.completed(self.enqueue('wua'))['result']['logical_messages'],8)
        assets=self.completed(self.enqueue('extract_assets'))
        self.assertTrue(self.completed(self.enqueue('verify_assets',input_job=assets['id']))['result']['pass'])
        self.assertTrue((Path(backup['output'])/'MANIFEST.private.json').exists())

    def test_request_idempotency_and_external_writer_failure(self):
        with writer_lock(self.state):
            request_id=str(uuid.uuid4())
            one=self.enqueue('verify',request_id=request_id)
            two=self.enqueue('verify',request_id=request_id)
            self.assertEqual(one['id'],two['id'])
            until=time.monotonic()+3
            while time.monotonic()<until and self.coordinator.jobs[-1]['status'] in ('queued','running'):time.sleep(.05)
            self.assertEqual(self.coordinator.jobs[-1]['status'],'failed')
            self.assertIn('diagnostic_directory',self.coordinator.jobs[-1])
            self.assertNotIn('output',self.coordinator.jobs[-1])
            self.assertEqual(self.post('/api/jobs',{'kind':'backup','acknowledge':True,'request_id':request_id}).status_code,400)

    def test_safe_watch_pause_for_job_and_stop(self):
        self.assertEqual(self.post('/api/watch',{'enabled':True,'assets':True}).status_code,200)
        until=time.monotonic()+8
        while time.monotonic()<until and not self.coordinator.watch_latest:time.sleep(.05)
        self.assertIsNotNone(self.coordinator.watch_latest)
        self.completed(self.enqueue('verify'))
        until=time.monotonic()+8
        while time.monotonic()<until and not self.coordinator.watch:time.sleep(.05)
        self.assertTrue(self.coordinator.desired_watch)
        self.post('/api/watch',{'enabled':False})
        until=time.monotonic()+8
        while time.monotonic()<until and self.coordinator.watch:time.sleep(.05)
        self.assertIsNone(self.coordinator.watch)

    def test_overlap_is_rejected_before_any_runtime_write(self):
        for target in (self.state,self.root/'fixture'/'synthetic-live'):
            before={p.relative_to(target) for p in target.rglob('*')}
            with self.assertRaises(ValueError):checked_runtime(self.state,target)
            self.assertEqual(before,{p.relative_to(target) for p in target.rglob('*')})
        with patch('wechat_capture_v2.dashboard.directory',side_effect=ValueError('linked path')):
            with self.assertRaises(ValueError):checked_runtime(self.state,self.root/'new-console')
        self.assertFalse((self.root/'new-console').exists())

    def test_atomic_replace_failure_does_not_poison_restart(self):
        path=self.root/'replacement.json';atomic_json(path,{'old':True})
        with patch('wechat_capture_v2.dashboard.os.replace',side_effect=OSError('synthetic interrupted replace')):
            with self.assertRaises(OSError):atomic_json(path,{'not_published':True})
        self.assertEqual(json.loads(path.read_text()),{'old':True})
        # Legacy stale temp is neither used nor overwritten by the new attempt.
        stale=self.root/'replacement.json.new';stale.write_text('synthetic partial')
        atomic_json(path,{'new':True})
        self.assertEqual(json.loads(path.read_text()),{'new':True})
        self.assertEqual(stale.read_text(),'synthetic partial')

    def test_safe_shutdown_finishes_current_and_interrupts_queue_without_watch_resume(self):
        started=threading.Event();release=threading.Event()
        def execute(job):started.set();release.wait(8);return {'pass':True},None
        with patch.object(self.coordinator,'_execute',side_effect=execute):
            first=self.enqueue('verify');self.assertTrue(started.wait(4))
            second=self.enqueue('verify');third=self.enqueue('verify')
            self.coordinator.desired_watch=True
            response=self.post('/api/shutdown',{'acknowledge':True})
            self.assertEqual(response.status_code,200)
            self.assertTrue(self.coordinator.status()['closing'])
            self.assertEqual(self.post('/api/watch',{'enabled':True}).status_code,400)
            self.assertEqual(self.post('/api/jobs',{'kind':'verify','acknowledge':True}).status_code,400)
            release.set();self.assertTrue(self.shutdown_event.wait(5))
        values={j['id']:j['status'] for j in self.coordinator.jobs}
        self.assertEqual(values[first['id']],'completed');self.assertEqual(values[second['id']],'interrupted');self.assertEqual(values[third['id']],'interrupted')
        self.assertFalse(self.coordinator.desired_watch);self.assertIsNone(self.coordinator.watch)


if __name__=='__main__':unittest.main()
