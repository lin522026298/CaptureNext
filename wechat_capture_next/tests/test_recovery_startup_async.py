"""Small event-gated startup contracts: no real archive, capture or UI."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.request import Request, build_opener, ProxyHandler

from wechat_capture_next.recovery_core import RecoveryCore
from wechat_capture_next import product_host
from wechat_capture_next.service import CaptureService


class RecoveryAsyncStartupTests(unittest.TestCase):
    def setUp(self):
        evidence=Path(__file__).resolve().parents[2]/'working/wechat_product_20261022/async-offline-startup'
        evidence.mkdir(parents=True,exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(prefix='synthetic-',dir=evidence)
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.entered=threading.Event();self.release=threading.Event();self.readers=[];self.calls=[]
        self.addCleanup(self.release.set)
        self.failure=False

    def fake_view(self,path):
        self.calls.append(str(path));self.entered.set()
        if not self.release.wait(8):raise TimeoutError('synthetic authentication gate not released')
        if self.failure:raise ValueError('synthetic invalid receipt')
        class Reader:
            def __init__(reader):reader.closed=False
            def summary(reader):
                return dict(mode='offline_readonly',receipt_root=str(path),snapshot_id='a'*64,
                    source_connected=False,capture_started=False,login_started=False,files_hash_verified=True)
            def close(reader):reader.closed=True
        reader=Reader();self.readers.append(reader);return reader

    def core(self,offline=None):
        return RecoveryCore(self.root/'base',state=self.root/'state',union_root=self.root/'union',
            repository_root=self.root/'state-repo',union_repository=self.root/'union-repo',
            paired_repository=self.root/'paired',offline=offline)

    def wait(self,predicate):
        end=time.monotonic()+4
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.005)
        self.fail('synthetic contract deadline exceeded')

    def test_constructor_and_status_do_not_wait_for_complete_authentication(self):
        with patch('wechat_capture_next.recovery_core.OfflineView',side_effect=self.fake_view),\
             patch.object(CaptureService,'__init__',side_effect=AssertionError('live capture forbidden')):
            core=self.core(self.root/'copy')
            try:
                self.assertTrue(self.entered.wait(2));self.assertFalse(self.release.is_set())
                status=core.control_snapshot()['product']
                self.assertTrue(status['offline_loading']);self.assertIsNone(status['offline_view'])
                self.assertEqual(status['offline_initial_job'],status['offline_open_job']['id'])
                self.assertEqual(status['offline_open_job']['phase'],'offline_authentication')
                durable=json.loads((core.output_root/'operations.private.json').read_text(encoding='utf-8'))
                self.assertEqual(durable['jobs'][0]['job']['phase'],'offline_authentication')
                self.release.set();self.wait(lambda:not core.control_snapshot()['product']['offline_loading'])
                self.assertTrue(core.control_snapshot()['product']['offline_view']['files_hash_verified'])
                self.assertEqual(core.jobs_snapshot()['jobs'][0]['status'],'completed')
            finally:self.release.set();core.close()
            self.assertTrue(self.readers[0].closed)
            restarted=self.core()
            try:
                self.assertEqual(restarted.jobs_snapshot()['jobs'][0]['status'],'completed')
                self.assertIsNone(restarted.offline_view);self.assertEqual(len(self.calls),1)
            finally:restarted.close()

    def test_authentication_failure_is_durable_and_recovery_stays_operable(self):
        self.failure=True
        with patch('wechat_capture_next.recovery_core.OfflineView',side_effect=self.fake_view),\
             patch.object(CaptureService,'__init__',side_effect=AssertionError('live capture forbidden')):
            core=self.core(self.root/'invalid-copy')
            try:
                self.assertTrue(self.entered.wait(2));self.release.set()
                self.wait(lambda:not core.control_snapshot()['product']['offline_loading'])
                self.assertIsNone(core.offline_view)
                self.assertEqual(core.jobs_snapshot()['jobs'][0]['status'],'failed')
                self.assertEqual(core.control_snapshot()['product']['offline_open_job']['error_type'],'ValueError')
                job=core.submit(dict(action='close_restored'))
                self.wait(lambda:any(j['id']==job['id'] and j['status']=='completed' for j in core.jobs_snapshot()['jobs']))
            finally:self.release.set();core.close()
            restarted=self.core()
            try:
                self.assertTrue(any(j['action']=='open_restored' and j['status']=='failed' for j in restarted.jobs_snapshot()['jobs']))
                self.assertEqual(len(self.calls),1);self.assertFalse(restarted.control_snapshot()['watching'])
            finally:restarted.close()

    def test_manual_open_publishes_only_authenticated_new_view_and_status_remains_available(self):
        self.release.set()
        with patch('wechat_capture_next.recovery_core.OfflineView',side_effect=self.fake_view),\
             patch.object(CaptureService,'__init__',side_effect=AssertionError('live capture forbidden')):
            core=self.core(self.root/'first-copy')
            try:
                self.wait(lambda:core.offline_view is not None)
                old=core.offline_view;self.entered.clear();self.release.clear()
                job=core.submit(dict(action='open_restored',path=str(self.root/'second-copy')))
                self.assertTrue(self.entered.wait(2))
                status=core.control_snapshot()['product'];jobs=core.jobs_snapshot()['jobs']
                self.assertTrue(status['offline_loading']);self.assertIs(core.offline_view,old)
                self.assertEqual(status['offline_view']['receipt_root'],str(self.root/'first-copy'))
                self.assertEqual(next(j for j in jobs if j['id']==job['id'])['phase'],'offline_authentication')
                self.release.set();self.wait(lambda:not core.control_snapshot()['product']['offline_loading'])
                self.assertEqual(core.offline_view.summary()['receipt_root'],str(self.root/'second-copy'))
                self.assertTrue(old.closed);verified=core.offline_view
                self.failure=True;self.entered.clear();self.release.clear()
                failed=core.submit(dict(action='open_restored',path=str(self.root/'invalid-copy')))
                self.assertTrue(self.entered.wait(2));self.release.set()
                self.wait(lambda:not core.control_snapshot()['product']['offline_loading'])
                self.assertIs(core.offline_view,verified);self.assertFalse(verified.closed)
                self.assertEqual(next(j for j in core.jobs_snapshot()['jobs'] if j['id']==failed['id'])['status'],'failed')
            finally:self.release.set();core.close()

    def test_initial_job_identity_survives_worker_completion_before_submit_returns(self):
        self.release.set();original_submit=RecoveryCore.submit
        def completed_before_return(core,payload):
            job=original_submit(core,payload)
            self.wait(lambda:next(j for j in core.jobs_snapshot()['jobs'] if j['id']==job['id'])['status']=='completed')
            self.assertIsNone(core.initial_offline_job)
            return job
        with patch('wechat_capture_next.recovery_core.OfflineView',side_effect=self.fake_view),\
             patch.object(RecoveryCore,'submit',completed_before_return),\
             patch.object(CaptureService,'__init__',side_effect=AssertionError('live capture forbidden')):
            core=self.core(self.root/'fast-copy')
            try:
                status=core.control_snapshot()['product']
                self.assertEqual(status['offline_initial_job'],status['offline_open_job']['id'])
                self.assertEqual(status['offline_open_job']['status'],'completed')
                self.assertFalse(status['offline_loading']);self.assertTrue(status['offline_view']['files_hash_verified'])
            finally:core.close()

    def test_close_drains_current_authentication_and_does_not_replay_queued_write(self):
        with patch('wechat_capture_next.recovery_core.OfflineView',side_effect=self.fake_view),\
             patch.object(CaptureService,'__init__',side_effect=AssertionError('live capture forbidden')):
            core=self.core(self.root/'copy');closer=None
            try:
                self.assertTrue(self.entered.wait(2))
                queued=core.submit(dict(action='restore_pair',snapshot_id='b'*64,name='must-not-run'))
                closer=threading.Thread(target=core.close);closer.start()
                self.wait(lambda:core.closing);self.assertTrue(closer.is_alive())
                self.release.set();closer.join(4);self.assertFalse(closer.is_alive())
                self.assertTrue(self.readers[0].closed);self.assertFalse((core.output_root/'must-not-run').exists())
            finally:
                self.release.set()
                if closer:closer.join(4)
                core.close()
            restarted=self.core()
            try:
                rows={j['id']:j for j in restarted.jobs_snapshot()['jobs']}
                self.assertEqual(rows[queued['id']]['status'],'interrupted_unconfirmed')
                self.assertEqual(rows[core.initial_offline_job]['status'],'completed')
                self.assertEqual(len(self.calls),1);self.assertFalse(restarted.pending)
                self.assertFalse((core.output_root/'must-not-run').exists())
            finally:restarted.close()

    def test_cli_bootstrap_and_http_status_precede_authentication_gate(self):
        bootstrap=threading.Event();quit_pipe=threading.Event();output=io.StringIO();errors=io.StringIO();result=[]
        class Sink:
            def write(sink,text):
                output.write(text)
                if '\n' in output.getvalue():bootstrap.set()
                return len(text)
            def flush(sink):pass
        class Input:
            def __iter__(source):return source
            def __next__(source):
                if not quit_pipe.wait(8):raise TimeoutError('synthetic parent pipe gate')
                raise StopIteration
        def run():result.append(product_host.main(['--root',str(self.root),'--offline',str(self.root/'copy')]))
        with patch('wechat_capture_next.recovery_core.OfflineView',side_effect=self.fake_view),\
             patch.object(CaptureService,'__init__',side_effect=AssertionError('live capture forbidden')),\
             patch('sys.stdin',Input()),redirect_stdout(Sink()),redirect_stderr(errors):
            host=threading.Thread(target=run);host.start()
            try:
                self.assertTrue(self.entered.wait(2));self.assertTrue(bootstrap.wait(2))
                self.assertFalse(self.release.is_set())
                boot=json.loads(output.getvalue().splitlines()[0]);self.assertEqual(boot['mode'],'recovery')
                request=Request(boot['url']+'/api/product',headers={'X-Capture-Token':boot['token']})
                with build_opener(ProxyHandler({})).open(request,timeout=2) as response:status=json.load(response)
                self.assertTrue(status['product']['offline_loading']);self.assertIsNone(status['product']['offline_view'])
            finally:
                self.release.set();quit_pipe.set();host.join(5)
            self.assertFalse(host.is_alive());self.assertEqual(result,[0])
        self.assertTrue(self.readers[0].closed)


if __name__=='__main__':unittest.main()
