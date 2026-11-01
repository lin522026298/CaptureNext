"""Product lifecycle/maintenance tests: synthetic state only, no desktop input."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.request import Request, build_opener, ProxyHandler

from wechat_capture_next.product import ProductCore
from wechat_capture_next.product_host import ProductHost, product_read
from wechat_capture_next import product_settings
from wechat_capture_next.cut_reuse import ExactCut
from wechat_capture_next.tests import test_service as fixtures
from wechat_capture_next.tests import test_union_delivery as delivery_fixtures


class ProductTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    pages = fixtures.ServiceTests.pages
    publish = fixtures.ServiceTests.publish
    init_service = fixtures.ServiceTests.init_service
    prepared = delivery_fixtures.UnionDeliveryTests.prepared

    def tearDown(self):
        self.doCleanups()
        fixtures.ServiceTests.tearDown(self)

    def core(self):
        self.prepared()
        settings=dict(product_settings.DEFAULTS,auto_capture=False)
        with patch('wechat_capture_next.product.preferences.load',return_value=settings):
            core=ProductCore(self.state,self.root/'product',union_root=self.formal,
                repository_root=self.state_repo,union_repository=self.union_repo,interval=.05)
        self.addCleanup(core.close)
        self.wait(core)
        return core

    def wait(self,core,job=None,status='completed'):
        end=time.monotonic()+30
        while time.monotonic()<end:
            snapshot=core.jobs_snapshot()['jobs']
            if job:
                result=next(j for j in snapshot if j['id']==job['id'])
                if result['status'] not in ('queued','running') and not core.control_snapshot()['busy']:
                    self.assertEqual(result['status'],status,result)
                    return result
            elif not any(j['status'] in ('queued','running') for j in snapshot) and not core.control_snapshot()['busy']:
                return
            time.sleep(.01)
        self.fail('product job did not settle')

    def test_two_borrowed_listeners_share_core_and_closing_webui_keeps_worker_lock(self):
        core=self.core()
        host=ProductHost(core);self.addCleanup(host.close)
        first=host.set_webui(True)
        worker=core.thread
        oldtoken=host.browser[0].token
        self.assertNotEqual(oldtoken,host.desktop[0].token)
        host.set_webui(False)
        self.assertTrue(worker.is_alive())
        self.assertFalse(core.closing)
        host.set_webui(True)
        self.assertNotEqual(oldtoken,host.browser[0].token)
        self.assertIs(core,host.browser[0].coordinator)
        self.assertIs(core,host.desktop[0].coordinator)
        self.assertEqual(first['enabled'],True)
        job=core.submit(dict(action='start_watch'));self.wait(core,job)
        host.set_webui(False)
        self.assertTrue(core.watching)
        self.wait(core,core.submit(dict(action='stop_watch')))

    def test_backup_pair_reopen_and_exact_no_change_reuse_then_real_restore(self):
        core=self.core()
        first=self.wait(core,core.submit(dict(action='backup_pair')))
        self.assertTrue(core.thread.is_alive())
        first_hash=hashlib.sha256((self.union_repo/'repository.sqlite').read_bytes()).hexdigest()
        second=self.wait(core,core.submit(dict(action='backup_pair')))
        self.assertTrue(second['result']['reused_exact_authenticated_cut'])
        self.assertTrue(second['result']['noop'])
        self.assertEqual(first_hash,hashlib.sha256((self.union_repo/'repository.sqlite').read_bytes()).hexdigest())
        snapshots=product_read(core,'/api/union-backups',{})['snapshots']
        self.assertEqual(len(snapshots),1)
        restored=self.wait(core,core.submit(dict(action='restore_pair',snapshot_id=snapshots[0]['snapshot_id'],name='restored')))
        self.assertTrue(restored['result']['attachments_closed'])
        self.assertTrue((self.root/'product'/'restored'/'state'/'objects.sqlite').is_file())

    def test_maintenance_waits_for_reader_gate_and_memory_status_stays_available(self):
        core=self.core()
        core.reader_gate.acquire()
        try:
            job=core.submit(dict(action='deep_verify'))
            end=time.monotonic()+5
            while not core.maintenance and time.monotonic()<end:time.sleep(.01)
            self.assertTrue(core.control_snapshot()['product']['maintenance'])
            self.assertTrue(product_read(core,'/api/product',{})['busy'])
            with self.assertRaises(BlockingIOError):product_read(core,'/api/assets',{})
        finally:core.reader_gate.release()
        self.wait(core,job)
        self.assertIsNotNone(core.service)

    def test_pending_union_retries_after_capture_commit_and_failure(self):
        core=self.core()
        with patch('wechat_capture_next.union_archive.sync_union',side_effect=OSError('synthetic')):
            self.wait(core,core.submit(dict(action='sync_union')),status='failed')
        self.assertEqual(core.union_status['status'],'pending')
        self.wait(core,core.submit(dict(action='capture',full=False,assets=False)))
        self.assertEqual(core.union_status['status'],'caught_up')

    def test_asset_only_progress_does_not_rescan_message_membership(self):
        core=self.core()
        with patch.object(core,'_sync') as sync:
            core._after_capture(dict(mode='asset_continuation',status='local_complete_assets_pending',databases=[]))
            sync.assert_not_called()
            core._after_capture(dict(mode='changed_shards',databases=[dict(status='accepted',new_versions=0,new_interpretations=1)]))
            sync.assert_called_once()

    def test_unified_messages_export_and_idempotent_settings(self):
        core=self.core()
        messages=product_read(core,'/api/union-messages',{'limit':['50']})
        self.assertEqual(len(messages['rows']),40)
        self.wait(core,core.submit(dict(action='export_union',name='full.jsonl')))
        rows=[json.loads(line) for line in (self.root/'product'/'full.jsonl').read_text(encoding='utf-8').splitlines()]
        observations=[r['record'] for r in rows if r['kind']=='message_observation']
        self.assertEqual(len(observations),40)
        self.assertIn('raw_record_json',observations[0])
        self.assertTrue(any(r['kind']=='source_device' for r in rows))
        self.assertTrue(any(r['kind']=='source_snapshot' for r in rows))
        value=dict(product_settings.DEFAULTS,auto_capture=False)
        self.wait(core,core.submit(dict(action='settings',value=value)))
        before=core.settings_path.read_bytes()
        self.wait(core,core.submit(dict(action='settings',value=value)))
        self.assertEqual(before,core.settings_path.read_bytes())
        with self.assertRaises(ValueError):core.submit(dict(action='settings',value=dict(value,backup_hours=0)))

    @unittest.skipUnless(os.name=='nt','Windows deny-write guards required')
    def test_exact_cut_detects_same_size_same_timestamp_tamper(self):
        p=self.root/'cut.txt';p.write_bytes(b'first')
        proof=ExactCut();proof.remember([p],dict(pass_all=True),expected={p:hashlib.sha256(b'first').hexdigest()})
        st=p.stat();p.write_bytes(b'other');os.utime(p,ns=(st.st_atime_ns,st.st_mtime_ns))
        self.assertIsNone(proof.lookup([p]))

    def test_schedule_windows_and_settings_types(self):
        self.assertTrue(product_settings.in_window(2,23,6))
        self.assertFalse(product_settings.in_window(12,23,6))
        self.assertTrue(product_settings.in_window(12,0,0))
        with self.assertRaises(ValueError):product_settings.validate(dict(product_settings.DEFAULTS,auto_capture=1))

    def test_multiple_readers_coexist_without_false_maintenance(self):
        core=self.core()
        self.assertTrue(core.reader_gate.acquire(False))
        self.assertTrue(core.reader_gate.acquire(False))
        try:
            assets=product_read(core,'/api/assets',{})
            self.assertEqual(assets['total'],1)
            self.assertEqual(assets['rows'][0]['file_sha'],self.file_sha)
        finally:
            core.reader_gate.release();core.reader_gate.release()

    def test_deep_verify_never_promotes_failed_integrity_or_reuses_it(self):
        core=self.core()
        with patch('wechat_capture_next.compact_archive.CompactArchive.integrity_check',
                   return_value=dict(quick_check=['ok'],foreign_key_check=[['broken']],fts_verified=True)):
            job=self.wait(core,core.submit(dict(action='deep_verify')),status='failed')
        self.assertIsNone(core._verify_reuse.proof)
        self.assertNotIn('pass_all',job.get('result') or {})
        self.wait(core,core.submit(dict(action='deep_verify')))

    def test_close_failure_fails_closed_instead_of_reusing_dead_connection(self):
        core=self.core()
        original=core.service.close
        def broken_close():
            original()
            raise OSError('synthetic close fault')
        with patch.object(core.service,'close',side_effect=broken_close):
            core.submit(dict(action='deep_verify'))
            core.thread.join(10)
        self.assertFalse(core.thread.is_alive())
        self.assertTrue(core.closing)
        self.assertIsNone(core.service)

    def test_schedule_enqueues_once_and_persists_completed_attempt(self):
        core=self.core()
        core.settings=dict(core.settings,heavy_start=0,heavy_end=0)
        core._schedule_last['deep_verify']=0
        core._schedule_tick()
        ident=core._schedule_jobs['deep_verify']
        core._schedule_tick()
        self.assertEqual(core._schedule_jobs['deep_verify'],ident)
        self.wait(core)
        core._schedule_tick()
        self.assertGreater(core._schedule_last['deep_verify'],0)
        self.assertNotIn('deep_verify',core._schedule_jobs)
        ledger=json.loads((core.output_root/'schedule.private.json').read_text(encoding='utf-8'))
        self.assertEqual(ledger,core._schedule_last)

    def test_schedule_passes_explicit_secret_preference_both_directions(self):
        core=self.core();core._scheduler_stop.set();core.scheduler.join()
        for enabled in (False,True):
            with self.subTest(enabled=enabled):
                core.settings=dict(core.settings,heavy_start=0,heavy_end=0,backup_include_secrets=enabled)
                core._schedule_last['backup_pair']=0;core._schedule_jobs.clear()
                with patch.object(core,'submit',return_value=dict(id='scheduled-proof')) as submit:
                    core._schedule_tick()
                submit.assert_called_once_with(dict(action='backup_pair',include_secrets=enabled))
                self.assertIs(core.settings['backup_include_secrets'],enabled)

    def test_manual_secret_choice_does_not_change_plan_preference(self):
        core=self.core();core._scheduler_stop.set();core.scheduler.join()
        for planned,manual in ((False,True),(True,False)):
            with self.subTest(planned=planned,manual=manual):
                core.settings=dict(core.settings,backup_include_secrets=planned)
                with patch.object(core,'_perform',return_value=dict(synthetic_only=True)) as perform:
                    self.wait(core,core.submit(dict(action='backup_pair',include_secrets=manual)))
                self.assertIs(perform.call_args.args[1]['include_secrets'],manual)
                self.assertIs(core.settings['backup_include_secrets'],planned)

    def test_mutation_after_backup_cannot_become_authenticated_reuse(self):
        core=self.core()
        from wechat_capture_next.union_delivery import backup_owned
        def tamper(*args,**kwargs):
            result=backup_owned(*args,**kwargs)
            view=next((core.state/'cache').glob('*.db'))
            raw=view.read_bytes();view.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
            return result
        with patch('wechat_capture_next.union_delivery.backup_owned',side_effect=tamper):
            self.wait(core,core.submit(dict(action='backup_pair')),status='failed')
        self.assertIsNone(core._backup_reuse.proof)

    def test_new_unbacked_report_after_backup_cannot_become_authenticated_reuse(self):
        core=self.core()
        from wechat_capture_next.union_delivery import backup_owned
        def add_file(*args,**kwargs):
            result=backup_owned(*args,**kwargs)
            (core.state/'reports'/'late-synthetic.json').write_text('{}',encoding='utf-8')
            return result
        with patch('wechat_capture_next.union_delivery.backup_owned',side_effect=add_file):
            self.wait(core,core.submit(dict(action='backup_pair')),status='failed')
        self.assertIsNone(core._backup_reuse.proof)

    def test_schedule_ledger_write_failure_remains_dirty_and_retries(self):
        core=self.core()
        core.settings=dict(core.settings,heavy_start=0,heavy_end=0)
        core._schedule_last['deep_verify']=0
        core._schedule_tick();self.wait(core)
        with patch('wechat_capture_next.product.preferences.atomic_json',side_effect=PermissionError('synthetic')):
            with self.assertRaises(PermissionError):core._schedule_tick()
        self.assertTrue(core._schedule_dirty)
        core._schedule_tick()
        self.assertFalse(core._schedule_dirty)


if __name__=='__main__':unittest.main()
