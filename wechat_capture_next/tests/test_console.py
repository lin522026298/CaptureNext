"""Synthetic-only HTTP, queue, writer ownership and real offline workflows."""
from contextlib import closing
import hashlib
from http.client import RemoteDisconnected
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler

from wechat_capture_next.console import create_server, checked_output, MAX_BODY
from wechat_capture_next.tests import test_service as fixtures
from wechat_capture_v2.common import writer_lock


class ConsoleTests(unittest.TestCase):
    pages = fixtures.ServiceTests.pages
    publish = fixtures.ServiceTests.publish
    init_service = fixtures.ServiceTests.init_service

    def setUp(self):
        fixtures.ServiceTests.setUp(self)
        with closing(self.init_service()) as service:
            self.state = service.state
        # Keep exports outside the synthetic bound account, just as production
        # attachment APIs require. This is never the user's source tree.
        self.output_temp = tempfile.TemporaryDirectory()
        self.output = Path(self.output_temp.name)/'console'
        self.web = self.root/'test-web'
        self.web.mkdir()
        (self.web/'index.html').write_text('<!doctype html><html><head><script src="/app.js" defer></script></head><body>synthetic</body></html>',encoding='utf-8')
        (self.web/'app.js').write_text('window.synthetic=true;',encoding='utf-8')
        (self.web/'style.css').write_text('body{color:black}',encoding='utf-8')
        self.web_patch = patch('wechat_capture_next.console.WEB', self.web)
        self.web_patch.start()
        self.server = create_server(self.state, self.output, queue_size=2, interval=.03, reconcile_seconds=300)
        self.engine = self.server.coordinator
        self.http_thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval':.02}, daemon=True)
        self.http_thread.start()
        self.opener = build_opener(ProxyHandler({}))
        self.headers = {'X-Capture-Token': self.server.token, 'Origin': self.server.base_url}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.http_thread.join(3)
        self.web_patch.stop()
        self.output_temp.cleanup()
        fixtures.ServiceTests.tearDown(self)

    def request(self, path, payload=None, *, method=None, headers=None, raw=None):
        current = dict(self.headers) if headers is None else headers
        if raw is None and payload is not None:
            raw = json.dumps(payload).encode()
        if raw is not None:
            current = {'Content-Type':'application/json', **current}
        request = Request(self.server.base_url+path, data=raw, headers=current,
                          method=method or ('POST' if raw is not None else 'GET'))
        try:
            response = self.opener.open(request, timeout=8)
        except HTTPError as exc:
            response = exc
        with response:
            data = response.read()
            try:
                value = json.loads(data)
            except ValueError:
                value = data.decode('utf-8')
            return response.code, value, response.headers

    def enqueue(self, action, **params):
        code, result, _ = self.request('/api/jobs', dict(action=action, **params))
        self.assertEqual(code, 202, result)
        return result

    def completed(self, job, status='completed'):
        end = time.monotonic()+20
        while time.monotonic()<end:
            value = next(item for item in self.engine.jobs_snapshot()['jobs'] if item['id']==job['id'])
            if value['status'] not in ('queued','running'):
                current = self.engine.control_snapshot()['current_job']
                if current and current['id'] == job['id']:
                    time.sleep(.005)  # Wait for the final statistics boundary.
                    continue
                self.assertEqual(value['status'], status, value)
                return value
            time.sleep(.01)
        self.fail('synthetic job did not finish')

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.http_thread.join(3)

    def restart_server(self, output, **options):
        self.stop_server()
        self.output = output
        self.server = create_server(self.state, output, **options)
        self.engine = self.server.coordinator
        self.http_thread = threading.Thread(target=self.server.serve_forever,
            kwargs={'poll_interval':.02}, daemon=True)
        self.http_thread.start()
        self.headers = {'X-Capture-Token':self.server.token, 'Origin':self.server.base_url}

    def test_explicit_same_instance_roots_reuse_without_duplicate_outputs(self):
        import shutil
        self.completed(self.enqueue('capture'))
        self.completed(self.enqueue('sync_wua', verify=True))
        initial = self.completed(self.enqueue('backup'))
        repository, managed = self.output/'backups', self.output/'managed-wua'
        archive, database = managed/'archive.wua.sqlite', repository/'repository.sqlite'
        reference = Path(self.output_temp.name)/'reference'/'archive.sqlite'
        reference.parent.mkdir()
        shutil.copyfile(archive, reference)
        protected = (archive, database, reference, self.source)
        before = {path:hashlib.sha256(path.read_bytes()).hexdigest() for path in protected}
        new_output = Path(self.output_temp.name)/'reused-console'
        arguments = [repository, managed]
        if os.name == 'nt':
            import ctypes
            for index, path in enumerate(arguments):
                buffer = ctypes.create_unicode_buffer(32768)
                self.assertTrue(ctypes.windll.kernel32.GetShortPathNameW(str(path),buffer,len(buffer)))
                arguments[index] = Path(buffer.value)
                self.assertTrue(arguments[index].samefile(path))
        self.restart_server(new_output, repository_root=arguments[0], managed_root=arguments[1])
        status = self.request('/api/status')[1]
        self.assertEqual(status['repository_root'], str(repository))
        self.assertEqual(status['managed_root'], str(managed))
        snapshots = self.request('/api/backups')[1]['snapshots']
        self.assertEqual([row['id'] for row in snapshots], [initial['result']['snapshot_id']])
        self.assertFalse((new_output/'backups').exists())
        self.assertFalse((new_output/'managed-wua').exists())
        self.assertEqual(self.completed(self.enqueue('sync_wua'))['result']['added_observations'], 0)
        repeated = self.completed(self.enqueue('backup'))
        self.assertTrue(repeated['result']['noop'])
        self.assertEqual(repeated['result']['snapshot_id'], initial['result']['snapshot_id'])
        restored = self.completed(self.enqueue('restore', snapshot_id=initial['result']['snapshot_id'], name='restored-bound'))
        self.assertTrue(restored['result']['verification']['pass'])
        compared = self.completed(self.enqueue('compare', reference=str(reference), name='bound-comparison'))
        self.assertTrue(compared['result']['raw_native_equal'])
        self.assertTrue(compared['result']['message_fields_equal'])
        self.assertEqual(before, {path:hashlib.sha256(path.read_bytes()).hexdigest() for path in protected})
        self.assertFalse((new_output/'backups').exists())
        self.assertFalse((new_output/'managed-wua').exists())

    def test_explicit_fresh_roots_are_created_by_jobs_not_startup_or_get(self):
        parent = Path(self.output_temp.name)
        repository, managed = parent/'fresh-repository', parent/'fresh-managed'
        self.restart_server(parent/'fresh-console', repository_root=repository, managed_root=managed)
        self.assertFalse(repository.exists())
        self.assertFalse(managed.exists())
        listing = self.request('/api/backups')[1]
        self.assertEqual(listing['snapshots'], [])
        self.assertEqual(listing['integrity_scope'], 'manifest_metadata_only')
        self.assertFalse(listing['contents_verified'])
        self.assertFalse(repository.exists())
        self.completed(self.enqueue('capture'))
        self.completed(self.enqueue('sync_wua'))
        self.assertTrue((managed/'OWNER.private.json').exists())
        self.assertFalse(repository.exists())
        self.completed(self.enqueue('backup'))
        self.assertTrue((repository/'OWNER.private.json').exists())

    def test_bound_root_owner_schema_links_and_overlap_fail_before_output_creation(self):
        identity = self.engine._catalog_instance
        parent = Path(self.output_temp.name)
        self.stop_server()
        cases = []
        for label, option, owner in (
            ('wrong-cas-instance','repository_root',{'schema':'next-cas-backup-1','catalog_instance':'foreign'}),
            ('wrong-managed-instance','managed_root',{'schema':'next-managed-wua-1','catalog_instance':'foreign'}),
            ('wrong-cas-schema','repository_root',{'schema':'next-managed-wua-1','catalog_instance':identity}),
            ('wrong-managed-schema','managed_root',{'schema':'next-cas-backup-1','catalog_instance':identity}),
            ('extra-owner-field','repository_root',{'schema':'next-cas-backup-1','catalog_instance':identity,'extra':True}),
            ('historical-cas-no-owner','repository_root',None),
            ('historical-no-owner','managed_root',None)):
            root = parent/label
            root.mkdir()
            if owner is not None:
                (root/'OWNER.private.json').write_text(json.dumps(owner), encoding='utf-8')
            else:
                filename = 'repository.sqlite' if option == 'repository_root' else 'archive.wua.sqlite'
                (root/filename).write_bytes(b'historical export must not be adopted')
            cases.append((label, {option:root}))
        linked = parent/'hardlinked-owner'
        linked.mkdir()
        original = parent/'owner-source.json'
        original.write_text(json.dumps({'schema':'next-managed-wua-1','catalog_instance':identity}), encoding='utf-8')
        os.link(original, linked/'OWNER.private.json')
        cases.append(('hardlinked-owner', {'managed_root':linked}))
        linked_archive = parent/'hardlinked-managed-archive'
        linked_archive.mkdir()
        (linked_archive/'OWNER.private.json').write_text(
            json.dumps({'schema':'next-managed-wua-1','catalog_instance':identity}), encoding='utf-8')
        historical = parent/'historical-input.sqlite'
        historical.write_bytes(b'historical input must remain unmodified')
        os.link(historical, linked_archive/'archive.wua.sqlite')
        cases.append(('hardlinked-archive', {'managed_root':linked_archive}))
        for label, options in (
            ('state-child',{'repository_root':self.state/'new-repository'}),
            ('source-account-child',{'managed_root':self.source.parent.parent/'media'/'new-managed'}),
            ('overlap',{'repository_root':parent/'overlapping', 'managed_root':parent/'overlapping'/'nested'}),
            ('contains-console',{'repository_root':parent})):
            cases.append((label,options))
        for index, (label, options) in enumerate(cases):
            output = parent/('rejected-console-'+str(index))
            if label == 'contains-console':
                options = {'repository_root':parent}
            with self.subTest(label=label):
                inputs = {p:hashlib.sha256(p.read_bytes()).hexdigest()
                    for root in options.values() if root.exists()
                    for p in root.iterdir() if p.is_file()}
                with self.assertRaises((ValueError, RuntimeError, FileNotFoundError)):
                    create_server(self.state, output, **options)
                self.assertFalse(output.exists())
                self.assertEqual(inputs, {p:hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs})

    @unittest.skipUnless(os.name=='nt','Windows DOS alias and junction boundaries')
    def test_explicit_bound_roots_canonicalize_aliases_and_reject_reparse(self):
        import ctypes
        parent = Path(self.output_temp.name)
        self.stop_server()
        for index, root in enumerate((self.state, self.source.parent.parent)):
            buffer = ctypes.create_unicode_buffer(32768)
            if not ctypes.windll.kernel32.GetShortPathNameW(str(root),buffer,len(buffer)):
                self.fail('synthetic DOS alias lookup failed')
            candidate = Path(buffer.value)/'must-not-create'
            output = parent/('alias-rejected-'+str(index))
            with self.assertRaises((ValueError,RuntimeError)):
                create_server(self.state,output,repository_root=candidate)
            self.assertFalse(candidate.exists())
            self.assertFalse(output.exists())
        # A symlink fixture is optional on accounts lacking symlink privilege;
        # owner/file hardlink checks remain covered without that privilege.
        linked = parent/'linked-root'
        try:
            linked.symlink_to(self.state, target_is_directory=True)
        except OSError:
            # Directory junctions do not require Windows symlink privilege.
            # The exact synthetic target stays in this test's temp roots.
            import subprocess
            subprocess.run(['cmd.exe','/c','mklink','/J',str(linked),str(self.state)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW)
        with self.assertRaises(ValueError):
            create_server(self.state,parent/'linked-console',managed_root=linked/'child')
        self.assertFalse((parent/'linked-console').exists())

    def test_serve_cli_forwards_optional_binding_roots_without_opening_state(self):
        from wechat_capture_next import __main__ as cli
        from wechat_capture_next import console
        options = ['--state',str(self.state),'--output-root',str(self.output),
                   '--repository-root',str(self.output/'backups'),'--managed-root',str(self.output/'managed-wua'),
                   '--port','23456']
        with patch.object(sys,'argv',['wechat_capture_next','serve',*options]), \
                patch('wechat_capture_next.console.main',return_value='synthetic-cli') as run:
            self.assertEqual(cli.main(),'synthetic-cli')
            forwarded = run.call_args.args[0]
            for flag in ('--repository-root','--managed-root'):
                self.assertEqual(forwarded[forwarded.index(flag)+1],options[options.index(flag)+1])
        with patch.object(console, 'create_server') as create, patch('builtins.print'):
            create.return_value.serve_forever.side_effect = KeyboardInterrupt
            console.main(options)
            create.assert_called_once_with(self.state, self.output, 23456,
                repository_root=self.output/'backups', managed_root=self.output/'managed-wua')
            create.return_value.server_close.assert_called_once()

    def test_auth_host_origin_body_path_and_safe_bootstrap(self):
        self.assertEqual(self.request('/api/status', headers={})[0],403)
        self.assertEqual(self.request('/api/jobs', {'action':'verify'}, headers={'X-Capture-Token':self.server.token})[0],403)
        for host in ('evil.test', '127.0.0.1', '127.0.0.1:1', f'127.0.0.1:{self.server.server_port}.evil'):
            self.assertEqual(self.request('/api/status',headers={**self.headers,'Host':host})[0],400)
        self.assertEqual(self.request('/api/status',headers={**self.headers,'Origin':'https://evil.test'})[0],403)
        self.assertEqual(self.request('/api/status',headers={'X-Capture-Token':self.server.token})[0],200)
        self.assertEqual(self.request('/api/status',headers={**self.headers,'X-Capture-Token':'wrong'})[0],403)
        self.assertEqual(self.request('/api/jobs',raw=b'{')[0],400)
        self.assertEqual(self.request('/api/jobs',raw=b'{"action":"verify","action":"capture"}')[0],400)
        for path in ('/../config.private.json','/%2e%2e/config.private.json','/app.js/../config.private.json'):
            self.assertEqual(self.request(path)[0],400)
        self.assertEqual(self.request('/config.private.json')[0],404)
        self.assertEqual(self.request('/api/status?limit=1&limit=2')[0],400)
        code, html, headers = self.request('/',headers={})
        self.assertEqual(code,200)
        self.assertIn('window.__BOOTSTRAP__',html)
        self.assertIn(self.server.token,html)
        self.assertNotIn(self.server.token,self.server.base_url)
        self.assertIn('nonce-',headers['Content-Security-Policy'])
        self.assertIn("frame-ancestors 'none'",headers['Content-Security-Policy'])
        self.assertEqual(headers['Cache-Control'],'no-store')
        self.assertEqual(headers['Referrer-Policy'],'no-referrer')
        self.assertEqual(headers['X-Content-Type-Options'],'nosniff')
        self.assertNotIn('Access-Control-Allow-Origin',headers)
        self.assertEqual(self.request('/app.js',headers={})[0],200)
        self.assertEqual(self.request('/style.css',headers={})[0],200)
        self.assertEqual(self.server.server_address[0],'127.0.0.1')

    def test_oversized_body_is_rejected_without_enqueue_or_service_loss(self):
        # The server never consumes attacker-sized bodies to promise a reply.
        # Windows can reset a connection closed with unread bytes; either an
        # explicit 413 or that transport rejection is valid, never acceptance.
        before = self.engine.jobs_snapshot()
        for _ in range(5):
            try:
                code, _, _ = self.request('/api/jobs', raw=b'x'*(MAX_BODY+1))
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, RemoteDisconnected):
                pass
            else:
                self.assertEqual(code, 413)
            self.assertEqual(self.engine.jobs_snapshot(), before)
            self.assertEqual(self.request('/api/status')[0], 200)

    def test_real_queued_capture_verify_validate_sync_backup_restore_and_reports(self):
        captured = self.completed(self.enqueue('capture'))
        self.assertEqual(captured['result']['summary']['active_messages'],40)
        self.assertTrue(self.completed(self.enqueue('verify'))['result']['pass'])
        self.assertTrue(self.completed(self.enqueue('validate',name='independent-check'))['result']['pass_all'])
        sync = self.completed(self.enqueue('sync_wua',verify=True))
        self.assertEqual(sync['result']['added_versions'],40)
        backup = self.completed(self.enqueue('backup',output_name='first-snapshot'))
        self.assertFalse(backup['result']['includes_secrets'])
        snapshot = backup['result']['snapshot_id']
        code, snapshots, _ = self.request('/api/backups')
        self.assertEqual(code,200)
        self.assertEqual(snapshots['snapshots'][0]['id'],snapshot)
        restored = self.completed(self.enqueue('restore',snapshot_id=snapshot,output_name='restored-copy'))
        self.assertEqual(restored['result']['state'],'complete')
        self.assertTrue(restored['result']['offline'])
        self.assertFalse(restored['result']['watch_started'])
        self.assertTrue((self.output/'restored-copy'/'RESTORE.complete.private.json').exists())
        self.assertFalse((self.output/'restored-copy'/'90_SECRETS_PLAINTEXT_RESTRICTED'/'keyring.json').exists())
        code, reports, _ = self.request('/api/reports')
        self.assertEqual(code,200)
        self.assertEqual(reports['rows'][0]['errors_count'],0)
        import shutil
        reference = self.root/'reference'/'archive.sqlite'
        reference.parent.mkdir()
        shutil.copyfile(self.output/'managed-wua'/'archive.wua.sqlite',reference)
        before = hashlib.sha256(reference.read_bytes()).hexdigest()
        compare = self.completed(self.enqueue('compare',reference_path=str(reference),name='comparison'))
        self.assertTrue(compare['result']['raw_native_equal'])
        self.assertTrue(compare['result']['message_fields_equal'])
        self.assertEqual(hashlib.sha256(reference.read_bytes()).hexdigest(),before)

    def test_read_apis_do_not_construct_service_and_message_pages_are_not_collection_caps(self):
        self.completed(self.enqueue('capture'))
        with closing(sqlite3.connect(self.state/'catalog.sqlite')) as db:
            before = db.execute('SELECT id,status FROM cycle ORDER BY id').fetchall()
        with patch('wechat_capture_next.console.CaptureService', side_effect=AssertionError('GET constructed writer')):
            for _ in range(3):
                code, status, _ = self.request('/api/status')
                self.assertEqual(code,200)
                self.assertEqual(status['summary']['active_messages'],40)
                self.assertEqual(status['scope'],'仅本机已落盘')
                self.assertNotIn('synthetic 1',json.dumps(status))
            code, page, _ = self.request('/api/messages?limit=7&offset=0')
            self.assertEqual(code,200)
            self.assertEqual(page['total'],40)
            self.assertEqual(len(page['rows']),7)
            self.assertEqual(page['next_offset'],7)
            code, query, _ = self.request('/api/messages?q=synthetic%201&limit=50')
            self.assertEqual(code,200)
            self.assertEqual(query['total'],11)
            self.assertTrue(all('synthetic 1' in row['body_text'] for row in query['rows']))
            self.assertEqual(self.request('/api/messages?limit=201')[0],400)
            self.assertEqual(self.request('/api/messages?offset=-1')[0],400)
            self.assertEqual(self.request('/api/assets')[1]['total'],0)
        with closing(sqlite3.connect(self.state/'catalog.sqlite')) as db:
            self.assertEqual(before,db.execute('SELECT id,status FROM cycle ORDER BY id').fetchall())

    def test_status_uses_atomic_published_counts_without_http_count_or_worker_connection(self):
        from wechat_capture_next import console as module
        self.completed(self.enqueue('capture'))
        baseline = self.request('/api/status')[1]
        self.assertEqual(baseline['summary']['active_messages'], 40)
        self.assertEqual(baseline['service_epoch'], 1)
        self.assertTrue(baseline['summary_valid'])
        self.assertEqual(baseline['summary_scope'], 'last_committed_worker_boundary')
        self.assertIn('not_same_cut', baseline['cycle_scope'])
        readonly = module._readonly
        forbidden = []
        def without_count(state):
            db = readonly(state)
            def authorize(action, name, value, database, trigger):
                if action == sqlite3.SQLITE_FUNCTION and (value or name or '').casefold() == 'count':
                    forbidden.append(threading.get_ident())
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            db.set_authorizer(authorize)
            return db
        with patch.object(module, '_readonly', side_effect=without_count), \
                patch.object(self.engine, '_read_summary', side_effect=AssertionError('HTTP requested new counts')), \
                patch.object(self.engine.service.catalog, 'summary', side_effect=AssertionError('HTTP used worker SQLite')):
            for _ in range(12):
                code, data, _ = self.request('/api/status')
                self.assertEqual(code, 200)
                for key in ('summary','summary_as_of','summary_generation','service_epoch'):
                    self.assertEqual(data[key], baseline[key])
        self.assertEqual(forbidden, [])

    def test_capture_reuses_its_summary_and_idle_never_recounts_or_retimes(self):
        with patch.object(self.engine, '_read_summary', side_effect=AssertionError('capture was counted twice')):
            self.completed(self.enqueue('capture'))
            self.assertEqual(self.request('/api/status')[1]['summary']['active_messages'], 40)
        service = self.engine.service
        idle = dict(status='idle', mode='metadata_poll', cycle_id=None, summary=dict(service._summary_cache))
        with patch.object(service, 'capture', return_value=idle) as capture, \
                patch.object(self.engine, '_read_summary', wraps=self.engine._read_summary) as read:
            self.completed(self.enqueue('start_watch'))
            baseline = self.request('/api/status')[1]
            end = time.monotonic()+3
            while capture.call_count < 4 and time.monotonic() < end:
                time.sleep(.01)
            self.assertGreaterEqual(capture.call_count, 4)
            for _ in range(5):
                status = self.request('/api/status')[1]
                for key in ('summary','summary_as_of','summary_generation','service_epoch'):
                    self.assertEqual(status[key], baseline[key])
            self.assertEqual(read.call_count, 1)  # The explicit start job only.
            self.completed(self.enqueue('stop_watch'))

    def test_failed_job_refreshes_committed_shards_on_owned_worker(self):
        self.completed(self.enqueue('capture'))
        baseline = self.request('/api/status')[1]
        worker_reads = []
        committed, release = threading.Event(), threading.Event()
        original_read = self.engine._read_summary
        def counted():
            worker_reads.append(threading.get_ident())
            return original_read()
        def commit_then_fail(*_):
            db = self.engine.service.catalog.db
            with db:
                db.execute('UPDATE head SET active=0 WHERE version_id=(SELECT version_id FROM head WHERE active=1 LIMIT 1)')
            committed.set()
            if not release.wait(10):
                raise RuntimeError('test release timeout')
            raise RuntimeError('synthetic failure after a committed shard')
        with patch.object(self.engine, '_execute', side_effect=commit_then_fail), \
                patch.object(self.engine, '_read_summary', side_effect=counted):
            job = self.enqueue('verify')
            try:
                self.assertTrue(committed.wait(3))
                busy = self.request('/api/status')[1]
                self.assertTrue(busy['busy'])
                self.assertTrue(busy['summary_stale'])
                self.assertEqual(busy['summary'], baseline['summary'])
                self.assertEqual(busy['summary_generation'], baseline['summary_generation'])
                self.assertEqual(busy['summary_as_of'], baseline['summary_as_of'])
            finally:
                release.set()
            self.completed(job, status='failed')
        status = self.request('/api/status')[1]
        self.assertEqual(status['summary']['active_messages'], 39)
        self.assertEqual(status['summary']['versions'], 40)
        self.assertGreater(status['summary_generation'], baseline['summary_generation'])
        self.assertFalse(status['summary_stale'])
        self.assertEqual(worker_reads, [self.engine.thread.ident])

    def test_service_reopen_publishes_new_epoch_from_constructor_cache(self):
        self.completed(self.enqueue('capture'))
        baseline = self.request('/api/status')[1]
        media = self.source.parent.parent/'epoch-media'
        media.mkdir()
        previous_service = self.engine.service
        with patch.object(self.engine, '_read_summary', side_effect=AssertionError('reopen cache was recounted')):
            self.completed(self.enqueue('configure_assets', root=str(media)))
        status = self.request('/api/status')[1]
        self.assertIsNot(self.engine.service, previous_service)
        self.assertEqual(status['service_epoch'], baseline['service_epoch']+1)
        self.assertGreater(status['summary_generation'], baseline['summary_generation'])
        self.assertEqual(status['summary'], baseline['summary'])
        self.assertTrue(status['asset_enabled'])

    def test_failed_statistics_refresh_invalidates_status_until_a_successful_boundary(self):
        self.completed(self.enqueue('capture'))
        generation = self.request('/api/status')[1]['summary_generation']
        service = self.engine.service
        idle = dict(status='idle', mode='metadata_poll', cycle_id=None, summary=dict(service._summary_cache))
        with patch.object(self.engine, '_read_summary', side_effect=sqlite3.OperationalError('synthetic metrics read failure')) as read, \
                patch.object(service, 'capture', return_value=idle) as capture:
            self.completed(self.enqueue('verify'))
            self.assertEqual(self.request('/api/status')[0], 503)
            self.assertFalse(self.engine.control_snapshot()['summary_valid'])
            self.completed(self.enqueue('start_watch'))
            end = time.monotonic()+3
            while capture.call_count < 3 and time.monotonic() < end:
                time.sleep(.01)
            self.assertGreaterEqual(capture.call_count, 3)
            self.assertEqual(self.request('/api/status')[0], 503)
            self.assertEqual(self.engine._summary_generation, generation)
            self.assertEqual(read.call_count, 2)  # verify/start, never idle.
            self.completed(self.enqueue('stop_watch'))
        self.completed(self.enqueue('verify'))
        code, status, _ = self.request('/api/status')
        self.assertEqual(code, 200)
        self.assertTrue(status['summary_valid'])
        self.assertGreater(status['summary_generation'], generation)

    def test_http_manual_statistics_refresh_recovers_without_capture_or_source_reads(self):
        self.completed(self.enqueue('capture'))
        baseline = self.request('/api/status')[1]
        service = self.engine.service
        with patch.object(self.engine, '_read_summary', side_effect=sqlite3.OperationalError('synthetic metrics failure')):
            self.completed(self.enqueue('verify'))
        self.assertEqual(self.request('/api/status')[0], 503)
        self.assertFalse(self.engine.control_snapshot()['watching'])
        catalog = self.state/'catalog.sqlite'
        before = hashlib.sha256(catalog.read_bytes()).hexdigest()
        original_read = self.engine._read_summary
        readers = []
        def counted():
            readers.append(threading.get_ident())
            return original_read()
        with patch.object(self.engine, '_read_summary', side_effect=counted), \
                patch.object(service, 'capture', side_effect=AssertionError('recovery must not capture')), \
                patch.object(service, 'verify_state', side_effect=AssertionError('recovery is statistics only')):
            # The actual authenticated HTTP path remains usable when status is 503.
            code, job, _ = self.request('/api/jobs', {'action':'refresh_status'})
            self.assertEqual(code, 202, job)
            done = self.completed(job)
        self.assertEqual(readers, [self.engine.thread.ident])
        self.assertEqual(done['result'], {'summary_refreshed':True, 'read_only':True})
        code, status, _ = self.request('/api/status')
        self.assertEqual(code, 200)
        self.assertTrue(status['summary_valid'])
        self.assertFalse(status['watching'])
        self.assertEqual(status['summary'], baseline['summary'])
        self.assertGreater(status['summary_generation'], baseline['summary_generation'])
        self.assertEqual(status['service_epoch'], baseline['service_epoch'])
        self.assertEqual(hashlib.sha256(catalog.read_bytes()).hexdigest(), before)

    def test_manual_statistics_refresh_failure_stays_503_without_implicit_retry(self):
        generation = self.request('/api/status')[1]['summary_generation']
        with patch.object(self.engine, '_read_summary', side_effect=sqlite3.OperationalError('synthetic metrics failure')) as read:
            self.completed(self.enqueue('refresh_status'), status='failed')
            self.assertEqual(read.call_count, 1)
        self.assertEqual(self.request('/api/status')[0], 503)
        self.assertFalse(self.engine.control_snapshot()['summary_valid'])
        self.assertEqual(self.engine._summary_generation, generation)
        self.assertFalse(self.engine.control_snapshot()['watching'])
        # Recovery neither bypasses normal authorization nor accepts source options.
        self.assertEqual(self.request('/api/jobs', {'action':'refresh_status'}, headers={})[0], 403)
        self.assertEqual(self.request('/api/jobs', {'action':'refresh_status'},
            headers={'X-Capture-Token':self.server.token})[0], 403)
        self.assertEqual(self.request('/api/jobs', {'action':'refresh_status', 'assets':True})[0], 400)
        self.assertEqual(self.request('/api/status')[0], 503)

    def test_retry_ui_only_allows_explicit_statistics_action_while_disconnected(self):
        script = (Path(__file__).parents[1]/'web'/'app.js').read_text(encoding='utf-8')
        self.assertIn("$('retry-connection').addEventListener('click', () => void queue('refresh_status'))", script)
        self.assertIn("(!state.connected && action !== 'refresh_status')", script)
        self.assertIn("if (state.submitting || state.status.closing ||", script)
        self.assertIn("button.disabled = !state.connected || state.submitting || workPending", script)

    def test_concurrent_status_never_mixes_snapshot_generations_and_copies_values(self):
        from concurrent.futures import ThreadPoolExecutor
        from wechat_capture_next.console import SUMMARY_KEYS
        started, release = threading.Event(), threading.Event()
        def publish_many(*_):
            for _ in range(50):
                generation = self.engine._summary_generation+1
                self.assertTrue(self.engine._refresh_summary({'summary':{key:generation for key in SUMMARY_KEYS}}))
                started.set()
                time.sleep(.002)
            if not release.wait(10):
                raise RuntimeError('test release timeout')
            return {'pass':True}
        with patch.object(self.engine, '_execute', side_effect=publish_many):
            job = self.enqueue('verify')
            try:
                self.assertTrue(started.wait(3))
                detached = self.engine.control_snapshot()
                detached['summary']['versions'] = -999
                def read_many(_):
                    rows = []
                    for _ in range(10):
                        code, value, _ = self.request('/api/status')
                        self.assertEqual(code, 200)
                        rows.append(value)
                    return rows
                with ThreadPoolExecutor(max_workers=4) as pool:
                    groups = list(pool.map(read_many, range(4)))
                for value in (row for group in groups for row in group):
                    self.assertEqual(set(value['summary'].values()), {value['summary_generation']})
                    self.assertEqual(value['service_epoch'], 1)
                    self.assertTrue(value['busy'])
                    self.assertTrue(value['summary_stale'])
                    self.assertTrue(value['summary_as_of'])
            finally:
                release.set()
            self.completed(job)

    def test_statistics_do_not_commit_or_rollback_an_unexpected_service_transaction(self):
        self.completed(self.enqueue('capture'))
        def leave_transaction(*_):
            db = self.engine.service.catalog.db
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE head SET active=0')
            return {'pass':True}
        with patch.object(self.engine, '_execute', side_effect=leave_transaction):
            self.completed(self.enqueue('verify'))
        self.assertEqual(self.request('/api/status')[0], 503)
        found = []
        def recover_transaction(*_):
            db = self.engine.service.catalog.db
            found.append(db.in_transaction)
            db.rollback()
            return {'pass':True}
        with patch.object(self.engine, '_execute', side_effect=recover_transaction):
            self.completed(self.enqueue('verify'))
        self.assertEqual(found, [True])
        code, status, _ = self.request('/api/status')
        self.assertEqual(code, 200)
        self.assertEqual(status['summary']['active_messages'], 40)

    def test_compare_synchronizes_new_versions_instead_of_comparing_stale_managed_cut(self):
        import shutil

        self.completed(self.enqueue('capture'))
        self.assertEqual(self.completed(self.enqueue('sync_wua'))['result']['added_versions'], 40)
        managed = self.output/'managed-wua'/'archive.wua.sqlite'
        reference = self.root/'cold-reference'/'archive.sqlite'
        reference.parent.mkdir()
        shutil.copyfile(managed, reference)
        reference_sha = hashlib.sha256(reference.read_bytes()).hexdigest()

        # Change only the synthetic encrypted source after taking the cold cut.
        # Both the original row and its revision must remain in WUA history.
        with closing(sqlite3.connect(self.plain)) as db, db:
            db.execute(f'UPDATE "{fixtures.TABLE}" SET message_content=? WHERE local_id=1',
                       ('revision after the managed cut',))
            db.execute(f'INSERT INTO "{fixtures.TABLE}" VALUES(-99,777,1,7,1,?,NULL,NULL,-999)',
                       ('late synthetic message after the managed cut',))
        self.publish()
        captured = self.completed(self.enqueue('capture'))
        self.assertEqual(captured['result']['summary']['versions'], 42)
        with closing(sqlite3.connect(managed.as_uri()+'?mode=ro', uri=True)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM message_observation').fetchone()[0], 40)

        compared = self.completed(self.enqueue('compare', reference=str(reference),
                                               name='freshness-comparison'), status='warning')
        result = compared['result']
        self.assertEqual(result['comparison_basis'], 'current_catalog_synchronized')
        self.assertEqual(result['synchronized_observations'], 2)
        self.assertFalse(result['raw_native_equal'])
        self.assertFalse(result['account_label_equal'])
        self.assertFalse(result['message_fields_equal'])
        self.assertEqual((result['current_only'], result['reference_only']), (2, 0))
        with closing(sqlite3.connect(managed.as_uri()+'?mode=ro', uri=True)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM message_observation').fetchone()[0], 42)
        self.assertEqual(hashlib.sha256(reference.read_bytes()).hexdigest(), reference_sha)

    def test_bounded_queue_rejects_without_losing_jobs_and_stop_uses_safe_boundary(self):
        started, release = threading.Event(), threading.Event()
        original = self.engine._execute
        def slow(action, params, ident):
            if action=='verify':
                started.set()
                if not release.wait(10):
                    raise RuntimeError('test release timeout')
            return original(action,params,ident)
        self.completed(self.enqueue('start_watch'))
        with patch.object(self.engine,'_execute',side_effect=slow):
            first = self.enqueue('verify')
            self.assertTrue(started.wait(5))
            second = self.enqueue('stop_watch')
            third = self.enqueue('capture')
            code, error, _ = self.request('/api/jobs',{'action':'sync_wua'})
            self.assertEqual(code,429,error)
            self.assertEqual(self.engine.jobs_snapshot()['queued'],2)
            self.assertTrue(self.request('/api/status')[1]['watching'])
            release.set()
            for job in (first,second,third):
                self.completed(job)
        self.assertFalse(self.request('/api/status')[1]['watching'])

    def test_watch_idle_does_not_append_jobs_or_cycles(self):
        self.completed(self.enqueue('capture'))
        self.completed(self.enqueue('start_watch'))
        # First periodic full acceptance may create one cycle. Later unchanged
        # 30 ms ticks are deliberately idle and manufacture no jobs/reports.
        time.sleep(.2)
        first = self.request('/api/reports')[1]['total']
        jobs = len(self.engine.jobs_snapshot()['jobs'])
        time.sleep(.2)
        self.assertEqual(self.request('/api/reports')[1]['total'],first)
        self.assertEqual(len(self.engine.jobs_snapshot()['jobs']),jobs)
        self.completed(self.enqueue('stop_watch'))

    def test_output_traversal_existing_reparse_and_hardlinks_rejected(self):
        for name in ('../escape','folder/file','C:\\escape','..','CON.txt','name.','backups'):
            self.assertEqual(self.request('/api/jobs',dict(action='validate',name=name))[0],400)
        existing = self.output/'existing'
        existing.mkdir()
        self.assertEqual(self.request('/api/jobs',dict(action='validate',name='existing'))[0],400)
        self.assertEqual(self.request('/api/jobs',dict(action='backup',include_secrets='true'))[0],400)
        self.assertEqual(self.request('/api/jobs',dict(action='verify',command='arbitrary'))[0],400)
        for target in (self.state,self.source.parent):
            with self.assertRaises(ValueError):
                checked_output(self.state,target)
        linked = Path(self.output_temp.name)/'linked'
        linked.mkdir()
        os.link(self.output/'OWNER.private.json',linked/'OWNER.private.json')
        try:
            with self.assertRaises(ValueError):
                checked_output(self.state,linked)
        finally:
            (linked/'OWNER.private.json').unlink()

    def test_writer_lock_is_owned_for_server_lifetime_and_failed_start_does_not_adopt_output(self):
        with self.assertRaises(OSError):
            with writer_lock(self.state):
                pass
        other = Path(self.output_temp.name)/'other-console'
        with self.assertRaises(RuntimeError):
            create_server(self.state,other)
        self.assertFalse(other.exists())

    def test_configure_assets_reopens_binding_then_archives_and_exports_original(self):
        media = self.source.parent.parent/'media'
        media.mkdir()
        raw = b'attachment original, not a preview\x00\xff'*200
        (media/'original.dat').write_bytes(raw)
        configured = self.completed(self.enqueue('configure_assets',root=str(media)))
        self.assertTrue(configured['result']['changed'])
        self.completed(self.enqueue('capture'))  # Configured assets are on by default.
        code, assets, _ = self.request('/api/assets')
        self.assertEqual(code,200)
        self.assertEqual(assets['total'],1)
        asset = assets['rows'][0]
        self.assertEqual(asset['file_sha'],hashlib.sha256(raw).hexdigest())
        result = self.completed(self.enqueue('export_asset',file_sha=asset['file_sha'],output_name='original.dat'))
        self.assertEqual((self.output/'original.dat').read_bytes(),raw)
        self.assertEqual(result['result']['sha256'],asset['file_sha'])
        self.assertTrue(self.completed(self.enqueue('verify'))['result']['pass'])

    def test_latest_interpretation_is_browsed_without_changing_immutable_version(self):
        self.completed(self.enqueue('capture'))
        original = self.engine._execute
        body = '<img src=x onerror=alert(1)>latest-interpretation'
        def reinterpret(action, params, ident):
            db = self.engine.service.catalog.db  # Called only by the owned worker.
            row = db.execute('SELECT id,normalized_json,first_capture FROM version ORDER BY rowid LIMIT 1').fetchone()
            normalized = json.loads(row[1])
            normalized['body_text'] = body
            text = json.dumps(normalized,ensure_ascii=False,sort_keys=True,separators=(',',':'))
            digest = hashlib.sha256(text.encode()).hexdigest()
            with db:
                db.execute('INSERT INTO interpretation VALUES(?,?,?,?)',(row[0],digest,text,row[2]))
                db.execute('INSERT INTO interpretation_head VALUES(?,?,?)',(row[0],digest,row[2]))
            return original(action,params,ident)
        with patch.object(self.engine,'_execute',side_effect=reinterpret):
            self.completed(self.enqueue('verify'))
        code, page, headers = self.request('/api/messages?q=latest-interpretation')
        self.assertEqual(code,200)
        self.assertEqual(page['total'],1)
        self.assertEqual(page['rows'][0]['body_text'],body)
        self.assertTrue(headers['Content-Type'].startswith('application/json'))
        self.assertEqual(self.request('/api/messages?offset=999999999999999999999999')[0],400)

    def test_idempotent_retries_and_concurrent_same_requests_reuse_job(self):
        from concurrent.futures import ThreadPoolExecutor
        payload=dict(action='capture',request_id='retry-same-capture-0001')
        with ThreadPoolExecutor(max_workers=6) as pool:
            jobs=list(pool.map(lambda _:self.engine.submit(payload),range(6)))
        self.assertEqual(len({job['id'] for job in jobs}),1)
        first=self.completed(jobs[0])
        retry=self.engine.submit(payload)
        self.assertEqual(first['id'],retry['id'])
        self.assertEqual(retry['status'],'completed')
        self.assertEqual(self.request('/api/jobs',dict(action='verify',request_id=payload['request_id']))[0],400)

    def test_distinct_requests_preserve_stop_start_stop_order(self):
        self.completed(self.enqueue('start_watch'))
        started, release = threading.Event(), threading.Event()
        original = self.engine._execute
        def hold_first_stop(action, params, ident):
            if action == 'stop_watch' and not started.is_set():
                started.set()
                if not release.wait(10):
                    raise RuntimeError('test release timeout')
            return original(action, params, ident)
        with patch.object(self.engine, '_execute', side_effect=hold_first_stop):
            first = self.enqueue('stop_watch', request_id='ordered-stop-first')
            try:
                self.assertTrue(started.wait(3))
                second = self.enqueue('start_watch', request_id='ordered-start-second')
                third = self.enqueue('stop_watch', request_id='ordered-stop-final')
                self.assertEqual(len({first['id'], second['id'], third['id']}), 3)
            finally:
                release.set()
            for job in (first, second, third):
                self.completed(job)
        self.assertFalse(self.engine.control_snapshot()['watching'])

    def test_backups_get_never_locks_writes_or_recovers_repository(self):
        from wechat_capture_next import backup as backup_module
        self.completed(self.enqueue('capture'))
        job = self.completed(self.enqueue('backup'))
        repository = self.output/'backups'
        (repository/'repository.lock').unlink()  # GET must not recreate it.
        def inventory():
            return {p.name: (p.stat().st_size, p.stat().st_mtime_ns,
                            hashlib.sha256(p.read_bytes()).hexdigest()) for p in repository.iterdir()}
        before = inventory()
        with patch.object(backup_module, '_writer', side_effect=AssertionError('GET opened writer')), \
                patch.object(backup_module, '_repository_lock', side_effect=AssertionError('GET opened writer lock')), \
                patch.object(backup_module, '_integrity', side_effect=AssertionError('GET scanned full repository')):
            code, snapshots, _ = self.request('/api/backups')
            self.assertEqual(code, 200)
            self.assertEqual(snapshots['snapshots'][0]['id'], job['result']['snapshot_id'])
            self.assertEqual(snapshots['integrity_scope'], 'manifest_metadata_only')
            self.assertFalse(snapshots['contents_verified'])
            self.assertEqual(inventory(), before)
            journal = repository/(backup_module.DATABASE+'-journal')
            journal.write_bytes(b'synthetic recovery marker')
            try:
                with_journal = inventory()
                self.assertEqual(self.request('/api/backups')[0], 503)
                self.assertEqual(inventory(), with_journal)
            finally:
                journal.unlink()
        self.assertFalse((repository/'repository.lock').exists())

    def test_restore_insufficient_space_is_safe_explicit_job_failure(self):
        from types import SimpleNamespace
        from wechat_capture_next import backup as backup_module
        self.completed(self.enqueue('capture'))
        backup = self.completed(self.enqueue('backup'))
        database = self.engine.repository_root/'repository.sqlite'
        before = hashlib.sha256(database.read_bytes()).hexdigest()
        with patch.object(backup_module.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)):
            job = self.completed(self.enqueue('restore', snapshot_id=backup['result']['snapshot_id'],
                name='space-rejected'), status='failed')
        self.assertEqual(job['error_type'], 'InsufficientRestoreSpace')
        self.assertEqual(job['error'], '可用空间不足，未开始恢复，请选择空间充足的新目标')
        self.assertFalse((self.output/'space-rejected').exists())
        self.assertEqual(before, hashlib.sha256(database.read_bytes()).hexdigest())

    def test_incomplete_results_not_green_and_status_error_count_is_exact(self):
        for value in ({'status':'partial'},{'pass':False},{'pass_all':False},
                      {'raw_native_equal':False},{'account_label_equal':False},{'message_fields_equal':False}):
            with patch.object(self.engine,'_execute',return_value=value):
                self.completed(self.enqueue('verify'),status='warning')
        original=self.engine._execute
        def many_errors(action,params,ident):
            if action=='verify':
                catalog=self.engine.service.catalog
                cycle=catalog.begin_cycle('synthetic-errors')
                catalog.finish_cycle(cycle,dict(schema='capture-next-cycle-1',status='partial',databases=[],
                    errors=[{'error_type':'synthetic'} for _ in range(25)]))
                return {'pass':False}
            return original(action,params,ident)
        with patch.object(self.engine,'_execute',side_effect=many_errors):
            self.completed(self.enqueue('verify'),status='warning')
        status=self.request('/api/status')[1]
        self.assertEqual(status['last_cycle']['errors_count'],25)
        self.assertEqual(len(status['last_cycle']['errors']),20)
        self.assertTrue(status['last_cycle']['errors_sample_truncated'])

    @unittest.skipUnless(os.name=='nt','Windows-specific DOS alias boundary')
    def test_dos_alias_cannot_place_output_in_state_or_account(self):
        import ctypes
        api=ctypes.windll.kernel32.GetShortPathNameW
        for root in (self.state,self.source.parent.parent):
            buffer=ctypes.create_unicode_buffer(32768)
            if not api(str(root),buffer,len(buffer)) or Path(buffer.value)==root:
                continue
            alias=Path(buffer.value)
            self.assertTrue(alias.samefile(root))
            target=alias/'must-not-be-created'
            with self.assertRaises(ValueError):
                checked_output(self.state,target)
            self.assertFalse(target.exists())

    def test_jobs_are_bounded_metadata_and_shutdown_interrupts_only_pending_work(self):
        with patch.object(self.engine,'_execute',return_value={'pass':True}):
            for _ in range(105):
                self.completed(self.enqueue('verify'))
        self.assertEqual(len(self.engine.jobs_snapshot()['jobs']),100)
        started, release = threading.Event(), threading.Event()
        def slow(*_):
            started.set()
            release.wait(10)
            return {'pass':True}
        with patch.object(self.engine,'_execute',side_effect=slow):
            first = self.enqueue('verify')
            self.assertTrue(started.wait(3))
            second = self.enqueue('capture')
            closing_thread = threading.Thread(target=self.engine.close)
            closing_thread.start()
            try:
                self.assertTrue(self.engine.control_snapshot()['closing'])
                self.assertEqual(self.request('/api/jobs',{'action':'verify'})[0],400)
            finally:
                release.set()
                closing_thread.join(4)
            self.completed(first)
            self.completed(second,status='interrupted')
        self.assertFalse(self.engine.thread.is_alive())


if __name__ == '__main__':
    unittest.main()
