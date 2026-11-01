"""Next-only synthetic attachment acceptance; never opens installed WeChat."""
from contextlib import closing
import hashlib
from io import BytesIO
from itertools import count
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import zlib

from wechat_capture_next import assets
from wechat_capture_next.service import CaptureService, initialize
from wechat_capture_v2.common import canonical, digest_file, write_json_new
from wechat_capture_v2.objects import CHUNK_BYTES, PendingImport


class AssetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='next-assets-synthetic-')
        self.root = Path(self.temp.name)
        self.account = self.root/'synthetic-account'
        self.database = self.account/'db_storage'
        self.media = self.account/'msg'/'attach'
        self.database.mkdir(parents=True)
        self.media.mkdir(parents=True)
        keys = self.root/'keys.json'
        write_json_new(keys, {'databases':[{'relative_path':'fixture.db', 'verified':True,
                                          'raw_encryption_key_hex':'11'*32}]})
        self.state = self.root/'next-state'
        initialize(self.state, self.database, keys, source_id='synthetic-source',
                   account_alias='synthetic-account', asset_root=self.media)
        self.service = CaptureService(self.state)

    def tearDown(self):
        self.service.close()
        self.temp.cleanup()

    def add_media(self, relative='a.dat', data=b'raw attachment bytes'):
        path = self.media/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(data)
        return path

    def capture(self, **kwargs):
        return assets.capture_assets(self.service, 'synthetic-cycle', **kwargs)

    def reconnect(self):
        self.service.close()
        assets.recover_asset_configuration(self.state)
        self.service = CaptureService(self.state)

    def test_raw_history_changes_no_caps_and_inventory(self):
        path = self.add_media()
        first = self.capture()
        self.assertEqual((first['files_seen'], first['new_versions']), (1, 1))
        self.assertIsNone(first['history_time_limit'])
        old_sha = digest_file(path)
        with path.open('wb') as stream:
            stream.write(b'edited attachment with distinct length')
        second = self.capture()
        self.assertEqual(second['new_versions'], 1)
        self.assertEqual(self.capture()['new_versions'], 0)
        verified = assets.verify_assets(self.service)
        self.assertEqual(verified['asset_history_references_verified'], 2)
        self.assertEqual(verified['asset_references_verified'], 1)
        self.assertEqual(verified['files_verified'], 2)
        info = assets.inventory_assets(self.service)
        self.assertEqual(info['files'], 1)
        self.assertFalse(info['content_read'])
        self.assertEqual(info['message_media_association'], 'not_implemented')
        exported = self.root/'exported-old.raw'
        assets.export_asset(self.service, old_sha, exported)
        self.assertEqual(exported.read_bytes(), b'raw attachment bytes')

    def test_actual_raw_stream_roundtrip_multichunk_and_exclusive(self):
        data = bytes(range(256))*(CHUNK_BYTES//64+13)
        path = self.add_media(data=data)
        self.capture()
        sha = digest_file(path)
        out = self.root/'new-output'/'raw.bin'
        report = assets.export_asset(self.service, sha, out)
        self.assertEqual(report['bytes'], len(data))
        self.assertEqual(out.read_bytes(), data)
        with self.assertRaises(FileExistsError):
            assets.export_asset(self.service, sha, out)
        self.assertEqual(out.read_bytes(), data)
        self.assertEqual(path.read_bytes(), data)

    def test_empty_file_is_published_and_exported(self):
        path = self.add_media(data=b'')
        self.assertEqual(self.capture()['new_versions'], 1)
        out = self.root/'empty.raw'
        assets.export_asset(self.service, digest_file(path), out)
        self.assertEqual(out.read_bytes(), b'')

    def test_export_requires_history_and_published_file(self):
        path = self.add_media()
        obj = self.service.objects.add(path)
        with self.assertRaises(ValueError):
            assets.export_asset(self.service, obj['sha256'], self.root/'unauthorized')
        self.capture()
        with self.service.objects.db:
            self.service.objects.db.execute('DELETE FROM file')
        with self.assertRaises(KeyError):
            assets.export_asset(self.service, obj['sha256'], self.root/'unpublished')

    def test_verify_missing_history_file_current_and_size(self):
        path = self.add_media()
        self.capture()
        sha = digest_file(path)
        with self.service.catalog.db:
            self.service.catalog.db.execute('UPDATE asset_history SET bytes=bytes+1')
        with self.assertRaisesRegex(ValueError, 'size-mismatched|retained history'):
            assets.verify_assets(self.service)
        with self.service.catalog.db:
            self.service.catalog.db.execute('UPDATE asset_history SET bytes=bytes-1')
            self.service.catalog.db.execute('DELETE FROM asset_history')
        with self.assertRaisesRegex(ValueError, 'retained history'):
            assets.verify_assets(self.service)
        with self.service.catalog.db:
            self.service.catalog.db.execute('INSERT INTO asset_history VALUES(?,?,?,?,?)',
                ('synthetic-source', 'a.dat', sha, path.stat().st_size, 'synthetic-cycle'))
        with self.service.objects.db:
            self.service.objects.db.execute('DELETE FROM file')
        with self.assertRaisesRegex(ValueError, 'missing'):
            assets.verify_assets(self.service)

    def test_missing_old_history_object_is_not_hidden_by_current(self):
        path = self.add_media()
        self.capture()
        old = digest_file(path)
        with path.open('wb') as stream:
            stream.write(b'new raw bytes')
        self.capture()
        with self.service.objects.db:
            self.service.objects.db.execute('DELETE FROM file WHERE hash=?', (old,))
        with self.assertRaisesRegex(ValueError, 'missing'):
            assets.verify_assets(self.service)

    def test_corrupt_export_removes_only_owned_incomplete_output(self):
        path = self.add_media()
        self.capture()
        with self.service.objects.db:
            self.service.objects.db.execute('UPDATE chunk SET data=?', (b'corrupt',))
        out = self.root/'failed.raw'
        with self.assertRaises((ValueError, zlib.error)):
            assets.export_asset(self.service, digest_file(path), out)
        self.assertFalse(out.exists())
        self.assertEqual(path.read_bytes(), b'raw attachment bytes')

    def test_preview_unsupported_keeps_raw_and_no_output(self):
        path = self.add_media(data=b'not a supported DAT')
        self.capture()
        out = self.root/'unsupported.png'
        result = assets.preview_asset(self.service, digest_file(path), out)
        self.assertEqual(result['status'], 'unsupported')
        self.assertTrue(result['raw_preserved'])
        self.assertFalse(out.exists())
        raw = self.root/'kept.raw'
        assets.export_asset(self.service, digest_file(path), raw)
        self.assertEqual(raw.read_bytes(), path.read_bytes())

    def test_preview_legacy_xor_validates_full_image_separate_from_raw(self):
        from PIL import Image
        image = BytesIO()
        Image.new('RGB', (8, 9), (4, 100, 200)).save(image, format='PNG')
        plain = image.getvalue()
        raw = bytes(b ^ 0x65 for b in plain)
        path = self.add_media(data=raw)
        self.capture()
        out = self.root/'preview.png'
        result = assets.preview_asset(self.service, digest_file(path), out)
        self.assertEqual(result['status'], 'decoded')
        self.assertEqual(out.read_bytes(), plain)
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(assets.verify_assets(self.service)['files_verified'], 1)

    def test_export_cannot_touch_account_or_state(self):
        path = self.add_media()
        self.capture()
        for out in (self.state/'new.raw', self.account/'new.raw', self.database/'new.raw'):
            with self.subTest(out=out), self.assertRaises(ValueError):
                assets.export_asset(self.service, digest_file(path), out)
        for value in ('../bad', 'A'*64, 'a'*63):
            with self.assertRaises(ValueError):
                assets.export_asset(self.service, value, self.root/'out')

    def test_time_slices_eventually_capture_complete_file_without_total_cap(self):
        self.add_media(data=bytes(range(255))*6000)
        rounds = 0
        versions = 0
        while rounds < 100:
            result = self.capture(budget_seconds=0.000001)
            versions += result['new_versions']
            rounds += 1
            if result['complete']:
                break
        self.assertGreater(rounds, 1)
        self.assertLess(rounds, 100)
        self.assertEqual(versions, 1)
        self.assertEqual(assets.verify_assets(self.service)['files_verified'], 1)

    def test_force_upgrades_sliced_incremental_pass_and_reimports_skipped_prefix(self):
        first = self.add_media('a-prefix.dat', b'prefix already captured')
        second = self.add_media('b-tail.dat', b'tail already captured')
        self.capture()
        # The incremental slice skips a-prefix using its unchanged stamp and
        # pauses before reaching b-tail. Full reconciliation must start again.
        # Windows' bundled runtime may expose a 15.625 ms monotonic clock;
        # deterministic scheduling avoids a tiny slice accidentally finishing.
        with patch.object(assets.time, 'monotonic', side_effect=count().__next__):
            incremental = self.capture(budget_seconds=0.5)
        self.assertFalse(incremental['complete'])
        self.assertIsNotNone(self.service._asset_iterator)
        self.assertFalse(self.service._asset_force)
        with patch.object(assets, '_KnownSourceCheck', wraps=assets._KnownSourceCheck) as importer:
            full = self.capture(force=True)
        self.assertTrue(full['complete'])
        self.assertEqual([call.args[1] for call in importer.call_args_list], [first, second])
        self.assertEqual(full['verified_unchanged_files'], 2)

    def test_existing_full_pass_is_not_restarted_on_each_forced_slice(self):
        self.add_media('a.dat', b'a'*(CHUNK_BYTES*3))
        self.add_media('b.dat', b'b'*(CHUNK_BYTES*2))
        with patch.object(assets, 'PendingImport', wraps=PendingImport) as importer, \
                patch.object(assets.time, 'monotonic', side_effect=count().__next__):
            self.assertFalse(self.capture(force=True, budget_seconds=0.5)['complete'])
            iterator = self.service._asset_iterator
            pending = self.service._pending_asset
            self.assertIsNotNone(pending)
            self.capture(force=True, budget_seconds=0.5)
            self.assertIs(self.service._asset_iterator, iterator)
            self.assertIs(self.service._pending_asset[2], pending[2])
            self.assertTrue(self.capture(force=True)['complete'])
        self.assertEqual(importer.call_count, 2)

    def test_assets_need_scan_metadata_new_changed_and_active_pass(self):
        first = self.add_media()
        self.assertTrue(assets.assets_need_scan(self.service))
        self.capture()
        with patch.object(Path, 'open', side_effect=AssertionError('metadata proof must not read file bytes')):
            self.assertFalse(assets.assets_need_scan(self.service))
        with first.open('ab') as stream:
            stream.write(b'changed-size')
        self.assertTrue(assets.assets_need_scan(self.service))
        self.capture()
        self.add_media('new.dat')
        self.assertTrue(assets.assets_need_scan(self.service))
        self.capture()
        self.assertFalse(assets.assets_need_scan(self.service))
        self.service._asset_iterator = iter(())
        self.assertTrue(assets.assets_need_scan(self.service))
        self.service._asset_iterator = None
        self.service._pending_asset = object()
        self.assertTrue(assets.assets_need_scan(self.service))
        self.service._pending_asset = None
        previous = self.service.config['asset_root']
        self.service.config['asset_root'] = None
        self.assertFalse(assets.assets_need_scan(self.service))
        self.service.config['asset_root'] = previous

    def test_namespace_aliases_are_rejected_before_alias_disk_access(self):
        aliases = ('\\\\?\\C:\\example\\new', '\\\\.\\C:\\example\\new',
                   '\\\\server\\share\\new', '/??/C:/example/new', '/Device/HarddiskVolume1/new')
        for alias in aliases:
            with self.subTest(alias=alias), patch.object(os.path, 'lexists',
                    side_effect=AssertionError('alias must be rejected lexically')):
                with self.assertRaises(ValueError):
                    assets._absolute(alias)

    def test_source_change_mid_pending_never_accepted(self):
        path = self.add_media(data=b'a'*(CHUNK_BYTES*3))
        # This tests mutation of an existing pending generation, not how a
        # 1us budget lands on a Windows coarse monotonic clock. Establish the
        # precondition explicitly; cooperative slicing is tested separately.
        pending = PendingImport(self.service.objects,path)
        self.service._pending_asset = ('a.dat',path,pending)
        with path.open('wb') as stream:
            stream.write(b'changed')
        # Stop exactly after rejecting this pending generation; otherwise a
        # coarse clock may also import the NEW valid file in the same call.
        with patch.object(assets.time,'monotonic',side_effect=count().__next__):
            result = self.capture(budget_seconds=0.5)
        self.assertTrue(result['errors'])
        self.assertEqual(self.service.catalog.db.execute('SELECT count(*) FROM asset_history').fetchone()[0], 0)

    def test_database_subtree_is_not_acquired_as_attachment(self):
        with (self.database/'cipher.db').open('xb') as stream:
            stream.write(b'database independently authenticated')
        assets.configure_asset_root(self.service, self.account)
        self.add_media()
        self.assertEqual(self.capture()['files_seen'], 1)
        self.assertEqual(assets.inventory_assets(self.service)['files'], 1)

    def test_configure_only_asset_root_and_restart_binding(self):
        before = dict(self.service.config)
        target = self.account/'alternate'
        target.mkdir()
        result = assets.configure_asset_root(self.service, target)
        self.assertTrue(result['changed'])
        after = dict(self.service.config)
        self.assertEqual({k:v for k,v in before.items() if k != 'asset_root'},
                         {k:v for k,v in after.items() if k != 'asset_root'})
        self.assertFalse((self.state/assets.JOURNAL).exists())
        self.reconnect()
        self.assertEqual(self.service.config['asset_root'], str(target))
        self.assertEqual(self.service.catalog.db.execute(
            "SELECT count(*) FROM meta WHERE key LIKE 'next_asset_root_change:%'").fetchone()[0], 1)

    def test_unsafe_configuration_paths_and_output_overlap(self):
        sibling = self.root/'other-account'
        sibling.mkdir()
        out = self.account/'declared-output'
        out.mkdir()
        for target in (sibling, self.state, self.root, Path('relative'), self.account/'msg'/'..'/'msg'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                assets.configure_asset_root(self.service, target)
        with self.assertRaisesRegex(ValueError, 'output'):
            assets.configure_asset_root(self.service, out, output_roots=(out,))

    def test_hardlinked_source_readonly_cas_deduplicated_without_source_writes(self):
        path = self.add_media()
        linked = self.media/'hardlink.dat'
        try:
            os.link(path, linked)
        except OSError as exc:
            self.skipTest(str(exc))
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_nlink) for p in (path, linked)}
        assets.configure_asset_root(self.service, self.media)
        result = self.capture()
        self.assertFalse(result['errors'])
        self.assertTrue(result['complete'])
        self.assertEqual(self.service.catalog.db.execute('SELECT count(*) FROM asset').fetchone()[0], 2)
        self.assertEqual(self.service.objects.db.execute('SELECT count(*) FROM file').fetchone()[0], 1)
        self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_nlink) for p in (path, linked)})
        with self.assertRaisesRegex(ValueError, 'hardlink'):
            assets._file(linked)  # No weakening of state/config/output guards.

    def test_linked_ancestor_is_rejected_without_following(self):
        link = self.account/'linked'
        try:
            link.symlink_to(self.media, target_is_directory=True)
        except OSError as exc:
            self.skipTest(str(exc))
        with self.assertRaises(ValueError):
            assets.configure_asset_root(self.service, link)
        with self.assertRaises(ValueError):
            assets.configure_asset_root(self.service, link/'missing')

    def test_reparse_attribute_is_rejected(self):
        original = Path.lstat
        target = self.media
        def fake(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == target:
                class Reparse:
                    st_mode = result.st_mode
                    st_file_attributes = 0x400
                return Reparse()
            return result
        with patch.object(Path, 'lstat', fake), self.assertRaises(ValueError):
            assets.configure_asset_root(self.service, self.media)

    def test_configuration_crash_recovery_every_durable_stage(self):
        for index, stage in enumerate(('after_journal', 'after_staged', 'after_config',
                                      'after_binding', 'before_journal_remove')):
            target = self.account/f'change-{index}'
            target.mkdir()
            def fail(current):
                if current == stage:
                    raise RuntimeError('synthetic process interruption')
            with self.subTest(stage=stage):
                old = dict(self.service.config)
                with self.assertRaises(RuntimeError):
                    assets.configure_asset_root(self.service, target, fault=fail)
                self.assertTrue((self.state/assets.JOURNAL).exists())
                self.reconnect()
                self.assertEqual(self.service.config['asset_root'], str(target))
                self.assertEqual(self.service.config['source_id'], old['source_id'])
                self.assertEqual(self.service.config['account_alias'], old['account_alias'])
                self.assertFalse((self.state/assets.JOURNAL).exists())
                self.assertFalse((self.state/assets.STAGED).exists())

    def test_killed_process_during_random_temp_writes_never_publishes_partial_authority(self):
        script = '''
from contextlib import closing
import os, sys
from wechat_capture_next.service import CaptureService
from wechat_capture_next.assets import configure_asset_root
from wechat_capture_v2.common import writer_lock
def stop(stage):
    if stage == sys.argv[3]:
        print('ready-to-kill', flush=True)
        sys.stdin.buffer.read(1)
        os._exit(91)
with writer_lock(sys.argv[1]):
    with closing(CaptureService(sys.argv[1])) as service:
        configure_asset_root(service, sys.argv[2], fault=stop)
raise SystemExit(92)
'''
        for index, stage in enumerate(('journal_temp_partial', 'journal_temp_fsynced',
                                      'staged_temp_partial', 'staged_temp_fsynced')):
            with self.subTest(stage=stage):
                target = self.account/f'kill-target-{index}'
                target.mkdir()
                old_config = (self.state/'config.private.json').read_bytes()
                old_asset_root = self.service.config['asset_root']
                self.service.close()
                process = subprocess.Popen([sys.executable, '-c', script, str(self.state), str(target), stage],
                    cwd=Path(__file__).resolve().parents[2], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                timer = threading.Timer(20, process.kill)
                timer.daemon = True
                timer.start()
                try:
                    ready = process.stdout.readline().strip()
                    if ready != 'ready-to-kill':
                        _, error = process.communicate(timeout=10)
                        self.fail('subprocess did not reach write boundary: '+ready+' '+error)
                    process.kill()  # real TerminateProcess/SIGKILL, no Python unwind
                    process.communicate(timeout=10)
                finally:
                    timer.cancel()
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=10)
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual((self.state/'config.private.json').read_bytes(), old_config)
                self.assertFalse((self.state/assets.STAGED).exists())
                self.assertEqual((self.state/assets.JOURNAL).exists(), stage.startswith('staged_'))
                leftovers = {path.name:path.read_bytes() for path in self.state.glob('.*.pending')}
                self.assertTrue(leftovers)
                self.service = CaptureService(self.state)  # constructor performs recovery
                expected = str(target) if stage.startswith('staged_') else old_asset_root
                self.assertEqual(self.service.config['asset_root'], expected)
                self.assertFalse((self.state/assets.JOURNAL).exists())
                self.assertFalse((self.state/assets.STAGED).exists())
                self.assertEqual(leftovers, {path.name:path.read_bytes() for path in self.state.glob('.*.pending')})
                # Prepublication leftovers neither become authority nor block
                # the next explicit, independently validated configuration.
                assets.configure_asset_root(self.service, target)
                self.reconnect()

    def test_truncated_published_journal_fails_closed_without_changing_original(self):
        original = (self.state/'config.private.json').read_bytes()
        journal = self.state/assets.JOURNAL
        with journal.open('xb') as stream:
            stream.write(b'{"schema":"next-asset-config-journal-1",')
        with self.assertRaises(json.JSONDecodeError):
            assets.recover_asset_configuration(self.state)
        self.assertEqual((self.state/'config.private.json').read_bytes(), original)
        self.assertTrue(journal.exists())

    def test_unrecognized_fixed_staging_is_preserved_and_not_adopted(self):
        original = (self.state/'config.private.json').read_bytes()
        staged = self.state/assets.STAGED
        with staged.open('xb') as stream:
            stream.write(b'unknown data is not a journal')
        with self.assertRaisesRegex(ValueError, 'unexplained'):
            assets.recover_asset_configuration(self.state)
        self.assertEqual((self.state/'config.private.json').read_bytes(), original)
        self.assertEqual(staged.read_bytes(), b'unknown data is not a journal')

    def test_journal_never_authorizes_source_or_account_change(self):
        target = self.account/'next-media'
        target.mkdir()
        with self.assertRaises(RuntimeError):
            assets.configure_asset_root(self.service, target,
                fault=lambda stage: (_ for _ in ()).throw(RuntimeError()) if stage == 'after_journal' else None)
        journal_path = self.state/assets.JOURNAL
        journal = json.loads(journal_path.read_text(encoding='utf-8'))
        bad = json.loads(journal['new_text'])
        bad['source_id'] = 'other-source'
        journal['new_text'] = canonical(bad)+'\n'
        with journal_path.open('w', encoding='utf-8') as stream:
            stream.write(canonical(journal))
        with self.assertRaisesRegex(ValueError, 'more than asset_root'):
            assets.recover_asset_configuration(self.state)
        self.assertEqual(json.loads((self.state/'config.private.json').read_text())['source_id'], 'synthetic-source')

    def test_binding_tamper_is_not_recovered(self):
        target = self.account/'next-media'
        target.mkdir()
        with self.assertRaises(RuntimeError):
            assets.configure_asset_root(self.service, target,
                fault=lambda stage: (_ for _ in ()).throw(RuntimeError()) if stage == 'after_journal' else None)
        with self.service.catalog.db:
            self.service.catalog.db.execute("UPDATE meta SET value='tampered' WHERE key='source_binding'")
        with self.assertRaisesRegex(ValueError, 'outside the journaled transition'):
            assets.recover_asset_configuration(self.state)
        self.assertTrue((self.state/assets.JOURNAL).exists())

    def seed_unpublished(self):
        raw = b'orphan unfinished raw chunk'
        sha = hashlib.sha256(raw).hexdigest()
        with self.service.objects.db:
            self.service.objects.db.execute('INSERT INTO chunk VALUES(?,?,?)', (sha, len(raw), zlib.compress(raw)))
            self.service.objects.db.execute('INSERT INTO file_chunk VALUES(?,?,?)', ('a'*64, 0, sha))
        return sha, len(raw)

    def test_prune_abandoned_pending_chunks_preserves_all_published_history(self):
        path = self.add_media(data=b'published-old')
        self.capture()
        with path.open('wb') as stream:
            stream.write(b'published-new')
        self.capture()
        published_before = list(self.service.objects.db.execute('SELECT * FROM file ORDER BY hash'))
        history_before = list(map(tuple, self.service.catalog.db.execute('SELECT * FROM asset_history')))
        orphan_sha, size = self.seed_unpublished()
        result = assets.prune_unpublished(self.service)
        self.assertEqual(result['unpublished_maps_removed'], 1)
        self.assertEqual(result['chunks_removed'], 1)
        self.assertEqual(result['logical_chunk_bytes_removed'], size)
        self.assertEqual(result['published_files_removed'], 0)
        self.assertFalse(result['physical_file_shrink_guaranteed'])
        self.assertEqual(published_before, list(self.service.objects.db.execute('SELECT * FROM file ORDER BY hash')))
        self.assertEqual(history_before, list(map(tuple, self.service.catalog.db.execute('SELECT * FROM asset_history'))))
        self.assertEqual(assets.verify_assets(self.service)['files_verified'], 2)
        self.assertIsNone(self.service.objects.db.execute('SELECT 1 FROM chunk WHERE hash=?', (orphan_sha,)).fetchone())

    def test_prune_rollback_after_each_mutating_stage(self):
        self.add_media()
        self.capture()
        self.seed_unpublished()
        def state():
            return {table:list(self.service.objects.db.execute(f'SELECT * FROM {table} ORDER BY 1'))
                    for table in ('file', 'file_chunk', 'chunk')}
        before = state()
        for stage in ('after_maps', 'after_chunks'):
            def fail(current):
                if current == stage:
                    raise RuntimeError('synthetic rollback')
            with self.subTest(stage=stage), self.assertRaises(RuntimeError):
                assets.prune_unpublished(self.service, fault=fail)
            self.assertEqual(state(), before)
            self.assertTrue(assets.verify_assets(self.service)['pass'])

    def test_prune_retains_published_unreferenced_files_and_shared_chunks(self):
        path = self.add_media()
        # Published objects without an asset row may still belong to another
        # supported use. GC is never a published-object retention policy.
        published = self.service.objects.add(path)
        chunk_key = self.service.objects.db.execute('SELECT hash FROM chunk').fetchone()[0]
        with self.service.objects.db:
            self.service.objects.db.execute('INSERT INTO file_chunk VALUES(?,?,?)', ('f'*64, 0, chunk_key))
        result = assets.prune_unpublished(self.service)
        self.assertEqual(result['unpublished_maps_removed'], 1)
        self.assertEqual(result['chunks_removed'], 0)
        self.assertIsNotNone(self.service.objects.db.execute('SELECT hash FROM file WHERE hash=?',
            (published['sha256'],)).fetchone())
        self.assertEqual(self.service.objects.verify_all()['files_verified'], 1)

    def test_prune_is_blocked_by_unpublished_history_reference(self):
        path = self.add_media()
        self.capture()
        with self.service.objects.db:
            self.service.objects.db.execute('DELETE FROM file')
        self.seed_unpublished()
        before = list(self.service.objects.db.execute('SELECT * FROM file_chunk ORDER BY 1'))
        with self.assertRaisesRegex(ValueError, 'missing'):
            assets.prune_unpublished(self.service)
        self.assertEqual(before, list(self.service.objects.db.execute('SELECT * FROM file_chunk ORDER BY 1')))

    def test_prune_refuses_pending_non_next_or_foreign_connection(self):
        path = self.add_media(data=b'a'*(CHUNK_BYTES*2))
        # A microsecond wall-clock budget does not deterministically establish
        # an in-flight import. Seed the real pending object for this guard test;
        # cooperative producer progress is covered by separate slice tests.
        pending = PendingImport(self.service.objects, path)
        self.service._pending_asset = ('a.dat', path, pending)
        with self.assertRaisesRegex(ValueError, 'pending'):
            assets.prune_unpublished(self.service)
        self.assertIs(self.service._pending_asset[2], pending)
        self.service._pending_asset = None
        original = self.service.objects.path
        self.service.objects.path = self.root/'unrelated.sqlite'
        with self.assertRaisesRegex(ValueError, 'exact object'):
            assets.prune_unpublished(self.service)
        self.service.objects.path = original
        marker = self.state/'next.private.json'
        with marker.open('w', encoding='utf-8') as stream:
            stream.write(canonical({'schema':'not-next'}))
        with self.assertRaisesRegex(ValueError, 'explicit next'):
            assets.prune_unpublished(self.service)


if __name__ == '__main__':
    unittest.main()
