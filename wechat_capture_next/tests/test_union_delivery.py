"""Synthetic operational delivery; no user state, live keys, or UI."""
from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
import uuid
from unittest.mock import patch

from wechat_capture_next import union_delivery as module
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.service import CaptureService, initialize
from wechat_capture_next.tests import test_service as fixtures
from wechat_capture_next.union_archive import sync_union
from wechat_capture_next.union_assets import import_asset_union
from wechat_capture_v2.common import digest_file
from wechat_capture_v2.objects import Objects


class UnionDeliveryTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    pages = fixtures.ServiceTests.pages
    publish = fixtures.ServiceTests.publish
    init_service = fixtures.ServiceTests.init_service

    def tearDown(self):
        self.doCleanups()
        fixtures.ServiceTests.tearDown(self)

    def prepared(self):
        self.formal = self.root/'formal'
        self.payload = b'old PC original opaque media\x00\xff' * 20000
        binary = self.root/'original.dat'; binary.write_bytes(self.payload)
        retained = self.root/'retained.sqlite'
        with closing(Objects(retained)) as objects:
            info = objects.add(binary)
            self.file_sha = info['sha256']
            objects.db.execute('CREATE TABLE asset(source_id,relative_path,file_sha,bytes,stamp_json,cycle_id,unknown_blob)')
            objects.db.execute('CREATE TABLE asset_history(source_id,relative_path,file_sha,bytes,cycle_id)')
            objects.db.execute('INSERT INTO asset VALUES(?,?,?,?,?,?,?)',
                ('oldPC', 'raw/not-extracted.dat', self.file_sha, len(self.payload), ' {"raw":1e999} ', 'old-evidence', b'\xffunknown'))
            objects.db.execute('INSERT INTO asset_history VALUES(?,?,?,?,?)',
                ('oldPC', 'raw/not-extracted.dat', self.file_sha, len(self.payload), 'old-evidence'))
            objects.db.commit()
        with closing(self.init_service()) as service:
            self.state = service.state
            service.capture(force=True)
            sync_union(service, self.formal)
            with CompactArchive(self.formal/'archive.wua.sqlite') as archive:
                import_asset_union(archive, service, retained, 'synthetic-oldPC')
        self.state_repo, self.union_repo = self.root/'state-repo', self.root/'union-repo'

    def deliver(self, name='backup-receipt'):
        return module.backup(self.state, self.formal, self.state_repo, self.union_repo, self.root/name)

    def take_source_offline(self):
        self.source.unlink()
        if self.wal.exists():
            self.wal.unlink()
        self.source.parent.rmdir()
        self.keys.unlink()
        self.assertFalse(self.source.parent.exists())

    def test_offline_backup_fresh_restore_and_real_deep_attachment_closure(self):
        self.prepared()
        self.take_source_offline()
        source_hash = digest_file(self.formal/'archive.wua.sqlite')
        with patch.object(CaptureService, '__init__', side_effect=AssertionError('live constructor forbidden')):
            backed = self.deliver()
            self.assertFalse(backed['attachments_closed'])
            self.assertTrue(backed['exact_post_pin_companion'])
            self.assertFalse(backed['disaster_backup'])
            self.assertFalse(backed['implicit_sync'])
            restored = module.restore(self.state_repo, self.union_repo,
                backed['union_snapshot']['snapshot_id'], self.root/'restored')
        self.assertTrue(restored['attachments_closed'])
        self.assertTrue(restored['referenced_cas_bytes_verified'])
        self.assertFalse(restored['capture_started'])
        self.assertFalse(restored['source_reconnected'])
        target = self.root/'restored'
        self.assertTrue((target/module.COMPLETE).is_file())
        self.assertEqual(source_hash, digest_file(target/'union'/'archive.wua.sqlite'))
        with closing(Objects(target/'state'/'objects.sqlite')) as objects:
            media = target/'restored-byte-readback.dat'
            objects.restore(self.file_sha, media)
            self.assertEqual(self.payload, media.read_bytes())
        self.assertFalse(self.source.parent.exists())

    def test_stats_is_readonly_without_config_keys_constructors_or_schema_writes(self):
        self.prepared()
        self.take_source_offline()
        before = {str(path): (path.stat().st_size, digest_file(path))
            for folder in (self.state, self.formal) for path in folder.rglob('*') if path.is_file()}
        with (patch.object(CaptureService, '__init__', side_effect=AssertionError('no live service')),
              patch.object(module, '_config', side_effect=AssertionError('stats needs no config'))):
            result = module.stats(self.state, self.formal)
        self.assertTrue(result['readonly'])
        self.assertFalse(result['assets']['closure_complete'])
        self.assertFalse(result['fts_verified'])
        after = {str(path): (path.stat().st_size, digest_file(path))
            for folder in (self.state, self.formal) for path in folder.rglob('*') if path.is_file()}
        self.assertEqual(before, after)

    def test_sync_imports_current_without_capture_and_is_only_live_constructor_command(self):
        self.prepared()
        with patch.object(CaptureService, 'capture', side_effect=AssertionError('must never capture')):
            result = module.sync(self.state, self.formal, verify=True)
        self.assertEqual('sync', result['command'])
        self.assertFalse(result['implicit_capture'])
        self.assertFalse(result['capture_started'])
        self.assertEqual(40, module.stats(self.state, self.formal)['stats']['observations'])

    def test_bad_companion_rejected_before_fresh_output_creation(self):
        self.prepared()
        backed = self.deliver()
        snapshot = backed['union_snapshot']['snapshot_id']
        bad_manifest = module.state_backup.inspect_snapshot(self.state_repo, backed['state_snapshot']['snapshot_id'])
        bad_manifest['files']['objects.sqlite']['sha256'] = '0'*64
        output = self.root/'must-not-create'
        with patch.object(module.state_backup, 'inspect_snapshot', return_value=bad_manifest):
            with self.assertRaisesRegex(ValueError, 'exact union companion'):
                module.restore(self.state_repo, self.union_repo, snapshot, output)
        self.assertFalse(output.exists())
        # A second valid repository with a different catalog UUID cannot supply
        # the companion snapshot at all; no guessed latest snapshot is used.
        wrong = self.root/'wrong-repo'; wrong.mkdir()
        (wrong/'sentinel').write_bytes(b'never adopt foreign repository')
        with self.assertRaises((FileNotFoundError, ValueError)):
            module.restore(wrong, self.union_repo, snapshot, output)
        self.assertFalse(output.exists())
        self.assertEqual(b'never adopt foreign repository', (wrong/'sentinel').read_bytes())

    def test_same_catalog_other_union_repository_rejected_before_any_output_or_state_cut(self):
        self.prepared()
        owner = json.loads((self.formal/'OWNER.private.json').read_text(encoding='utf-8'))
        foreign = dict(schema=module.union_backup.SCHEMA,
                       catalog_instance=owner['catalog_instance'], union_id=str(uuid.uuid4()))
        with module.union_backup._session(self.union_repo, foreign, create=True):
            pass
        before = {p.name: p.read_bytes() for p in self.union_repo.iterdir()}
        with patch.object(module, '_offline', side_effect=AssertionError('must not open any state writer')):
            with self.assertRaisesRegex(ValueError, 'foreign union backup owner'):
                self.deliver('wrong-UUID')
        self.assertFalse((self.root/'wrong-UUID').exists())
        self.assertFalse(self.state_repo.exists())
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.union_repo.iterdir()})

    def test_union_uuid_rechecked_after_taking_both_os_locks_before_receipt(self):
        self.prepared()
        actual_lock = module.writer_lock
        @contextmanager
        def changed_before_lock(path):
            with actual_lock(path):
                if path == self.formal:
                    with CompactArchive(self.formal/'archive.wua.sqlite') as archive, archive.transaction():
                        archive._db.execute("UPDATE archive_meta SET value=? WHERE key='next_union_id'", (str(uuid.uuid4()),))
                yield
        with patch.object(module, 'writer_lock', changed_before_lock):
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                self.deliver('identity-raced')
        self.assertFalse((self.root/'identity-raced').exists())
        self.assertFalse(self.state_repo.exists())
        self.assertFalse(self.union_repo.exists())

    def test_other_valid_current_state_identity_is_rejected_before_receipt_or_rw(self):
        self.prepared()
        other = self.root/'other-current'
        initialize(other, self.source.parent, self.keys, source_id='fixture',
                   account_alias='fixture', self_username='self')
        with closing(CaptureService(other)) as service:
            service.capture(force=True)
            sync_union(service, self.root/'other-formal')
        before = {str(p.relative_to(other)): p.read_bytes() for p in other.rglob('*') if p.is_file()}
        output = self.root/'mismatched-state'
        with patch.object(module, '_offline', side_effect=AssertionError('identity must precede any writer')):
            with self.assertRaisesRegex(ValueError, 'state/formal union identity mismatch'):
                module.backup(other, self.formal, self.state_repo, self.union_repo, output)
        self.assertFalse(output.exists())
        self.assertFalse(self.state_repo.exists())
        self.assertFalse(self.union_repo.exists())
        self.assertEqual(before, {str(p.relative_to(other)): p.read_bytes() for p in other.rglob('*') if p.is_file()})

    def test_existing_output_overlap_relative_and_hardlink_fail_without_mutation(self):
        self.prepared()
        existing = self.root/'existing'; existing.mkdir()
        sentinel = existing/'sentinel'; sentinel.write_bytes(b'existing output stays untouched')
        with self.assertRaises(FileExistsError):
            module.backup(self.state, self.formal, self.state_repo, self.union_repo, existing)
        self.assertEqual([sentinel], list(existing.iterdir()))
        self.assertEqual(b'existing output stays untouched', sentinel.read_bytes())
        with self.assertRaisesRegex(ValueError, 'absolute'):
            module.stats('relative-state', self.formal)
        with self.assertRaisesRegex(ValueError, 'independent'):
            module.backup(self.state, self.formal, self.state/'inside', self.union_repo, self.root/'bad-out')
        target = self.state/'objects.sqlite'
        alias = self.root/'CAS-hardlink'; os.link(target, alias)
        try:
            with self.assertRaisesRegex(ValueError, 'hardlinked'):
                self.deliver('hardlink-out')
            self.assertFalse((self.root/'hardlink-out').exists())
        finally:
            alias.unlink()
        self.assertFalse(self.state_repo.exists())

    def test_partialfailure_keeps_state_snapshot_and_never_writes_complete(self):
        self.prepared()
        output = self.root/'partial'
        with patch.object(module.union_backup, 'backup_archive', side_effect=RuntimeError('synthetic companion failure')):
            with self.assertRaisesRegex(RuntimeError, 'synthetic'):
                self.deliver('partial')
        self.assertTrue((output/module.PARTIAL).exists())
        self.assertTrue((output/module.FAILURE).exists())
        self.assertFalse((output/module.COMPLETE).exists())
        self.assertTrue((self.state_repo/'repository.sqlite').exists())
        # Retry is explicit, with a NEW receipt root; no state/cut mutation.
        self.assertTrue(self.deliver('retry')['exact_post_pin_companion'])

    def test_lock_order_survives_closed_writers_until_cold_companion_finishes(self):
        self.prepared()
        active, calls = [], []
        actual_lock, actual_backup = module.writer_lock, module.union_backup.backup_archive
        @contextmanager
        def tracked(path):
            with actual_lock(path):
                active.append(path)
                try:
                    yield
                finally:
                    active.pop()
        def companion(*args, **kwargs):
            self.assertEqual([self.state, self.formal], active)
            # These mandatory Windows sharing guards fail with any retained
            # RW SQLite handle; all writers must really have been closed.
            from wechat_capture_next.union_archive import cold_input
            with cold_input(self.state/'catalog.sqlite'), cold_input(self.state/'objects.sqlite'):
                calls.append('cold')
            return actual_backup(*args, **kwargs)
        with patch.object(module, 'writer_lock', tracked), patch.object(
                module.union_backup, 'backup_archive', side_effect=companion):
            self.deliver()
        self.assertEqual(['cold'], calls)
        self.assertEqual([], active)

    def test_restore_deep_verification_failure_retains_partial_without_success(self):
        self.prepared()
        backed = self.deliver()
        output = self.root/'restore-failed'
        with patch.object(module, 'verify_union_assets', side_effect=ValueError('synthetic failed deep verification')):
            with self.assertRaisesRegex(ValueError, 'failed deep'):
                module.restore(self.state_repo, self.union_repo, backed['union_snapshot']['snapshot_id'], output)
        self.assertTrue((output/module.FAILURE).exists())
        self.assertTrue((output/'state'/'catalog.sqlite').is_file())
        self.assertTrue((output/'union'/'archive.wua.sqlite').is_file())
        self.assertFalse((output/module.COMPLETE).exists())
        self.assertFalse((output/'union'/'RESTORE.complete.private.json').exists())

    def test_cli_help_stats_backup_restore_and_existing_restore_output(self):
        self.prepared()
        command = [sys.executable, '-m', 'wechat_capture_next.union_delivery']
        env = dict(os.environ, PYTHONUTF8='1')
        def run(*args):
            return subprocess.run(command+list(map(str, args)), capture_output=True, text=True,
                                  encoding='utf-8', env=env, timeout=60)
        help_result = run('--help')
        self.assertEqual(0, help_result.returncode)
        self.assertIn('不启动采集', help_result.stdout)
        status = run('stats', '--state', self.state, '--union', self.formal)
        self.assertEqual(0, status.returncode, status.stderr)
        self.assertTrue(json.loads(status.stdout)['readonly'])
        backed = run('backup', '--state', self.state, '--union', self.formal,
                     '--state-repo', self.state_repo, '--union-repo', self.union_repo, '--out', self.root/'cli-backup')
        self.assertEqual(0, backed.returncode, backed.stderr)
        snapshot = json.loads(backed.stdout)['union_snapshot']['snapshot_id']
        restored = run('restore', '--state-repo', self.state_repo, '--union-repo', self.union_repo,
                       '--snapshot', snapshot, '--out', self.root/'cli-restore')
        self.assertEqual(0, restored.returncode, restored.stderr)
        self.assertTrue(json.loads(restored.stdout)['attachments_closed'])
        receipt = self.root/'cli-restore'/module.COMPLETE
        before = receipt.read_bytes()
        refused = run('restore', '--state-repo', self.state_repo, '--union-repo', self.union_repo,
                      '--snapshot', snapshot, '--out', self.root/'cli-restore')
        self.assertEqual(1, refused.returncode)
        self.assertEqual(before, receipt.read_bytes())


if __name__ == '__main__':
    unittest.main()
