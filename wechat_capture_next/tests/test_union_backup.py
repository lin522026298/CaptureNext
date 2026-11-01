"""Independent companion backup tests, using isolated synthetic state only."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import random
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.test_wua_store import observation
from wechat_capture_next import backup as state_backup
from wechat_capture_next import union_backup as module
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.union_archive import sync_union
from wechat_capture_next.tests import test_service as fixtures
from wechat_capture_v2.common import canonical, digest_file


class UnionBackupTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    pages = fixtures.ServiceTests.pages
    publish = fixtures.ServiceTests.publish
    init_service = fixtures.ServiceTests.init_service

    def tearDown(self):
        self.doCleanups()
        fixtures.ServiceTests.tearDown(self)

    def prepared(self, *, large=False):
        self.service = self.init_service()
        self.addCleanup(self.service.close)
        self.service.capture(force=True)
        self.formal = self.root/'formal'
        sync_union(self.service, self.formal)
        self.archive = self.formal/'archive.wua.sqlite'
        self.union_id = module.ensure_union_id(self.archive)
        if large:
            with CompactArchive(self.archive) as archive:
                archive.import_observations({'source_id': 'large-synthetic'},
                    {'snapshot_id': 'large-synthetic'}, [observation(server_id=900,
                        raw_record={'blob': random.Random(719).randbytes(3*1024*1024)})])
        self.state_repo = self.root/'state-backup'
        self.state_snapshot = state_backup.backup(self.service, self.state_repo)['snapshot_id']
        self.instance = self.service.catalog.db.execute(
            "SELECT value FROM meta WHERE key='next_catalog_instance'").fetchone()[0]
        empty = hashlib.sha256(canonical([]).encode()).hexdigest()
        self.binding = dict(schema='next-union-assets-1', union_id=self.union_id, owner_id=self.union_id,
            cas_id='capture-next-objects:'+self.instance, catalog_instance=self.instance,
            references=0, reference_sha256=empty, metadata_rows=0, metadata_sha256=empty,
            available=0, missing=0, deep_verified=0, closure_complete=True,
            integrity_scope='metadata+pins+published_CAS_full_bytes',
            message_media_association='not_implemented', portable_restore_verified=False,
            verification_scope='whole_union', origin_id=None)
        self.repository = self.root/'union-backup'

    def backup(self, **kwargs):
        return module.backup_archive(self.archive, self.state_repo, self.state_snapshot, self.repository,
            state_catalog=self.service.state/'catalog.sqlite',
            state_objects=self.service.state/'objects.sqlite', asset_binding=self.binding, **kwargs)

    def add_message(self):
        with CompactArchive(self.archive) as archive:
            archive.import_observations({'source_id': 'extra-synthetic'},
                {'snapshot_id': 'extra-synthetic'}, [observation(server_id=999, body_text='new message')])

    def test_companion_metadata_restore_and_exact_noop(self):
        self.prepared()
        before_source = digest_file(self.archive)
        before_state_repo = digest_file(self.state_repo/state_backup.DATABASE)
        first = self.backup()
        before_repo = digest_file(self.repository/module.DATABASE)
        again = self.backup()
        self.assertTrue(again['noop'])
        self.assertEqual(first['snapshot_id'], again['snapshot_id'])
        self.assertEqual(before_repo, digest_file(self.repository/module.DATABASE))
        self.assertEqual(before_state_repo, digest_file(self.state_repo/state_backup.DATABASE))
        self.assertEqual(before_source, digest_file(self.archive))
        manifest = module.inspect_snapshot(self.repository, first['snapshot_id'])
        self.assertEqual(manifest['state_companion']['snapshot_id'], self.state_snapshot)
        self.assertEqual(manifest['asset_binding'], self.binding)
        output = self.root/'metadata-restored'
        result = module.restore_archive(self.repository, first['snapshot_id'], output)
        self.assertTrue(result['metadata_only'])
        self.assertFalse(result['attachments_closed'])
        self.assertTrue(result['integrity']['fts_verified'])
        self.assertEqual(before_source, digest_file(output/'archive.wua.sqlite'))
        self.assertTrue((output/'RESTORE.complete.private.json').is_file())
        self.assertFalse(result['capture_started'])
        self.assertFalse(result['login_started'])
        with self.assertRaises(ValueError):
            module.restore_archive(self.repository, first['snapshot_id'], output)

    def test_incremental_union_chunks_and_snapshot_failure_rollback(self):
        self.prepared(large=True)
        first = self.backup()
        self.add_message()
        before = digest_file(self.repository/module.DATABASE)

        def fail(stage, db):
            if stage == 'snapshot':
                raise RuntimeError('synthetic snapshot failure')

        with self.assertRaisesRegex(RuntimeError, 'snapshot failure'):
            self.backup(fault=fail)
        self.assertEqual(before, digest_file(self.repository/module.DATABASE))
        second = self.backup()
        manifest = module.inspect_snapshot(self.repository, second['snapshot_id'])
        self.assertGreater(second['new_chunks'], 0)
        self.assertLess(second['new_chunks'], len(manifest['archive']['chunks']))
        self.assertNotEqual(first['snapshot_id'], second['snapshot_id'])

    def test_stale_pre_pin_state_snapshot_fails_before_repository_creation(self):
        self.prepared()
        with self.service.catalog.db:
            self.service.catalog.db.execute("INSERT INTO meta VALUES('synthetic-asset-pin','pinned')")
        later = state_backup.backup(self.service, self.state_repo)['snapshot_id']
        with self.assertRaisesRegex(ValueError, 'post-pin'):
            self.backup()
        self.assertFalse(self.repository.exists())
        self.state_snapshot = later
        self.assertFalse(self.backup()['noop'])

    def test_offline_companion_is_required_for_attachment_closure(self):
        self.prepared()
        snapshot = self.backup()['snapshot_id']
        state_output = self.root/'offline-state'
        state_backup.restore(self.state_repo, self.state_snapshot, state_output)
        offline = SimpleNamespace(state=state_output)
        seen = []

        def verify(archive, state):
            self.assertIs(state, offline)
            self.assertEqual(archive._db.execute(
                "SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()[0], self.union_id)
            seen.append(True)
            return dict(self.binding)

        result = module.restore_archive(self.repository, snapshot, self.root/'closed-restored',
            offline_state=offline, asset_verifier=verify)
        self.assertTrue(result['attachments_closed'])
        self.assertFalse(result['metadata_only'])
        self.assertEqual(seen, [True])
        # An unrelated or changed CAS must fail before invoking the verifier.
        with (state_output/'objects.sqlite').open('ab') as stream:
            stream.write(b'unrelated bytes')
        with self.assertRaisesRegex(ValueError, 'exact companion'):
            module.restore_archive(self.repository, snapshot, self.root/'wrong-state-restored',
                offline_state=offline, asset_verifier=lambda *a: self.fail('must not verify wrong state'))
        self.assertFalse((self.root/'wrong-state-restored'/'RESTORE.complete.private.json').exists())

    def test_corrupt_chunk_never_marks_restore_complete_and_partial_is_retained(self):
        self.prepared()
        snapshot = self.backup()['snapshot_id']
        with closing(sqlite3.connect(self.repository/module.DATABASE)) as db, db:
            db.execute('UPDATE chunk SET data=? WHERE hash=(SELECT hash FROM chunk LIMIT 1)', (b'corrupt',))
        output = self.root/'corrupt-restored'
        with self.assertRaises(ValueError):
            module.restore_archive(self.repository, snapshot, output)
        self.assertTrue((output/'RESTORE.partial.private.json').exists())
        self.assertFalse((output/'RESTORE.complete.private.json').exists())

    def test_owner_paths_state_journal_and_source_identity_fail_closed(self):
        self.prepared()
        foreign = self.repository
        foreign.mkdir()
        marker = foreign/'historical-original'
        marker.write_bytes(b'protected original')
        with self.assertRaises(FileNotFoundError):
            self.backup()
        self.assertEqual(marker.read_bytes(), b'protected original')
        self.repository = self.root/'union-backup-2'
        original = self.binding['union_id']
        self.binding['union_id'] = str(__import__('uuid').uuid4())
        with self.assertRaisesRegex(ValueError, 'binding identity'):
            self.backup()
        self.binding['union_id'] = original
        journal = self.state_repo/(state_backup.DATABASE+'-journal')
        journal.write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'recovery'):
            self.backup()
        self.assertFalse(self.repository.exists())

    def test_restore_verification_failure_and_single_file_output(self):
        self.prepared()
        snapshot = self.backup()['snapshot_id']
        output = self.root/'failed-restored'
        with patch.object(CompactArchive, 'integrity_check', side_effect=ValueError('synthetic integrity failure')):
            with self.assertRaisesRegex(ValueError, 'integrity failure'):
                module.restore_archive(self.repository, snapshot, output)
        self.assertTrue((output/'RESTORE.partial.private.json').exists())
        self.assertFalse((output/'RESTORE.complete.private.json').exists())
        result = module.restore_archive(self.repository, snapshot, self.root/'single.sqlite', as_file=True)
        self.assertTrue(result['metadata_only'])
        self.assertEqual(digest_file(self.root/'single.sqlite'), digest_file(self.archive))

    def test_restore_sidecars_and_protected_companion_trees_are_rejected(self):
        self.prepared()
        snapshot = self.backup()['snapshot_id']
        target = self.root/'sidecar.sqlite'
        journal = target.with_name(target.name+'-journal')
        journal.write_bytes(b'protected stale sidecar')
        with self.assertRaisesRegex(ValueError, 'sidecar'):
            module.restore_archive(self.repository, snapshot, target, as_file=True)
        self.assertFalse(target.exists())
        self.assertEqual(journal.read_bytes(), b'protected stale sidecar')
        for root in (self.state_repo, self.service.state, self.source.parent.parent):
            with self.subTest(root_name=root.name):
                with self.assertRaisesRegex(ValueError, 'protected'):
                    module.restore_archive(self.repository, snapshot, root/'must-not-create')
                self.assertFalse((root/'must-not-create').exists())

    def test_manifest_tampering_and_inconsistent_summary_fail_closed(self):
        self.prepared()
        self.binding['missing'] = 1
        with self.assertRaisesRegex(ValueError, 'inconsistent'):
            self.backup()
        self.assertFalse(self.repository.exists())
        self.binding['missing'] = 0
        snapshot = self.backup()['snapshot_id']
        with closing(sqlite3.connect(self.repository/module.DATABASE)) as db, db:
            row = db.execute('SELECT manifest_json FROM snapshot WHERE id=?', (snapshot,)).fetchone()[0]
            changed = json.loads(row)
            changed['semantic_digest'] = '0'*64
            db.execute('UPDATE snapshot SET manifest_json=? WHERE id=?', (canonical(changed), snapshot))
        output = self.root/'tampered-restored'
        with self.assertRaisesRegex(ValueError, 'authentication'):
            module.restore_archive(self.repository, snapshot, output)
        self.assertFalse(output.exists())

    def test_origin_subset_and_missing_binding_cannot_claim_whole_union_companion(self):
        self.prepared()
        whole = dict(self.binding)
        for complete in (False, True):
            self.binding = dict(whole, verification_scope='origin_subset', origin_id='origin-a',
                                closure_complete=complete)
            with self.subTest(closure_complete=complete):
                with self.assertRaisesRegex(ValueError, 'whole-union'):
                    self.backup()
                self.assertFalse(self.repository.exists())
        self.binding = None
        with self.assertRaisesRegex(ValueError, 'explicit canonical asset binding'):
            self.backup()
        self.assertFalse(self.repository.exists())
        # Explicit whole-union zero-assets evidence is acceptable, but backup
        # alone still does not constitute an offline attachment restore proof.
        self.binding = whole
        snapshot = self.backup()['snapshot_id']
        state_output = self.root/'scope-offline-state'
        state_backup.restore(self.state_repo, self.state_snapshot, state_output)
        subset = dict(whole, verification_scope='origin_subset', origin_id='origin-a')
        output = self.root/'scope-rejected-restore'
        with self.assertRaisesRegex(ValueError, 'whole-union'):
            module.restore_archive(self.repository, snapshot, output,
                offline_state=SimpleNamespace(state=state_output), asset_verifier=lambda *args: subset)
        self.assertFalse((output/'RESTORE.complete.private.json').exists())
        restored = module.restore_archive(self.repository, snapshot, self.root/'scope-metadata-restore')
        self.assertTrue(restored['metadata_only'])
        self.assertFalse(restored['attachments_closed'])

    @unittest.skipUnless(os.name == 'nt', 'Windows mandatory sharing guards')
    def test_closed_state_hashes_once_and_guard_blocks_writes_through_publication(self):
        self.prepared()
        self.service.close()
        paths = [self.service.state/name for name in ('catalog.sqlite', 'objects.sqlite')]
        seen = []
        real = module.digest_file

        def counted(path):
            seen.append(Path(path))
            return real(path)

        def check_guard(stage, db):
            if stage == 'chunks':
                for path in paths:
                    with self.assertRaises(OSError):
                        with path.open('r+b'):
                            self.fail('mandatory guard admitted a writer')

        with patch.object(module, 'digest_file', side_effect=counted):
            first = self.backup(fault=check_guard)
        self.assertEqual([seen.count(path) for path in paths], [1, 1])
        seen.clear()
        with patch.object(module, 'digest_file', side_effect=counted):
            second = self.backup(fault=check_guard)
        self.assertTrue(second['noop'])
        self.assertEqual(first['snapshot_id'], second['snapshot_id'])
        self.assertEqual([seen.count(path) for path in paths], [1, 1])
        # Every acquired handle must have been released, not cached globally.
        for path in paths:
            with path.open('r+b'):
                pass

    @unittest.skipUnless(os.name == 'nt', 'Windows retained-writer fallback')
    def test_existing_rw_fallback_hashes_twice_and_rejects_same_stamp_mutation(self):
        self.prepared()  # Both state databases retain write-capable handles.
        paths = [self.service.state/name for name in ('catalog.sqlite', 'objects.sqlite')]
        seen = []
        real = module.digest_file

        def counted(path):
            seen.append(Path(path))
            return real(path)

        def mutate(stage, db):
            if stage == 'chunks':
                target = paths[1]
                before = target.stat()
                with target.open('r+b') as stream:
                    byte = stream.read(1)
                    stream.seek(0)
                    stream.write(bytes([byte[0] ^ 1]))
                os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
                self.assertEqual(module.stamp(target), (before.st_dev, before.st_ino,
                                                       before.st_size, before.st_mtime_ns))

        with patch.object(module, 'digest_file', side_effect=counted):
            with self.assertRaisesRegex(ValueError, 'companion changed'):
                self.backup(fault=mutate)
        self.assertEqual([seen.count(path) for path in paths], [2, 2])
        with closing(sqlite3.connect(self.repository/module.DATABASE)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM snapshot').fetchone()[0], 0)

    @unittest.skipUnless(os.name == 'nt', 'Windows mixed guard/fallback')
    def test_partial_guard_success_is_held_and_cleaned_when_other_state_file_falls_back(self):
        self.prepared()
        self.service.catalog.close()  # Catalog can freeze, Objects still cannot.
        paths = [self.service.state/name for name in ('catalog.sqlite', 'objects.sqlite')]
        real = module.digest_file
        seen = []

        def counted(path):
            seen.append(Path(path))
            return real(path)

        def verify_mixed(stage, db):
            if stage == 'chunks':
                with self.assertRaises(OSError):
                    with paths[0].open('r+b'):
                        self.fail('first guard was discarded after second failed')
                with paths[1].open('r+b'):
                    pass

        with patch.object(module, 'digest_file', side_effect=counted):
            self.backup(fault=verify_mixed)
        self.assertEqual([seen.count(path) for path in paths], [1, 2])
        with paths[0].open('r+b'):
            pass

    def test_non_windows_does_not_treat_metadata_as_a_mandatory_guard(self):
        self.prepared()
        paths = [self.service.state/name for name in ('catalog.sqlite', 'objects.sqlite')]
        from contextlib import ExitStack
        # Replace this module's os reference, not global os.name/Path behavior.
        with ExitStack() as stack, patch.object(module, 'os', SimpleNamespace(name='posix')):
            with patch.object(module, 'cold_input', side_effect=AssertionError('no mandatory non-Windows guard')):
                self.assertEqual(module._freeze_state_inputs(stack, paths), {path: None for path in paths})

    def test_process_death_after_chunk_write_recovers_owned_repository(self):
        self.prepared()
        first = self.backup()
        self.add_message()
        before = digest_file(self.repository/module.DATABASE)
        arguments = self.root/'crash-arguments.json'
        arguments.write_text(canonical(dict(source=str(self.archive), state_repo=str(self.state_repo),
            state_snapshot=self.state_snapshot, output=str(self.repository),
            state_catalog=str(self.service.state/'catalog.sqlite'), state_objects=str(self.service.state/'objects.sqlite'),
            binding=self.binding)), encoding='utf-8')
        code = '''import json,os,sys
from wechat_capture_next.union_backup import backup_archive
a=json.load(open(sys.argv[1],encoding='utf-8'))
def die(stage,db):
 if stage=='snapshot': os._exit(79)
backup_archive(a['source'],a['state_repo'],a['state_snapshot'],a['output'],state_catalog=a['state_catalog'],state_objects=a['state_objects'],asset_binding=a['binding'],fault=die)
'''
        # Parent's open service does not write; the child only reads its owned
        # state files, with no service construction, acquisition or login.
        run = subprocess.run([sys.executable, '-c', code, str(arguments)], capture_output=True)
        self.assertEqual(run.returncode, 79, run.stderr)
        self.assertEqual(module.inspect_snapshot(self.repository, first['snapshot_id'])['state_companion']['snapshot_id'], self.state_snapshot)
        self.assertEqual(before, digest_file(self.repository/module.DATABASE))
        self.assertFalse(self.backup()['noop'])


if __name__ == '__main__':
    unittest.main()
