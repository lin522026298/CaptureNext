"""Synthetic-only capture-next CAS backup/restore and real-crash boundaries."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

from wechat_capture_next import backup as module
from wechat_capture_next.backup import backup, restore, list_snapshots, inspect_snapshot, CHUNK_BYTES
from wechat_capture_next.service import CaptureService, initialize
from wechat_capture_next.tests import test_service as fixtures
from wechat_capture_v2.common import canonical, digest_file
from wechat_capture_v2.tests.test_backend import KEY


class BackupTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    pages = fixtures.ServiceTests.pages
    publish = fixtures.ServiceTests.publish
    def init_service(self):
        self.keys = self.root/'keys.json'
        self.keys.write_text(canonical({'databases': [{'relative_path': self.source.name,
            'verified': True, 'raw_encryption_key_hex': KEY.hex()}]}), encoding='utf-8')
        # Model the real account layout: protect all siblings of db_storage,
        # while keeping state/repository outside the synthetic account tree.
        live = self.root/'account'/'db_storage'
        live.mkdir(parents=True)
        self.source = self.source.replace(live/self.source.name)
        self.wal = self.source.with_name(self.source.name+'-wal')
        initialize(self.root/'state', live, self.keys, source_id='fixture',
            account_alias='fixture', self_username='self')
        return CaptureService(self.root/'state')

    def tearDown(self):
        # unittest cleanups normally run after tearDown; close Windows SQLite
        # handles before this fixture deletes its isolated TemporaryDirectory.
        self.doCleanups()
        fixtures.ServiceTests.tearDown(self)

    def prepared(self):
        service = self.init_service()
        self.addCleanup(service.close)
        self.assertEqual(service.capture(force=True)['status'], 'local_complete')
        return service

    def db(self):
        db = sqlite3.connect(self.root/'repository'/module.DATABASE)
        self.addCleanup(db.close)
        return db

    def snapshot(self, service, **kwargs):
        return backup(service, self.root/'repository', **kwargs)

    def source_hashes(self):
        return {p.name: digest_file(p) for p in self.source.parent.iterdir() if p.is_file()}

    def test_roundtrip_views_pages_reports_and_offline_verify(self):
        service = self.prepared()
        # Historical standalone reports and catalog-compressed current reports
        # are both retained; a CAS snapshot does not export report_json itself.
        report = service.state/'reports'/'historical.json'
        report.write_text(canonical({'old': 'retained'}), encoding='utf-8')
        source_before = self.source_hashes()
        first = self.snapshot(service)
        manifest = inspect_snapshot(self.root/'repository', first['snapshot_id'])
        self.assertNotIn(module.SECRETS, manifest['files'])
        self.assertIn(report.relative_to(service.state).as_posix(), manifest['files'])
        self.assertEqual(len(list_snapshots(self.root/'repository')), 1)
        output = self.root/'restored'
        # Source probing and the normal service constructor are forbidden in
        # offline restore, even though this fixture's live source still exists.
        real_stat, real_lstat = Path.stat, Path.lstat
        source_root = self.source.parent
        def no_source_stat(path, *args, **kwargs):
            if path.is_relative_to(source_root):
                raise AssertionError('offline restore must not inspect live sources')
            return real_stat(path, *args, **kwargs)
        def no_source_lstat(path, *args, **kwargs):
            if path.is_relative_to(source_root):
                raise AssertionError('offline restore must not inspect live sources')
            return real_lstat(path, *args, **kwargs)
        with patch.object(CaptureService, '__init__', side_effect=AssertionError('must remain offline')), \
                patch.object(Path, 'stat', no_source_stat), patch.object(Path, 'lstat', no_source_lstat):
            result = restore(self.root/'repository', first['snapshot_id'], output)
        self.assertTrue(result['verification']['pass'])
        self.assertEqual(result['verification']['current_views_verified'], 1)
        self.assertFalse(result['watch_started'])
        self.assertFalse(result['login_started'])
        self.assertTrue((output/'RESTORE.complete.private.json').is_file())
        self.assertFalse((output/'RESTORE.partial.private.json').exists())
        for name, entry in manifest['files'].items():
            self.assertEqual(digest_file(output/name), entry['sha256'])
        self.assertEqual(source_before, self.source_hashes())
        with closing(CaptureService(output)) as restored:
            self.assertTrue(restored.verify_state()['pass'])
            for ident, in restored.catalog.db.execute('SELECT id FROM cycle'):
                self.assertEqual(restored.catalog.report(ident), service.catalog.report(ident))

    def test_noop_byteidentity_and_single_file_single_chunk_delta(self):
        service = self.prepared()
        report = service.state/'reports'/'large.json'
        # Deliberately no attempt to interpret standalone report contents.
        report.write_bytes(b'A'*CHUNK_BYTES + b'B'*CHUNK_BYTES + b'C'*CHUNK_BYTES)
        first = self.snapshot(service)
        before = digest_file(self.root/'repository'/module.DATABASE)
        second = self.snapshot(service)
        self.assertTrue(second['noop'])
        self.assertEqual(first['snapshot_id'], second['snapshot_id'])
        self.assertEqual(before, digest_file(self.root/'repository'/module.DATABASE))
        old = inspect_snapshot(self.root/'repository', first['snapshot_id'])
        with report.open('r+b') as stream:
            stream.seek(CHUNK_BYTES + 12)
            stream.write(b'x')
        with patch.object(module.zlib, 'compress', wraps=module.zlib.compress) as compress:
            third = self.snapshot(service)
        self.assertEqual(third['new_chunks'], 1)
        self.assertEqual(compress.call_count, 1)
        new = inspect_snapshot(self.root/'repository', third['snapshot_id'])
        self.assertEqual(len(list_snapshots(self.root/'repository')), 2)
        changed = [name for name in old['files'] if old['files'][name] != new['files'][name]]
        self.assertEqual(changed, ['reports/large.json'])
        restored = self.root/'delta-restored'
        restore(self.root/'repository', third['snapshot_id'], restored)
        self.assertEqual(report.read_bytes(), (restored/'reports'/'large.json').read_bytes())

    def test_secret_opt_in_and_source_unchanged(self):
        service = self.prepared()
        before = self.source_hashes()
        first = self.snapshot(service)
        second = self.snapshot(service, include_secrets=True)
        self.assertFalse(first['includes_secrets'])
        self.assertTrue(second['includes_secrets'])
        restore(self.root/'repository', second['snapshot_id'], self.root/'with-key')
        self.assertEqual((service.state/module.SECRETS).read_bytes(), (self.root/'with-key'/module.SECRETS).read_bytes())
        self.assertEqual(before, self.source_hashes())

    def test_foreign_owner_and_existing_target_unchanged(self):
        service = self.prepared()
        first = self.snapshot(service)
        repository = self.root/'repository'
        owner_path = repository/'OWNER.private.json'
        owner = json.loads(owner_path.read_text(encoding='utf-8'))
        owner['catalog_instance'] = 'foreign-owner'
        owner_path.write_text(canonical(owner), encoding='utf-8')
        before = digest_file(repository/module.DATABASE)
        with self.assertRaises(ValueError):
            self.snapshot(service)
        self.assertEqual(before, digest_file(repository/module.DATABASE))
        owner['catalog_instance'] = service.catalog.db.execute("SELECT value FROM meta WHERE key='next_catalog_instance'").fetchone()[0]
        owner_path.write_text(canonical(owner), encoding='utf-8')
        target = self.root/'existing'
        target.mkdir()
        (target/'protected').write_bytes(b'never overwritten')
        with self.assertRaises(FileExistsError):
            restore(repository, first['snapshot_id'], target)
        self.assertEqual((target/'protected').read_bytes(), b'never overwritten')
        foreign = self.root/'foreign-unowned'
        foreign.mkdir()
        (foreign/'keep').write_bytes(b'historical')
        with self.assertRaises(FileNotFoundError):
            backup(service, foreign)
        self.assertEqual((foreign/'keep').read_bytes(), b'historical')

    def test_missing_and_corrupt_chunks_rejected_without_publication(self):
        service = self.prepared()
        first = self.snapshot(service)
        db = self.db()
        key, original = db.execute('SELECT hash,data FROM chunk LIMIT 1').fetchone()
        db.execute('UPDATE chunk SET data=? WHERE hash=?', (b'bad compression', key))
        db.commit()
        with self.assertRaises(ValueError):
            restore(self.root/'repository', first['snapshot_id'], self.root/'corrupt')
        self.assertTrue((self.root/'corrupt'/'RESTORE.partial.private.json').exists())
        self.assertTrue((self.root/'corrupt'/'RESTORE.failure.private.json').exists())
        self.assertFalse((self.root/'corrupt'/'RESTORE.complete.private.json').exists())
        db.execute('UPDATE chunk SET data=? WHERE hash=?', (original, key))
        db.execute('DELETE FROM chunk WHERE hash=?', (key,))
        db.commit()
        with self.assertRaises(ValueError):
            restore(self.root/'repository', first['snapshot_id'], self.root/'missing')
        # FK validation may reject before the fresh target is created.
        self.assertFalse((self.root/'missing'/'RESTORE.complete.private.json').exists())

    def test_published_metadata_list_never_scans_payloads_but_full_apis_still_verify(self):
        service = self.prepared()
        first = self.snapshot(service)
        repository = self.root/'repository'
        db = self.db()
        key, = db.execute('SELECT chunk_hash FROM snapshot_chunk LIMIT 1').fetchone()
        # Deliberately corrupt a referenced chunk with a large synthetic BLOB.
        # A metadata list cannot certify this payload; full APIs must reject it.
        db.execute('UPDATE chunk SET data=zeroblob(?) WHERE hash=?', (8*CHUNK_BYTES, key))
        db.commit()
        readonly = module._readonly
        forbidden = []
        def guarded_readonly(path, **kwargs):
            reader = readonly(path, **kwargs)
            def authorize(action, table, column, database, trigger):
                if ((action == sqlite3.SQLITE_READ and table == 'chunk' and column in ('data','bytes'))
                        or (action == sqlite3.SQLITE_PRAGMA and table in ('integrity_check','quick_check'))):
                    forbidden.append((action, table, column))
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            reader.set_authorizer(authorize)
            return reader
        with patch.object(module, '_readonly', side_effect=guarded_readonly), \
                patch.object(module, '_integrity', side_effect=AssertionError('metadata list ran full integrity')):
            listed = module.list_published_snapshots(repository)
            self.assertEqual([row['snapshot_id'] for row in listed], [first['snapshot_id']])
        self.assertEqual(forbidden, [])
        integrity = module._integrity
        checked = []
        def checked_integrity(connection):
            checked.append(Path(connection.execute('PRAGMA database_list').fetchone()[2]))
            return integrity(connection)
        with patch.object(module, '_integrity', side_effect=checked_integrity):
            with self.assertRaises(ValueError):
                self.snapshot(service)
            self.assertIn(repository/module.DATABASE, checked)
            checked.clear()
            with self.assertRaises(ValueError):
                restore(repository, first['snapshot_id'], self.root/'payload-corrupt-restore')
            self.assertIn(repository/module.DATABASE, checked)
        self.assertFalse((self.root/'payload-corrupt-restore'/'RESTORE.complete.private.json').exists())
        db.execute('UPDATE snapshot SET manifest_json=manifest_json||? WHERE id=?', (' ', first['snapshot_id']))
        db.commit()
        with patch.object(module, '_readonly', side_effect=guarded_readonly), \
                patch.object(module, '_integrity', side_effect=AssertionError('metadata list ran full integrity')):
            with self.assertRaisesRegex(ValueError, 'manifest authentication'):
                module.list_published_snapshots(repository)
        self.assertEqual(forbidden, [])

    def test_restore_space_preflight_refuses_before_creating_target_or_touching_inputs(self):
        from types import SimpleNamespace
        service = self.prepared()
        first = self.snapshot(service)
        repository = self.root/'repository'
        source_before = self.source_hashes()
        inputs = {p.name:digest_file(p) for p in repository.iterdir()}
        existing = self.root/'restore-destination'
        existing.mkdir()
        output = existing/'not-created-parent'/'restored'
        with patch.object(module.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)) as capacity, \
                patch.object(module, '_restore_file', side_effect=AssertionError('restore started copying')):
            with self.assertRaises(module.InsufficientRestoreSpace):
                restore(repository, first['snapshot_id'], output)
            capacity.assert_called_once_with(existing)
            # Incremental/no-op backup has no full-snapshot space threshold.
            self.assertTrue(self.snapshot(service)['noop'])
            capacity.assert_called_once_with(existing)
        self.assertFalse(output.exists())
        self.assertFalse(output.parent.exists())
        self.assertEqual(inputs, {p.name:digest_file(p) for p in repository.iterdir()})
        self.assertEqual(source_before, self.source_hashes())

    def test_restore_space_margin_boundary_and_normal_full_verification(self):
        from types import SimpleNamespace
        service = self.prepared()
        first = self.snapshot(service)
        repository = self.root/'repository'
        manifest = inspect_snapshot(repository, first['snapshot_id'])
        needed = sum(value['bytes'] for value in manifest['files'].values()) + module.RESTORE_MARGIN_BYTES
        output = self.root/'space-boundary-restore'
        with patch.object(module.shutil, 'disk_usage', return_value=SimpleNamespace(free=needed-1)):
            with self.assertRaises(module.InsufficientRestoreSpace):
                restore(repository, first['snapshot_id'], output)
        self.assertFalse(output.exists())
        with patch.object(module.shutil, 'disk_usage', return_value=SimpleNamespace(free=needed)), \
                patch.object(module, '_integrity', wraps=module._integrity) as integrity:
            result = restore(repository, first['snapshot_id'], output)
            self.assertTrue(result['verification']['pass'])
            self.assertGreater(integrity.call_count, 0)
        self.assertTrue((output/'RESTORE.complete.private.json').exists())

    def test_metadata_list_rejects_missing_or_mismatched_chunk_references(self):
        service = self.prepared()
        first = self.snapshot(service)
        db = self.db()
        key, = db.execute('SELECT chunk_hash FROM snapshot_chunk WHERE snapshot_id=? LIMIT 1', (first['snapshot_id'],)).fetchone()
        db.execute('DELETE FROM snapshot_chunk WHERE snapshot_id=? AND chunk_hash=?', (first['snapshot_id'], key))
        db.commit()
        with patch.object(module, '_integrity', side_effect=AssertionError('metadata list ran full integrity')):
            with self.assertRaisesRegex(ValueError, 'reference set'):
                module.list_published_snapshots(self.root/'repository')
            db.execute('INSERT INTO snapshot_chunk VALUES(?,?)', (first['snapshot_id'], key))
            db.execute('DELETE FROM chunk WHERE hash=?', (key,))
            db.commit()
            with self.assertRaisesRegex(ValueError, 'missing chunk'):
                module.list_published_snapshots(self.root/'repository')

    def rewrite_manifest(self, ident, transform):
        db = self.db()
        manifest = json.loads(db.execute('SELECT manifest_json FROM snapshot WHERE id=?', (ident,)).fetchone()[0])
        transform(manifest)
        text = canonical(manifest)
        replacement = hashlib.sha256(text.encode()).hexdigest()
        db.execute('UPDATE snapshot SET id=?,manifest_json=? WHERE id=?', (replacement, text, ident))
        db.execute('UPDATE snapshot_chunk SET snapshot_id=? WHERE snapshot_id=?', (replacement, ident))
        db.commit()
        return replacement

    def test_manifest_traversal_absolute_alias_and_forbidden_files(self):
        service = self.prepared()
        original = self.snapshot(service)['snapshot_id']
        for bad in ('../escaped.json', '/outside.json', 'C:/absolute.json',
                    'reports/../../escaped.json', 'reports/a/../b.json', 'cache/aux.db',
                    'writer.lock', 'reports/CON.json', 'reports\\outside.json',
                    'reports/COM¹.json', 'reports/COM².json', 'reports/LPT³.json', 'reports/CON .json',
                    'reports/control\x01.json', 'reports/NUL\x00.json', 'reports/<name>.json',
                    'reports/quote".json', 'reports/pipe|.json', 'reports/question?.json', 'reports/star*.json'):
            def transform(value):
                # Keep required files intact: rejection must actually exercise
                # this malicious extra pathname, not fail missing-config first.
                value['files'][bad] = dict(value['files']['config.private.json'])
            new = self.rewrite_manifest(original, transform)
            with self.assertRaises(ValueError, msg=bad):
                restore(self.root/'repository', new, self.root/'invalid')
            self.assertFalse((self.root/'invalid').exists())
            # Back to the canonical authentic manifest for the next attack.
            original = self.rewrite_manifest(new, lambda v: v['files'].pop(bad))

    def test_manifest_hash_tamper_refused(self):
        service = self.prepared()
        ident = self.snapshot(service)['snapshot_id']
        db = self.db()
        db.execute("UPDATE snapshot SET manifest_json='{}' WHERE id=?", (ident,))
        db.commit()
        with self.assertRaises(ValueError):
            restore(self.root/'repository', ident, self.root/'tampered')
        self.assertFalse((self.root/'tampered').exists())

    def test_manifest_source_boundary_lie_rejected_before_output(self):
        service = self.prepared()
        ident = self.snapshot(service)['snapshot_id']
        forged = self.rewrite_manifest(ident, lambda value: value.__setitem__('source_roots', []))
        # A forged manifest must not authorize writing under the real source.
        output = service.root/'forbidden-restore'
        with self.assertRaises(ValueError):
            restore(self.root/'repository', forged, output)
        self.assertFalse(output.exists())

    def test_backup_refuses_existing_corrupt_cas_and_older_cut_reuses_snapshot(self):
        service = self.prepared()
        first = self.snapshot(service)
        report = service.state/'reports'/'temporary.json'
        report.write_bytes(b'delta')
        self.snapshot(service)
        report.unlink()
        before = digest_file(self.root/'repository'/module.DATABASE)
        reused = self.snapshot(service)
        self.assertTrue(reused['noop'])
        self.assertEqual(reused['snapshot_id'], first['snapshot_id'])
        self.assertEqual(before, digest_file(self.root/'repository'/module.DATABASE))
        db = self.db()
        key, = db.execute('SELECT hash FROM chunk LIMIT 1').fetchone()
        db.execute('UPDATE chunk SET data=? WHERE hash=?', (b'corrupt', key))
        db.commit()
        with self.assertRaises(ValueError):
            self.snapshot(service)

    def test_backup_failure_rolls_back_and_retry(self):
        service = self.prepared()
        first = self.snapshot(service)
        db = self.db()
        original_counts = tuple(db.execute('SELECT (SELECT count(*) FROM chunk),(SELECT count(*) FROM snapshot)').fetchone())
        (service.state/'reports'/'new.json').write_text('new chunk', encoding='utf-8')
        actual = module._add_file
        def fail(db, path, **kwargs):
            result = actual(db, path, **kwargs)
            if path.name == 'new.json':
                raise RuntimeError('synthetic interruption after chunk insert')
            return result
        with patch.object(module, '_add_file', side_effect=fail):
            with self.assertRaises(RuntimeError):
                self.snapshot(service)
        self.assertEqual(original_counts, tuple(db.execute('SELECT (SELECT count(*) FROM chunk),(SELECT count(*) FROM snapshot)').fetchone()))
        self.assertEqual(list_snapshots(self.root/'repository')[0]['snapshot_id'], first['snapshot_id'])
        self.assertFalse(self.snapshot(service)['noop'])
        self.assertEqual(len(list_snapshots(self.root/'repository')), 2)

    def test_full_backup_verifies_pages_once_and_only_after_both_databases_frozen(self):
        service = self.prepared()
        integrity, verify = module._integrity, service.verify_state
        pages_checked = []
        def checked(db):
            name = Path(db.execute('PRAGMA database_list').fetchone()[2]).name
            if name.endswith('.pages.sqlite'):
                self.assertTrue(service.catalog.db.in_transaction)
                self.assertTrue(service.objects.db.in_transaction)
                pages_checked.append(name)
            return integrity(db)
        def frozen_verify():
            for obj in (service.catalog, service.objects):
                self.assertTrue(obj.db.in_transaction)
                path = obj.db.execute('PRAGMA database_list').fetchone()[2]
                with closing(sqlite3.connect(path, timeout=0)) as other:
                    with self.assertRaises(sqlite3.OperationalError):
                        other.execute('BEGIN IMMEDIATE')
            return verify()
        with patch.object(module, '_integrity', side_effect=checked), \
                patch.object(service, 'verify_state', side_effect=frozen_verify):
            self.snapshot(service)
        self.assertEqual(len(pages_checked), 1)
        self.assertFalse(service.catalog.db.in_transaction)
        self.assertFalse(service.objects.db.in_transaction)

    def test_verified_block_lru_is_transaction_local_and_bounded(self):
        from collections import OrderedDict
        service = self.prepared()
        block = b'repeated' * (CHUNK_BYTES // 8)
        key = hashlib.sha256(block).hexdigest()
        for name in ('a.json', 'b.json', 'c.json'):
            (service.state/'reports'/name).write_bytes(block * 8)
        first = self.snapshot(service)
        before = digest_file(self.root/'repository'/module.DATABASE)
        real_block = module._block
        seen = []
        def counted(db, current):
            seen.append(current)
            return real_block(db, current)
        with patch.object(module, '_block', side_effect=counted):
            second = self.snapshot(service)
        self.assertEqual(seen.count(key), 1)  # 24 source blocks, one CAS readback.
        self.assertTrue(second['noop'])
        self.assertEqual(first['snapshot_id'], second['snapshot_id'])
        self.assertEqual(before, digest_file(self.root/'repository'/module.DATABASE))
        # A proof from a previous backup must never mask later corruption.
        db = self.db()
        db.execute('UPDATE chunk SET data=? WHERE hash=?', (b'corrupt', key))
        db.commit()
        with self.assertRaises(ValueError):
            self.snapshot(service)
        db.execute('UPDATE chunk SET data=? WHERE hash=?', (module.zlib.compress(block, 1), key))
        db.commit()
        path = self.root/'lru.bin'
        path.write_bytes(b''.join(bytes([i])*CHUNK_BYTES for i in range(12)))
        cache = OrderedDict()
        with db:
            module._add_file(db, path, verified_blocks=cache)
            module._add_file(db, path, verified_blocks=cache)
            self.assertLessEqual(sum(map(len, cache.values())), module.VERIFIED_BLOCK_CACHE_BYTES)

    def test_corrupt_pages_after_preflight_never_publishes_snapshot(self):
        service = self.prepared()
        pages = service.view_path(self.source.name).with_suffix('.pages.sqlite')
        frozen = module._frozen
        from contextlib import contextmanager
        @contextmanager
        def corrupt_then_freeze(current):
            pages.write_bytes(b'not a sqlite database')
            with frozen(current):
                yield
        with patch.object(module, '_frozen', side_effect=corrupt_then_freeze):
            with self.assertRaises(sqlite3.DatabaseError):
                self.snapshot(service)
        self.assertFalse((self.root/'repository').exists())

    def test_dirty_pending_pages_sidecar_and_transaction_refused(self):
        service = self.prepared()
        view = service.view_path(self.source.name)
        for path in (view.with_suffix('.dirty'), view.with_suffix('.pending'),
                     Path(str(view.with_suffix('.pages.sqlite'))+'-wal')):
            path.write_bytes(b'partial')
            with self.assertRaises(ValueError):
                self.snapshot(service)
            path.unlink()
        service.catalog.db.execute('BEGIN IMMEDIATE')
        try:
            with self.assertRaises(ValueError):
                self.snapshot(service)
        finally:
            service.catalog.db.rollback()

    def test_pending_asset_publication_refused_before_any_backup_work(self):
        service = self.prepared()
        before = list(service.catalog.db.execute('SELECT key,value FROM meta ORDER BY key'))
        with patch.object(service, '_pending_asset', object()), \
                patch.object(module, '_consistent_config', side_effect=AssertionError('backup progressed')), \
                patch.object(service, 'verify_state', side_effect=AssertionError('backup verification started')):
            with self.assertRaisesRegex(ValueError, 'pending asset'):
                self.snapshot(service)
        self.assertFalse((self.root/'repository').exists())
        self.assertEqual(before, list(service.catalog.db.execute('SELECT key,value FROM meta ORDER BY key')))
        self.assertTrue(self.snapshot(service)['snapshot_id'])

    def test_state_source_and_repository_overlap_refused(self):
        service = self.prepared()
        first = self.snapshot(service)
        for target in (service.state/'nested', service.state, service.state.parent,
                       service.root/'nested', service.root, service.root.parent/'msg'/'nested'):
            with self.assertRaises(ValueError):
                backup(service, target)
        for target in (service.state/'nested', service.root/'restored', self.root/'repository'/'nested',
                       service.root.parent/'msg'/'restore'):
            with self.assertRaises(ValueError):
                restore(self.root/'repository', first['snapshot_id'], target)
            self.assertFalse(target.exists())

    def test_asset_transition_disk_config_and_source_binding_refused(self):
        service = self.prepared()
        for name in ('asset-root-change.private.json', 'asset-root-config.private.json'):
            target = service.state/name
            target.write_text('{}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'transition'):
                self.snapshot(service)
            self.assertFalse((self.root/'repository').exists())
            target.unlink()
        target = service.state/'config.private.json'
        original = target.read_bytes()
        stale = dict(service.config, asset_root=str(self.root/'account'/'msg'))
        target.write_text(canonical(stale), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'configuration differ'):
            self.snapshot(service)
        self.assertFalse((self.root/'repository').exists())
        target.write_bytes(original)
        service.catalog.db.execute("UPDATE meta SET value='stale source binding' WHERE key='source_binding'")
        service.catalog.db.commit()
        with self.assertRaisesRegex(ValueError, 'binding differ'):
            self.snapshot(service)
        self.assertFalse((self.root/'repository').exists())

    def test_explicit_secret_request_requires_keyring(self):
        service = self.prepared()
        (service.state/module.SECRETS).unlink()
        with self.assertRaisesRegex(FileNotFoundError, 'requires.*keyring'):
            self.snapshot(service, include_secrets=True)
        self.assertFalse((self.root/'repository').exists())
        self.assertFalse(self.snapshot(service)['includes_secrets'])

    def test_namespace_aliases_rejected_before_filesystem_changes(self):
        service = self.prepared()
        first = self.snapshot(service)
        aliases = ('\\\\?\\E:\\forbidden', '\\\\.\\C:\\forbidden', '//server/share/forbidden',
                   '\\??\\C:\\forbidden', '\\Device\\HarddiskVolume1\\forbidden',
                   'C:\\forbidden\x00name', 'C:\\forbidden\x01name')
        for alias in aliases:
            with self.assertRaises(ValueError, msg=repr(alias)):
                backup(service, alias)
            with self.assertRaises(ValueError, msg=repr(alias)):
                list_snapshots(alias)
            with self.assertRaises(ValueError, msg=repr(alias)):
                inspect_snapshot(alias, first['snapshot_id'])
            with self.assertRaises(ValueError, msg=repr(alias)):
                module.recover_repository(alias)
            with self.assertRaises(ValueError, msg=repr(alias)):
                restore(self.root/'repository', first['snapshot_id'], alias)
        for alias in aliases[:5]:
            with self.assertRaises(ValueError, msg=repr(alias)):
                module._external_root(alias)

    def crash_child(self, code, expected=79, *extra):
        result = subprocess.run([sys.executable, '-c', code, str(self.root/'repository'), *extra],
            cwd=Path(module.__file__).resolve().parent.parent,
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_real_process_death_during_initial_schema_is_atomic_and_retryable(self):
        service = self.prepared()
        identity = module.catalog_identity(service)
        self.crash_child('''
import os, sys
from wechat_capture_next import backup as b
owner = dict(schema=b.SCHEMA, catalog_instance=sys.argv[2])
path, owner = b._repository(sys.argv[1], owner, create=True)
def crash(stage, db):
    if stage == 'schema_begin':
        db.execute('PRAGMA cache_size=1')
        db.execute('PRAGMA cache_spill=ON')
    if stage == 'schema_before_commit':
        os._exit(79)
with b._repository_lock(path):
    b._writer(path, owner, fault=crash)
raise AssertionError('crash hook was not called')
''', 79, identity)
        journal = self.root/'repository'/(module.DATABASE+'-journal')
        self.assertTrue(journal.is_file())
        # A hot journal is handled by SQLite, not ignored by immutable reads or
        # hand-deleted. Empty rolled-back schema can be initialized atomically.
        self.assertEqual(list_snapshots(self.root/'repository'), [])
        self.assertFalse(journal.exists())
        recovered = module.recover_repository(self.root/'repository')
        self.assertEqual(recovered['snapshots'], 0)
        first = self.snapshot(service)
        self.assertFalse(first['noop'])
        restore(self.root/'repository', first['snapshot_id'], self.root/'initial-crash-restored')

    def test_real_process_death_in_chunk_transaction_preserves_published_snapshot(self):
        service = self.prepared()
        first = self.snapshot(service)
        before = digest_file(self.root/'repository'/module.DATABASE)
        # Every public entry point must recover, not just explicit recovery.
        for entrypoint in ('list', 'inspect', 'restore', 'backup', 'recover'):
            self.crash_child('''
import hashlib, os, sys, zlib
from wechat_capture_next import backup as b
with b._repository_session(sys.argv[1]) as (path, owner, db, recovered):
    db.execute('PRAGMA cache_size=1')
    db.execute('PRAGMA cache_spill=ON')
    db.execute('BEGIN IMMEDIATE')
    block = os.urandom(b.CHUNK_BYTES)
    db.execute('INSERT INTO chunk VALUES(?,?,?)',
        (hashlib.sha256(block).hexdigest(), len(block), zlib.compress(block)))
    os._exit(79)
''')
            journal = self.root/'repository'/(module.DATABASE+'-journal')
            self.assertTrue(journal.is_file(), entrypoint)
            self.assertEqual(journal.read_bytes()[:8], b'\xd9\xd5\x05\xf9\x20\xa1\x63\xd7', entrypoint)
            if entrypoint == 'list':
                self.assertEqual(list_snapshots(self.root/'repository')[0]['snapshot_id'], first['snapshot_id'])
            elif entrypoint == 'inspect':
                self.assertIn('catalog.sqlite', inspect_snapshot(self.root/'repository', first['snapshot_id'])['files'])
            elif entrypoint == 'restore':
                restore(self.root/'repository', first['snapshot_id'], self.root/'after-crash')
            elif entrypoint == 'backup':
                self.assertTrue(self.snapshot(service)['noop'])
            else:
                self.assertTrue(module.recover_repository(self.root/'repository')['journal_present'])
            self.assertFalse(journal.exists(), entrypoint)
            self.assertEqual(before, digest_file(self.root/'repository'/module.DATABASE), entrypoint)
        self.assertEqual(len(list_snapshots(self.root/'repository')), 1)

    def test_partial_unknown_schema_and_linked_journal_fail_closed(self):
        service = self.prepared()
        identity = module.catalog_identity(service)
        repo, owner = module._repository(self.root/'repository',
            dict(schema=module.SCHEMA, catalog_instance=identity), create=True)
        with closing(sqlite3.connect(repo/module.DATABASE)) as db:
            db.execute('CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            db.commit()
        before = digest_file(repo/module.DATABASE)
        with self.assertRaisesRegex(ValueError, 'unknown or incomplete'):
            module.recover_repository(repo)
        self.assertEqual(before, digest_file(repo/module.DATABASE))
        journal = repo/(module.DATABASE+'-journal')
        outside = self.root/'outside-journal'
        outside.write_bytes(b'external')
        os.link(outside, journal)
        try:
            with self.assertRaisesRegex(ValueError, 'hardlinked'):
                module.recover_repository(repo)
            self.assertEqual(outside.read_bytes(), b'external')
        finally:
            journal.unlink()

    def test_superjournal_reference_refused_without_external_access(self):
        service = self.prepared()
        self.snapshot(service)
        journal = self.root/'repository'/(module.DATABASE+'-journal')
        name = str(self.root/'must-not-open').encode()
        journal.write_bytes(b'private journal payload'+name+len(name).to_bytes(4, 'big')+
            sum(name).to_bytes(4, 'big')+b'\xd9\xd5\x05\xf9\x20\xa1\x63\xd7')
        before = journal.read_bytes()
        with self.assertRaisesRegex(ValueError, 'superjournal'):
            module.recover_repository(self.root/'repository')
        self.assertEqual(before, journal.read_bytes())
        self.assertFalse((self.root/'must-not-open').exists())

    def test_restore_verification_failure_leaves_explicit_partial(self):
        service = self.prepared()
        first = self.snapshot(service)
        with patch.object(CaptureService, 'verify_state', side_effect=ValueError('synthetic verification')):
            with self.assertRaises(ValueError):
                restore(self.root/'repository', first['snapshot_id'], self.root/'partial')
        self.assertTrue((self.root/'partial'/'RESTORE.failure.private.json').is_file())
        self.assertFalse((self.root/'partial'/'RESTORE.complete.private.json').exists())
        # Existing partial directories cannot be adopted on retry.
        with self.assertRaises(FileExistsError):
            restore(self.root/'repository', first['snapshot_id'], self.root/'partial')

    def test_hardlink_sidecar_and_output_ancestor_refused(self):
        service = self.prepared()
        target = service.state/'reports'/'linked.json'
        original = self.root/'protected.json'
        original.write_bytes(b'protected')
        os.link(original, target)
        try:
            with self.assertRaises(ValueError):
                self.snapshot(service)
        finally:
            target.unlink()
        first = self.snapshot(service)
        dbfile = self.root/'repository'/module.DATABASE
        linked = self.root/'linked.sqlite'
        os.link(dbfile, linked)
        try:
            with self.assertRaises(ValueError):
                list_snapshots(self.root/'repository')
        finally:
            linked.unlink()
        link = self.root/'linked-directory'
        outside = self.root/'outside'
        outside.mkdir()
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest('local account cannot create directory symlinks')
        with self.assertRaises(ValueError):
            restore(self.root/'repository', first['snapshot_id'], link/'new')
        self.assertFalse((outside/'new').exists())


if __name__ == '__main__':
    unittest.main()
