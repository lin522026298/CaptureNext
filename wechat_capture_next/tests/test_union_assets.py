"""Only synthetic stores; no configured source, account, key, or acquisition."""
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from wechat_capture_v2.objects import Objects, CHUNK_BYTES
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.union_assets import (plan_asset_union, import_asset_union,
    verify_union_assets, decode_asset_row, verify_published_object)


class OfflineService:
    def __init__(self, state):
        from types import SimpleNamespace
        self.state = Path(state)
        self.catalog = SimpleNamespace(path=self.state/'catalog.sqlite',
                                       db=sqlite3.connect(self.state/'catalog.sqlite'))
        self.catalog.db.row_factory = sqlite3.Row
        self.catalog.db.execute('PRAGMA foreign_keys=ON')
        self.objects = Objects(self.state/'objects.sqlite')
        self._pending_asset = None

    def close(self):
        self.catalog.db.close()
        self.objects.close()


class UnionAssetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root/'current'; self.state.mkdir()
        with closing(sqlite3.connect(self.state/'catalog.sqlite')) as db:
            db.execute('CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            db.execute("INSERT INTO meta VALUES('next_catalog_instance','synthetic-instance')")
            db.commit()
        self.service = OfflineService(self.state)
        self.shared = self.root/'shared.dat'
        self.shared.write_bytes(b'shared-current-only' * 1000)
        self.shared_info = self.service.objects.add(self.shared)
        self.missing = self.root/'missing.dat'
        self.missing.write_bytes(b'Z' * CHUNK_BYTES + b'Q' * CHUNK_BYTES + b'tail')
        self.retained = self.root/'retained.sqlite'
        with closing(Objects(self.retained)) as objects:
            self.missing_info = objects.add(self.missing)
            objects.db.execute('''CREATE TABLE asset(source_id TEXT,relative_path TEXT,file_sha TEXT,
                bytes INTEGER,stamp_json TEXT,cycle_id TEXT,unknown_blob BLOB,unknown_real REAL)''')
            objects.db.execute('''CREATE TABLE asset_history(source_id TEXT,relative_path TEXT,file_sha TEXT,
                bytes INTEGER,cycle_id TEXT,unknown_text TEXT)''')
            self.literal = ' { "mtime":1e999, "escaped":"\\u4f60", "repeat":1, "repeat":2 } '
            objects.db.execute('INSERT INTO asset VALUES(?,?,?,?,?,?,?,?)', ('old-device',
                '../original-metadata-only/path.dat', self.missing_info['sha256'], self.missing_info['bytes'],
                self.literal, 'old-cycle', b'\x00\xffunknown', -1.25))
            objects.db.execute('INSERT INTO asset_history VALUES(?,?,?,?,?,?)', ('old-device',
                '../original-metadata-only/path.dat', self.shared_info['sha256'], self.shared_info['bytes'],
                'earlier-cycle', 'unknown\x00field'))
            objects.db.execute('INSERT INTO asset_history VALUES(?,?,?,?,?,?)', ('old-device',
                '../original-metadata-only/path.dat', self.missing_info['sha256'], self.missing_info['bytes'],
                'old-cycle', 'same raw bytes, independent history'))
            objects.db.commit()
        self.original = self.retained.read_bytes()

    def tearDown(self):
        self.service.close()
        self.temporary.cleanup()

    def archive(self, name='union'):
        root = self.root/name
        root.mkdir(exist_ok=True)
        return CompactArchive(root/'archive.wua.sqlite', create=True)

    def test_plan_readonly_then_union_replay_and_full_preservation(self):
        with self.archive() as archive:
            before = [Path(obj.path).read_bytes() for obj in (self.service.catalog, self.service.objects)]
            plan = plan_asset_union(archive, self.service, self.retained, 'old', source_receipt='opaque not a path')
            self.assertEqual((1, 1), (plan['existing_files'], plan['missing_files']))
            self.assertEqual({'asset': 1, 'asset_history': 2}, plan['source_rows'])
            self.assertFalse(plan['object_bytes_verified'])
            self.assertEqual(before, [Path(obj.path).read_bytes() for obj in (self.service.catalog, self.service.objects)])
            self.assertFalse(archive._db.execute("SELECT 1 FROM sqlite_master WHERE name='next_union_asset_meta'").fetchone())
            calls = []
            original_verify = verify_published_object
            def verify(db, sha, size):
                calls.append((db, sha))
                return original_verify(db, sha, size)
            with patch('wechat_capture_next.union_assets.verify_published_object', side_effect=verify):
                result = import_asset_union(archive, self.service, self.retained, 'old', source_receipt={'receipt_sha': 'opaque'})
            self.assertEqual((1, 1), (result['imported_files'], result['existing_files_verified']))
            self.assertEqual(2, len(calls))
            self.assertEqual(2, len({sha for db, sha in calls}))
            self.assertEqual(3, result['added_metadata_observations'])
            self.assertEqual(2, self.service.objects.db.execute('SELECT count(*) FROM file').fetchone()[0])
            self.assertFalse(self.service.catalog.db.execute("SELECT 1 FROM sqlite_master WHERE name='cycle'").fetchone())
            rows = [decode_asset_row(archive.pool.get_text(r[0])) for r in archive._db.execute(
                "SELECT payload_id FROM next_union_asset_observation WHERE source_table='asset'")]
            self.assertEqual(self.literal, rows[0]['stamp_json'])
            self.assertEqual(b'\x00\xffunknown', rows[0]['unknown_blob'])
            self.assertEqual(-1.25, rows[0]['unknown_real'])
            summary = verify_union_assets(archive, self.service)
            self.assertTrue(summary['closure_complete'])
            self.assertEqual((2, 2, 0, 2), (summary['references'], summary['available'], summary['missing'], summary['deep_verified']))
            self.assertEqual(summary['union_id'], result['owner_id'])
            changes = [db.total_changes for db in (archive._db, self.service.catalog.db, self.service.objects.db)]
            files = [Path(archive.path).read_bytes(), self.service.catalog.path.read_bytes(), self.service.objects.path.read_bytes()]
            def sqlite_footprint():
                return {str(path): (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
                    for folder in (self.state, Path(archive.path).parent)
                    for path in folder.glob('*.sqlite*') if path.is_file()}
            footprint = sqlite_footprint()
            replay = import_asset_union(archive, self.service, self.retained, 'old', source_receipt={'receipt_sha': 'opaque'})
            self.assertTrue(replay['replay'])
            self.assertEqual(0, replay['added_metadata_observations'])
            self.assertEqual(0, replay['imported_files'])
            self.assertEqual(changes, [db.total_changes for db in (archive._db, self.service.catalog.db, self.service.objects.db)])
            self.assertEqual(files, [Path(archive.path).read_bytes(), self.service.catalog.path.read_bytes(), self.service.objects.path.read_bytes()])
            self.assertEqual(footprint, sqlite_footprint())
            self.assertEqual(summary, verify_union_assets(archive, self.service))
        self.assertEqual(self.original, self.retained.read_bytes())

    def test_missing_bytes_and_duplicate_metadata_fail_without_target_mutation(self):
        with self.archive() as archive:
            with closing(sqlite3.connect(self.retained)) as source:
                source.execute('DELETE FROM file')
                source.commit()
            plan = plan_asset_union(archive, self.service, self.retained, 'missing')
            self.assertFalse(plan['ready'])
            before = archive._db.total_changes
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                import_asset_union(archive, self.service, self.retained, 'missing')
            self.assertEqual(before, archive._db.total_changes)
            with closing(sqlite3.connect(self.retained)) as source:
                source.execute('INSERT INTO asset SELECT * FROM asset')
                source.commit()
            with self.assertRaisesRegex(ValueError, 'duplicate logical'):
                plan_asset_union(archive, self.service, self.retained, 'duplicate')

    def test_wrong_archive_connection_and_origin_subset_cannot_claim_whole_closure(self):
        with self.archive() as archive, self.archive('other') as other:
            connection = archive._db
            archive._db = other._db
            try:
                with self.assertRaisesRegex(ValueError, 'union connection'):
                    plan_asset_union(archive, self.service, self.retained, 'old')
            finally:
                archive._db = connection
            import_asset_union(archive, self.service, self.retained, 'A')
            def stop(stage):
                if stage == 'after_pending_commit':
                    raise RuntimeError('stop pending B')
            with self.assertRaises(RuntimeError):
                import_asset_union(archive, self.service, self.retained, 'B', fault=stop)
            subset = verify_union_assets(archive, self.service, origin_id='A')
            self.assertEqual('origin_subset', subset['verification_scope'])
            self.assertEqual('A', subset['origin_id'])
            self.assertEqual(2, subset['deep_verified'])
            self.assertFalse(subset['closure_complete'])
            with self.assertRaisesRegex(ValueError, 'pending'):
                verify_union_assets(archive, self.service)

    def test_explicit_empty_metadata_is_zero_but_absent_extension_is_not(self):
        with self.archive() as archive:
            with self.assertRaisesRegex(ValueError, 'absent'):
                verify_union_assets(archive, self.service)
            with closing(sqlite3.connect(self.retained)) as source:
                source.execute('DELETE FROM asset')
                source.execute('DELETE FROM asset_history')
                source.commit()
            import_asset_union(archive, self.service, self.retained, 'empty-observed-set')
            summary = verify_union_assets(archive, self.service)
            self.assertEqual('whole_union', summary['verification_scope'])
            self.assertIsNone(summary['origin_id'])
            self.assertEqual(0, summary['references'])
            self.assertEqual(0, summary['deep_verified'])
            self.assertTrue(summary['closure_complete'])
            self.assertEqual(1, self.service.objects.db.execute('SELECT count(*) FROM file').fetchone()[0])

    def test_each_observation_requires_same_origin_active_receipt_without_deletion(self):
        from wua.store import _json
        with self.archive() as archive:
            import_asset_union(archive, self.service, self.retained, 'A')
            orphan = dict(archive._db.execute('SELECT * FROM next_union_asset_observation LIMIT 1').fetchone())
            orphan['origin_id'] = 'unreceipted-origin'
            orphan['observation_id'] = 'asset_' + hashlib.sha256(_json([orphan['origin_id'],
                orphan['source_table'], orphan['row_key'], orphan['row_sha']]).encode()).hexdigest()
            archive._db.execute('INSERT INTO next_union_asset_observation VALUES(?,?,?,?,?,?,?,?,?,?)', tuple(orphan.values()))
            self.assertEqual([], list(archive._db.execute('PRAGMA foreign_key_check')))
            before = archive._db.total_changes
            with self.assertRaisesRegex(ValueError, 'same-origin active receipt coverage'):
                verify_union_assets(archive, self.service)
            self.assertEqual(before, archive._db.total_changes)
            self.assertEqual(4, archive._db.execute('SELECT count(*) FROM next_union_asset_observation').fetchone()[0])
            # Subset A remains verifiable, but cannot claim whole-union closure.
            subset = verify_union_assets(archive, self.service, origin_id='A')
            self.assertFalse(subset['closure_complete'])
            receipt = archive._db.execute('SELECT origin_id,artifact_sha FROM next_union_asset_receipt').fetchone()
            archive._db.execute('INSERT INTO next_union_asset_member VALUES(?,?,?)',
                                 (receipt[0], receipt[1], orphan['observation_id']))
            with self.assertRaisesRegex(ValueError, 'same-origin active receipt coverage'):
                verify_union_assets(archive, self.service)

    def test_receipt_coverage_point_lookup_and_vm_work_scale_linearly(self):
        import shutil
        vm_counts = []
        for count in (100, 200, 400):
            retained = self.root/f'scale-{count}.sqlite'
            shutil.copyfile(self.retained, retained)
            with closing(sqlite3.connect(retained)) as source:
                source.execute('DELETE FROM asset')
                source.execute('DELETE FROM asset_history')
                source.executemany('INSERT INTO asset VALUES(?,?,?,?,?,?,?,?)',
                    (('same-origin', f'media/{i:06d}.dat', self.shared_info['sha256'],
                      self.shared_info['bytes'], ' {"original": true} ', 'old-cycle', b'unknown', 1.5)
                     for i in range(count)))
                source.commit()
            with self.archive(f'scale-union-{count}') as archive:
                import_asset_union(archive, self.service, retained, 'scale')
                steps, queries = [0], []
                def progress():
                    steps[0] += 1
                    return 0
                archive._db.set_progress_handler(progress, 1)
                archive._db.set_trace_callback(queries.append)
                try:
                    self.assertEqual(count, verify_union_assets(archive, self.service, deep=False)['metadata_rows'])
                finally:
                    archive._db.set_progress_handler(None, 0)
                    archive._db.set_trace_callback(None)
                vm_counts.append(steps[0])
                actual = next(query for query in queries if 'NOT EXISTS' in query and
                              'next_union_asset_member_observation' in query)
                plan = ' '.join(str(tuple(row)) for row in archive._db.execute('EXPLAIN QUERY PLAN '+actual))
                self.assertIn('COVERING INDEX next_union_asset_member_observation', plan)
                self.assertIn('observation_id=? AND origin_id=?', plan)
                self.assertNotIn('SCAN m', plan)
        self.assertLess(vm_counts[1], vm_counts[0] * 3, vm_counts)
        self.assertLess(vm_counts[2], vm_counts[1] * 3, vm_counts)

    def test_linked_lock_and_sidecars_rejected_before_lock_writes(self):
        import os
        with self.archive() as archive:
            sentinel = self.root/'protected-empty-file'
            sentinel.write_bytes(b'')
            linked_lock = self.state/'writer.lock'
            os.link(sentinel, linked_lock)
            try:
                with self.assertRaisesRegex(ValueError, 'hardlinked'):
                    import_asset_union(archive, self.service, self.retained, 'old')
                self.assertEqual(b'', sentinel.read_bytes())
                self.assertFalse(archive._db.execute("SELECT 1 FROM sqlite_master WHERE name='next_union_asset_meta'").fetchone())
            finally:
                linked_lock.unlink()
            sidecar = Path(str(self.service.objects.path)+'-journal')
            os.link(sentinel, sidecar)
            try:
                with self.assertRaisesRegex(ValueError, 'sidecar'):
                    plan_asset_union(archive, self.service, self.retained, 'old')
                self.assertEqual(b'', sentinel.read_bytes())
            finally:
                sidecar.unlink()

    def test_ancestor_symlink_is_not_resolved_before_preflight(self):
        with self.archive() as archive:
            alias = self.root/'state-alias'
            try:
                alias.symlink_to(self.state, target_is_directory=True)
            except (PermissionError, OSError):
                self.skipTest('directory symlink privilege unavailable')
            original_state = self.service.state
            self.service.state = alias
            try:
                with self.assertRaisesRegex(ValueError, 'links/reparse'):
                    import_asset_union(archive, self.service, self.retained, 'old')
                self.assertFalse((self.state/'writer.lock').exists())
            finally:
                self.service.state = original_state
                alias.unlink()

    def test_existing_shared_corruption_is_not_trusted_and_pending_can_resume(self):
        with self.archive() as archive:
            row = self.service.objects.db.execute('SELECT hash,data FROM chunk LIMIT 1').fetchone()
            self.service.objects.db.execute('UPDATE chunk SET data=? WHERE hash=?', (b'broken', row[0]))
            self.service.objects.db.commit()
            with self.assertRaises((ValueError, zlib_error())):
                import_asset_union(archive, self.service, self.retained, 'old')
            self.assertEqual('pending', archive._db.execute('SELECT status FROM next_union_asset_receipt').fetchone()[0])
            self.service.objects.db.execute('UPDATE chunk SET data=? WHERE hash=?', (row[1], row[0]))
            self.service.objects.db.commit()
            result = import_asset_union(archive, self.service, self.retained, 'old')
            self.assertTrue(result['resumed_pending'])
            self.assertTrue(verify_union_assets(archive, self.service)['closure_complete'])

    def test_target_chunk_collision_rolls_back_new_file_and_keeps_pending(self):
        with self.archive() as archive:
            with closing(sqlite3.connect(self.retained)) as source:
                key, size, payload = source.execute('SELECT hash,bytes,data FROM chunk LIMIT 1').fetchone()
            self.service.objects.db.execute('INSERT INTO chunk VALUES(?,?,?)', (key, size, b'not-zlib'))
            self.service.objects.db.commit()
            with self.assertRaises((ValueError, zlib_error())):
                import_asset_union(archive, self.service, self.retained, 'old')
            self.assertFalse(self.service.objects.db.execute('SELECT 1 FROM file WHERE hash=?',
                (self.missing_info['sha256'],)).fetchone())

    def test_pin_and_identity_corruption_fail_closed_and_shallow_summary_is_explicit(self):
        with self.archive() as archive:
            import_asset_union(archive, self.service, self.retained, 'old')
            summary = verify_union_assets(archive, self.service, deep=False)
            self.assertFalse(summary['closure_complete'])
            self.assertEqual(0, summary['deep_verified'])
            self.service.catalog.db.execute('DELETE FROM external_asset_ref WHERE file_sha=?', (self.shared_info['sha256'],))
            self.service.catalog.db.commit()
            with self.assertRaisesRegex(ValueError, 'pin missing'):
                verify_union_assets(archive, self.service)
            import_asset_union(archive, self.service, self.retained, 'old')
            self.service.catalog.db.execute("UPDATE meta SET value='other-instance' WHERE key='next_catalog_instance'")
            self.service.catalog.db.commit()
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                verify_union_assets(archive, self.service)

    def test_shared_hyphenated_union_uuid_and_offline_verify_is_readonly(self):
        import uuid
        with self.archive() as archive:
            identity = str(uuid.uuid4())
            archive._db.execute("INSERT INTO archive_meta VALUES('next_union_id',?)", (identity,))
            result = import_asset_union(archive, self.service, self.retained, 'old')
            self.assertEqual(identity, result['owner_id'])
            expected = verify_union_assets(archive, self.service)
            target = archive.path
        with CompactArchive(target, readonly=True) as archive:
            before = Path(target).read_bytes()
            self.assertEqual(expected, verify_union_assets(archive, self.service))
            self.assertEqual(before, Path(target).read_bytes())

    def test_real_os_exit_three_database_commit_windows(self):
        stages = ('after_pending_commit', 'after_object_commit', 'after_pins_commit', 'before_union_commit')
        self.service.close()
        # Each crash case has independent target state and metadata; retained is
        # the same immutable synthetic source and is never opened by Objects.
        try:
            for stage in stages:
                with self.subTest(stage=stage):
                    state = self.root/('state-' + stage); state.mkdir()
                    with closing(sqlite3.connect(state/'catalog.sqlite')) as db:
                        db.execute('CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
                        db.execute("INSERT INTO meta VALUES('next_catalog_instance','synthetic-instance')")
                        db.commit()
                    service = OfflineService(state)
                    service.objects.add(self.shared)
                    service.close()
                    union = self.root/('union-' + stage); union.mkdir()
                    target = union/'archive.wua.sqlite'
                    with CompactArchive(target, create=True):
                        pass
                    code = '''import os,sys
from wechat_capture_next.tests.test_union_assets import OfflineService
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.union_assets import import_asset_union
service=OfflineService(sys.argv[1])
with CompactArchive(sys.argv[2]) as archive:
 def fault(stage):
  if stage==sys.argv[4]: os._exit(79)
 import_asset_union(archive,service,sys.argv[3],'crash',fault=fault)
'''
                    child = subprocess.run([sys.executable, '-c', code, str(state), str(target), str(self.retained), stage],
                                           capture_output=True, text=True, timeout=30)
                    self.assertEqual(79, child.returncode, child.stderr)
                    with closing(OfflineService(state)) as service, CompactArchive(target) as archive:
                        receipt = archive._db.execute('SELECT status FROM next_union_asset_receipt').fetchone()
                        self.assertEqual('pending', receipt[0])
                        result = import_asset_union(archive, service, self.retained, 'crash')
                        self.assertTrue(result['resumed_pending'])
                        self.assertTrue(verify_union_assets(archive, service)['closure_complete'])
                        self.assertEqual(2, service.objects.db.execute('SELECT count(*) FROM file').fetchone()[0])
                        again = import_asset_union(archive, service, self.retained, 'crash')
                        self.assertTrue(again['replay'])
            self.assertEqual(self.original, self.retained.read_bytes())
        finally:
            self.service = OfflineService(self.state)


def zlib_error():
    import zlib
    return zlib.error


if __name__ == '__main__':
    unittest.main()
