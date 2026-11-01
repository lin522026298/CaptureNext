"""Independent synthetic closure probes. Run this module explicitly.

No imported TestCase classes, configured state, live source, or real archive.
"""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch
import zipfile
import zlib

from wechat_capture_next.tests import test_service as synthetic_fixtures
from wechat_capture_next.tests import test_union_id_first as id_fixtures
from wechat_capture_next.tests import test_union_delivery as delivery_fixtures
from wechat_capture_next import union_delivery
from wechat_capture_next import backup as state_backup
from wechat_capture_next import union_backup
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.union_archive import sync_union, import_catalog
from wechat_capture_next.union_assets import import_asset_union, verify_union_assets
from wechat_capture_next.zip_assets import import_zip_assets, decode_zip_info
from wechat_capture_v2.objects import Objects
from wua.store import _json


class IndependentUnionDelivery(unittest.TestCase):
    setUp = synthetic_fixtures.ServiceTests.setUp
    pages = synthetic_fixtures.ServiceTests.pages
    publish = synthetic_fixtures.ServiceTests.publish
    init_service = synthetic_fixtures.ServiceTests.init_service

    def tearDown(self):
        self.doCleanups()
        synthetic_fixtures.ServiceTests.tearDown(self)

    def prepared(self):
        service = self.init_service()
        self.addCleanup(service.close)
        self.assertEqual(service.capture(force=True)['status'], 'local_complete')
        formal = self.root/'formal'
        sync_union(service, formal)
        return service, formal/'archive.wua.sqlite'

    def retained(self, name, data):
        original = self.root/(name+'.bin')
        original.write_bytes(data)
        path = self.root/(name+'.retained.sqlite')
        with closing(Objects(path)) as source:
            info = source.add(original)
            source.db.execute('''CREATE TABLE asset(source_id TEXT,relative_path TEXT,
                file_sha TEXT,bytes INTEGER,stamp_json TEXT,cycle_id TEXT)''')
            source.db.execute('''CREATE TABLE asset_history(source_id TEXT,relative_path TEXT,
                file_sha TEXT,bytes INTEGER,cycle_id TEXT)''')
            source.db.execute('INSERT INTO asset VALUES(?,?,?,?,?,?)',
                (name, name+'.bin', info['sha256'], info['bytes'], '{}', 'retained-cycle'))
            source.db.execute('INSERT INTO asset_history VALUES(?,?,?,?,?)',
                (name, name+'.bin', info['sha256'], info['bytes'], 'retained-cycle'))
            source.db.commit()
        return path, info

    def offline(self, state):
        handles = []
        for name in ('catalog.sqlite', 'objects.sqlite'):
            path = state/name
            db = sqlite3.connect(path)
            db.row_factory = sqlite3.Row
            self.addCleanup(db.close)
            handles.append(SimpleNamespace(path=path, db=db))
        return SimpleNamespace(state=state, catalog=handles[0], objects=handles[1])

    @unittest.skipUnless(os.name == 'nt', 'Windows mandatory sharing guard')
    def test_cold_guard_closes_after_initial_metadata_failure(self):
        path = self.root/'metadata-fault.sqlite'
        path.write_bytes(b'synthetic guard resource probe')
        # A child bounds any leaked mandatory OS handle to the child lifetime;
        # the review runner and its fixture cleanup never inherit that handle.
        code = '''
import json
from pathlib import Path
import sys
from unittest.mock import patch
from wechat_capture_next.union_archive import cold_input
path = Path(sys.argv[1])
with patch('wechat_capture_next.union_archive.stamp', side_effect=RuntimeError('synthetic metadata fault')):
    try:
        with cold_input(path):
            raise AssertionError('metadata failure must precede entry')
    except RuntimeError as error:
        assert str(error) == 'synthetic metadata fault'
blocked = False
try:
    with path.open('r+b'):
        pass
except PermissionError:
    blocked = True
print(json.dumps({'writer_blocked_after_failed_entry': blocked}))
'''
        child = subprocess.run([sys.executable, '-c', code, str(path)],
            capture_output=True, text=True, check=True, timeout=30)
        self.assertFalse(json.loads(child.stdout)['writer_blocked_after_failed_entry'],
            'failed context entry leaked a mandatory sharing handle until process exit')

    def test_filtered_asset_verification_cannot_certify_whole_union_with_pending_missing_origin(self):
        service, target = self.prepared()
        retained_a, info_a = self.retained('origin-A', b'closed A attachment')
        retained_b, info_b = self.retained('origin-B', b'pending B attachment not in companion')
        with CompactArchive(target) as archive:
            import_asset_union(archive, service, retained_a, 'A')

            def stop(stage):
                if stage == 'after_pending_commit':
                    raise RuntimeError('synthetic B cut before CAS publication')

            with self.assertRaisesRegex(RuntimeError, 'before CAS'):
                import_asset_union(archive, service, retained_b, 'B', fault=stop)
            self.assertIsNone(service.objects.db.execute('SELECT 1 FROM file WHERE hash=?',
                (info_b['sha256'],)).fetchone())
            with self.assertRaisesRegex(ValueError, 'pending'):
                verify_union_assets(archive, service)
            subset = verify_union_assets(archive, service, origin_id='A')
        state_repo = self.root/'state-repository'
        state_id = state_backup.backup(service, state_repo)['snapshot_id']
        union_repo = self.root/'union-repository'
        # Correct behavior may refuse the subset at snapshot binding time.
        try:
            snapshot = union_backup.backup_archive(target, state_repo, state_id, union_repo,
                state_catalog=service.state/'catalog.sqlite', state_objects=service.state/'objects.sqlite',
                asset_binding=subset)
        except ValueError as error:
            self.assertRegex(str(error), 'whole.union.*scope|scope.*whole|subset')
            return
        offline_state = self.root/'offline-state'
        state_backup.restore(state_repo, state_id, offline_state)
        restored = self.root/'restored-union'
        # Or restoration may refuse a subset verifier for a whole-union claim.
        try:
            result = union_backup.restore_archive(union_repo, snapshot['snapshot_id'], restored,
                offline_state=self.offline(offline_state),
                asset_verifier=lambda archive, state: verify_union_assets(archive, state, origin_id='A'))
        except ValueError as error:
            self.assertRegex(str(error), 'whole.union.*scope|scope.*whole|subset')
            return
        self.assertFalse(result['attachments_closed'],
            'A-only verification certified a whole union containing pending B and missing B bytes')

    def test_unreceipted_asset_observation_cannot_pass_whole_union_provenance_verification(self):
        service, target = self.prepared()
        retained, info = self.retained('origin-A', b'published bytes with one real receipt')
        with CompactArchive(target) as archive:
            import_asset_union(archive, service, retained, 'A')
            row = dict(archive._db.execute('SELECT * FROM next_union_asset_observation LIMIT 1').fetchone())
            # Simulate a coherent lost/omitted membership relation: payload and
            # file bytes remain valid; only the artifact provenance is absent.
            row['origin_id'] = 'unreceipted-origin'
            row['observation_id'] = 'asset_'+hashlib.sha256(_json([
                row['origin_id'], row['source_table'], row['row_key'], row['row_sha']]).encode()).hexdigest()
            with archive.transaction():
                archive._db.execute('INSERT INTO next_union_asset_observation VALUES(?,?,?,?,?,?,?,?,?,?)',
                                    tuple(row.values()))
            self.assertEqual(list(archive._db.execute('PRAGMA foreign_key_check')), [])
            with self.assertRaises(ValueError):
                verify_union_assets(archive, service)

    def test_receipt_coverage_check_does_not_scan_all_origin_members_for_each_observation(self):
        service, _ = self.prepared()
        instructions = []
        for count in (100, 200):
            source, _ = self.retained('vm-'+str(count), b'one object shared by many metadata rows')
            with closing(sqlite3.connect(source)) as db:
                for number in range(1, count):
                    db.execute('''INSERT INTO asset SELECT source_id,?,file_sha,bytes,stamp_json,cycle_id
                        FROM asset LIMIT 1''', ('path-'+str(number),))
                    db.execute('''INSERT INTO asset_history SELECT source_id,?,file_sha,bytes,cycle_id
                        FROM asset_history LIMIT 1''', ('path-'+str(number),))
                db.commit()
            root = self.root/('vm-union-'+str(count))
            root.mkdir()
            with CompactArchive(root/'archive.wua.sqlite', create=True) as archive:
                import_asset_union(archive, service, source, 'A')
                ticks = [0]

                def progress():
                    ticks[0] += 1
                    return 0

                archive._db.set_progress_handler(progress, 100)
                try:
                    result = verify_union_assets(archive, service)
                finally:
                    archive._db.set_progress_handler(None, 0)
                self.assertTrue(result['closure_complete'])
                instructions.append(ticks[0]*100)
        self.assertLess(instructions[1], 3*instructions[0],
            f'doubling metadata caused quadratic verification VM work: {instructions}')

    def test_two_actual_origins_roundtrip_closes_real_bytes_and_preserves_current_provenance(self):
        service, target = self.prepared()
        current = tuple(service.catalog.db.execute('SELECT count(*) FROM asset').fetchone())
        history = tuple(service.catalog.db.execute('SELECT count(*) FROM asset_history').fetchone())
        data = {'A': b'synthetic A bytes', 'B': b'synthetic B bytes' * 10000}
        identities = {}
        with CompactArchive(target) as archive:
            for name, raw in data.items():
                retained, info = self.retained('origin-'+name, raw)
                identities[name] = info
                import_asset_union(archive, service, retained, name)
            binding = verify_union_assets(archive, service)
            self.assertTrue(binding['closure_complete'])
            self.assertEqual(binding['references'], 2)
        self.assertEqual(tuple(service.catalog.db.execute('SELECT count(*) FROM asset').fetchone()), current)
        self.assertEqual(tuple(service.catalog.db.execute('SELECT count(*) FROM asset_history').fetchone()), history)
        state_repo, union_repo = self.root/'state-repository', self.root/'union-repository'
        state_id = state_backup.backup(service, state_repo)['snapshot_id']
        snapshot = union_backup.backup_archive(target, state_repo, state_id, union_repo,
            state_catalog=service.state/'catalog.sqlite', state_objects=service.state/'objects.sqlite',
            asset_binding=binding)
        state_output = self.root/'offline-state'
        state_backup.restore(state_repo, state_id, state_output)
        offline = self.offline(state_output)
        result = union_backup.restore_archive(union_repo, snapshot['snapshot_id'], self.root/'offline-union',
            offline_state=offline, asset_verifier=verify_union_assets)
        self.assertTrue(result['attachments_closed'])
        self.assertFalse(result['metadata_only'])
        self.assertFalse(result['attachment_verification']['portable_restore_verified'])
        self.assertEqual(result['attachment_verification']['deep_verified'], 2)
        with closing(sqlite3.connect((state_output/'objects.sqlite').as_uri()+'?mode=ro', uri=True)) as db:
            # The frozen streaming restore algorithm reads the actual restored
            # CAS on a read-only connection, not any source or summary replay.
            for name, info in identities.items():
                destination = self.root/(name+'-raw-readback.bin')
                Objects.restore(SimpleNamespace(db=db), info['sha256'], destination)
                self.assertEqual(destination.read_bytes(), data[name])

    def test_windows_zip_attributes_and_distinct_unicode_names_preserve_actual_bytes(self):
        service = self.init_service()
        self.addCleanup(service.close)
        prefix = 'source_C_xwechat_files/msg/'
        data = {prefix+'照片/封面.JPG': b'first raw Windows media',
                prefix+'照片/封面（二）.jpg': b'second distinct Chinese name',
                prefix+'file/e\u0301.dat': b'decomposed Unicode filename',
                prefix+'file/é.dat': b'precomposed Unicode filename'}
        source = self.root/'windows-source.zip'
        with zipfile.ZipFile(source, 'w') as writer:
            directory = zipfile.ZipInfo(prefix+'照片/')
            directory.create_system, directory.external_attr = 0, 0x10
            writer.writestr(directory, b'')
            for name, payload in data.items():
                info = zipfile.ZipInfo(name)
                info.create_system, info.external_attr = 0, 0x20
                info.compress_type = zipfile.ZIP_DEFLATED
                info.extra, info.comment = b'\xfe\xca\x03\x00raw', b'comment\x00\xff'
                writer.writestr(info, payload)
            writer.writestr('source_C_xwechat_files/db_storage/outside.db', b'excluded explicit scope')
        original = source.read_bytes()
        output = self.root/'windows-metadata.sqlite'
        result = import_zip_assets(service, source, output,
            expected_sha256=hashlib.sha256(original).hexdigest(), source_id='windows-synthetic')
        self.assertEqual(result['members_verified'], len(data))
        self.assertEqual(result['directory_entries'], 1)
        self.assertEqual(result['outside_prefix_file_entries'], 1)
        with closing(sqlite3.connect(output)) as metadata:
            rows = list(metadata.execute('''SELECT relative_path,file_sha,zip_info_json,
                zip_filename_raw,zip_member_ordinal FROM asset ORDER BY zip_member_ordinal'''))
        self.assertEqual([row[0] for row in rows], list(data))
        for name, sha, encoded, raw_name, ordinal in rows:
            decoded_info = decode_zip_info(encoded)
            self.assertEqual(decoded_info['create_system'], 0)
            self.assertEqual(decoded_info['external_attr'], 0x20)
            self.assertEqual(decoded_info['extra'], b'\xfe\xca\x03\x00raw')
            self.assertEqual(decoded_info['comment'], b'comment\x00\xff')
            self.assertEqual(raw_name, name.encode('utf-8'))
            destination = self.root/('readback-'+str(ordinal)+'.raw')
            service.objects.restore(sha, destination)
            self.assertEqual(destination.read_bytes(), data[name])
        self.assertEqual(source.read_bytes(), original)

    def test_unsafe_zip_member_outside_selected_prefix_rejects_before_any_cas_publication(self):
        service = self.init_service()
        self.addCleanup(service.close)
        source = self.root/'unsafe-outside.zip'
        with zipfile.ZipFile(source, 'w') as writer:
            writer.writestr('source_C_xwechat_files/msg/valid.dat', b'would otherwise be publishable')
            writer.writestr('outside/../unsafe.dat', b'not selected, still must fail')
        before = [tuple(row) for row in service.objects.db.execute('SELECT * FROM file')]
        output = self.root/'unsafe-outside.sqlite'
        with self.assertRaisesRegex(ValueError, 'unsafe ZIP'):
            import_zip_assets(service, source, output,
                expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), source_id='synthetic')
        self.assertFalse(output.exists())
        self.assertEqual([tuple(row) for row in service.objects.db.execute('SELECT * FROM file')], before)

    def test_zip_declared_size_cannot_hide_additional_inflated_bytes(self):
        service = self.init_service()
        self.addCleanup(service.close)
        source = self.root/'underdeclared-member.zip'
        content = b'prefix' + b'whole inflated suffix must not silently disappear'
        prefix = content[:6]
        with zipfile.ZipFile(source, 'w', compression=zipfile.ZIP_DEFLATED) as writer:
            writer.writestr('source_C_xwechat_files/msg/underdeclared.dat', content)
        container = bytearray(source.read_bytes())
        local, central = container.index(b'PK\x03\x04'), container.index(b'PK\x01\x02')
        # Both headers consistently lie about the output size and CRC. Python's
        # ZipExtFile normally clamps returned bytes to that size, despite the
        # complete deflate stream containing additional plaintext.
        for offset, crc_field, length_field in ((local, 14, 22), (central, 16, 24)):
            struct.pack_into('<I', container, offset+crc_field, zlib.crc32(prefix))
            struct.pack_into('<I', container, offset+length_field, len(prefix))
        source.write_bytes(container)
        with zipfile.ZipFile(source) as reader:
            self.assertEqual(reader.read(reader.infolist()[0]), prefix)
        output = self.root/'underdeclared-metadata.sqlite'
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            import_zip_assets(service, source, output,
                expected_sha256=hashlib.sha256(container).hexdigest(), source_id='synthetic')
        self.assertFalse(output.exists())

    def test_interpretation_replacement_with_unchanged_counts_and_mtime_still_regresses(self):
        root = self.root/'independent-id-replacement'
        root.mkdir()
        source, target = id_fixtures.fixture(root, count=8, raw_bytes=512)
        before_stamp, target_hash = source.stat(), hashlib.sha256(target.read_bytes()).hexdigest()
        with closing(sqlite3.connect(source)) as db, db:
            before_counts = db.execute('SELECT (SELECT count(*) FROM version),(SELECT count(*) FROM interpretation)').fetchone()
            # A synthetic retained CTAS table has no production immutable
            # triggers; simulate a same-count source substitution, not a writer.
            db.execute('ALTER TABLE interpretation RENAME TO old_interpretation')
            db.execute('CREATE TABLE interpretation AS SELECT * FROM old_interpretation')
            db.execute('DROP TABLE old_interpretation')
            identity, old_hash = db.execute('SELECT version_id,normalization_hash FROM interpretation LIMIT 1').fetchone()
            db.execute('UPDATE interpretation SET normalization_hash=? WHERE version_id=? AND normalization_hash=?',
                ('f'*64, identity, old_hash))
            self.assertEqual(before_counts, db.execute('SELECT (SELECT count(*) FROM version),(SELECT count(*) FROM interpretation)').fetchone())
        os.utime(source, ns=(before_stamp.st_atime_ns, before_stamp.st_mtime_ns))
        with CompactArchive(target) as archive:
            with self.assertRaisesRegex(ValueError, 'regressed'):
                import_catalog(archive, source, origin_id='wide')
            self.assertNotIn('union_catalog', [row[1] for row in archive._db.execute('PRAGMA database_list')])
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), target_hash)


class IndependentDeliveryCLI(unittest.TestCase):
    setUp = synthetic_fixtures.ServiceTests.setUp
    pages = synthetic_fixtures.ServiceTests.pages
    publish = synthetic_fixtures.ServiceTests.publish
    init_service = synthetic_fixtures.ServiceTests.init_service
    prepare_delivery = delivery_fixtures.UnionDeliveryTests.prepared

    def tearDown(self):
        self.doCleanups()
        synthetic_fixtures.ServiceTests.tearDown(self)

    def test_same_catalog_foreign_union_repository_rejected_before_any_receipt_or_state_snapshot(self):
        self.prepare_delivery()
        owner = json.loads((self.formal/'OWNER.private.json').read_text(encoding='utf-8'))
        # A valid empty repository owned by another union of this same catalog
        # is not an invalid directory; catalog-only preflight cannot detect it.
        wrong_owner = dict(schema=union_backup.SCHEMA,
            catalog_instance=owner['catalog_instance'], union_id=str(uuid.uuid4()))
        with union_backup._session(self.union_repo, wrong_owner, create=True):
            pass
        before = {str(path): path.read_bytes() for path in self.union_repo.iterdir() if path.is_file()}
        output = self.root/'foreign-union-preflight'
        with self.assertRaisesRegex(ValueError, 'union|owner|identity|foreign'):
            union_delivery.backup(self.state, self.formal, self.state_repo, self.union_repo, output)
        self.assertFalse(output.exists(), 'foreign union identity was discovered only after writing a delivery receipt')
        self.assertFalse(self.state_repo.exists(), 'foreign union identity was discovered only after publishing state backup')
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.union_repo.iterdir() if path.is_file()})

    def test_offline_cli_never_loads_live_configuration_and_restores_every_exact_manifest_file(self):
        self.prepare_delivery()
        delivery_fixtures.UnionDeliveryTests.take_source_offline(self)
        before_stats = {str(path): path.read_bytes()
            for root in (self.state, self.formal) for path in root.rglob('*') if path.is_file()}
        with (patch.object(union_delivery.CaptureService, '__init__', side_effect=AssertionError('live constructor')),
              patch('wechat_capture_v2.service.load_config', side_effect=AssertionError('live source/key configuration'))):
            status = union_delivery.stats(self.state, self.formal)
            self.assertFalse(status['assets']['closure_complete'])
            self.assertEqual(before_stats, {str(path): path.read_bytes()
                for root in (self.state, self.formal) for path in root.rglob('*') if path.is_file()})
            backed = union_delivery.backup(self.state, self.formal,
                self.state_repo, self.union_repo, self.root/'offline-backup')
            restored = union_delivery.restore(self.state_repo, self.union_repo,
                backed['union_snapshot']['snapshot_id'], self.root/'offline-restored')
        state_manifest = state_backup.inspect_snapshot(self.state_repo, backed['state_snapshot']['snapshot_id'])
        for relative, entry in state_manifest['files'].items():
            expected = hashlib.sha256((self.state/relative).read_bytes()).hexdigest()
            actual = hashlib.sha256((self.root/'offline-restored'/'state'/relative).read_bytes()).hexdigest()
            self.assertEqual(expected, entry['sha256'], relative)
            self.assertEqual(actual, entry['sha256'], relative)
        self.assertTrue(restored['attachments_closed'])
        self.assertFalse(restored['portable_restore_verified'])
        self.assertFalse(self.source.parent.exists())
        self.assertFalse(self.keys.exists())

    def test_busy_union_os_lock_refuses_before_output_and_releases_state_lock(self):
        self.prepare_delivery()
        output = self.root/'busy-union-receipt'
        with union_delivery.writer_lock(self.formal):
            with self.assertRaises((OSError, BlockingIOError)):
                union_delivery.backup(self.state, self.formal, self.state_repo, self.union_repo, output)
        self.assertFalse(output.exists())
        self.assertFalse(self.state_repo.exists())
        self.assertFalse(self.union_repo.exists())
        with union_delivery.writer_lock(self.state):
            pass

    def test_inner_companion_rejects_same_catalog_other_union_without_repository_mutation(self):
        self.prepare_delivery()
        backed = union_delivery.backup(self.state, self.formal,
            self.state_repo, self.union_repo, self.root/'valid-backup')
        other = self.root/'other-union-repo'
        wrong_owner = dict(schema=union_backup.SCHEMA,
            catalog_instance=backed['asset_verification']['catalog_instance'], union_id=str(uuid.uuid4()))
        with union_backup._session(other, wrong_owner, create=True):
            pass
        before = {str(path): path.read_bytes() for root in (other, self.state_repo, self.formal)
                  for path in root.rglob('*') if path.is_file()}
        with self.assertRaisesRegex(ValueError, 'foreign union backup owner'):
            union_backup.backup_archive(self.formal/'archive.wua.sqlite',
                self.state_repo, backed['state_snapshot']['snapshot_id'], other,
                state_catalog=self.state/'catalog.sqlite', state_objects=self.state/'objects.sqlite',
                asset_binding=backed['asset_verification'])
        self.assertEqual(before, {str(path): path.read_bytes() for root in (other, self.state_repo, self.formal)
                                 for path in root.rglob('*') if path.is_file()})

    def test_valid_other_state_formal_identity_mismatch_is_preflight_not_partial_delivery(self):
        self.prepare_delivery()
        from wechat_capture_next.service import initialize, CaptureService
        other_state = self.root/'valid-other-state'
        initialize(other_state, self.source.parent, self.keys,
            source_id='other-fixture', account_alias='fixture', self_username='self')
        with closing(CaptureService(other_state)) as other:
            sync_union(other, self.root/'other-formal')
        output = self.root/'wrong-state-pair'
        with self.assertRaisesRegex(ValueError, 'state/formal union identity mismatch'):
            union_delivery.backup(other_state, self.formal,
                self.state_repo, self.union_repo, output)
        self.assertFalse(output.exists(), 'known wrong state/formal identity created a partial delivery')
        self.assertFalse(self.state_repo.exists())
        self.assertFalse(self.union_repo.exists())


if __name__ == '__main__':
    unittest.main()
