"""Independent synthetic import/rollback review; never opens production paths."""
from contextlib import closing
import hashlib
import json
import os
import sqlite3
import unittest
from unittest.mock import patch

from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.exports import export_wua
from wechat_capture_next import union_archive as union
from wechat_capture_next.tests import test_service as fixtures
from wechat_capture_v2.common import canonical
from wechat_capture_v2.tests.test_backend import TABLE


class IndependentUnionTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    tearDown = fixtures.ServiceTests.tearDown
    pages = fixtures.ServiceTests.pages
    publish = fixtures.ServiceTests.publish
    init_service = fixtures.ServiceTests.init_service

    def test_catalog_delta_all_versions_interpretations_and_regression(self):
        with closing(self.init_service()) as service, CompactArchive(':memory:') as archive:
            service.capture(force=True)
            initial = union.import_catalog(archive, service.state/'catalog.sqlite', origin_id='live')
            self.assertEqual(initial['added_versions'], 40)
            with closing(sqlite3.connect(self.plain)) as db, db:
                db.execute(f'UPDATE "{TABLE}" SET message_content=? WHERE local_id=1', ('revision',))
                db.execute(f'INSERT INTO "{TABLE}" VALUES(-99,777,1,7,1,?,NULL,NULL,-999)', ('old backlog',))
            self.publish()
            service.capture(force=True)
            with service.catalog.db:
                version = service.catalog.db.execute(
                    'SELECT id,normalized_json,first_capture FROM version ORDER BY id LIMIT 1').fetchone()
                normalized = json.loads(version['normalized_json'])
                normalized['body_text'] = 'independent revised interpretation'
                literal = canonical(normalized)
                service.catalog.db.execute('''INSERT INTO db_capture SELECT 'independent-interpretation',cycle_id,
                    source_id,relative_path,signature,evidence_json,message_count,accepted
                    FROM db_capture WHERE id=?''', (version['first_capture'],))
                service.catalog.db.execute('INSERT INTO interpretation VALUES(?,?,?,?)',
                    (version['id'], hashlib.sha256(literal.encode()).hexdigest(), literal, 'independent-interpretation'))
            with patch.object(archive, '_desired_state', side_effect=AssertionError('delta must not full rebuild')):
                added = union.import_catalog(archive, service.state/'catalog.sqlite', origin_id='live')
            self.assertEqual((added['added_versions'], added['added_interpretations']), (2, 1))
            self.assertEqual(archive.semantic_digest(), export_wua(service, self.root/'fresh.sqlite')['semantic_digest'])
            before = archive.semantic_digest()
            archive._db.execute("INSERT INTO next_union_version VALUES('live','absent-from-source')")
            with self.assertRaisesRegex(ValueError, 'regressed'):
                union.import_catalog(archive, service.state/'catalog.sqlite', origin_id='live')
            self.assertEqual(before, archive.semantic_digest())
            self.assertNotIn('union_catalog', [r[1] for r in archive._db.execute('PRAGMA database_list')])

    def test_failure_after_delta_rolls_back_everything_closes_attachment_and_retries(self):
        with closing(self.init_service()) as service, CompactArchive(':memory:') as archive:
            service.capture(force=True)
            before = archive.semantic_digest()
            actual = union.rebuild_delta

            def fail(*args, **kwargs):
                actual(*args, **kwargs)
                raise RuntimeError('independent failure after derived writes')

            with patch.object(union, 'rebuild_delta', side_effect=fail):
                with self.assertRaisesRegex(RuntimeError, 'independent failure'):
                    union.import_catalog(archive, service.state/'catalog.sqlite', origin_id='live')
            self.assertEqual(before, archive.semantic_digest())
            self.assertEqual(archive.new_observation_ids, [])
            self.assertEqual(archive._db.execute('SELECT count(*) FROM next_merge_projection').fetchone()[0], 0)
            self.assertEqual(archive._db.execute('SELECT count(*) FROM content_payload').fetchone()[0], 0)
            self.assertNotIn('union_catalog', [r[1] for r in archive._db.execute('PRAGMA database_list')])
            self.assertEqual(union.import_catalog(archive, service.state/'catalog.sqlite', origin_id='live')['added_versions'], 40)

    def test_frozen_archive_failure_has_no_receipt_or_partial_data_and_replay_is_exact(self):
        with closing(self.init_service()) as service, CompactArchive(':memory:') as archive:
            service.capture(force=True)
            source = self.root/'frozen-input.sqlite'
            expected = export_wua(service, source)['semantic_digest']
            source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
            before = archive.semantic_digest()
            actual = archive.insert_prepared

            def fail(*args, **kwargs):
                actual(*args, **kwargs)
                raise RuntimeError('independent interrupted input')

            with patch.object(archive, 'insert_prepared', side_effect=fail):
                with self.assertRaisesRegex(RuntimeError, 'independent interrupted'):
                    union.import_archive(archive, source, origin_id='frozen')
            self.assertEqual(before, archive.semantic_digest())
            self.assertEqual(archive.new_observation_ids, [])
            self.assertIsNone(archive._db.execute(
                "SELECT name FROM sqlite_master WHERE name='next_union_artifact'").fetchone())
            result = union.import_archive(archive, source, origin_id='frozen')
            self.assertEqual(result['raw_rows_decoded'], 40)
            self.assertEqual(archive.semantic_digest(), expected)
            with patch.object(archive, 'import_legacy_rows', side_effect=AssertionError('receipt must skip decoding')):
                replay = union.import_archive(archive, source, origin_id='frozen')
            self.assertEqual(replay['raw_rows_decoded'], 0)
            self.assertEqual(source_sha, hashlib.sha256(source.read_bytes()).hexdigest())

    def test_frozen_wal_mode_archive_never_creates_source_sidecars(self):
        with closing(self.init_service()) as service, CompactArchive(':memory:') as archive:
            service.capture(force=True)
            source = self.root/'wal-mode-input.sqlite'
            expected = export_wua(service, source)['semantic_digest']
            with closing(sqlite3.connect(source)) as db:
                self.assertEqual(db.execute('PRAGMA journal_mode=WAL').fetchone()[0], 'wal')
            before = sorted(path.name for path in source.parent.iterdir())
            self.assertFalse(source.with_name(source.name+'-wal').exists())
            source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
            union.import_archive(archive, source, origin_id='cold-wal')
            self.assertEqual(expected, archive.semantic_digest())
            self.assertEqual(source_sha, hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(before, sorted(path.name for path in source.parent.iterdir()))

    def test_catalog_rejects_invalid_origins_before_opening_source(self):
        with CompactArchive(':memory:') as archive:
            for origin in (None, '', 'x'*201, False, 123):
                with self.subTest(origin_type=type(origin).__name__):
                    with self.assertRaisesRegex(ValueError, 'stable import origin'):
                        union.import_catalog(archive, self.root/'absent.sqlite', origin_id=origin)

    def test_requested_deep_verification_failure_is_still_transactional(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            source = self.root/'verify-input.sqlite'
            export_wua(service, source)
            for kind in ('archive', 'catalog'):
                with self.subTest(kind=kind), CompactArchive(':memory:') as archive:
                    before = archive.semantic_digest()
                    with patch.object(archive, 'integrity_check', side_effect=ValueError('independent verify failure')):
                        with self.assertRaisesRegex(ValueError, 'independent verify failure'):
                            if kind == 'archive':
                                union.import_archive(archive, source, origin_id='frozen', verify=True)
                            else:
                                union.import_catalog(archive, service.state/'catalog.sqlite', origin_id='live', verify=True)
                    self.assertEqual(before, archive.semantic_digest())
                    self.assertEqual(archive.new_observation_ids, [])
                    self.assertNotIn('union_catalog', [r[1] for r in archive._db.execute('PRAGMA database_list')])

    def test_formal_sync_can_reopen_its_own_lock_and_replay(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            target = self.root/'formal-independent'
            first = union.sync_union(service, target, verify=True)
            before = hashlib.sha256((target/'archive.wua.sqlite').read_bytes()).hexdigest()
            second = union.sync_union(service, target, verify=True)
            self.assertEqual(first['semantic_digest'], second['semantic_digest'])
            self.assertEqual(second['current']['added_versions'], 0)
            self.assertEqual(before, hashlib.sha256((target/'archive.wua.sqlite').read_bytes()).hexdigest())

    @unittest.skipUnless(os.name == 'nt', 'Windows sharing policy')
    def test_cold_guard_refuses_existing_writer_and_live_sidecars(self):
        source = self.root/'cold-guard.sqlite'
        with closing(sqlite3.connect(source)) as db:
            db.execute('CREATE TABLE sample(value)')
            db.commit()
        with source.open('r+b'):
            with self.assertRaises(OSError):
                with union.cold_input(source):
                    self.fail('existing write handle was not excluded')
        with union.cold_input(source):
            with closing(sqlite3.connect(source.as_uri()+'?mode=ro', uri=True)) as db:
                db.execute('BEGIN')
                self.assertEqual(db.execute('SELECT count(*) FROM sample').fetchone()[0], 0)
        journal = source.with_name(source.name+'-journal')
        journal.write_bytes(b'synthetic nonempty journal')
        with self.assertRaisesRegex(ValueError, 'cold'):
            with union.cold_input(source):
                self.fail('live journal was ignored')


if __name__ == '__main__':
    unittest.main()
