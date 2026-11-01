from copy import deepcopy
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tests.test_wua_store import observation
from wua.store import ArchiveStore, _json
from wechat_capture_next.compact_archive import CompactArchive, OBSERVATION_COLUMNS, connect_archive
from wechat_capture_next.content_pool import render_text


def import_rows(archive, snapshot, rows, source='device'):
    return archive.import_observations({'source_id': source},
        {'source_id': source, 'snapshot_id': snapshot}, rows)


class CompactArchiveTests(unittest.TestCase):
    def test_locator_revision_lookup_uses_physical_index_and_linear_decode_work(self):
        with CompactArchive(':memory:') as archive:
            count = 100
            locator_calls = []
            def render(*args):
                value = render_text(*args)
                if value in {str(i) for i in range(count)}:
                    locator_calls.append(value)
                return value
            archive._db.create_function('next_content_render', 4, render)
            rows = [observation(native_locator=i, server_id=i + 1000) for i in range(count)]
            import_rows(archive, 'snapshot', rows)
            self.assertLessEqual(len(locator_calls), count * 2)
            locator_calls.clear()
            before = archive._db.total_changes
            import_rows(archive, 'snapshot', rows)
            self.assertEqual(before, archive._db.total_changes)
            self.assertLessEqual(len(locator_calls), count * 2)
            plan = ' '.join(str(tuple(row)) for row in archive._db.execute('''EXPLAIN QUERY PLAN
                SELECT 1 FROM observation_record WHERE snapshot_id=? AND db_relative_path=?
                AND table_name=? AND native_locator_json=? LIMIT 1''', ('snapshot', 'x', 'x', 1)))
            self.assertIn('observation_locator', plan)
            self.assertIn('native_locator_json=?', plan)

    def test_integrity_authenticates_unique_payload_then_all_raw_bindings(self):
        with CompactArchive(':memory:') as archive:
            raw = {'shared': 'exact raw payload'}
            import_rows(archive, 'snapshot', [observation(native_locator=i, raw_record=raw)
                                              for i in range(10)])
            raw_id = archive._db.execute('SELECT raw_record_json FROM observation_record LIMIT 1').fetchone()[0]
            calls = []
            original = archive.pool._read
            def read(identity, *args):
                calls.append(identity)
                return original(identity, *args)
            archive.pool._read = read
            result = archive.integrity_check()
            self.assertEqual(10, result['raw_observations_verified'])
            self.assertEqual(1, calls.count(raw_id))
            self.assertEqual(archive._db.execute('SELECT count(*) FROM content_payload').fetchone()[0], len(calls))
            archive._db.execute('DROP TRIGGER observation_record_no_update')
            archive._db.execute("UPDATE observation_record SET row_hash='tampered' WHERE observation_id=(SELECT observation_id FROM observation_record LIMIT 1)")
            with self.assertRaisesRegex(ValueError, 'binding mismatch'):
                archive.integrity_check()
        with CompactArchive(':memory:') as archive:
            import_rows(archive, 'snapshot', [observation(raw_record={'unique': 'raw'})])
            archive._db.execute('PRAGMA foreign_keys=OFF')
            archive._db.execute('DROP TRIGGER content_payload_no_delete')
            archive._db.execute('DELETE FROM content_payload WHERE id=(SELECT raw_record_json FROM observation_record LIMIT 1)')
            self.assertTrue(list(archive._db.execute('PRAGMA foreign_key_check')))
            with self.assertRaisesRegex(ValueError, 'binding mismatch'):
                archive.integrity_check()

    def test_memory_connection_enforces_readonly_uri_attach(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root)/'source.sqlite'
            with closing(sqlite3.connect(source)) as db:
                db.execute('CREATE TABLE protected(value TEXT)')
                db.execute("INSERT INTO protected VALUES('source')")
                db.commit()
            original = source.read_bytes()
            with closing(connect_archive(':memory:')) as db:
                db.execute('ATTACH DATABASE ? AS input_source', (source.as_uri()+'?mode=ro',))
                self.assertEqual('source', db.execute('SELECT value FROM input_source.protected').fetchone()[0])
                with self.assertRaises(sqlite3.OperationalError):
                    db.execute("INSERT INTO input_source.protected VALUES('unauthorized')")
            self.assertEqual(original, source.read_bytes())

    def test_no_fts_and_revision_counts_keep_frozen_semantics(self):
        with ArchiveStore(':memory:') as old, CompactArchive(':memory:', fts=False) as new:
            for archive in (old, new):
                import_rows(archive, 'snapshot', [observation(raw_record={'value': 1}, body_text='original')])
            results = []
            for archive in (old, new):
                results.append(import_rows(archive, 'snapshot',
                    [observation(raw_record={'value': 2}, body_text='revised searchable')]))
            self.assertEqual(results[0], results[1])
            self.assertEqual(old.semantic_digest(), new.semantic_digest())
            self.assertFalse(new.fts_enabled)
            self.assertEqual(old.list_messages(search='searchable'), new.list_messages(search='searchable'))

    def test_stats_do_not_read_compatibility_views_or_decode_content(self):
        with CompactArchive(':memory:') as archive:
            import_rows(archive, 'snapshot', [observation(body_text='large' * 1000)])
            expected = archive.stats()
            queries = []
            archive._db.set_trace_callback(queries.append)
            archive._db.create_function('next_content_render', 4,
                lambda *args: (_ for _ in ()).throw(AssertionError('stats decoded content')))
            self.assertEqual(expected, archive.stats())
            self.assertTrue(any('observation_record' in query for query in queries))
            self.assertFalse(any('message_observation' in query or 'logical_message' in query for query in queries))

    def test_frozen_semantics_search_conflicts_types_and_exact_replay(self):
        body = '保留正文"\\\n🙂' * 200
        rows = [observation(native_locator=1, body_text=body,
                    raw_record={'body': body, 'binary': bytes(range(256)), 'unknown': [None, False, 3, 2.5]},
                    unknown_extension={'number': 42, 'string': '42', 'nil': None}),
                observation(native_locator=2, body_text='conflicting searchable original')]
        with ArchiveStore(':memory:') as old, CompactArchive(':memory:') as new:
            for archive in (old, new):
                import_rows(archive, 'first', rows)
                import_rows(archive, 'second', [observation(native_locator=3, server_id=500,
                    body_text='candidate body', event_time=100), observation(native_locator=4,
                    server_id=None, body_text='candidate body', event_time=100)])
            self.assertEqual(old.semantic_digest(), new.semantic_digest())
            self.assertEqual(old.stats(), new.stats())
            for search in (None, 'searchable', '正文', '%', '_', 'candidate body', '不存在'):
                self.assertEqual(old.list_messages(search=search), new.list_messages(search=search))
            for row in old.list_messages():
                self.assertEqual(old.get_observations(row['logical_id']), new.get_observations(row['logical_id']))
            self.assertEqual(old.coverage(), new.coverage())
            before = new._db.total_changes
            self.assertEqual(0, import_rows(new, 'first', rows)['added_observations'])
            self.assertEqual(before, new._db.total_changes)
            self.assertEqual([], new.new_observation_ids)
            self.assertGreater(new.storage_stats()['canonical_json_recipes'], 0)
            self.assertEqual(['ok'], new.integrity_check()['quick_check'])

    def test_union_two_legacy_origins_and_reimport_is_zero_write(self):
        with ArchiveStore(':memory:') as pc, ArchiveStore(':memory:') as current, CompactArchive(':memory:') as target:
            import_rows(pc, 'pc-snapshot', [observation(native_locator=1)], 'pc')
            import_rows(current, 'current-snapshot', [observation(native_locator=1),
                observation(native_locator=2, server_id=2, body_text='unique current')], 'current')
            target.import_legacy_rows(pc._db, {'origin_id': 'old-pc', 'kind': 'legacy'})
            target.import_legacy_rows(current._db, {'origin_id': 'current', 'kind': 'legacy'})
            self.assertEqual(3, target.stats()['observations'])
            self.assertEqual(2, target.stats()['logical_messages'])
            self.assertEqual(2, target.stats()['sources'])
            body_id = target._db.execute('SELECT body_text FROM observation_record WHERE observation_id=?',
                (pc._db.execute('SELECT observation_id FROM message_observation').fetchone()[0],)).fetchone()[0]
            self.assertEqual(2, target._db.execute('SELECT count(*) FROM observation_record WHERE body_text=?', (body_id,)).fetchone()[0])
            before = target._db.total_changes
            target.import_legacy_rows(pc._db, {'origin_id': 'old-pc', 'kind': 'legacy'})
            target.import_legacy_rows(current._db, {'origin_id': 'current', 'kind': 'legacy'})
            self.assertEqual(before, target._db.total_changes)
            self.assertEqual(3, target._db.execute('SELECT count(*) FROM next_import_member').fetchone()[0])

    def test_legacy_noncanonical_literal_json_is_not_reprepared(self):
        with ArchiveStore(':memory:') as source, CompactArchive(':memory:') as target:
            import_rows(source, 'snapshot', [observation()])
            fixture = sqlite3.connect(':memory:')
            try:
                for table in ('archive_meta', 'source_device', 'source_snapshot', 'message_observation'):
                    columns = [r[1] for r in source._db.execute(f'PRAGMA table_info({table})')]
                    fixture.execute(f'CREATE TABLE {table}(' + ','.join(columns) + ')')
                    fixture.executemany(f'INSERT INTO {table} VALUES(' + ','.join('?' for _ in columns) + ')',
                                         (tuple(r) for r in source._db.execute(f'SELECT * FROM {table}')))
                raw = '{ "x": 1.00, "x": 2, "未知": [true, null, "\\u4f60"] }'
                normalized = fixture.execute('SELECT normalized_json FROM message_observation').fetchone()[0]
                normalized = ' ' + normalized + '\n'
                fixture.execute('UPDATE message_observation SET raw_record_json=?,row_hash=?,normalized_json=?',
                                 (raw, hashlib.sha256(raw.encode()).hexdigest(), normalized))
                target.import_legacy_rows(fixture, 'literal-origin')
                output = target._db.execute('SELECT raw_record_json,normalized_json FROM message_observation').fetchone()
                self.assertEqual((raw, normalized), tuple(output))
            finally:
                fixture.close()

    def test_immutable_interpretation_collision_and_fts_failure_roll_back(self):
        with CompactArchive(':memory:') as archive:
            import_rows(archive, 'one', [observation(body_text='first body')])
            before = archive.semantic_digest(), archive.storage_stats()
            prepared = dict(archive._db.execute('SELECT * FROM message_observation').fetchone())
            prepared['normalized_json'] = ' ' + prepared['normalized_json']
            with self.assertRaises(ValueError), archive.transaction():
                archive.insert_prepared(prepared)
            self.assertEqual(before, (archive.semantic_digest(), archive.storage_stats()))
            if archive.fts_enabled:
                archive._db.set_authorizer(lambda action, a, b, database, caller:
                    sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT and a == 'message_fts' else sqlite3.SQLITE_OK)
                with self.assertRaises(sqlite3.DatabaseError):
                    import_rows(archive, 'two', [observation(native_locator=2, body_text='new second body')])
                archive._db.set_authorizer(None)
                self.assertEqual(before, (archive.semantic_digest(), archive.storage_stats()))
                self.assertEqual([], archive.new_observation_ids)

    def test_unique_body_external_fts_and_representative_reference(self):
        with CompactArchive(':memory:') as archive:
            import_rows(archive, 'one', [observation(native_locator=1, server_id=1, body_text='shared body'),
                observation(native_locator=2, server_id=2, body_text='shared body')])
            self.assertEqual(1, archive.storage_stats()['unique_bodies'])
            columns = [row[1] for row in archive._db.execute('PRAGMA table_info(logical_record)')]
            self.assertNotIn('body_text', columns)
            if archive.fts_enabled:
                self.assertEqual(1, archive._db.execute('SELECT count(*) FROM message_fts').fetchone()[0])
                self.assertEqual(2, len(archive.list_messages(search='shared')))
                names = {r[0] for r in archive._db.execute('SELECT name FROM sqlite_master')}
                self.assertNotIn('message_fts_content', names)
                archive._db.execute("INSERT INTO message_fts(message_fts,rank) VALUES('integrity-check',1)")
                body_id = archive._db.execute('SELECT id FROM body_record').fetchone()[0]
                archive._db.execute('DELETE FROM message_fts WHERE rowid=?', (body_id,))
                self.assertEqual([], archive.list_messages(search='shared'))
                with self.assertRaises(sqlite3.DatabaseError):
                    archive.integrity_check()
                self.assertTrue(archive.rebuild_logical()['search_index_repaired'])
                self.assertEqual(2, len(archive.list_messages(search='shared')))

    def test_readonly_reopen_no_implicit_migration_and_full_repair(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'archive.sqlite'
            with CompactArchive(path, create=True) as archive:
                import_rows(archive, 'one', [observation(body_text='searchable body')])
                digest = archive.semantic_digest()
                archive._db.execute('DELETE FROM next_merge_projection')
                self.assertFalse(archive.rebuild_logical()['rebuild_changed'])
                self.assertEqual(1, archive._db.execute('SELECT count(*) FROM next_merge_projection').fetchone()[0])
                before_check = path.read_bytes()
                self.assertEqual(archive.fts_enabled, archive.integrity_check()['fts_verified'])
                self.assertEqual(before_check, path.read_bytes())
            with CompactArchive(path, readonly=True) as archive:
                self.assertEqual(digest, archive.semantic_digest())
                self.assertEqual(1, len(archive.list_messages(search='searchable')))
                self.assertFalse(archive.integrity_check()['fts_verified'])
                self.assertEqual('not_verified_readonly', archive.integrity_check()['fts_status'])
                with self.assertRaises(PermissionError):
                    archive.rebuild_logical()
            with self.assertRaises(ValueError):
                ArchiveStore(path, readonly=True)
            legacy = Path(root)/'legacy.sqlite'
            with ArchiveStore(legacy):
                pass
            before = legacy.read_bytes()
            with self.assertRaises(ValueError):
                CompactArchive(legacy, create=True)
            self.assertEqual(before, legacy.read_bytes())


if __name__ == '__main__':
    unittest.main()
