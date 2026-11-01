from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from wechat_capture_next.catalog import Catalog, pack
from wechat_capture_v2.common import canonical


class CatalogTests(unittest.TestCase):
    def test_slots_round_trip_unicode_nested_duplicates_and_fallback(self):
        samples = [canonical({'time': 'same', 'nested': {'time': 'same'}, 'row_scan_reused_from': None,
                              'text': '中文\x1e\\"'}),
                   canonical({'time': [1, None], 'row_scan_reused_from': {'id': 3}}),
                   canonical({'no_slots': True}), '{ "time": "noncanonical", "x": null }', '[]']
        for text in samples:
            template, slots, _ = pack(text)
            values = json.loads(slots)
            from wechat_capture_next.catalog import TIME, REUSE
            self.assertEqual(template.replace(TIME, values.get('t', '')).replace(REUSE, values.get('r', '')), text)

    def test_native_readonly_attach_exact_sha_and_migration_rollback(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work)/'catalog.sqlite'
            with closing(Catalog(path, compact_new=False)) as catalog:
                cycle = catalog.begin_cycle('full')
                text = canonical({'time': 'then', 'reader': {'schema': '原文'}, 'row_scan_reused_from': None})
                with catalog.db:
                    catalog.db.execute('INSERT INTO db_capture VALUES(?,?,?,?,?,?,?,?)', ('capture',cycle,'s','x','sig',text,0,'then'))
                    catalog.db.execute('INSERT INTO checkpoint VALUES(?,?,?,?,?)', ('s','x','capture','sig','{}'))
                with self.assertRaises(RuntimeError):
                    catalog.enable_compact(fault=lambda _: (_ for _ in ()).throw(RuntimeError('crash')))
                self.assertFalse(catalog.compact)
                self.assertEqual(catalog.db.execute('SELECT evidence_json FROM db_capture').fetchone()[0], text)
                catalog.enable_compact()
                self.assertEqual(list(catalog.db.execute('PRAGMA foreign_key_check')), [])
                self.assertEqual(catalog.db.execute('PRAGMA foreign_key_list(checkpoint)').fetchone()[2], 'capture_record')
            with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as external:
                actual = external.execute('SELECT evidence_json FROM db_capture').fetchone()[0]
                self.assertEqual(actual.encode(), text.encode())
                self.assertEqual(hashlib.sha256(actual.encode()).digest(), hashlib.sha256(text.encode()).digest())
            with closing(sqlite3.connect(':memory:', uri=True)) as external:
                external.execute('ATTACH DATABASE ? AS source', (path.as_uri()+'?mode=ro',))
                self.assertEqual(external.execute('SELECT evidence_json FROM source.db_capture').fetchone()[0], text)
            with closing(Catalog(path)) as reopened:
                self.assertTrue(reopened.verify_templates()['compact'])

    def test_repeated_accepts_stable_templates_and_no_intermediate_leak(self):
        with tempfile.TemporaryDirectory() as work, closing(Catalog(Path(work)/'catalog.sqlite')) as catalog:
            cycle = catalog.begin_cycle('full')
            for i in range(1000):
                evidence = {'time': str(i), 'authentication': {'profile': 'fixed', 'pages': 99}}
                with catalog.db:
                    catalog.db.execute('INSERT INTO db_capture VALUES(?,?,?,?,?,?,?,?)',
                        (str(i),cycle,'s','x','sig',canonical(evidence),0,str(i)))
                    evidence['reader'] = {'schema': 'fixed'}
                    catalog.db.execute('UPDATE db_capture SET evidence_json=?,message_count=1 WHERE id=?', (canonical(evidence), str(i)))
            self.assertEqual(catalog.verify_templates()['templates'], 1)
            self.assertEqual(catalog.db.execute('SELECT count(*) FROM db_capture').fetchone()[0], 1000)
            with self.assertRaises(sqlite3.IntegrityError), catalog.db:
                catalog.db.execute('UPDATE evidence_template SET text=?', ('corrupt',))
            self.assertEqual(catalog.db.execute('PRAGMA quick_check').fetchone()[0], 'ok')

    def test_insert_failure_rolls_back_template_and_capture(self):
        with tempfile.TemporaryDirectory() as work, closing(Catalog(Path(work)/'catalog.sqlite')) as catalog:
            cycle = catalog.begin_cycle('full')
            with self.assertRaises(RuntimeError), catalog.db:
                catalog.db.execute('INSERT INTO db_capture VALUES(?,?,?,?,?,?,?,?)',
                    ('x',cycle,'s','x','sig',canonical({'time': 'now', 'reader': {'x': 1}}),0,'now'))
                raise RuntimeError('interrupted before checkpoint')
            self.assertEqual(catalog.verify_templates()['templates'], 0)
            self.assertEqual(catalog.db.execute('SELECT count(*) FROM db_capture').fetchone()[0], 0)

    def test_hash_collision_is_rejected(self):
        with tempfile.TemporaryDirectory() as work, closing(Catalog(Path(work)/'catalog.sqlite')) as catalog:
            cycle = catalog.begin_cycle('full')
            catalog.db.create_function('next_template_sha', 1, lambda _: 'collision')
            with catalog.db:
                catalog.db.execute('INSERT INTO db_capture VALUES(?,?,?,?,?,?,?,?)', ('a',cycle,'s','x','sig','{}',0,'now'))
            with self.assertRaises(sqlite3.IntegrityError), catalog.db:
                catalog.db.execute('INSERT INTO db_capture VALUES(?,?,?,?,?,?,?,?)', ('b',cycle,'s','x','sig','[]',0,'now'))
            self.assertEqual(catalog.db.execute('SELECT count(*) FROM db_capture').fetchone()[0], 1)

    def test_explicit_migration_backup_and_existing_managed_archive(self):
        from wechat_capture_next.tests.test_service import ServiceTests
        from wechat_capture_next.migrate_evidence import migrate
        from wechat_capture_next.sync_wua import sync_wua
        fixture = ServiceTests()
        fixture.setUp()
        try:
            with patch.object(Catalog, 'enable_compact', return_value=False):
                service = fixture.init_service()
            with closing(service):
                service.capture(force=True)
                target = fixture.root/'managed'
                first = sync_wua(service, target, verify=True)
                path = target/'archive.wua.sqlite'
                old_sha = hashlib.sha256(path.read_bytes()).hexdigest()
                report = migrate(service, fixture.root/'migration')
                self.assertTrue(report['exact_expanded_tables_match'])
                self.assertEqual(sync_wua(service, target, verify=True)['semantic_digest'], first['semantic_digest'])
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), old_sha)
                self.assertFalse(migrate(service, fixture.root/'not-created')['changed'])
                self.assertFalse((fixture.root/'not-created').exists())
        finally:
            fixture.tearDown()

    def test_unknown_format_fails_before_startup_writes(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work)/'catalog.sqlite'
            with closing(Catalog(path)) as catalog:
                with catalog.db:
                    catalog.db.execute("UPDATE meta SET value='future-format' WHERE key='next_evidence_storage'")
                catalog.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, 'unsupported'):
                Catalog(path)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_new_state_initialization_resumes_compaction_after_interrupt(self):
        from wechat_capture_next.tests.test_service import ServiceTests
        from wechat_capture_next.service import CaptureService
        fixture = ServiceTests()
        fixture.setUp()
        try:
            with patch.object(Catalog, 'enable_compact', return_value=False):
                with closing(fixture.init_service()) as service:
                    state = service.state
                    self.assertFalse(service.catalog.compact)
            with closing(CaptureService(state)) as service:
                self.assertTrue(service.catalog.compact)
                report = service.capture(force=True)
                self.assertEqual(report['status'], 'local_complete')
        finally:
            fixture.tearDown()

    def test_zero_schema_initialization_and_partial_extension_fail_closed(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work)/'catalog.sqlite'
            path.touch()
            with closing(Catalog(path)) as catalog:
                self.assertFalse(catalog.compact)
                catalog.enable_compact()
                catalog.db.execute('DROP TRIGGER capture_no_delete')
                catalog.db.commit()
            with self.assertRaisesRegex(ValueError,'incomplete'):
                Catalog(path)


if __name__ == '__main__':
    unittest.main()
