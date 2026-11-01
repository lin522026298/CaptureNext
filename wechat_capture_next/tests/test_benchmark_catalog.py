from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from wechat_capture_next.benchmark_catalog import benchmark, cohort_from_trial
from wechat_capture_next.catalog import Catalog
from wechat_capture_next.reports import decode_report, encode_report, MAGIC, FORMAT as REPORT_FORMAT
from wechat_capture_v2.common import canonical, write_json_new


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root/'source'
        self.state.mkdir()
        self.source = self.state/'catalog.sqlite'
        with closing(Catalog(self.source, compact_new=False)) as catalog:
            with catalog.db:
                # Deliberately noncanonical report/evidence text must survive.
                for index, ident in enumerate(('before', 'cohort', 'after')):
                    report = '{ "status": "ok", "id": "'+ident+'" }'
                    catalog.db.execute('INSERT INTO cycle VALUES(?,?,?,?,?,?)',
                        (ident, str(index), str(index+1), 'full', 'ok', report))
                    for item in range(4):
                        evidence = canonical(dict(time=ident, row_scan_reused_from=ident,
                            reader={'fixed': 'shared'*500}, same_signature='yes'))
                        if item == 3:
                            evidence = '{ "time": "'+ident+'", "unusual": true }'
                        capture = ident+str(item)
                        catalog.db.execute('INSERT INTO db_capture VALUES(?,?,?,?,?,?,?,?)',
                            (capture, ident, 'source', 'message.db', 'same', evidence, 1, ident))
                report = canonical(dict(schema='capture-next-cycle-1', status='ok',
                    databases=[dict(capture_id='cohort0', relative_path='message.db', status='accepted',
                        reader={'fixed':'shared'*500}, rows=0, new_versions=0,
                        verified_identical_decoded_rows_reused=True, preserved_extra='keep')]))
                catalog.db.execute('UPDATE cycle SET report_json=? WHERE id=?', (report, 'cohort'))
                catalog.db.execute('INSERT INTO version VALUES(?,?,?,?,?,?,?,?,?,?)',
                    ('version','source','account','message.db','Msg','{}','hash',b'raw','{"body":"private"}','cohort0'))
                catalog.db.execute('INSERT INTO head VALUES(?,?,?,?,?,?,?)',
                    ('source','message.db','Msg','{}','version','cohort0',1))
                catalog.db.execute('INSERT INTO transition VALUES(?,?,?,?)', (1,'cohort0','version','new'))

    def tearDown(self):
        self.temp.cleanup()

    def test_same_inputs_exact_bytes_integrity_and_reports(self):
        original = hashlib.sha256(self.source.read_bytes()).hexdigest()
        result = benchmark(self.source, ['cohort'], self.root/'replay')
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), original)
        self.assertEqual(result['inputs']['baseline']['cycles'], 2)
        self.assertEqual(result['inputs']['cohort']['captures'], 4)
        self.assertEqual(result['message_payload_source_cohort']['version']['rows'], 1)
        self.assertFalse(result['message_payload_source_cohort']['replayed'])
        self.assertEqual(result['message_payload_source_cohort']['transitions'], {'new':1})
        self.assertEqual(result['arms']['legacy']['report_files_added'], 1)
        self.assertEqual(result['arms']['compact']['report_files_added'], 0)
        for arm in result['arms'].values():
            self.assertEqual(arm['after']['quick_check'], ['ok'])
            self.assertEqual(arm['after']['foreign_key_check'], [])
            self.assertEqual(arm['after']['checkpoint_truncate'][0], 0)
            self.assertEqual(arm['exact_expanded_identity'], result['source_exact_expanded_identity'])
            self.assertIsNone(arm['temporary_peak_bytes'])
            self.assertGreaterEqual(arm['logical_write_bytes'], 0)
        for label in ('legacy','compact'):
            with closing(sqlite3.connect(self.root/'replay'/label/'catalog.sqlite')) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM version').fetchone()[0], 0)
                finished, stored = db.execute('SELECT finished,report_json FROM cycle WHERE id=?', ('cohort',)).fetchone()
                self.assertEqual(finished, '2')
                self.assertEqual(stored.startswith(MAGIC), label == 'compact')
                self.assertEqual(json.loads(decode_report(db, stored))['databases'][0]['preserved_extra'], 'keep')
                fallback = db.execute('SELECT report_json FROM cycle WHERE id=?', ('after',)).fetchone()[0]
                self.assertEqual(fallback, '{ "status": "ok", "id": "after" }')
        saved = json.loads((self.root/'replay'/'RESULT.json').read_text(encoding='utf-8'))
        self.assertTrue(saved['exact_identity_equal'])

    def test_reject_missing_duplicate_unsafe_or_reused_output(self):
        for ids in ([], ['cohort','cohort'], ['missing']):
            with self.assertRaises(ValueError):
                benchmark(self.source, ids, self.root/'unused')
        for path in (self.state/'nested', self.root):
            with self.assertRaises((ValueError, FileExistsError)):
                benchmark(self.source, ['cohort'], path)
        output = self.root/'existing'
        output.mkdir()
        with self.assertRaises(FileExistsError):
            benchmark(self.source, ['cohort'], output)
        self.assertFalse((self.root/'unused').exists())

    def test_reject_source_wal_without_settling_it(self):
        wal = Path(str(self.source)+'-wal')
        with wal.open('xb') as stream:
            stream.write(b'not safe to ignore')
        with self.assertRaisesRegex(ValueError, 'nonempty WAL'):
            benchmark(self.source, ['cohort'], self.root/'unused')
        self.assertEqual(wal.read_bytes(), b'not safe to ignore')

    def test_trial_ids_and_validation(self):
        trial = self.root/'trial'
        trial.mkdir()
        write_json_new(trial/'RESULT.json', dict(returncode=0,endpoints={'end':{}},
            events=dict(cycles=2,idle=1,partial=0)))
        rows = [dict(event='cycle',report=dict(status='ok',cycle_id='cohort')),
                dict(event='cycle',report=dict(status='idle',cycle_id=None))]
        with (trial/'cycles.private.jsonl').open('x',encoding='utf-8') as stream:
            stream.write('\n'.join(json.dumps(row) for row in rows)+'\n')
        self.assertEqual(cohort_from_trial(trial), ['cohort'])

    def test_compact_source_view_preserves_row_order_and_bytes(self):
        with closing(Catalog(self.source)) as catalog:
            catalog.enable_compact()
            text = catalog.db.execute('SELECT report_json FROM cycle WHERE id=?', ('cohort',)).fetchone()[0]
            with catalog.db:
                catalog.db.execute('UPDATE cycle SET report_json=? WHERE id=?',
                                   (encode_report(catalog.db, text), 'cohort'))
        result = benchmark(self.source, ['cohort'], self.root/'from-compact')
        self.assertTrue(result['exact_identity_equal'])
        self.assertEqual(result['inputs']['cohort']['captures'], 4)
        self.assertGreater(result['inputs']['cohort']['evidence_json_bytes'], 0)

    def test_trial_rejects_duplicates_or_inconsistent_counts(self):
        trial = self.root/'bad-trial'
        trial.mkdir()
        write_json_new(trial/'RESULT.json', dict(returncode=0,endpoints={'end':{}},
            events=dict(cycles=2,idle=0,partial=0)))
        row = dict(event='cycle',report=dict(status='ok',cycle_id='cohort'))
        with (trial/'cycles.private.jsonl').open('x',encoding='utf-8') as stream:
            stream.write((json.dumps(row)+'\n')*2)
        with self.assertRaises(ValueError):
            cohort_from_trial(trial)

    def test_literal_report_storage_key_cannot_be_mistaken_for_envelope(self):
        literal = canonical(dict(storage=REPORT_FORMAT, root='literal', entries=['unchanged']))
        with closing(Catalog(self.source)) as catalog, catalog.db:
            catalog.db.execute('UPDATE cycle SET report_json=? WHERE id=?', (literal, 'after'))
        result = benchmark(self.source, ['cohort'], self.root/'literal-storage')
        self.assertTrue(result['exact_identity_equal'])
        for label in ('legacy', 'compact'):
            with closing(sqlite3.connect(self.root/'literal-storage'/label/'catalog.sqlite')) as db:
                stored = db.execute('SELECT report_json FROM cycle WHERE id=?', ('after',)).fetchone()[0]
                self.assertEqual(stored, literal)
                self.assertEqual(decode_report(db, stored), literal)


if __name__ == '__main__':
    unittest.main()
