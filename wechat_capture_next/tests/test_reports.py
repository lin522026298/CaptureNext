from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from wechat_capture_next.catalog import Catalog
from wechat_capture_next.reports import encode_report, decode_report, FORMAT, MAGIC
from wechat_capture_v2.common import canonical


class ReportTests(unittest.TestCase):
    def test_reference_round_trip_unknown_fields_and_immutable_final_evidence(self):
        with tempfile.TemporaryDirectory() as work, closing(Catalog(Path(work)/'catalog.sqlite')) as catalog:
            cycle = catalog.begin_cycle('full')
            auth = dict(changed_plain_pages=0,decrypted_pages=0,frozen_wal_bytes=100,memory_wal_bytes=100,
                        main_copy_bytes=0,temporary_wal_bytes=0)
            evidence = canonical(dict(time='now', authentication=auth,reader={'schema': '结构'*100}))
            with catalog.db:
                catalog.db.execute('INSERT INTO db_capture VALUES(?,?,?,?,?,?,?,?)', ('a',cycle,'s','x','sig',evidence,0,'now'))
            entry = dict(relative_path='x',status='accepted',capture_id='a',**auth,reader={'schema': '结构'*100},
                         rows=0,new_versions=0,verified_identical_decoded_rows_reused=True,unknown=[False,None,'新字段'])
            report = dict(schema='capture-next-cycle-1',status='local_complete',databases=[entry,dict(status='unchanged_metadata',relative_path='y')],
                          errors=[],finished='now',unknown=None)
            text = canonical(report)
            encoded = encode_report(catalog.db, text)
            self.assertTrue(encoded.startswith(MAGIC))
            self.assertLess(len(encoded.encode()),len(text.encode()))
            self.assertEqual(decode_report(catalog.db, encoded),text)
            catalog.finish_cycle(cycle,report)
            self.assertEqual(catalog.report(cycle),text)
            self.assertEqual(catalog.verify_reports(),1)
            with self.assertRaises(sqlite3.IntegrityError), catalog.db:
                catalog.db.execute('UPDATE db_capture SET message_count=9 WHERE id=?', ('a',))
            with self.assertRaises(sqlite3.IntegrityError), catalog.db:
                catalog.db.execute('DELETE FROM capture_record WHERE id=?', ('a',))
            value=json.loads(encoded[len(MAGIC):])
            value['root']['status']='corrupt'
            with self.assertRaisesRegex(ValueError,'hash mismatch'):
                decode_report(catalog.db,MAGIC+canonical(value))
            value=json.loads(encoded[len(MAGIC):])
            value['entries'][0]['c']='missing'
            with self.assertRaisesRegex(ValueError,'missing accepted'):
                decode_report(catalog.db,MAGIC+canonical(value))

    def test_literal_noncanonical_reports_and_fail_closed_future_envelopes(self):
        with closing(sqlite3.connect(':memory:')) as db:
            for text in ('{}','[1,2]','{ "schema": "capture-next-cycle-1", "databases": [] }',
                         canonical({'schema':'capture-next-cycle-1','databases':[],'storage':FORMAT}),
                         canonical({'storage':'next-cycle-capture-refs-999'})):
                self.assertEqual(encode_report(db,text),text)
                self.assertEqual(decode_report(db,text),text)
            with self.assertRaisesRegex(ValueError,'unsupported'):
                decode_report(db,'\x1enext-cycle-capture-refs-999\n{}')


if __name__ == '__main__':
    unittest.main()
