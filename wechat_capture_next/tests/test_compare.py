from pathlib import Path
import sqlite3
from contextlib import closing
import tempfile
import unittest

from wua.store import ArchiveStore
from tests.test_wua_store import observation
from wechat_capture_next.compare import compare_wua
from wechat_capture_v2.common import digest_file


class CompareTests(unittest.TestCase):
    def test_damaged_payload_and_unsupported_rules_never_compare_equal(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            inputs = []
            for name in ('current','reference'):
                folder = root/name
                folder.mkdir()
                path = folder/'archive.sqlite'
                with ArchiveStore(path) as archive:
                    archive.import_observations({'source_id':name},{'source_id':name,'snapshot_id':name},
                        [observation(native_locator=1,body_text='same')])
                inputs.append(path)
            with closing(sqlite3.connect(inputs[1])) as db, db:
                for name, in db.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='message_observation'").fetchall():
                    db.execute('DROP TRIGGER "'+name.replace('"','""')+'"')
                db.execute("UPDATE message_observation SET raw_record_json='{}'")
            before = [digest_file(p) for p in inputs]
            with self.assertRaisesRegex(ValueError,'raw observation hash'):
                compare_wua(*inputs,root/'reports'/'damaged.json')
            self.assertEqual(before,[digest_file(p) for p in inputs])
            self.assertFalse((root/'reports'/'damaged.json').exists())
            with closing(sqlite3.connect(inputs[0])) as db, db:
                db.execute("UPDATE archive_meta SET value='unknown-future' WHERE key='rule_version'")
            with self.assertRaisesRegex(ValueError,'schema or rule'):
                compare_wua(*inputs,root/'reports'/'future.json')

    def test_snapshot_ids_and_repeated_observations_do_not_inflate_differences(self):
        with tempfile.TemporaryDirectory() as work:
            root=Path(work)
            paths=[]
            for name in ('current','reference'):
                folder=root/name
                folder.mkdir()
                path=folder/'archive.sqlite'
                with ArchiveStore(path) as archive:
                    archive.import_observations({'source_id':name},{'source_id':name,'snapshot_id':name},[observation(native_locator=1,body_text='same')])
                    if name=='current':
                        archive.import_observations({'source_id':name},{'source_id':name,'snapshot_id':'repeat'},[observation(native_locator=1,body_text='same')])
                paths.append(path)
            before=[digest_file(p) for p in paths]
            result=compare_wua(*paths,root/'reports'/'comparison.json')
            self.assertTrue(result['raw_native_without_account_label']['equal'])
            self.assertTrue(result['message_fields_without_account_label']['equal'])
            self.assertEqual([digest_file(p) for p in paths],before)
            with self.assertRaises(ValueError):
                compare_wua(*paths,paths[0].parent/'new.json')
