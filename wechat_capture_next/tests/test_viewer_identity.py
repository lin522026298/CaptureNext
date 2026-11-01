from contextlib import closing
import sqlite3
import tempfile
from pathlib import Path
import unittest
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next import viewer,viewer_identity as module
from wechat_capture_v2.common import digest_file


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'contacts.sqlite';self.archive=CompactArchive(':memory:');self.addCleanup(self.archive.close)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('CREATE TABLE contact(id INTEGER PRIMARY KEY,username,remark,nick_name,alias,unknown_blob,unknown_real)')
            db.executemany('INSERT INTO contact VALUES(?,?,?,?,?,?,?)',
                [(1,'user-a','same name','','',b'\x00\xff',1.5),(2,'user-b','same name','nickname','',b'\x00\xff',-0.25)])
            db.commit()
    def ingest(self,source='a',evidence=None):
        return module.import_contact(self.archive,source_id=source,account_alias='account',relative='contact/contact.db',
            capture_id='capture',evidence=evidence or dict(plaintext=dict(sha256=digest_file(self.path))),path=self.path)
    def test_replay_and_renaming_preserve_exact_source_history(self):
        self.ingest();before=self.archive._db.total_changes;self.assertTrue(self.ingest()['noop'])
        self.assertEqual(self.archive._db.total_changes,before)
        with closing(sqlite3.connect(self.path)) as db:db.execute("UPDATE contact SET remark='changed' WHERE id=1");db.commit()
        self.ingest();self.ingest('other-source')
        self.assertEqual({r['name'] for r in viewer.names(self.archive,'account','user-a')},{'same name','changed'})
        self.assertEqual(module.verify(self.archive)['rows_verified'],6)
        blobs=self.archive._db.execute("SELECT count(*) FROM content_payload WHERE kind='bytes'").fetchone()[0]
        self.assertEqual(blobs,1)
    def test_wrong_accepted_hash_rolls_back_and_projection_tamper_rejected(self):
        with self.assertRaises(ValueError):self.ingest(evidence=dict(plaintext=dict(sha256='0'*64)))
        self.assertIsNone(self.archive._db.execute("SELECT 1 FROM archive_meta WHERE key='next_viewer_schema'").fetchone())
        self.ingest();self.archive._db.execute("UPDATE next_viewer_identity SET name='bad'")
        with self.assertRaises(ValueError):module.verify(self.archive)
        with self.assertRaises(ValueError):self.archive.integrity_check()


if __name__=='__main__':unittest.main()
