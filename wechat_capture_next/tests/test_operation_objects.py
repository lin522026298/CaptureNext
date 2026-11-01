from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from wechat_capture_next.operation_objects import verified_object_scope


class ObjectProofTests(unittest.TestCase):
    def setup_db(self):
        db=sqlite3.connect(':memory:');self.addCleanup(db.close)
        db.execute('CREATE TABLE file(hash TEXT PRIMARY KEY,bytes INTEGER)')
        db.execute('CREATE TABLE blob_test(data BLOB)');db.execute("INSERT INTO blob_test VALUES(x'0102')")
        sha=hashlib.sha256(b'ab').hexdigest();db.execute('INSERT INTO file VALUES(?,2)',(sha,));db.commit()
        db.execute('BEGIN IMMEDIATE');return db,sha,dict(pass_=True,files_verified=1,logical_bytes_verified=2)
    def test_scoped_read_reuse_and_expiry(self):
        db,sha,result=self.setup_db();result['pass']=result.pop('pass_')
        with verified_object_scope(db,result) as proof:
            proof.assert_for(db);proof.covers(sha,2)
            self.assertEqual(db.execute('PRAGMA query_only').fetchone()[0],1)
            with self.assertRaises(sqlite3.OperationalError):db.execute("UPDATE blob_test SET data=x'0000'")
            with self.assertRaises(ValueError):proof.covers(sha,2)
        self.assertEqual(db.execute('PRAGMA query_only').fetchone()[0],0)
        with self.assertRaises(ValueError):proof.assert_for(db)
    def test_commit_begin_without_writes_still_invalidates(self):
        db,sha,result=self.setup_db();result['pass']=result.pop('pass_')
        with verified_object_scope(db,result) as proof:
            db.commit();db.execute('BEGIN')
            with self.assertRaises(ValueError):proof.assert_for(db)
    def test_connection_substitution_and_missing_object_rejected(self):
        db,sha,result=self.setup_db();result['pass']=result.pop('pass_')
        with verified_object_scope(db,result) as proof,closing(sqlite3.connect(':memory:')) as other:
            with self.assertRaises(ValueError):proof.assert_for(other)
            with self.assertRaises(ValueError):proof.covers('0'*64,2)
            with self.assertRaises(ValueError):proof.covers(sha,3)
    def test_blob_write_blocked_and_close_invalidates(self):
        db,sha,result=self.setup_db();result['pass']=result.pop('pass_')
        with verified_object_scope(db,result) as proof:
            with self.assertRaises(sqlite3.OperationalError):
                with db.blobopen('blob_test','data',1,readonly=False) as blob:blob.write(b'xx')
            db.close()
            with self.assertRaises(ValueError):proof.assert_for(db)


if __name__=='__main__':unittest.main()
