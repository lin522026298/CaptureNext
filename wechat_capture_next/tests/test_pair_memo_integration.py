from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from wechat_capture_next import pair_repository as repo,pair_readback_memo as memory
from wechat_capture_next.union_archive import cold_input


@unittest.skipUnless(os.name=='nt','requires enforceable Windows deny-write guards')
class MemoIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.input=self.root/'input';self.input.write_bytes(bytes(range(256))*8193)
        self.files={'state/catalog.sqlite':self.input};self.target=self.root/'repo'
        self.owner=dict(schema=repo.SCHEMA,catalog_instance='synthetic',union_id='synthetic')
        self.scope=dict(verification_profile='synthetic-1')
        repo.publish(self.target,self.owner,self.files,self.scope)
        self.memo=memory.PairReadbackMemo()
    def unchanged(self):
        with cold_input(self.input):return repo.unchanged(self.target,self.owner,self.files,self.scope,_memo=self.memo)
    def test_cold_auth_then_full_file_hash_reuse_without_block_decode_or_repository_write(self):
        before=hashlib.sha256((self.target/repo.DATABASE).read_bytes()).hexdigest()
        cold=self.unchanged();self.assertTrue(cold['repository_block_authentication_executed_now'])
        with patch.object(repo,'verify_files',side_effect=AssertionError('repeat decode forbidden')),\
             patch.object(memory,'digest_file',wraps=memory.digest_file) as hashed:
            warm=self.unchanged()
        self.assertTrue(warm['reused_same_process_authenticated_repository_cut'])
        self.assertTrue(warm['repository_full_file_sha_executed_now'])
        self.assertFalse(warm['repository_block_authentication_executed_now'])
        self.assertIn(self.target/repo.DATABASE,[call.args[0] for call in hashed.call_args_list])
        self.assertEqual(hashlib.sha256((self.target/repo.DATABASE).read_bytes()).hexdigest(),before)
    def test_source_same_size_same_time_change_misses_and_clears_old_proof(self):
        self.unchanged();original=self.input.read_bytes();stamp=self.input.stat()
        self.input.write_bytes(b'x'+original[1:]);os.utime(self.input,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
        self.assertIsNone(self.unchanged())
        self.input.write_bytes(original);os.utime(self.input,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
        with patch.object(repo,'verify_files',side_effect=RuntimeError('cold authentication required')):
            with self.assertRaisesRegex(RuntimeError,'required'):self.unchanged()
    def test_corrupted_same_size_same_time_repository_is_not_reused(self):
        self.unchanged();path=self.target/repo.DATABASE;stamp=path.stat()
        with closing(sqlite3.connect(path)) as db:payload=db.execute("SELECT data FROM block WHERE kind='D' LIMIT 1").fetchone()[0]
        data=bytearray(path.read_bytes());needle=payload[8:32];position=data.find(needle)
        self.assertGreaterEqual(position,0);data[position]^=1;path.write_bytes(data)
        os.utime(path,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
        with self.assertRaises((ValueError,sqlite3.DatabaseError)):self.unchanged()
    def test_all_repository_inputs_remain_guarded_through_warm_lookup(self):
        self.unchanged();lookup=self.memo.lookup
        def guarded(*args,**kwargs):
            for path in [self.input,*(self.target/name for name in (repo.DATABASE,'OWNER.private.json','repository.lock'))]:
                with self.assertRaises(OSError):
                    with path.open('r+b'):pass
            return lookup(*args,**kwargs)
        with patch.object(memory.PairReadbackMemo,'lookup',side_effect=guarded):self.unchanged()
    def test_extra_file_and_reset_never_import_a_persisted_proof(self):
        self.unchanged();extra=self.target/'unexpected-proof.json';extra.write_text('{}')
        with self.assertRaises(ValueError):self.unchanged()
        self.assertEqual(extra.read_text(),'{}')


if __name__=='__main__':unittest.main()
