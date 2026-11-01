from types import SimpleNamespace
import sqlite3
import unittest

from wechat_capture_next import benchmark_file_media as benchmark


class FileMediaQATests(unittest.TestCase):
    def test_prefilter_uses_exact_tokens_and_names_and_budget_disables(self):
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE asset_history(relative_path)')
            db.executemany('INSERT INTO asset_history VALUES(?)', [('Video/'+('a'*32)+'.mp4',),('File/名字.pdf',)])
            archive=SimpleNamespace(_db=sqlite3.connect(':memory:'))
            self.addCleanup(archive._db.close)
            index=benchmark.retained_prefilter(archive,db)
            self.assertTrue(benchmark.intersects(index,[dict(md5='a'*32,filename=None)]))
            self.assertTrue(benchmark.intersects(index,[dict(md5=None,filename='名字.pdf')]))
            self.assertFalse(benchmark.intersects(index,[dict(md5='b'*32,filename='名字(1).pdf')]))
            self.assertTrue(benchmark.intersects(index,[dict(md5=None,filename=None,token='a'*32)]))
            self.assertFalse(benchmark.intersects(index,[dict(md5=None,filename=None,token='b'*32)]))
            self.assertIsNone(benchmark.retained_prefilter(archive,db,budget=1))
            self.assertTrue(benchmark.intersects(None,[dict(md5='b'*32,filename=None)]))

    def test_private_receipt_projection_never_copies_xml_filename_or_key_fields(self):
        result=benchmark.redacted_verification('logical','video',dict(status='linked',file_sha='a'*64,
            bytes=123,md5='b'*32,filename='private name',body_text='private body',aeskey='secret',
            matching_claims=[dict(field='videomsg.md5',filename='private',observation_id='native')]))
        self.assertNotIn('filename',result);self.assertNotIn('body_text',result);self.assertNotIn('aeskey',result)
        self.assertEqual(result['matching_checksum_fields'],['videomsg.md5'])


if __name__=='__main__':unittest.main()
