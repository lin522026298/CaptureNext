from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest
from tools.sqlite_wal import audit_wal, checksum


def make_wal(frames, big=False):
    header=struct.pack('>IIIIII',0x377F0683 if big else 0x377F0682,3007000,4096,0,17,25)
    state=checksum(header,big_endian=big)
    out=header+struct.pack('>II',*state)
    for pgno,size,payload in frames:
        prefix=struct.pack('>II',pgno,size)
        state=checksum(prefix+payload,state,big)
        out+=prefix+header[16:24]+struct.pack('>II',*state)+payload
    return out


class WalTests(unittest.TestCase):
    def test_both_endian_checksum_and_commit(self):
        for big in (False,True):
            r=audit_wal(make_wal([(2,2,b'a'*4096)],big))
            self.assertTrue(r['pass'])
            self.assertEqual(r['committed_page_frames'],{2:1})

    def test_uncommitted_tail_never_selected(self):
        r=audit_wal(make_wal([(2,2,b'a'*4096),(2,0,b'b'*4096)]))
        self.assertEqual(r['committed_page_frames'],{2:1})
        self.assertEqual(r['uncommitted_valid_frames'],1)

    def test_commit_shrink_and_last_write(self):
        r=audit_wal(make_wal([(3,3,b'a'*4096),(2,0,b'b'*4096),(2,2,b'c'*4096)]))
        self.assertEqual(r['committed_page_frames'],{2:3})
        self.assertEqual(r['committed_database_pages'],2)

    def test_salt_mismatch_ends_generation(self):
        blob=bytearray(make_wal([(2,2,b'a'*4096),(1,2,b'b'*4096)]))
        blob[32+4120+8]^=1
        r=audit_wal(bytes(blob))
        self.assertTrue(r['pass'])
        self.assertEqual(r['current_generation_frames'],1)
        self.assertEqual(r['trailing_frames_after_salt_mismatch'],1)

    def test_corruption_stops_chain(self):
        blob=bytearray(make_wal([(2,2,b'a'*4096),(1,2,b'b'*4096)]))
        blob[100]^=1
        r=audit_wal(bytes(blob))
        self.assertFalse(r['pass'])
        self.assertEqual(r['checksum_failed_frame'],1)
        self.assertEqual(r['last_commit_frame'],0)

    def test_stale_generation_boundary_also_excludes_partial_preallocation(self):
        blob=bytearray(make_wal([(2,2,b'a'*4096),(1,2,b'b'*4096)]))
        blob[32+4120+8]^=1
        blob+=b'partial stale preallocation'
        r=audit_wal(bytes(blob))
        self.assertTrue(r['pass'])
        self.assertEqual(r['committed_page_frames'],{2:1})
        self.assertEqual(r['ignored_bytes_after_salt_mismatch'],4120+len(b'partial stale preallocation'))

    def test_hmac_validation_is_separate(self):
        r=audit_wal(make_wal([(2,2,b'\0'*4096)]),page_validator=lambda p,n:False)
        self.assertEqual(r['hmac_failed_frames'],[1])
        self.assertEqual(r['last_commit_frame'],0)
        self.assertFalse(r['pass'])

    def test_header_and_torn_tail(self):
        self.assertTrue(audit_wal(b'')['pass'])
        for blob in (b'bad',b'\0'*32):
            self.assertFalse(audit_wal(blob)['pass'])
        blob=make_wal([(2,2,b'a'*4096)])
        self.assertFalse(audit_wal(blob+b'torn')['pass'])
        bad=bytearray(blob)
        bad[24]^=1
        self.assertFalse(audit_wal(bytes(bad))['header_checksum_valid'])

    def test_overflow_page_with_zero_first_byte_is_not_filtered(self):
        r=audit_wal(make_wal([(2,2,b'\0'*4096)]))
        self.assertEqual(r['committed_page_frames'],{2:1})

    def test_real_sqlite_wal_checksums(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'test.db'
            con=sqlite3.connect(path)
            try:
                con.execute('PRAGMA journal_mode=WAL')
                con.execute('PRAGMA wal_autocheckpoint=0')
                con.execute('CREATE TABLE evidence(value TEXT)')
                con.commit()
                con.execute('INSERT INTO evidence VALUES(?)',('synthetic',))
                con.commit()
                r=audit_wal(Path(str(path)+'-wal').read_bytes())
                self.assertTrue(r['pass'])
                self.assertEqual(r['commit_frames'],2)
                self.assertGreaterEqual(r['last_commit_frame'],3)
                con.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchall()
                self.assertEqual(Path(str(path)+'-wal').stat().st_size,0)
                self.assertTrue(audit_wal(Path(str(path)+'-wal').read_bytes())['pass'])
            finally:
                con.close()


if __name__=='__main__':
    unittest.main()
