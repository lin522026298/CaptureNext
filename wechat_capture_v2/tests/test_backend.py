from contextlib import closing
import hashlib
import hmac
import json
import shutil
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes

from tools.sqlite_wal import checksum
from wechat_capture_v2.common import canonical,decoded,encoded,digest_file
from wechat_capture_v2.cipher import PageCipher,materialize,wal_prefix
from wechat_capture_v2.compare import compare_native
from wechat_capture_v2.objects import Objects,CHUNK_BYTES
from wechat_capture_v2.source import capture_pair
from wechat_capture_v2.store import Catalog
from wechat_capture_v2.planner import changed_tables

KEY=bytes(range(32))
SALT=bytes(range(16))
PEER="wxid_capture_synthetic_peer"
TABLE="Msg_"+hashlib.md5(PEER.encode()).hexdigest()


def make_plain(path,count=1,start=1):
    with closing(sqlite3.connect(path)) as db,db:
        db.execute("CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY)")
        db.executemany("INSERT INTO Name2Id(rowid,user_name) VALUES(?,?)",[(7,PEER),(19,"wxid_synthetic_self")])
        db.execute(f'''CREATE TABLE "{TABLE}"(local_id INTEGER PRIMARY KEY,server_id INTEGER,
            local_type INTEGER,real_sender_id INTEGER,create_time INTEGER,message_content BLOB,
            WCDB_CT_message_content INTEGER,packed_info_data BLOB,sort_seq INTEGER)''')
        db.executemany(f'INSERT INTO "{TABLE}" VALUES(?,?,1,7,?, ?,NULL,?,0)',
            ((i,i+1000000,i,"synthetic "+str(i),b"\x00\xff") for i in range(start,start+count)))


def empty_sqlite_page():
    data=bytearray(4096)
    data[:16]=b"SQLite format 3\x00"
    struct.pack_into(">H",data,16,4096)
    data[18:24]=bytes((1,1,80,64,32,32))
    for off,value in ((24,1),(28,1),(40,1),(44,4),(56,1),(92,1),(96,3046000)):
        struct.pack_into(">I",data,off,value)
    data[100]=13
    struct.pack_into(">H",data,105,4016)
    return bytes(data)


def encrypt(page,number=1):
    start=16 if number==1 else 0
    iv=bytes(reversed(range(16)))
    enc=Cipher(algorithms.AES(KEY),modes.CBC(iv)).encryptor()
    prefix=(SALT if number==1 else b"")+enc.update(page[start:4016])+enc.finalize()+iv
    mac_key=hashlib.pbkdf2_hmac("sha512",KEY,bytes(x^0x3A for x in SALT),2,dklen=32)
    mac=hmac.new(mac_key,prefix[start:]+struct.pack("<I",number),hashlib.sha512).digest()
    return prefix+mac


def make_wal(path,frames):
    header=struct.pack(">IIIIII",0x377F0682,3007000,4096,0,123,456)
    state=checksum(header)
    data=bytearray(header+struct.pack(">II",*state))
    for number,pages,page in frames:
        head=struct.pack(">IIII",number,pages,123,456)
        state=checksum(head[:8]+page,state)
        data.extend(head+struct.pack(">II",*state)+page)
    path.write_bytes(data)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.plain=self.root/"plain.db"
        make_plain(self.plain)
        self.catalog=Catalog(self.root/"catalog.sqlite")

    def tearDown(self):
        self.catalog.close()
        self.temp.cleanup()

    def ingest(self,**kwargs):
        cycle=self.catalog.begin_cycle("test")
        return self.catalog.ingest(cycle=cycle,source_id="fixture",account="fixture-account",relative="message/message_0.db",
            path=self.plain,evidence={"plaintext":{"sha256":digest_file(self.plain)}},signature=digest_file(self.plain),
            stamp_value={"test":True},self_username="wxid_synthetic_self",**kwargs)

    def test_full_replay_dedup_and_independent_compare(self):
        self.assertEqual(self.ingest()["new_versions"],1)
        self.assertEqual(self.ingest()["new_versions"],0)
        self.assertTrue(compare_native(self.catalog,"fixture","message/message_0.db",self.plain)["pass"])

    def test_late_old_same_sequence_and_changed_body_are_retained(self):
        self.ingest()
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute(f'INSERT INTO "{TABLE}" VALUES(-9,-9,1,7,-100,?,NULL,?,0)',("late old message",b"late"))
            db.execute(f'UPDATE "{TABLE}" SET message_content=? WHERE local_id=1',("revised\x00正文",))
        result=self.ingest()
        self.assertEqual(result["new_versions"],2)
        self.assertEqual(self.catalog.summary()["versions"],3)
        self.assertEqual(self.catalog.summary()["active_messages"],2)
        self.assertTrue(compare_native(self.catalog,"fixture","message/message_0.db",self.plain)["pass"])

    def test_full_backlog_exceeds_prior_100000_cap(self):
        self.ingest()
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.executemany(f'INSERT INTO "{TABLE}" VALUES(?,?,1,7,0,?,NULL,?,0)',
                ((i,i+1000000,"backlog",b"raw") for i in range(2,100007)))
        result=self.ingest()
        self.assertEqual(result["rows"],100006)
        self.assertEqual(result["new_versions"],100005)
        self.assertEqual(self.catalog.summary()["active_messages"],100006)

    def test_scan_failure_rolls_back_rows_and_checkpoint_together(self):
        self.ingest()
        previous=self.catalog.checkpoint("fixture","message/message_0.db")
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute(f'INSERT INTO "{TABLE}" VALUES(2,2,1,7,0,?,NULL,?,0)',("new",b"raw"))
        with self.assertRaisesRegex(RuntimeError,"interrupted"):
            self.ingest(fail_after=2)
        self.assertEqual(self.catalog.summary()["versions"],1)
        self.assertEqual(self.catalog.checkpoint("fixture","message/message_0.db"),previous)
        self.assertEqual(self.ingest()["new_versions"],1)

    def test_deleted_row_preserves_prior_raw_and_reappearing_transition(self):
        self.ingest()
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute(f'DELETE FROM "{TABLE}"')
        self.assertEqual(self.ingest()["disappeared_heads"],1)
        self.assertEqual(self.catalog.summary()["versions"],1)
        self.assertEqual(self.catalog.summary()["active_messages"],0)
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute(f'INSERT INTO "{TABLE}" VALUES(1,1000001,1,7,1,?,NULL,?,0)',('synthetic 1',b'\x00\xff'))
        result=self.ingest()
        self.assertEqual(result['new_versions'],0)
        self.assertEqual(self.catalog.summary()['active_messages'],1)
        self.assertEqual(self.catalog.db.execute('SELECT kind FROM transition ORDER BY id DESC LIMIT 1').fetchone()[0],'reappeared')

    def test_cross_shard_same_ids_not_overwritten(self):
        self.ingest()
        other=self.root/"other.db"
        make_plain(other)
        cycle=self.catalog.begin_cycle("test")
        self.catalog.ingest(cycle=cycle,source_id="fixture",account="fixture-account",relative="message/message_1.db",path=other,
            evidence={"plaintext":{"sha256":digest_file(other)}},signature=digest_file(other),stamp_value={})
        self.assertEqual(self.catalog.summary()["versions"],2)

    def test_long_body_no_export_truncation(self):
        long="全量\n"*30000
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute(f'UPDATE "{TABLE}" SET message_content=?',(long,))
        self.ingest()
        rows=list(self.catalog.versions())
        self.assertEqual(rows[0]["raw_record"]["message_content"],long)
        self.assertEqual(rows[0]["body_text"],long)

    def test_comparison_detects_missing_and_different_native_rows(self):
        self.ingest()
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute(f'UPDATE "{TABLE}" SET message_content=?',("different",))
            db.execute(f'INSERT INTO "{TABLE}" VALUES(2,2,1,7,0,?,NULL,?,0)',("missing",b"raw"))
        report=compare_native(self.catalog,"fixture","message/message_0.db",self.plain)
        self.assertFalse(report["pass"])
        self.assertEqual(report["missing_rows"],1)
        self.assertEqual(report["different_raw_rows"],1)

    def test_identity_mapping_change_keeps_raw_and_interpretation_history(self):
        self.ingest()
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute("UPDATE Name2Id SET user_name='wxid_synthetic_self_renamed' WHERE rowid=7")
        result=self.ingest()
        self.assertEqual(result['new_versions'],0)
        self.assertEqual(result['new_interpretations'],1)
        self.assertEqual(self.catalog.summary()['versions'],1)
        self.assertEqual(list(self.catalog.versions())[0]['sender_id'],'wxid_synthetic_self_renamed')
        self.assertEqual(self.ingest()['new_versions'],0)
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute("UPDATE Name2Id SET user_name=? WHERE rowid=7",(PEER,))
        self.ingest()
        self.assertEqual(list(self.catalog.versions())[0]['sender_id'],PEER)
        self.assertEqual(self.catalog.db.execute('SELECT count(*) FROM interpretation').fetchone()[0],2)

    def test_subset_scan_never_marks_other_tables_disappeared(self):
        second='Msg_'+hashlib.md5(b'other').hexdigest()
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute(f'CREATE TABLE "{second}" AS SELECT * FROM "{TABLE}"')
        self.ingest()
        self.assertEqual(self.catalog.summary()['active_messages'],2)
        result=self.ingest(selected_tables=[TABLE])
        self.assertEqual(result['rows'],1)
        self.assertEqual(result['disappeared_heads'],0)
        self.assertEqual(self.catalog.summary()['active_messages'],2)

    def test_planner_affected_table_and_identity_fallback(self):
        previous=self.root/'previous.db'
        shutil.copyfile(self.plain,previous)
        self.assertEqual(changed_tables(previous,self.plain)['tables'],[])
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute(f'UPDATE "{TABLE}" SET message_content=?',('changed',))
        plan=changed_tables(previous,self.plain)
        if plan['reason']=='page_planner_unavailable':
            self.assertIsNone(plan['tables'])  # Windows sqlite may omit dbstat.
        else:
            self.assertEqual(plan['tables'],[TABLE])
        shutil.copyfile(self.plain,previous)
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute("UPDATE Name2Id SET user_name='renamed' WHERE rowid=7")
        self.assertIsNone(changed_tables(previous,self.plain)['tables'])
        shutil.copyfile(self.plain,previous)
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute('CREATE TABLE extra(x)')
        self.assertEqual(changed_tables(previous,self.plain)['reason'],'schema_changed')


class CipherBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_tagged_values_roundtrip(self):
        value={"a":b"\xff\x00","b":{"$binary":"not a blob"},"c":-0.0,"d":2**62,"e":[None,"字\x00"]}
        self.assertEqual(decoded(json.loads(canonical(encoded(value)))),value)
        self.assertEqual(decoded(encoded(value))["c"].hex(),(-0.0).hex())

    def test_page_auth_and_legacy_compatible_materialization(self):
        page=empty_sqlite_page()
        encrypted=encrypt(page)
        self.assertEqual(PageCipher(KEY,SALT).decrypt(encrypted,1),page)
        raw=self.root/"encrypted.db"
        raw.write_bytes(encrypted)
        result=materialize(raw,self.root/"plain.db",KEY)
        self.assertEqual(result["quick_check"],["ok"])
        self.assertEqual((self.root/"plain.db").read_bytes(),page)
        bad=bytearray(encrypted); bad[100]^=1
        with self.assertRaisesRegex(ValueError,"HMAC"):
            PageCipher(KEY,SALT).decrypt(bytes(bad),1)

    def test_uncommitted_tail_does_not_replace_committed_page(self):
        raw=self.root/"encrypted.db"
        raw.write_bytes(encrypt(empty_sqlite_page()))
        committed=bytearray(empty_sqlite_page()); struct.pack_into(">I",committed,60,7)
        uncommitted=bytearray(empty_sqlite_page()); struct.pack_into(">I",uncommitted,60,99)
        wal=self.root/"source.wal"
        make_wal(wal,[(1,1,encrypt(bytes(committed))),(1,0,encrypt(bytes(uncommitted)))])
        materialize(raw,self.root/"plain.db",KEY,wal)
        with closing(sqlite3.connect(self.root/"plain.db")) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0],7)

    def test_wal_beyond_legacy_size_limit_streams_stale_tail(self):
        wal=self.root/"large.wal"
        make_wal(wal,[(1,1,encrypt(empty_sqlite_page()))])
        with wal.open("r+b") as stream:
            stream.truncate(512*1024*1024+4096)
        audit=wal_prefix(wal,PageCipher(KEY,SALT))
        self.assertEqual(audit["last_commit_frame"],1)
        self.assertEqual(audit["tail_reason"],"stale_generation_tail")

    def test_chunk_backup_dedup_restore_and_tamper_detection(self):
        source=self.root/"source.bin"
        source.write_bytes(b"A"*CHUNK_BYTES+b"B"*CHUNK_BYTES+b"tail")
        objects=Objects(self.root/"objects.sqlite")
        try:
            first=objects.add(source)
            self.assertEqual(objects.add(source),first)
            restored=self.root/"restored.bin"
            objects.restore(first["sha256"],restored)
            self.assertEqual(source.read_bytes(),restored.read_bytes())
            count=objects.db.execute("SELECT count(*) FROM chunk").fetchone()[0]
            with objects.db:
                objects.db.execute("UPDATE chunk SET data=? WHERE hash=(SELECT hash FROM chunk LIMIT 1)",(b"broken",))
            with self.assertRaises(Exception):
                objects.restore(first["sha256"],self.root/"bad.bin")
            self.assertEqual(count,3)
        finally:
            objects.close()

    def test_readonly_capture_retains_raw_and_trimmed_wal(self):
        raw=self.root/"live.db"
        raw.write_bytes(encrypt(empty_sqlite_page()))
        wal=Path(str(raw)+"-wal")
        make_wal(wal,[(1,1,encrypt(empty_sqlite_page()))])
        with wal.open("ab") as stream:
            stream.write(b"incomplete")
        before=(digest_file(raw),digest_file(wal))
        result=capture_pair(raw,self.root/"capture")
        self.assertEqual(before,(digest_file(raw),digest_file(wal)))
        self.assertEqual(result["wal"].stat().st_size,32+4120)
        self.assertEqual(result["raw_wal"].stat().st_size,32+4120+10)


if __name__=="__main__":
    unittest.main()
