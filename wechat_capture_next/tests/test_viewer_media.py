from contextlib import closing
from datetime import datetime,timezone
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tests.test_wua_store import observation
from wechat_capture_v2.common import digest_file
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.tests.test_union_assets import OfflineService
from wechat_capture_next import viewer_media as media
from wechat_capture_next.cas_stream import publish


class MediaTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        state=self.root/'state';state.mkdir()
        with closing(sqlite3.connect(state/'catalog.sqlite')) as db:
            db.execute('CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            db.execute("INSERT INTO meta VALUES('next_catalog_instance','synthetic-instance')");db.commit()
        self.service=OfflineService(state);self.addCleanup(self.service.close)
        self.archive=CompactArchive(self.root/'archive.sqlite',create=True);self.addCleanup(self.archive.close)
        self.archive._db.execute("INSERT INTO archive_meta VALUES('next_union_id','11111111111111111111111111111111')");self.archive._db.commit()
        self.when=1767225600;self.voice=b'\x02#!SILK_V3'+b'\0'*800
        self.path=self.root/'media.db'
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('CREATE TABLE Name2Id(user_name TEXT,unknown REAL)')
            db.execute('INSERT INTO Name2Id VALUES(?,?)',('room',1.25))
            db.execute('CREATE TABLE VoiceInfo(chat_name_id,svr_id,create_time,voice_data BLOB,unknown_blob BLOB,unknown_text)')
            db.executemany('INSERT INTO VoiceInfo VALUES(?,?,?,?,?,?)',[
                (1,100,self.when,self.voice,b'\x00\xff','exact'),(1,101,self.when,self.voice,b'\x00\xff','same bytes other message'),
                (1,102,self.when,self.voice,b'\x00\xff','time differs')]);db.commit()
        rows=[observation(native_locator=i,server_id=str(100+i),conversation_id='room',message_type='34',
                event_time=datetime.fromtimestamp(self.when+(1 if i==2 else 0),timezone.utc).isoformat()) for i in range(3)]
        self.archive.import_observations({'source_id':'a'},{'snapshot_id':'messages'},rows)
    def ingest(self,**kw):
        return media.import_voice(self.archive,self.service,source_id='a',account_alias='synthetic-account',
            relative='message/media_0.db',capture_id='accepted',evidence=dict(plaintext=dict(sha256=digest_file(self.path))),path=self.path,**kw)
    def test_raw_preservation_shared_cas_distinct_messages_and_exact_matching(self):
        self.ingest();result=media.verify(self.archive,self.service)
        self.assertEqual(result['unique_objects'],2)
        messages={m['server_id']:m for m in self.archive.list_messages()}
        one=media.for_message(self.archive,messages['100']['logical_id'])
        two=media.for_message(self.archive,messages['101']['logical_id'])
        self.assertEqual(one['status'],'linked');self.assertEqual(two['status'],'linked')
        self.assertNotEqual(messages['100']['logical_id'],messages['101']['logical_id'])
        self.assertEqual(one['rows'][0]['file_sha'],two['rows'][0]['file_sha'])
        self.assertEqual(media.for_message(self.archive,messages['102']['logical_id'])['status'],'candidate')
        row=self.archive._db.execute("SELECT payload_id FROM next_media_row WHERE table_name='VoiceInfo' LIMIT 1").fetchone()
        raw=media._decode(self.archive.pool.get_text(row[0]));self.assertEqual(raw['unknown_text'],'exact')
        self.assertEqual(raw['unknown_blob'],['cas_blob',hashlib.sha256(b'\x00\xff').hexdigest(),2])
        changes=[db.total_changes for db in (self.archive._db,self.service.catalog.db,self.service.objects.db)]
        self.assertTrue(self.ingest()['noop']);self.assertEqual(changes,[db.total_changes for db in (self.archive._db,self.service.catalog.db,self.service.objects.db)])
    def test_pending_crash_resume_and_projection_tamper(self):
        def fault(stage):
            if stage=='after_row':raise RuntimeError('synthetic crash')
        with self.assertRaises(RuntimeError):self.ingest(fault=fault)
        with self.assertRaisesRegex(ValueError,'pending'):media.verify(self.archive,self.service)
        self.ingest();self.assertEqual(media.verify(self.archive,self.service)['status'],'verified')
        self.archive._db.execute("UPDATE next_media_voice SET server_id='forged'");self.archive._db.commit()
        with self.assertRaisesRegex(ValueError,'projection'):media.verify(self.archive,self.service)
    def test_wrong_source_or_dictionary_does_not_associate(self):
        self.ingest()
        row=observation(native_locator=99,server_id='100',conversation_id='room',message_type='34',
                account_alias='other-account',event_time=datetime.fromtimestamp(self.when,timezone.utc).isoformat())
        self.archive.import_observations({'source_id':'other'},{'snapshot_id':'other'},[row])
        message=next(r for r in self.archive.list_messages() if r['account_alias']=='other-account')
        self.assertEqual(media.for_message(self.archive,message['logical_id'])['status'],'association_unknown')
    def test_stream_publication_replay_corruption_and_short_read(self):
        blob=b'large'+b'x'*600000
        info=publish(self.service.objects,io.BytesIO(blob),len(blob))
        self.assertEqual(info,publish(self.service.objects,io.BytesIO(blob),len(blob)))
        with self.assertRaisesRegex(ValueError,'short read'):publish(self.service.objects,io.BytesIO(b'x'),2)
        self.service.objects.db.execute("UPDATE chunk SET data=x'00'");self.service.objects.db.commit()
        with self.assertRaises(Exception):publish(self.service.objects,io.BytesIO(blob),len(blob))
    def test_different_native_contents_same_key_are_conflicting_candidates(self):
        self.ingest()
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('INSERT INTO VoiceInfo VALUES(?,?,?,?,?,?)',(1,100,self.when,b'different bytes',b'unknown','conflicting native row'));db.commit()
        self.ingest();self.assertEqual(media.verify(self.archive,self.service)['status'],'verified')
        message=next(m for m in self.archive.list_messages() if m['server_id']=='100')
        result=media.for_message(self.archive,message['logical_id'])
        self.assertEqual(result['status'],'candidate');self.assertEqual(len(result['rows']),3)
        self.assertTrue(all(r['native_content_conflict'] and r['status']=='candidate' for r in result['rows']))
    def test_raw_coverage_receipt_catches_deleted_original_and_projection(self):
        self.ingest()
        self.archive._db.execute("DELETE FROM next_media_row WHERE table_name='VoiceInfo' AND locator=1")
        self.archive._db.execute('DELETE FROM next_media_voice WHERE locator=1');self.archive._db.commit()
        with self.assertRaisesRegex(ValueError,'coverage'):media.verify(self.archive,self.service)


if __name__=='__main__':unittest.main()
