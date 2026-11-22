"""Scoped agent reads; all data and media are generated for these tests."""
import base64
from contextlib import closing
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tests.test_wua_store import observation
from wechat_capture_next.agent_archive import execute, parse, Refusal
from wechat_capture_next.cas_stream import publish
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.tests.test_union_assets import OfflineService
from wechat_capture_next import viewer_media


class AgentArchiveTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        base = self.root/'archives/wechat-next'
        self.state = base/'state'
        self.state.mkdir(parents=True)
        self.path = base/'unified/archive.wua.sqlite'
        self.path.parent.mkdir()
        (self.state/'config.private.json').write_text('{}',encoding='utf-8')
        with closing(sqlite3.connect(self.state/'catalog.sqlite')) as db, db:
            db.execute('CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            db.execute("INSERT INTO meta VALUES('next_catalog_instance','synthetic-instance')")
        self.blob = b'contract attachment fixture'
        self.sha,md5 = self.asset(self.blob,'File/fixture(2).bin')
        self.old_sha,_ = self.asset(b'prior version','File/fixture.bin')
        self.file_type = str((6 << 32) | 49)
        png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=')
        self.png = png
        self.image_sha,self.image_md5 = self.asset(png,'Image/'+hashlib.md5(png).hexdigest()+'.png')
        self.voice = b'\x02#!SILK_V3'+b'\0'*800
        self.voice_sha = hashlib.sha256(self.voice).hexdigest()
        source = self.root/'fixture-voice.sqlite'
        with closing(sqlite3.connect(source)) as db, db:
            db.executescript('CREATE TABLE Name2Id(user_name TEXT); CREATE TABLE VoiceInfo(chat_name_id,svr_id,create_time,voice_data BLOB);')
            db.execute("INSERT INTO Name2Id VALUES('room')")
            db.execute('INSERT INTO VoiceInfo VALUES(1,321,1767225600,?)',(self.voice,))
        self.ids = {}
        with closing(OfflineService(self.state)) as service, CompactArchive(self.path,create=True) as a:
            a._db.execute("INSERT INTO archive_meta VALUES('next_union_id','11111111111111111111111111111111')")
            for account in ('one','two'):
                claim = f'<md5>{md5}</md5>' if account=='one' else ''
                def row(n,body,kind,server=None):
                    return observation(account_alias=account,conversation_id='room',native_locator=n,
                        server_id=server or str(n),event_time='2026-01-01T00:00:00Z',body_text=body,message_type=kind)
                a.import_observations({'source_id':account},{'snapshot_id':account},[
                    row(1,'specific indexed phrase '+account,1),
                    row(2,f'<msg><appmsg><type>6</type><title>fixture.bin</title><appattach><totallen>{len(self.blob)}</totallen></appattach>{claim}</appmsg></msg>',self.file_type),
                    row(3,f'<msg><img md5="{self.image_md5}"/></msg>',3),
                    row(4,'[voice]',34,'321')])
            viewer_media.import_voice(a,service,source_id='one',account_alias='one',relative='message/media_0.db',
                capture_id='fixture',evidence={'plaintext':{'sha256':hashlib.sha256(source.read_bytes()).hexdigest()}},path=source)
            for row in a.list_messages(limit=20):
                self.ids[row['account_alias'],str(row['message_type'])]=row['logical_id']

    def asset(self,data,rel):
        with closing(OfflineService(self.state)) as service:
            sha = publish(service.objects,io.BytesIO(data),len(data))['sha256']
            with service.catalog.db as db:
                db.execute('CREATE TABLE IF NOT EXISTS asset_history(source_id,relative_path,file_sha,bytes,cycle_id)')
                db.execute('INSERT INTO asset_history VALUES(?,?,?,?,?)',('one',rel,sha,len(data),'accepted'))
        return sha,hashlib.md5(data).hexdigest()

    def call(self,*params):
        return execute(parse(['--root',str(self.root),*map(str,params)]))

    def verify_export(self,kind,typ,sha,data,extra=()):
        target = self.root/(kind+'.sample')
        self.call('export','--account','one','--id',self.ids['one',typ],
                  '--kind',kind,'--sha',sha,'--out',target,*extra)
        self.assertEqual(target.read_bytes(),data)
        with self.assertRaisesRegex(Refusal,'output_already_exists'):
            self.call('export','--account','one','--id',self.ids['one',typ],
                      '--kind',kind,'--sha',sha,'--out',target,*extra)

    def test_account_scoped_search_dates_context_and_no_sidecar_creation(self):
        old = {str(p):p.stat().st_size for p in self.path.parent.iterdir()}
        self.assertEqual([x['account'] for x in self.call('accounts')['rows']],['one','two'])
        rows = self.call('search','--account','two','--query','specific indexed phrase',
                         '--since','2026-01-01T00:00:00Z','--until','2026-01-02T00:00:00Z')['rows']
        self.assertEqual([r['body_text'] for r in rows],['specific indexed phrase two'])
        self.assertTrue(all(r['account_alias']=='two' for r in self.call('context','--account','two','--id',rows[0]['logical_id'])['rows']))
        with self.assertRaisesRegex(Refusal,'message_not_found_in_selected_account'):
            self.call('detail','--account','two','--id',self.ids['one','1'])
        self.assertEqual(old,{str(p):p.stat().st_size for p in self.path.parent.iterdir()})

    def test_file_candidate_cannot_export_and_verified_types_roundtrip(self):
        target = self.root/'unverified.bin'
        page = self.call('attachments','--account','one','--id',self.ids['one',self.file_type])['file_video']
        self.assertEqual({r['file_sha'] for r in page['rows']},{self.sha,self.old_sha})
        self.assertTrue(all('source_id' not in item and 'relative_path' not in item
                            for row in page['rows'] for item in row['evidence']))
        other = self.call('attachments','--account','two','--id',self.ids['two',self.file_type])
        self.assertEqual(other['file_video']['rows'],[])
        self.assertEqual(other['file_video']['status'],'association_unknown')
        images = self.call('attachments','--account','one','--id',self.ids['one','3'])['image']
        self.assertTrue(images['rows'])
        self.assertTrue(all('example_path' not in item for row in images['rows'] for item in row['evidence']))
        for account,sha in [('two',self.sha),('one',self.old_sha)]:
            with self.assertRaisesRegex(Refusal,'not_confirmed_for_this_message'):
                self.call('export','--account',account,'--id',self.ids[account,self.file_type],
                          '--kind','file','--sha',sha,'--out',target)
            self.assertFalse(target.exists())
        self.verify_export('file',self.file_type,self.sha,self.blob)
        self.verify_export('image','3',self.image_sha,self.png,('--expected-md5',self.image_md5))
        self.verify_export('voice','34',self.voice_sha,self.voice)

    def test_active_writer_committed_wal_visible_uncommitted_not_visible(self):
        with CompactArchive(self.path) as writer:
            writer._db.execute('PRAGMA journal_mode=WAL')
            writer.import_observations({'source_id':'one'},{'snapshot_id':'fresh'},[
                observation(account_alias='one',conversation_id='room',native_locator=100,
                    server_id='100',body_text='committed WAL token')])
            writer._db.execute('BEGIN IMMEDIATE')
            writer.insert_prepared(writer.prepared_observation('fresh',observation(account_alias='uncommitted',
                conversation_id='room',native_locator=101,server_id='101',body_text='uncommitted fixture')))
            try:
                rows = self.call('search','--account','one','--query','committed WAL token')['rows']
                self.assertEqual([r['body_text'] for r in rows],['committed WAL token'])
                self.assertNotIn('uncommitted',[r['account'] for r in self.call('accounts')['rows']])
            finally:
                writer._db.execute('ROLLBACK')


if __name__=='__main__':
    unittest.main()
