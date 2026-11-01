"""Full encrypted-file -> collector -> backup/restore/export synthetic tests."""
from contextlib import closing
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zlib
from unittest.mock import patch

from wechat_capture_v2.common import canonical,digest_file,writer_lock
from wechat_capture_v2.export import backup,export_jsonl,export_wua,restore_backup,extract_assets,verify_asset_tree
from wechat_capture_v2.imports import import_keyring,import_plain
from wechat_capture_v2.service import CaptureService,initialize
from wechat_capture_v2.tests.test_backend import KEY,TABLE,encrypt,make_plain
from wua.store import ArchiveStore
from wechat_capture_v2.common import decoded
from wechat_capture_v2.source import verify_unchanged_pair


def reserve80(path):
    """Use SQLite's documented file-control (38), only on a new test database."""
    library=ctypes.CDLL('sqlite3.dll') if sys.platform=='win32' else ctypes.CDLL('libsqlite3.so.0')
    pointer=ctypes.c_void_p()
    library.sqlite3_open.argtypes=[ctypes.c_char_p,ctypes.POINTER(ctypes.c_void_p)]
    library.sqlite3_file_control.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_int,ctypes.c_void_p]
    library.sqlite3_exec.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]
    library.sqlite3_close.argtypes=[ctypes.c_void_p]
    if library.sqlite3_open(str(path).encode('utf-8'),ctypes.byref(pointer)):
        raise RuntimeError('synthetic SQLite open failed')
    try:
        count=ctypes.c_int(80)
        if library.sqlite3_file_control(pointer,None,38,ctypes.byref(count)):
            raise RuntimeError('synthetic SQLite reserve control failed')
        if library.sqlite3_exec(pointer,b'VACUUM',None,None,None):
            raise RuntimeError('synthetic SQLite VACUUM failed')
    finally:
        library.sqlite3_close(pointer)
    if path.read_bytes()[20]!=80:
        raise RuntimeError('synthetic database reserve mismatch')


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.live=self.root/'live'
        self.live.mkdir()
        self.database=self.live/'db_storage'
        (self.database/'message').mkdir(parents=True)
        self.plain=self.root/'fixture.db'
        make_plain(self.plain)
        reserve80(self.plain)
        self.keyring=self.root/'incoming.json'
        self.keyring.write_text(canonical({'databases':[{'relative_path':'message/message_0.db',
            'verified':True,'raw_encryption_key_hex':KEY.hex()}]}),encoding='utf-8')
        self.refresh_source()
        self.state=self.root/'state'
        initialize(self.state,self.database,self.keyring,source_id='synthetic',account_alias='synthetic-account',
                   self_username='wxid_synthetic_self',asset_root=self.live)
        self.service=CaptureService(self.state)

    def refresh_source(self):
        data=self.plain.read_bytes()
        (self.database/'message'/'message_0.db').write_bytes(b''.join(
            encrypt(data[offset:offset+4096],offset//4096+1) for offset in range(0,len(data),4096)))

    def tearDown(self):
        self.service.close()
        self.temp.cleanup()

    def test_stop_backlog_reopen_and_lossless_exports(self):
        first=self.service.capture(force=True)
        self.assertEqual(first['summary']['active_messages'],1)
        self.service.close()
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute(f'INSERT INTO "{TABLE}" VALUES(-1,-1,1,7,-999,?,NULL,?,0)',('old sequence arrives offline',b'raw'))
        self.refresh_source()
        self.service=CaptureService(self.state)
        after=self.service.capture(force=True)
        self.assertEqual(after['summary']['active_messages'],2)
        self.assertEqual(after['databases'][0]['new_versions'],1)
        self.assertEqual(self.service.capture(force=True)['databases'][0]['new_versions'],0)
        result=export_jsonl(self.service,self.root/'export.jsonl')
        self.assertEqual(result['rows'],2)
        result=export_wua(self.service,self.root/'export.wua.sqlite')
        self.assertEqual(result['observations'],2)
        self.assertEqual(result['stats']['logical_messages'],2)

    def test_media_backup_restore_and_separate_database_extract(self):
        (self.live/'synthetic-asset.bin').write_bytes(b'asset'*10000)
        report=self.service.capture(force=True,assets=True)
        self.assertEqual(report['assets']['new_versions'],1)
        self.assertTrue(backup(self.service,self.root/'backup',include_secrets=True)['pass'])
        restored=self.root/'restored'
        self.assertTrue(restore_backup(self.root/'backup',restored)['pass'])
        other=CaptureService(restored)
        try:
            self.assertEqual(other.catalog.summary()['active_messages'],1)
            self.assertTrue(other.objects.verify_all()['pass'])
            self.assertEqual(extract_assets(other,self.root/'assets-restored')['files_restored'],1)
            self.assertEqual(digest_file(self.root/'assets-restored'/'synthetic-asset.bin'),digest_file(self.live/'synthetic-asset.bin'))
            self.assertTrue(verify_asset_tree(other,self.root/'assets-restored')['pass'])
            (self.root/'assets-restored'/'synthetic-asset.bin').write_bytes(b'tampered')
            self.assertFalse(verify_asset_tree(other,self.root/'assets-restored')['pass'])
            row=other.catalog.db.execute('SELECT evidence_json FROM db_capture LIMIT 1').fetchone()
            digest=json.loads(row[0])['plaintext']['sha256']
            other.objects.restore(digest,self.root/'extracted.db')
            self.assertEqual(digest_file(self.root/'extracted.db'),digest_file(self.plain))
            with closing(sqlite3.connect(self.root/'extracted.db')) as db:
                self.assertEqual(db.execute(f'SELECT count(*) FROM "{TABLE}"').fetchone()[0],1)
        finally:
            other.close()

    def test_key_import_verifies_current_account_and_rejects_wrong_key(self):
        self.assertTrue(import_keyring(self.service,self.keyring)['pass'])
        original=digest_file(self.state/'90_SECRETS_PLAINTEXT_RESTRICTED'/'keyring.json')
        bad=self.root/'bad.json'
        bad.write_text(canonical({'databases':[{'relative_path':'message/message_0.db','verified':True,
                'raw_encryption_key_hex':bytes(32).hex()}]}),encoding='utf-8')
        with self.assertRaises(ValueError):
            import_keyring(self.service,bad)
        self.assertEqual(digest_file(self.state/'90_SECRETS_PLAINTEXT_RESTRICTED'/'keyring.json'),original)

    def test_historical_plain_import_is_readonly_replay_deduplicated(self):
        manifest=self.root/'manifest.json'
        manifest.write_text(canonical({'source_meta':{'source_id':'old-source'},'account_alias':'synthetic-account',
            'self_username':'wxid_synthetic_self','databases':[{'relative_path':'message/message_0.db','path':str(self.plain)}]}),encoding='utf-8')
        original=digest_file(self.plain)
        self.assertEqual(import_plain(self.service,manifest)['new_versions'],1)
        self.assertEqual(import_plain(self.service,manifest)['new_versions'],0)
        self.assertEqual(digest_file(self.plain),original)

    def test_live_source_output_and_invalid_retry_are_rejected(self):
        with self.assertRaises(ValueError):
            export_jsonl(self.service,self.live/'not-allowed.jsonl')
        self.assertFalse((self.live/'not-allowed.jsonl').exists())
        with self.assertRaises(ValueError):
            self.service.capture(retries=0)

    def test_interpretation_changes_export_as_separate_observations(self):
        self.service.capture(force=True)
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute("UPDATE Name2Id SET user_name='renamed-synthetic-peer' WHERE rowid=7")
        self.refresh_source()
        self.service.capture(force=True)
        result=export_wua(self.service,self.root/'reinterpretation.wua.sqlite')
        self.assertEqual(result['observations'],2)

    def test_bulk_export_matches_unchanged_legacy_public_importer(self):
        self.service.capture(force=True)
        with closing(sqlite3.connect(self.plain)) as db,db:
            db.execute(f'UPDATE "{TABLE}" SET message_content=?',('new revision',))
        self.refresh_source()
        self.service.capture(force=True)
        actual=export_wua(self.service,self.root/'bulk.wua.sqlite')
        with ArchiveStore(self.root/'public.wua.sqlite') as expected:
            for capture in self.service.catalog.db.execute('SELECT * FROM db_capture ORDER BY rowid'):
                evidence=json.loads(capture['evidence_json'])
                records=[]
                for row in self.service.catalog.db.execute('SELECT * FROM version WHERE first_capture=?',(capture['id'],)):
                    item=json.loads(row['normalized_json'])
                    item['raw_record']=decoded(json.loads(zlib.decompress(row['raw_z'])))
                    item['input_database_sha256']=evidence['plaintext']['sha256']
                    item['input_schema_sha256']=evidence['reader']['schema_sha256']
                    records.append(item)
                expected.import_observations({'source_id':capture['source_id'],'platform':'windows','kind':'capture-v2-raw-observations'},
                    {'snapshot_id':capture['id'],'source_id':capture['source_id'],'basis':'authenticated-source-cut',
                     'evidence_sha256':hashlib.sha256(capture['evidence_json'].encode()).hexdigest()},records)
            self.assertEqual(actual['semantic_digest'],expected.semantic_digest())
            self.assertEqual(actual['stats'],expected.stats())

    def test_asset_time_slices_resume_without_total_count_limit(self):
        paths=[]
        for index in range(3):
            path=self.live/f'synthetic-{index}.bin'
            path.write_bytes(bytes([index])*100)
            paths.append((path.name,path))
        tick=[0.0]
        def clock():
            tick[0]+=0.1
            return tick[0]
        cycle=self.service.catalog.begin_cycle('asset_slices')
        with patch('wechat_capture_v2.service.source_files',side_effect=lambda root:iter(paths)),patch('wechat_capture_v2.service.time.monotonic',side_effect=clock):
            complete=False
            passes=total=0
            while not complete:
                result=self.service.capture_assets(cycle,force=True,budget_seconds=0.15)
                complete=result['complete']
                total+=result['new_versions']
                passes+=1
                self.assertLess(passes,20)  # store / readback / publication are separate slices
        self.assertGreater(passes,1)
        self.assertEqual(total,3)
        self.assertEqual(self.service.catalog.summary()['assets'],3)

    def test_source_unavailable_is_partial_and_next_cycle_recovers(self):
        self.service.capture(force=True)
        previous=self.service.catalog.checkpoint('synthetic','message/message_0.db')
        renamed=self.live/'db_storage.synthetic-offline'
        self.database.rename(renamed)
        try:
            self.assertEqual(self.service.capture(force=True)['status'],'partial')
            self.assertEqual(self.service.catalog.checkpoint('synthetic','message/message_0.db'),previous)
        finally:
            renamed.rename(self.database)
        self.assertEqual(self.service.capture(force=True)['status'],'local_complete')

    def test_verification_detects_missing_referenced_object(self):
        self.service.capture(force=True)
        self.assertTrue(self.service.verify_state()['pass'])
        with self.service.objects.db:
            self.service.objects.db.execute('DELETE FROM file')
        with self.assertRaisesRegex(ValueError,'missing backup objects'):
            self.service.verify_state()

    def test_watch_cli_combines_messages_with_resumable_asset_slices(self):
        (self.live/'asset-for-watch.bin').write_bytes(b'watch-asset')
        self.service.close()
        completed=subprocess.run([sys.executable,'-m','wechat_capture_v2','watch','--state',str(self.state),
            '--assets','--interval','0.01','--reconcile-seconds','300','--asset-budget-seconds','0.000001',
            '--run-seconds','0.2'],capture_output=True,text=True,encoding='utf-8',timeout=45)
        self.service=CaptureService(self.state)
        self.assertEqual(completed.returncode,0,completed.stderr)
        rows=[json.loads(line) for line in completed.stdout.splitlines()]
        self.assertTrue(rows[-1]['watch_finished'])
        self.assertEqual(rows[-1]['summary']['active_messages'],1)
        self.assertEqual(rows[-1]['summary']['assets'],1)

    def test_restored_backup_can_be_read_without_client_or_keys(self):
        self.service.capture(force=True)
        backup(self.service,self.root/'backup-no-keys',include_secrets=False)
        restored=self.root/'restored-no-keys'
        restore_backup(self.root/'backup-no-keys',restored)
        offline=self.root/'live.synthetic-offline'
        self.live.rename(offline)
        try:
            recovered=CaptureService(restored)
            try:
                self.assertEqual(recovered.keys,{})
                self.assertEqual(recovered.catalog.summary()['active_messages'],1)
                self.assertTrue(recovered.verify_state()['pass'])
                self.assertEqual(export_jsonl(recovered,self.root/'offline.jsonl')['rows'],1)
                self.assertEqual(recovered.capture(force=True)['status'],'partial')
            finally:
                recovered.close()
        finally:
            offline.rename(self.live)
        recovered=CaptureService(restored)
        try:
            self.assertTrue(import_keyring(recovered,self.keyring)['pass'])
            self.assertEqual(len(recovered.keys),1)
        finally:
            recovered.close()

    def test_ten_identical_reconciliations_reuse_only_committed_matching_parser(self):
        first=self.service.capture(force=True)
        captures=self.service.catalog.summary()['captures']
        objects=self.service.objects.db.execute('SELECT count(*) FROM file').fetchone()[0]
        for _ in range(10):
            row=self.service.capture(force=True,reuse_identical=True)
            self.assertEqual(row['databases'][0]['status'],'verified_unchanged')
        self.assertEqual(self.service.catalog.summary()['captures'],captures)
        self.assertEqual(self.service.objects.db.execute('SELECT count(*) FROM file').fetchone()[0],objects)
        self.service.interpretation_binding='synthetic-new-parser'
        self.assertEqual(self.service.capture(force=True,reuse_identical=True)['databases'][0]['status'],'accepted')

    def test_idle_poll_does_not_create_ledger_rows_or_reports(self):
        self.service.capture(force=True)
        before=(self.service.catalog.db.execute('SELECT count(*) FROM cycle').fetchone()[0],len(list((self.state/'reports').glob('*.json'))))
        for _ in range(10):
            self.assertEqual(self.service.capture()['status'],'idle')
        after=(self.service.catalog.db.execute('SELECT count(*) FROM cycle').fetchone()[0],len(list((self.state/'reports').glob('*.json'))))
        self.assertEqual(before,after)

    def test_same_metadata_corruption_detected_and_not_silently_skipped(self):
        self.service.capture(force=True)
        path=self.database/'message'/'message_0.db'
        info=path.stat();data=bytearray(path.read_bytes());data[500]^=1;path.write_bytes(data)
        os.utime(path,ns=(info.st_atime_ns,info.st_mtime_ns))
        report=self.service.capture(force=True,reuse_identical=True,retries=1)
        self.assertEqual(report['status'],'partial')
        self.assertIn('message/message_0.db',self.service._failed_databases)
        self.assertEqual(self.service.capture(retries=1)['status'],'partial')
        self.refresh_source();self.service._retry_schedule.clear()
        self.assertIn(self.service.capture(retries=1)['status'],('local_complete','local_complete_assets_pending'))

    def test_raw_wal_absent_empty_and_tail_change_are_not_interchangeable(self):
        self.service.capture(force=True)
        row=self.service.catalog.db.execute('SELECT evidence_json FROM db_capture LIMIT 1').fetchone()
        evidence=json.loads(row[0]);source=self.database/'message'/'message_0.db'
        self.assertIsNotNone(verify_unchanged_pair(source,evidence))
        wal=Path(str(source)+'-wal');wal.write_bytes(b'')
        self.assertIsNone(verify_unchanged_pair(source,evidence))
        empty={**evidence,'raw':{**evidence['raw'],'wal_raw':{'sha256':hashlib.sha256(b'').hexdigest()}}}
        self.assertIsNotNone(verify_unchanged_pair(source,empty))
        wal.write_bytes(b'changed uncommitted tail')
        self.assertIsNone(verify_unchanged_pair(source,empty))

    def test_idle_inventory_change_cannot_be_swallowed(self):
        self.service.capture(force=True)
        (self.database/'new.db').write_bytes(b'new unknown database')
        self.assertEqual(self.service.capture()['status'],'partial')

    def test_killed_writer_lock_releases_and_running_cycle_is_not_success(self):
        code="from wechat_capture_v2.common import writer_lock; import os,sys; x=writer_lock(sys.argv[1]); x.__enter__(); os._exit(7)"
        result=subprocess.run([sys.executable,'-c',code,str(self.state)],capture_output=True,timeout=30)
        self.assertEqual(result.returncode,7)
        with writer_lock(self.state):
            pass
        old=self.service.catalog.begin_cycle('synthetic_crashed_cycle')
        self.service.close()
        self.service=CaptureService(self.state)
        self.assertEqual(self.service.catalog.db.execute('SELECT status FROM cycle WHERE id=?',(old,)).fetchone()[0],'interrupted')
