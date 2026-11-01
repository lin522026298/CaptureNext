from contextlib import closing
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.tests import test_viewer_media as fixtures
from wechat_capture_next import viewer_media,media_pending


class PendingTests(unittest.TestCase):
    setUp=fixtures.MediaTests.setUp
    ingest=fixtures.MediaTests.ingest
    def failed(self):
        self.service.config=dict(source_id='a',account_alias='synthetic-account')
        self.service.view_path=lambda relative:self.path
        def fault(stage):
            if stage=='after_row':raise RuntimeError('synthetic failure')
        with self.assertRaises(RuntimeError):self.ingest(fault=fault)
    def test_rare_failure_preserves_old_cut_and_resumes_after_cache_advance(self):
        self.failed();original=self.path.read_bytes()
        result=media_pending.preserve(self.archive,self.service)
        self.assertEqual(result['copied_bytes'],len(original))
        self.assertEqual(media_pending.preserve(self.archive,self.service)['copied_bytes'],0)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('UPDATE VoiceInfo SET unknown_text=\'later cut\'');db.commit()
        media_pending.resume(self.archive,self.service)
        self.assertEqual(viewer_media.verify(self.archive,self.service)['status'],'verified')
        rows=[viewer_media._decode(self.archive.pool.get_text(r[0])) for r in self.archive._db.execute("SELECT payload_id FROM next_media_row WHERE table_name='VoiceInfo'")]
        self.assertEqual(rows[0]['unknown_text'],'exact')
        self.assertFalse(list((self.service.state/'tmp/native-media-pending').glob('*.db')))
        self.assertFalse(list((self.service.state/'tmp/native-media-pending').glob('*.pending')))
    def test_unavailable_old_cut_is_not_replaced_with_new_source_bytes(self):
        self.failed()
        with closing(sqlite3.connect(self.path)) as db:db.execute('UPDATE VoiceInfo SET unknown_text=\'new cut\'');db.commit()
        with self.assertRaisesRegex(ValueError,'unavailable'):media_pending.preserve(self.archive,self.service)
        with self.assertRaises(ValueError):media_pending.resume(self.archive,self.service)
        self.assertEqual(len(media_pending.pending_rows(self.archive)),1)
    def test_reopen_replays_pending_copy_after_original_was_replaced(self):
        self.failed();media_pending.preserve(self.archive,self.service)
        archive_path=self.archive.path
        self.archive.close()
        self.archive=CompactArchive(archive_path);self.addCleanup(self.archive.close)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE VoiceInfo SET unknown_text='new cache'");db.commit()
        result=media_pending.resume(self.archive,self.service)
        self.assertEqual(len(result),1)
        self.assertEqual(viewer_media.verify(self.archive,self.service)['status'],'verified')
        self.assertEqual(len(media_pending.pending_rows(self.archive)),0)
    def test_active_commit_before_cleanup_recovers_without_current_checkpoint(self):
        self.failed();media_pending.preserve(self.archive,self.service)
        snapshot=media_pending.pending_rows(self.archive)[0]['snapshot_id']
        root=self.service.state/'tmp/native-media-pending'
        (root/(snapshot+'.interrupted.pending')).write_bytes(b'partial copy')
        unknown=root/('media_'+'f'*64+'.db');unknown.write_bytes(b'unknown receipt')
        self.ingest()  # Simulates crash after active commit but before cleanup.
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE VoiceInfo SET unknown_text='later checkpoint'");db.commit()
        self.assertEqual(media_pending.resume(self.archive,self.service),[])
        self.assertFalse((root/(snapshot+'.db')).exists())
        self.assertFalse((root/(snapshot+'.interrupted.pending')).exists())
        self.assertEqual(unknown.read_bytes(),b'unknown receipt')
        self.assertEqual(viewer_media.verify(self.archive,self.service)['status'],'verified')
    def test_interrupted_copy_is_retryable_and_foreign_entries_are_not_removed(self):
        self.failed()
        with patch('wechat_capture_next.media_pending.os.rename',side_effect=OSError('synthetic publish failure')):
            with self.assertRaisesRegex(OSError,'publish failure'):
                media_pending.preserve(self.archive,self.service)
        root=self.service.state/'tmp/native-media-pending'
        self.assertFalse(list(root.glob('*.pending')))
        media_pending.preserve(self.archive,self.service)
        foreign=root/'unknown.txt';foreign.write_bytes(b'preserve me')
        with self.assertRaisesRegex(ValueError,'unknown'):
            media_pending.resume(self.archive,self.service)
        self.assertEqual(foreign.read_bytes(),b'preserve me')
        self.assertEqual(len(media_pending.pending_rows(self.archive)),1)
    def test_real_process_exit_after_active_commit_recovers_owned_old_cut(self):
        folder=self.root/'crashed-process';folder.mkdir()
        script='''import os,sys,tempfile
from unittest.mock import patch
from wechat_capture_next.tests import test_media_pending as tests
original=tempfile.TemporaryDirectory
with patch.object(tests.fixtures.tempfile,'TemporaryDirectory',lambda:original(dir=sys.argv[1])):
    f=tests.PendingTests('test_unavailable_old_cut_is_not_replaced_with_new_source_bytes');f.setUp()
f.failed();tests.media_pending.preserve(f.archive,f.service);f.ingest()
os._exit(73)
'''
        result=subprocess.run([sys.executable,'-c',script,str(folder)],capture_output=True)
        self.assertEqual(result.returncode,73,result.stderr.decode(errors='replace'))
        roots=list(folder.iterdir());self.assertEqual(len(roots),1);root=roots[0]
        from wechat_capture_next.tests.test_union_assets import OfflineService
        with closing(OfflineService(root/'state')) as service,CompactArchive(root/'archive.sqlite') as archive:
            service.config=dict(source_id='a',account_alias='synthetic-account')
            service.view_path=lambda relative:root/'media.db'
            self.assertEqual(len(list((service.state/'tmp/native-media-pending').glob('*.db'))),1)
            self.assertEqual(media_pending.resume(archive,service),[])
            self.assertFalse(list((service.state/'tmp/native-media-pending').glob('*.db')))
            self.assertEqual(viewer_media.verify(archive,service)['status'],'verified')
