"""Owned-worker integration with encrypted synthetic auxiliary media only."""
from contextlib import closing
import json
import sqlite3
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from wechat_capture_next import viewer_media, product_settings
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.product import ProductCore
from wechat_capture_next.tests import test_product as fixtures
from wechat_capture_next.state_guard import writer_lock
from wechat_capture_v2.common import canonical, digest_file
from wechat_capture_v2.tests.test_backend import KEY, encrypt
from wechat_capture_v2.tests.test_integration import reserve80


class ProductMediaPendingTests(unittest.TestCase):
    setUp=fixtures.ProductTests.setUp
    tearDown=fixtures.ProductTests.tearDown
    pages=fixtures.ProductTests.pages
    publish=fixtures.ProductTests.publish
    init_service=fixtures.ProductTests.init_service
    wait=fixtures.ProductTests.wait

    def core(self):
        fixtures.ProductTests.prepared(self)
        self.media_plain=self.root/'synthetic-media.sqlite'
        with closing(sqlite3.connect(self.media_plain)) as db:
            db.execute('CREATE TABLE Name2Id(user_name TEXT)')
            db.execute("INSERT INTO Name2Id VALUES('room')")
            db.execute('CREATE TABLE VoiceInfo(chat_name_id,svr_id,create_time,voice_data BLOB,unknown_text)')
            db.execute('INSERT INTO VoiceInfo VALUES(1,100,1767225600,?,?)',(b'original voice bytes','first cut'))
            db.commit()
        reserve80(self.media_plain)
        self.media_source=self.source.parent/'message/media_0.db'
        self.media_source.parent.mkdir()
        self.publish_media()
        keyring=self.state/'90_SECRETS_PLAINTEXT_RESTRICTED/keyring.json'
        value=json.loads(keyring.read_text(encoding='utf-8'))
        value['databases'].append(dict(relative_path='message/media_0.db',verified=True,raw_encryption_key_hex=KEY.hex()))
        keyring.write_text(canonical(value),encoding='utf-8')
        return self.reopen()

    def reopen(self):
        settings=dict(product_settings.DEFAULTS,auto_capture=False)
        with patch('wechat_capture_next.product.preferences.load',return_value=settings):
            core=ProductCore(self.state,self.root/'product',union_root=self.formal,
                repository_root=self.state_repo,union_repository=self.union_repo,interval=.05)
        self.addCleanup(core.close);self.wait(core)
        return core

    def publish_media(self):
        raw=self.media_plain.read_bytes()
        self.media_source.write_bytes(b''.join(encrypt(raw[i:i+4096],i//4096+1) for i in range(0,len(raw),4096)))

    def revise_media(self):
        with closing(sqlite3.connect(self.media_plain)) as db:
            db.execute("UPDATE VoiceInfo SET unknown_text='second cut'");db.commit()
        self.publish_media()

    def retained(self,core):
        with (writer_lock(self.formal),CompactArchive(self.formal/'archive.wua.sqlite',readonly=True) as archive,
              closing(sqlite3.connect((self.state/'catalog.sqlite').as_uri()+'?mode=ro',uri=True)) as catalog,
              closing(sqlite3.connect((self.state/'objects.sqlite').as_uri()+'?mode=ro',uri=True)) as objects):
            offline=SimpleNamespace(state=self.state,catalog=SimpleNamespace(path=self.state/'catalog.sqlite',db=catalog),
                objects=SimpleNamespace(path=self.state/'objects.sqlite',db=objects))
            viewer_media.verify(archive,offline)
            snapshots=[dict(r) for r in archive._db.execute('SELECT * FROM next_media_snapshot ORDER BY db_sha')]
            raw=[viewer_media._decode(archive.pool.get_text(r[0])) for r in archive._db.execute(
                "SELECT payload_id FROM next_media_row WHERE table_name='VoiceInfo'")]
            return snapshots,raw

    def checkpoint(self):
        with closing(sqlite3.connect((self.state/'catalog.sqlite').as_uri()+'?mode=ro',uri=True)) as db:
            return tuple(db.execute("SELECT * FROM checkpoint WHERE source_id='fixture' AND relative_path='message/media_0.db'").fetchone())

    def test_aux_only_capture_imports_new_exact_cut_without_message_rescan_or_db_copy(self):
        core=self.core()
        self.wait(core,core.submit(dict(action='capture',full=False,assets=False)))
        first,raw=self.retained(core)
        self.assertEqual(raw[0]['unknown_text'],'first cut')
        self.revise_media()
        with (patch.object(core,'_sync',side_effect=AssertionError('aux-only capture must not rescan message union')),
                patch.object(core,'_after_capture',wraps=core._after_capture) as after,
                patch('wechat_capture_next.media_pending.tempfile.mkstemp',side_effect=AssertionError('normal success must not copy native DB'))):
            self.wait(core,core.submit(dict(action='capture',full=False,assets=False)))
            result=after.call_args.args[0]
        media=next(row for row in result['databases'] if row['relative_path']=='message/media_0.db')
        self.assertEqual(media['status'],'accepted');self.assertEqual(media['new_versions'],0)
        snapshots,raw=self.retained(core)
        self.assertEqual({row['unknown_text'] for row in raw},{'first cut','second cut'})
        self.assertEqual(len(snapshots),2)
        self.assertTrue(all(row['source_id']=='fixture' and row['account_alias']=='fixture' and row['status']=='active' for row in snapshots))
        self.assertNotEqual(snapshots[0]['db_sha'],snapshots[1]['db_sha'])
        self.assertFalse((self.state/'tmp/native-media-pending').exists())

    def test_failed_partial_import_old_cut_survives_capture_advance_and_product_restart(self):
        core=self.core();original=viewer_media.import_voice
        def fail_partial(*args,**kwargs):
            def fault(stage):
                if stage=='after_row':raise RuntimeError('synthetic partial import crash')
            return original(*args,**kwargs,fault=fault)
        with patch('wechat_capture_next.viewer_media.import_voice',side_effect=fail_partial):
            self.wait(core,core.submit(dict(action='capture',full=False,assets=False)))
        self.assertEqual(core.media_status['status'],'pending')
        recovery=self.state/'tmp/native-media-pending'
        old_copy=next(recovery.glob('*.db'));old_sha=digest_file(old_copy)
        self.revise_media()
        core._media_retry_after=time.monotonic()+3600
        self.wait(core,core.submit(dict(action='capture',full=False,assets=False)))
        self.assertNotEqual(digest_file(core.service.view_path('message/media_0.db')),old_sha)
        self.assertEqual(digest_file(old_copy),old_sha)
        core.close();core=self.reopen()
        snapshots,raw=self.retained(core)
        self.assertEqual(len(snapshots),2)
        self.assertEqual({row['unknown_text'] for row in raw},{'first cut','second cut'})
        self.assertFalse(list(recovery.glob('*.db')))
        self.assertFalse(list(recovery.glob('*.pending')))
        self.assertEqual(core.media_status['status'],'ready')

    def test_preserve_failure_blocks_worker_before_capture_view_or_checkpoint_advance(self):
        core=self.core()
        self.wait(core,core.submit(dict(action='capture',full=False,assets=False)))
        before=digest_file(core.service.view_path('message/media_0.db'))
        checkpoint=self.checkpoint()
        self.revise_media()
        core.media_status=dict(status='pending');core._media_preserved=False
        with patch('wechat_capture_next.media_pending.preserve',side_effect=OSError('synthetic preservation refusal')):
            self.wait(core,core.submit(dict(action='capture',full=False,assets=False)),status='failed')
        self.assertEqual(digest_file(core.service.view_path('message/media_0.db')),before)
        self.assertEqual(self.checkpoint(),checkpoint)


if __name__=='__main__':unittest.main()
