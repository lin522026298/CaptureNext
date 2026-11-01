"""Cooperative assets, source gaps and write-amplification regressions."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
from wechat_capture_v2.objects import Objects,PendingImport,CHUNK_BYTES
from wechat_capture_v2.common import digest_file
from wechat_capture_v2.tests import test_integration as fixture


class PendingAssetTests(unittest.TestCase):
    def test_sliced_two_pass_publication_empty_and_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);objects=Objects(root/'objects.sqlite')
            try:
                for content in (b'',os.urandom(CHUNK_BYTES*4+13)):
                    path=root/'asset';path.write_bytes(content)
                    pending=PendingImport(objects,path)
                    pending.advance(time.monotonic())
                    key=hashlib.sha256(content).hexdigest()
                    self.assertIsNone(objects.db.execute('SELECT 1 FROM file WHERE hash=?',(key,)).fetchone())
                    # Simulated process restart: committed chunks remain, acceptance does not.
                    objects.close();objects=Objects(root/'objects.sqlite');pending=PendingImport(objects,path)
                    passes=0
                    while pending.result is None:
                        pending.advance(time.monotonic());passes+=1
                        self.assertLess(passes,40)
                    self.assertGreaterEqual(passes,3)
                    target=root/f'restored-{len(content)}';objects.restore(key,target)
                    self.assertEqual(target.read_bytes(),content)
                self.assertTrue(objects.verify_all()['pass'])
            finally:objects.close()

    def test_generation_change_and_low_space_never_publish(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);path=root/'asset';path.write_bytes(os.urandom(CHUNK_BYTES*3))
            objects=Objects(root/'objects.sqlite')
            try:
                pending=PendingImport(objects,path);pending.advance(time.monotonic())
                path.write_bytes(b'new generation')
                with self.assertRaises(RuntimeError):pending.advance(time.monotonic()+1)
                self.assertEqual(objects.db.execute('SELECT count(*) FROM file').fetchone()[0],0)
                pending=PendingImport(objects,path)
                with patch('wechat_capture_v2.objects.shutil.disk_usage',return_value=type('Disk',(),{'free':1})()):
                    with self.assertRaises(OSError):pending.advance(time.monotonic()+1)
                self.assertEqual(objects.db.execute('SELECT count(*) FROM file').fetchone()[0],0)
            finally:objects.close()


class ResidentRegressions(unittest.TestCase):
    setUp=fixture.IntegrationTests.setUp
    tearDown=fixture.IntegrationTests.tearDown
    refresh_source=fixture.IntegrationTests.refresh_source
    def test_unchanged_head_is_not_rewritten_but_checkpoint_advances(self):
        self.service.capture(force=True)
        rows=self.service.catalog.db.execute('SELECT * FROM head').fetchall()
        old=[tuple(r) for r in rows]
        checkpoint=self.service.catalog.checkpoint('synthetic','message/message_0.db')
        changes=self.service.catalog.db.execute('SELECT count(*) FROM transition').fetchone()[0]
        self.service.capture(force=True)
        self.assertEqual(old,[tuple(r) for r in self.service.catalog.db.execute('SELECT * FROM head')])
        self.assertNotEqual(checkpoint['capture_id'],self.service.catalog.checkpoint('synthetic','message/message_0.db')['capture_id'])
        self.assertEqual(changes,self.service.catalog.db.execute('SELECT count(*) FROM transition').fetchone()[0])

    def test_missing_inventory_stays_partial_and_backoff_has_no_ledger_writes(self):
        self.service.capture(force=True)
        source=self.database/'message'/'message_0.db';moved=self.root/'offline.db';source.rename(moved)
        try:
            report=self.service.capture()
            self.assertEqual(report['status'],'partial')
            total=self.service.catalog.db.execute('SELECT count(*) FROM cycle').fetchone()[0]
            for _ in range(5):
                report=self.service.capture();self.assertEqual(report['status'],'partial')
            self.assertEqual(total,self.service.catalog.db.execute('SELECT count(*) FROM cycle').fetchone()[0])
        finally:moved.rename(source)
        self.service._global_retry_at=0
        self.assertEqual(self.service.capture(reuse_identical=True)['status'],'local_complete')

    def test_message_rounds_continue_while_large_asset_pending(self):
        path=self.live/'new-large.bin';path.write_bytes(os.urandom(CHUNK_BYTES*8))
        first=self.service.capture(force=True,assets=True,asset_budget_seconds=.000001)
        self.assertFalse(first['assets']['complete'])
        self.assertEqual(first['summary']['assets'],0)
        # A database-only cycle is not blocked by the pending whole asset.
        self.assertEqual(self.service.capture()['summary']['active_messages'],1)
        for _ in range(50):
            result=self.service.capture(assets=True,asset_budget_seconds=.000001)
            if result['assets']['complete']:break
        self.assertTrue(result['assets']['complete'])
        self.assertEqual(result['summary']['assets'],1)
        self.assertEqual(digest_file(path),self.service.catalog.db.execute('SELECT file_sha FROM asset').fetchone()[0])

    def test_many_small_assets_finish_all_phases_in_one_available_slice(self):
        for index in range(100):(self.live/f'asset-{index}').write_bytes(bytes([index])*100)
        report=self.service.capture(force=True,assets=True,asset_budget_seconds=10)
        self.assertTrue(report['assets']['complete'])
        self.assertEqual(report['assets']['new_versions'],100)
