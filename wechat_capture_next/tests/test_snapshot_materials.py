"""Material presence declarations are metadata, never key/source readiness."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wechat_capture_next import pair_repository as repo
from wechat_capture_next import backup_listing


class SnapshotMaterialsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.repository=self.root/'repo'
        self.payload=self.root/'payload';self.payload.write_bytes(b'A'*8192)
        self.key=self.root/'key';self.key.write_bytes(b'{"synthetic_not_ready":true}')
        self.owner=dict(schema=repo.SCHEMA,catalog_instance='synthetic',union_id='synthetic')
        self.files={'state/catalog.sqlite':self.payload,'union/archive.wua.sqlite':self.payload}

    def publish(self,files=None,context=None):
        return repo.publish(self.repository,self.owner,files or self.files,context or {})

    def test_presence_uses_actual_manifest_members_not_context_claims(self):
        first=self.publish(context=dict(includes_secrets=True,provenance_included=True))
        with patch.object(repo.Blocks,'get',side_effect=AssertionError('listing must not read payload')), \
             patch.object(repo.Blocks,'walk',side_effect=AssertionError('listing must not reconstruct payload')):
            row=repo.snapshots(self.repository)[0]
        self.assertEqual(row['snapshot_id'],first['snapshot_id'])
        self.assertFalse(row['includes_secrets']);self.assertFalse(row['provenance_included'])
        files=dict(self.files);files['state/'+repo.legacy.SECRETS]=self.key
        for name in ('pre-evidence-catalog.sqlite.zst','legacy-bag-derived.tar.zst'):
            files['provenance/'+name]=self.payload
        second=self.publish(files,dict(includes_secrets=False,provenance_included=False))
        with patch.object(repo.Blocks,'get',side_effect=AssertionError('no key payload read')):
            row=repo.snapshots(self.repository)[0]
        self.assertEqual(row['snapshot_id'],second['snapshot_id'])
        self.assertTrue(row['includes_secrets']);self.assertTrue(row['provenance_included'])
        self.assertEqual(row['materials_scope'],'manifest_file_members_only_not_payload_or_live_source_verification')

    def test_keyed_point_needs_pin_to_survive_two_new_keyless_generations(self):
        for pinned in (False,True):
            with self.subTest(pinned=pinned):
                self.repository=self.root/('pinned' if pinned else 'rolling')
                self.payload.write_bytes(b'A'*8192)
                first=self.publish(dict(self.files,**{'state/'+repo.legacy.SECRETS:self.key}))
                if pinned:repo.pin(self.repository,first['snapshot_id'],True)
                self.payload.write_bytes(b'B'*8192);second=self.publish()
                before=repo.snapshots(self.repository)
                self.assertTrue(self.publish()['noop'])
                self.assertEqual(before,repo.snapshots(self.repository))
                self.payload.write_bytes(b'C'*8192);third=self.publish()
                rows=repo.snapshots(self.repository);ids={r['snapshot_id'] for r in rows}
                self.assertEqual(first['snapshot_id'] in ids,pinned)
                self.assertIn(second['snapshot_id'],ids);self.assertIn(third['snapshot_id'],ids)
                if pinned:
                    kept=next(r for r in rows if r['snapshot_id']==first['snapshot_id'])
                    self.assertTrue(kept['pinned']);self.assertTrue(kept['includes_secrets'])
                    out=self.root/'recovered-fixed'
                    repo.restore_files(self.repository,first['snapshot_id'],out)
                    self.assertEqual((out/'state'/repo.legacy.SECRETS).read_bytes(),self.key.read_bytes())

    def test_legacy_union_listing_does_not_guess_companion_keys(self):
        from types import SimpleNamespace
        with patch('wechat_capture_next.union_backup._repository',return_value=(self.root,{})), \
             patch('wechat_capture_next.union_backup._check'), \
             patch('wechat_capture_next.union_backup._manifest'), \
             patch('wechat_capture_next.backup._readonly',return_value=SimpleNamespace(
                 execute=lambda *args:[('a'*64,'synthetic')],close=lambda:None)):
            row=backup_listing._legacy(self.root)[0]
        self.assertIsNone(row['includes_secrets']);self.assertIsNone(row['provenance_included'])
