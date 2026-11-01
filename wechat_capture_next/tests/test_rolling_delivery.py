from pathlib import Path
from unittest.mock import patch
from contextlib import closing
import unittest

from wechat_capture_next.tests import test_union_delivery as fixture_module
from wechat_capture_next import rolling_delivery as delivery, pair_repository
from wechat_capture_next.service import CaptureService
from wechat_capture_v2.common import digest_file


class RollingDeliveryTests(unittest.TestCase):
    setUp=fixture_module.UnionDeliveryTests.setUp
    pages=fixture_module.UnionDeliveryTests.pages
    publish=fixture_module.UnionDeliveryTests.publish
    init_service=fixture_module.UnionDeliveryTests.init_service
    prepared=fixture_module.UnionDeliveryTests.prepared
    take_source_offline=fixture_module.UnionDeliveryTests.take_source_offline
    tearDown=fixture_module.UnionDeliveryTests.tearDown

    def test_full_pair_offline_restore_and_legacy_repositories_untouched(self):
        self.prepared()
        old=fixture_module.UnionDeliveryTests.deliver(self)
        hashes={p:digest_file(p) for p in (self.state_repo/'repository.sqlite',self.union_repo/'repository.sqlite')}
        self.take_source_offline()
        with patch.object(CaptureService,'__init__',side_effect=AssertionError('no live constructor')):
            result=delivery.backup(self.state,self.formal,self.root/'rolling',block_bytes=4096)
            restored=delivery.restore(self.root/'rolling',result['snapshot_id'],self.root/'restored-new')
        self.assertTrue(restored['attachments_closed'])
        self.assertFalse(restored['union_restore']['metadata_only'])
        self.assertFalse(restored['capture_started'])
        self.assertTrue((self.root/'restored-new/state/RESTORE.complete.private.json').exists())
        self.assertFalse((self.root/'restored-new/state/RESTORE.partial.private.json').exists())
        self.assertEqual(hashes,{p:digest_file(p) for p in hashes})

    def test_pair_boundary_rejects_before_state_lock_or_repo_creation(self):
        self.prepared()
        with self.assertRaises(ValueError):delivery.backup(self.state,self.formal,self.state/'illegal')
        self.assertFalse((self.state/'illegal').exists())

    def test_unchanged_pair_defers_orphan_cleanup_without_mutating_authenticated_cut(self):
        self.prepared();repo=self.root/'rolling'
        first=delivery.backup(self.state,self.formal,repo)
        with pair_repository.session(repo) as (db,_):
            pair_repository._put(db,'D',b'synthetic unreferenced backup bytes')
            db.commit()
        self.assertTrue(pair_repository.maintenance_pending(repo)['cleanup_pending'])
        before=digest_file(repo/pair_repository.DATABASE)
        with patch.object(pair_repository,'govern',side_effect=AssertionError('second readback/mutation forbidden')):
            again=delivery.backup(self.state,self.formal,repo)
        self.assertTrue(again['noop'])
        self.assertEqual(again['snapshot_id'],first['snapshot_id'])
        self.assertTrue(again['governance']['cleanup_pending'])
        self.assertTrue(again['governance']['maintenance_deferred'])
        self.assertFalse(again['governance']['cleanup_performed'])
        self.assertEqual(before,digest_file(repo/pair_repository.DATABASE))
        self.assertEqual(len(pair_repository.snapshots(repo)),1)
        # Only the explicit independent maintenance route drains this backlog.
        finished=pair_repository.govern(repo,seconds=300)
        self.assertFalse(finished['cleanup_pending'])

    def test_provenance_is_protected_before_restore_output_creation(self):
        self.prepared();provenance=self.root/'provenance';provenance.mkdir()
        for name in ('pre-evidence-catalog.sqlite.zst','legacy-bag-derived.tar.zst'):
            (provenance/name).write_bytes(b'synthetic-source')
        result=delivery.backup(self.state,self.formal,self.root/'rolling',provenance=provenance)
        out=provenance/'unexpected-restore'
        with self.assertRaises(ValueError):delivery.restore(self.root/'rolling',result['snapshot_id'],out)
        self.assertFalse(out.exists())

    def test_no_change_reuses_semantics_but_authenticates_repository_and_input(self):
        self.prepared();repo=self.root/'rolling'
        first=delivery.backup(self.state,self.formal,repo)
        before=digest_file(repo/pair_repository.DATABASE)
        with patch.object(delivery.CompactArchive,'integrity_check',side_effect=AssertionError('duplicate semantic scan')):
            again=delivery.backup(self.state,self.formal,repo)
        self.assertTrue(again['noop']);self.assertTrue(again['repository_bytes_verified_now'])
        self.assertFalse(again['semantic_verification_executed_now'])
        self.assertEqual(first['snapshot_id'],again['snapshot_id'])
        self.assertEqual(before,digest_file(repo/pair_repository.DATABASE))
        with pair_repository.session(repo) as (db,_):
            db.execute("UPDATE block SET data=x'000000' WHERE kind='D'");db.commit()
        with self.assertRaises(ValueError):delivery.backup(self.state,self.formal,repo)

    def test_same_operation_frozen_objects_are_verified_once_not_skipped(self):
        from wechat_capture_v2.objects import Objects
        from wechat_capture_next import union_assets
        self.prepared();original=Objects.verify_all
        with patch.object(Objects,'verify_all',autospec=True,side_effect=original) as verify_all,\
             patch.object(union_assets,'verify_published_object',side_effect=AssertionError('duplicate CAS byte pass')):
            result=delivery.backup(self.state,self.formal,self.root/'rolling')
        self.assertEqual(verify_all.call_count,1)
        with pair_repository.session(self.root/'rolling',readonly=True) as (db,owner):
            assets=pair_repository.manifest(db,result['snapshot_id'],owner)['context']['asset_binding']
        self.assertTrue(assets['object_bytes_verified'])
        self.assertGreater(assets['objects_reused_from_state_verification'],0)
        self.assertEqual(assets['unique_object_bytes_read_this_verifier'],0)
        self.assertGreater(assets['object_bytes_covered_by_same_operation_proof'],0)

    def test_old_1m_override_is_true_nochange_and_default_migrates_profile(self):
        self.prepared();repo=self.root/'rolling'
        old=delivery.backup(self.state,self.formal,repo,object_block_bytes=pair_repository.MAX_BLOCK)
        before=digest_file(repo/pair_repository.DATABASE)
        with patch.object(delivery.CompactArchive,'integrity_check',side_effect=AssertionError('must reuse explicit old profile')):
            same=delivery.backup(self.state,self.formal,repo,object_block_bytes=pair_repository.MAX_BLOCK)
        self.assertTrue(same['noop']);self.assertEqual(same['snapshot_id'],old['snapshot_id'])
        self.assertEqual(before,digest_file(repo/pair_repository.DATABASE))
        current=delivery.backup(self.state,self.formal,repo)
        self.assertFalse(current['noop']);self.assertNotEqual(current['snapshot_id'],old['snapshot_id'])
        with pair_repository.session(repo,readonly=True) as (db,owner):
            value=pair_repository.manifest(db,current['snapshot_id'],owner)
            self.assertEqual(value['context']['object_leaf_bytes'],16384)
            self.assertEqual(value['files']['state/objects.sqlite']['leaf_bytes'],16384)
        self.assertTrue(delivery.backup(self.state,self.formal,repo)['noop'])
        self.assertTrue(delivery.restore(repo,old['snapshot_id'],self.root/'old-1m-restored')['attachments_closed'])

    def test_offline_view_has_no_key_source_constructor_or_writes(self):
        from wechat_capture_next.offline_view import OfflineView
        from wechat_capture_next.compact_archive import CompactArchive
        from wechat_capture_next import viewer
        from wechat_capture_next.product_host import product_read
        from wechat_capture_next.reader_gate import ReaderGate
        from types import SimpleNamespace
        self.prepared();repo=self.root/'rolling'
        backed=delivery.backup(self.state,self.formal,repo)
        out=self.root/'offline';delivery.restore(repo,backed['snapshot_id'],out)
        self.take_source_offline()
        before={p:digest_file(p) for p in out.rglob('*') if p.is_file()}
        with patch.object(CaptureService,'__init__',side_effect=AssertionError('no live constructor')):
            reader=OfflineView(out)
            try:
                with CompactArchive(reader.union/'archive.wua.sqlite',readonly=True,immutable=True) as archive:
                    self.assertEqual(len(viewer.messages(archive)['rows']),40)
                    self.assertTrue(viewer.conversations(archive)['rows'])
                self.assertFalse(reader.summary()['capture_started'])
                core=SimpleNamespace(union_root=self.formal,offline_view=reader,reader_gate=ReaderGate(),maintenance=False,
                    control_snapshot=lambda:dict(product=dict(mode='normal')))
                self.assertTrue(product_read(core,'/api/conversations',dict(view=['restored']))['rows'])
                self.assertTrue(product_read(core,'/api/union-messages',dict(view=['restored']))['rows'])
            finally:reader.close()
        self.assertEqual(before,{p:digest_file(p) for p in out.rglob('*') if p.is_file()})
        with (out/'union/archive.wua.sqlite').open('r+b') as stream:stream.seek(500);stream.write(b'corrupt')
        with self.assertRaises(ValueError):OfflineView(out)


if __name__=='__main__':unittest.main()
