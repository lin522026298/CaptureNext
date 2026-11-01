from pathlib import Path
import unittest
from unittest.mock import patch

from wechat_capture_v2.common import digest_file
from wechat_capture_next import comparison_reblock as helper,pair_repository as repo
from wechat_capture_next.tests import test_pair_repository as fixtures


class ComparisonReblockTests(unittest.TestCase):
    setUp=fixtures.PairedTreeTests.setUp
    change=fixtures.PairedTreeTests.change

    def prepare(self,*,comparison=True):
        self.files['state/objects.sqlite']=self.input
        self.context=dict(comparison_only=comparison,protected_roots=[str(self.repository)])
        self.a=repo.publish(self.repository,self.owner,self.files,self.context,object_block_bytes=repo.MAX_BLOCK)
        self.original=self.input.read_bytes();self.change(1)
        self.b=repo.publish(self.repository,self.owner,self.files,{},object_block_bytes=repo.MAX_BLOCK)
        self.base={row['snapshot_id'] for row in repo.snapshots(self.repository)}

    def migrate(self,**kw):
        with patch.object(helper,'WORKING_ROOT',self.root):
            return helper.reblock(self.repository,self.a['snapshot_id'],**kw)

    def test_stream_migration_keeps_B_newA_and_all_other_roots(self):
        self.prepare();result=self.migrate()
        self.assertEqual({row['snapshot_id'] for row in repo.snapshots(self.repository)},
            {self.b['snapshot_id'],result['snapshot_id']})
        self.assertTrue(result['verification']['verified']);self.assertEqual(result['object_leaf_bytes'],16384)
        self.assertEqual(result['cost_scope'],'one_time_profile_migration_not_daily_backup')
        with repo.session(self.repository,readonly=True) as (db,owner):
            current=repo.manifest(db,result['snapshot_id'],owner)
            old_b=repo.manifest(db,self.b['snapshot_id'],owner)
            self.assertEqual(current['files']['state/catalog.sqlite']['root'],self.a['files']['state/catalog.sqlite']['root'])
            self.assertEqual(old_b['files']['state/objects.sqlite']['leaf_bytes'],repo.MAX_BLOCK)
        repo.restore_files(self.repository,result['snapshot_id'],self.root/'newA')
        self.assertEqual((self.root/'newA/state/objects.sqlite').read_bytes(),self.original)
        # Subsequent B backup with default profile can use this A16k leaf set.
        new_b=repo.publish(self.repository,self.owner,self.files,{},object_block_bytes=16384)
        self.assertTrue(new_b['verification']['verified'])
        self.assertTrue(repo.unchanged(self.repository,self.owner,self.files,{})['noop'])

    def test_non_working_noncomparison_latest_or_pinned_refused(self):
        self.prepare()
        before=digest_file(self.repository/repo.DATABASE)
        with self.assertRaisesRegex(ValueError,'project working'):
            helper.reblock(self.repository,self.a['snapshot_id'])
        self.assertEqual(before,digest_file(self.repository/repo.DATABASE))
        with patch.object(helper,'WORKING_ROOT',self.root):
            with self.assertRaises(ValueError):helper.reblock(self.repository,self.b['snapshot_id'])
        repo.pin(self.repository,self.a['snapshot_id'],True)
        with self.assertRaisesRegex(ValueError,'pinned'):self.migrate()
        self.assertEqual({row['snapshot_id'] for row in repo.snapshots(self.repository)},self.base)

    def test_noncomparison_A_is_never_reblocked(self):
        self.prepare(comparison=False)
        with self.assertRaisesRegex(ValueError,'comparison_only'):self.migrate()
        self.assertEqual({row['snapshot_id'] for row in repo.snapshots(self.repository)},self.base)

    def test_verify_and_govern_failures_never_evict_A_or_B(self):
        self.prepare()
        for phase in ('before_verify','before_gc_commit','before_commit'):
            def fault(event,db):
                if event==phase:raise RuntimeError('synthetic reblock failure')
            with self.subTest(phase=phase),self.assertRaises(RuntimeError):self.migrate(fault=fault)
            self.assertEqual({row['snapshot_id'] for row in repo.snapshots(self.repository)},self.base)
            for snapshot in self.base:
                with repo.session(self.repository,readonly=True) as (db,owner):
                    self.assertTrue(repo.verify_files(db,repo.manifest(db,snapshot,owner))['verified'])

    def test_corrupt_new_leaf_readback_rolls_back_without_eviction(self):
        self.prepare()
        def fault(event,db):
            if event=='before_verify':
                db.execute("UPDATE block SET data=x'00' WHERE kind='D' AND bytes=16384")
        with self.assertRaises(ValueError):self.migrate(fault=fault)
        self.assertEqual({row['snapshot_id'] for row in repo.snapshots(self.repository)},self.base)
        for snapshot in self.base:
            with repo.session(self.repository,readonly=True) as (db,owner):
                self.assertTrue(repo.verify_files(db,repo.manifest(db,snapshot,owner))['verified'])


if __name__=='__main__':unittest.main()
