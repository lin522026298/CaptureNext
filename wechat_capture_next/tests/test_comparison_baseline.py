import json
from unittest.mock import patch
import unittest

from wechat_capture_v2.common import digest_file
from wechat_capture_next import comparison_baseline as helper,pair_repository as repo,rolling_delivery
from wechat_capture_next.tests import test_rolling_delivery as fixtures


class ComparisonBaselineTests(unittest.TestCase):
    setUp=fixtures.RollingDeliveryTests.setUp
    pages=fixtures.RollingDeliveryTests.pages
    publish=fixtures.RollingDeliveryTests.publish
    init_service=fixtures.RollingDeliveryTests.init_service
    prepared=fixtures.RollingDeliveryTests.prepared
    take_source_offline=fixtures.RollingDeliveryTests.take_source_offline
    tearDown=fixtures.RollingDeliveryTests.tearDown

    def prepare_baseline(self,*,comparison=True,correct_link=True,owned=True):
        self.prepared();self.comparison=self.root/'comparison';self.preserved=self.root/'preserved-B'
        coarse=rolling_delivery.backup(self.state,self.formal,self.comparison,object_block_bytes=repo.MAX_BLOCK)
        self.coarse=coarse['snapshot_id']
        rolling_delivery.restore(self.comparison,self.coarse,self.preserved)
        with repo.session(self.comparison,readonly=True) as (db,owner):
            self.owner=owner;manifest=repo.manifest(db,self.coarse,owner)
        files={name:(self.state/name[6:] if name.startswith('state/') else self.formal/name[6:]) for name in manifest['files']}
        context=dict(manifest['context'],comparison_only=comparison,
            comparison_reblock=dict(retained_b_snapshot=self.coarse if correct_link else '0'*64))
        if not owned:context['protected_roots']=[str(self.state)]
        context.pop('object_leaf_bytes',None)
        keeper=repo.publish(self.comparison,self.owner,files,context,object_block_bytes=16384)
        self.keeper=keeper['snapshot_id'];self.base={self.coarse,self.keeper}
        with repo.session(self.comparison,readonly=True) as (db,owner):
            self.literal=db.execute('SELECT manifest FROM snapshot WHERE id=?',(self.keeper,)).fetchone()[0]
        self.preserved_hashes={path.relative_to(self.preserved).as_posix():digest_file(path) for path in self.preserved.rglob('*') if path.is_file()}

    def settle(self,**kw):
        with patch.object(helper,'WORKING_ROOT',self.root):
            return helper.settle(self.comparison,self.keeper,self.preserved,**kw)

    def points(self):
        with repo.session(self.comparison,readonly=True) as (db,_):
            return {row[0] for row in db.execute('SELECT id FROM snapshot')},[row[0] for row in db.execute('SELECT snapshot_id FROM generation')]

    def test_full_proof_exact_single_A16_no_duplicate_generation_and_B_copy_unchanged(self):
        self.prepare_baseline();result=self.settle(seconds=60)
        self.assertTrue(result['settled']);self.assertFalse(result['partial'])
        self.assertEqual(self.points(),({self.keeper},[self.keeper]))
        self.assertEqual(result['freelist_pages_after'],0);self.assertEqual(result['dead_blocks_after'],0)
        self.assertTrue(result['keeper_manifest_unchanged']);self.assertTrue(result['keeper_generation_sequence_preserved'])
        self.assertFalse(result['artificial_generation_added'])
        with repo.session(self.comparison,readonly=True) as (db,owner):
            self.assertEqual(db.execute('SELECT manifest FROM snapshot WHERE id=?',(self.keeper,)).fetchone()[0],self.literal)
            self.assertTrue(repo.verify_files(db,repo.manifest(db,self.keeper,owner))['verified'])
        self.assertEqual(self.preserved_hashes,{path.relative_to(self.preserved).as_posix():digest_file(path) for path in self.preserved.rglob('*') if path.is_file()})

    def test_keeper_proof_failure_preserves_both_before_any_metadata_retirement(self):
        self.prepare_baseline()
        with patch.object(repo,'verify_files',side_effect=ValueError('synthetic full-readback failure')):
            with self.assertRaises(ValueError):self.settle()
        self.assertEqual(self.points(),(self.base,[self.coarse,self.keeper]))

    def test_preserved_B_full_hash_or_exact_file_tree_failure_preserves_both(self):
        self.prepare_baseline();receipt=self.preserved/'DELIVERY.complete.private.json'
        original=receipt.read_text(encoding='utf-8');value=json.loads(original)
        optional=next(name for name in value['restored_files'] if name.startswith('state/cache/'))
        value['restored_files'].pop(optional);receipt.write_text(json.dumps(value),encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'file tree'):self.settle()
        self.assertEqual(self.points(),(self.base,[self.coarse,self.keeper]))
        receipt.write_text(original,encoding='utf-8')
        target=self.preserved/optional
        with target.open('r+b') as stream:stream.seek(100);stream.write(b'tampered')
        with self.assertRaisesRegex(ValueError,'verified receipt'):self.settle()
        self.assertEqual(self.points(),(self.base,[self.coarse,self.keeper]))

    def test_after_accept_cleanup_failure_is_partial_but_A16_and_preserved_B_remain(self):
        self.prepare_baseline()
        with patch.object(helper.pair_collection,'cleanup',return_value=dict(cleanup_pending=True,cleanup_error='synthetic')):
            result=self.settle()
        self.assertTrue(result['partial']);self.assertTrue(result['metadata_retirement_accepted'])
        self.assertEqual(self.points(),(self.base,[self.keeper]))
        self.assertTrue((self.preserved/'DELIVERY.complete.private.json').exists())
        with repo.session(self.comparison,readonly=True) as (db,owner):
            self.assertTrue(repo.verify_files(db,repo.manifest(db,self.keeper,owner))['verified'])

    def test_precommit_fault_rolls_back_and_postcommit_fault_reports_safe_partial(self):
        self.prepare_baseline()
        def before(phase,db):
            if phase=='before_retirement_commit':raise RuntimeError('synthetic precommit')
        with self.assertRaises(RuntimeError):self.settle(fault=before)
        self.assertEqual(self.points(),(self.base,[self.coarse,self.keeper]))
        def after(phase,db):
            if phase=='after_retirement_commit':raise RuntimeError('synthetic postcommit')
        result=self.settle(fault=after)
        self.assertTrue(result['partial']);self.assertEqual(result['post_accept_error_type'],'RuntimeError')
        self.assertEqual(self.points(),(self.base,[self.keeper]))

    def test_working_only_independent_boundary_latest_pin_and_link_required(self):
        self.prepare_baseline()
        with self.assertRaisesRegex(ValueError,'project working'):
            helper.settle(self.comparison,self.keeper,self.preserved)
        with patch.object(helper,'WORKING_ROOT',self.root):
            with self.assertRaisesRegex(ValueError,'independent'):
                helper.settle(self.comparison,self.keeper,self.comparison/'nested')
            with self.assertRaisesRegex(ValueError,'latest'):
                helper.settle(self.comparison,self.coarse,self.preserved)
        repo.pin(self.comparison,self.coarse,True)
        with self.assertRaisesRegex(ValueError,'pinned'):self.settle()
        self.assertEqual(self.points(),(self.base,[self.coarse,self.keeper]))

    def test_wrong_reblock_link_refused_before_full_proof_or_metadata_changes(self):
        self.prepare_baseline(correct_link=False)
        with patch.object(repo,'verify_files',side_effect=AssertionError('invalid scope must fail first')):
            with self.assertRaisesRegex(ValueError,'reblock'):self.settle()
        self.assertEqual(self.points(),(self.base,[self.coarse,self.keeper]))

    def test_noncomparison_keeper_is_refused(self):
        self.prepare_baseline(comparison=False)
        with self.assertRaisesRegex(ValueError,'comparison_only'):self.settle()
        self.assertEqual(self.points(),(self.base,[self.coarse,self.keeper]))

    def test_unowned_keeper_is_refused_before_file_proof(self):
        self.prepare_baseline(owned=False)
        with patch.object(repo,'verify_files',side_effect=AssertionError('unowned scope must fail first')):
            with self.assertRaisesRegex(ValueError,'own this'):self.settle()
        self.assertEqual(self.points(),(self.base,[self.coarse,self.keeper]))

    def test_invalid_collection_budget_never_retires_a_generation(self):
        self.prepare_baseline()
        for seconds in (-1,float('nan'),float('inf'),True):
            with self.subTest(seconds=seconds),self.assertRaisesRegex(ValueError,'budget'):
                self.settle(seconds=seconds)
        self.assertEqual(self.points(),(self.base,[self.coarse,self.keeper]))


if __name__=='__main__':unittest.main()
