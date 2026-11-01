from pathlib import Path
import hashlib
import os
import random
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from wechat_capture_next import pair_repository as repo


class PairedTreeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.repository=self.root/'repo';self.input=self.root/'input'
        self.input.write_bytes(random.Random(13).randbytes(4*1024*1024+307))
        self.owner=dict(schema=repo.SCHEMA,catalog_instance='synthetic-catalog',union_id='synthetic-union')
        self.files={'state/catalog.sqlite':self.input,'union/archive.wua.sqlite':self.input}
    def publish(self,**kw):return repo.publish(self.repository,self.owner,self.files,{},**kw)
    def restore(self,snapshot,name):
        out=self.root/name;repo.restore_files(self.repository,snapshot,out)
        return (out/'state/catalog.sqlite').read_bytes()
    def change(self,number):
        with self.input.open('r+b') as stream:stream.seek(100000+number*4096);stream.write(bytes([number])*50)
    def test_tree_all_supported_granularities_and_stable_noop(self):
        for size in repo.ALLOWED_BLOCKS:
            with self.subTest(size=size):
                self.repository=self.root/str(size)
                result=self.publish(block_bytes=size)
                self.assertEqual(self.input.read_bytes(),self.restore(result['snapshot_id'],'out-'+str(size)))
                before=hashlib.sha256((self.repository/repo.DATABASE).read_bytes()).hexdigest()
                self.assertTrue(self.publish(block_bytes=size)['noop'])
                self.assertEqual(before,hashlib.sha256((self.repository/repo.DATABASE).read_bytes()).hexdigest())
    def test_roll_two_pin_and_actual_reclaim(self):
        first=self.publish();old=self.input.read_bytes();repo.pin(self.repository,first['snapshot_id'],True)
        self.change(1);second=self.publish();middle=self.input.read_bytes()
        self.change(2);third=self.publish()
        self.assertEqual(len(repo.snapshots(self.repository)),3)
        self.assertEqual(old,self.restore(first['snapshot_id'],'first'))
        self.assertEqual(middle,self.restore(second['snapshot_id'],'second'))
        repo.pin(self.repository,first['snapshot_id'],False);governed=repo.govern(self.repository)
        self.assertEqual(len(repo.snapshots(self.repository)),2)
        self.assertIn(first['snapshot_id'],governed['expired_snapshots'])
        self.assertEqual(governed['freelist_pages_after'],0)
        self.assertGreater(governed['file_bytes_reclaimed'],0)
        self.assertEqual(self.input.read_bytes(),self.restore(third['snapshot_id'],'third'))
    def test_failed_readback_never_evicts_previous_success(self):
        first=self.publish();self.change(1);second=self.publish();self.change(2)
        def corrupt(phase,db):
            if phase=='before_verify':db.execute("UPDATE block SET data=x'000000' WHERE hash=(SELECT hash FROM block WHERE kind='D' LIMIT 1)")
        with self.assertRaises(ValueError):self.publish(fault=corrupt)
        self.assertEqual({r['snapshot_id'] for r in repo.snapshots(self.repository)},
                         {first['snapshot_id'],second['snapshot_id']})
    def test_before_acceptance_fault_never_evicts_previous_pair(self):
        first=self.publish();self.change(1);second=self.publish();self.change(2)
        def crash(phase,db):
            if phase=='before_commit':raise RuntimeError('synthetic interruption')
        with self.assertRaises(RuntimeError):self.publish(fault=crash)
        self.assertEqual({r['snapshot_id'] for r in repo.snapshots(self.repository)},
                         {first['snapshot_id'],second['snapshot_id']})
    def test_post_acceptance_collection_failure_is_pending_not_failed_backup(self):
        first=self.publish();self.change(1);second=self.publish();self.change(2)
        def crash(phase,db):
            if phase=='before_retention_commit':raise RuntimeError('synthetic collection failure')
        third=self.publish(fault=crash)
        self.assertTrue(third['verification']['verified'])
        self.assertTrue(third['governance']['cleanup_pending'])
        self.assertFalse(third['governance']['retention_committed'])
        self.assertEqual({r['snapshot_id'] for r in repo.snapshots(self.repository)},
            {first['snapshot_id'],second['snapshot_id'],third['snapshot_id']})
        self.assertEqual(self.input.read_bytes(),self.restore(third['snapshot_id'],'accepted-before-gc'))
        repo.govern(self.repository)
        self.assertEqual(len(repo.snapshots(self.repository)),2)
    def test_return_to_older_cut_uses_acceptance_order(self):
        original=self.input.read_bytes();first=self.publish();self.change(1);second=self.publish()
        self.input.write_bytes(original);again=self.publish()
        self.assertEqual(first['snapshot_id'],again['snapshot_id']);self.assertFalse(again['noop'])
        self.assertEqual(repo.snapshots(self.repository)[0]['snapshot_id'],first['snapshot_id'])
        self.change(2);fourth=self.publish()
        self.assertEqual({r['snapshot_id'] for r in repo.snapshots(self.repository)},
                         {first['snapshot_id'],fourth['snapshot_id']})
    def test_small_changes_bounded_repository_growth(self):
        first=self.publish();baseline=(self.repository/repo.DATABASE).stat().st_size
        for n in range(1,5):self.change(n);self.publish()
        self.assertLess((self.repository/repo.DATABASE).stat().st_size,baseline*1.2)
        self.assertEqual(len(repo.snapshots(self.repository)),2)
    def test_unknown_owner_and_restore_traversal_rejected(self):
        self.publish()
        with self.assertRaises(ValueError):repo.publish(self.repository,dict(self.owner,union_id='other'),self.files,{})
        with self.assertRaises(ValueError):repo.file_name('state/../outside')
        with self.assertRaises(ValueError):repo.file_name('union/unknown.exe')
    def test_empty_and_single_block(self):
        for n in (0,1,4096):
            self.input.write_bytes(b'x'*n);result=self.publish(block_bytes=4096)
            self.assertEqual(b'x'*n,self.restore(result['snapshot_id'],'empty-'+str(n)))

    def test_pinned_map_corruption_never_deletes_original_leaf(self):
        for disguise in (False,True):
            with self.subTest(disguise=disguise):
                self.repository=self.root/('corrupt-'+str(disguise))
                first=self.publish();repo.pin(self.repository,first['snapshot_id'],True)
                self.change(1);self.publish()
                with repo.session(self.repository) as (db,owner):
                    tree=repo.manifest(db,first['snapshot_id'],owner)['files']['state/catalog.sqlite']
                    key=tree['root'];leaf=key;height=tree['height']
                    while height:
                        leaf=db.execute('SELECT child FROM edge WHERE parent=? ORDER BY ordinal LIMIT 1',(leaf,)).fetchone()[0]
                        height-=1
                    db.execute('DELETE FROM edge WHERE parent=? AND ordinal=0',(key,))
                    if disguise:
                        db.execute('DELETE FROM edge WHERE parent=?',(key,))
                        db.execute("UPDATE block SET kind='D' WHERE hash=?",(key,))
                    db.commit()
                try:governed=repo.govern(self.repository)
                except ValueError:pass  # A shared corrupt map may fail latest authentication first.
                else:
                    self.assertTrue(governed['cleanup_pending'])
                    self.assertFalse(governed['retention_committed'])
                with repo.session(self.repository,readonly=True) as (db,_):
                    self.assertIsNotNone(db.execute('SELECT 1 FROM block WHERE hash=?',(leaf,)).fetchone())
                    self.assertIsNotNone(db.execute('SELECT 1 FROM snapshot WHERE id=?',(first['snapshot_id'],)).fetchone())
                # Each subcase must begin with different input bytes again.
                self.change(2)

    def test_real_process_exit_during_schema_and_publish_recovery(self):
        script='''import os,sys
from pathlib import Path
from wechat_capture_next import pair_repository as r
owner=dict(schema=r.SCHEMA,catalog_instance='synthetic-catalog',union_id='synthetic-union')
def fault(phase,db):
    if phase==sys.argv[3]:os._exit(73)
r.publish(Path(sys.argv[1]),owner,{'state/catalog.sqlite':Path(sys.argv[2]),'union/archive.wua.sqlite':Path(sys.argv[2])},{},fault=fault)
'''
        for index,phase in enumerate(('schema_before_commit','before_commit','after_retention_commit')):
            self.repository=self.root/('crash-'+phase)
            self.input.write_bytes(random.Random(150+index).randbytes(4*1024*1024+307))
            if phase!='schema_before_commit':self.publish();self.change(1);self.publish();self.change(2)
            child=subprocess.run([sys.executable,'-c',script,str(self.repository),str(self.input),phase],capture_output=True)
            self.assertEqual(child.returncode,73,child.stderr.decode(errors='replace'))
            result=self.publish()
            self.assertEqual(self.input.read_bytes(),self.restore(result['snapshot_id'],'recovered-'+phase))

    def test_reclaim_is_bounded_and_reports_remaining_space(self):
        self.publish()
        with repo.session(self.repository) as (db,_):
            db.execute('CREATE TEMP TABLE allocation(x)')
            result=repo._reclaim(db,self.repository,page_budget=0)
            self.assertIn('cleanup_pending',result)

    def test_object_profile_is_independent_and_old_restore_remains_valid(self):
        self.files.update({'state/objects.sqlite':self.input,'provenance/legacy-bag-derived.tar.zst':self.input})
        old=self.publish(object_block_bytes=repo.MAX_BLOCK)
        with repo.session(self.repository,readonly=True) as (db,owner):
            value=repo.manifest(db,old['snapshot_id'],owner)
            self.assertNotIn('object_leaf_bytes',value['context'])
            self.assertEqual(value['files']['state/objects.sqlite']['leaf_bytes'],repo.MAX_BLOCK)
        result=self.publish()
        with repo.session(self.repository,readonly=True) as (db,owner):
            value=repo.manifest(db,result['snapshot_id'],owner)
            self.assertEqual(value['context']['object_leaf_bytes'],16384)
            self.assertEqual(value['files']['state/objects.sqlite']['leaf_bytes'],16384)
            self.assertEqual(value['files']['state/catalog.sqlite']['leaf_bytes'],4096)
            self.assertEqual(value['files']['provenance/legacy-bag-derived.tar.zst']['leaf_bytes'],repo.MAX_BLOCK)
        self.assertEqual(self.restore(old['snapshot_id'],'old-object-profile'),self.input.read_bytes())
        self.assertEqual(self.restore(result['snapshot_id'],'new-object-profile'),self.input.read_bytes())

    def test_unchanged_old_override_keeps_implicit_1m_scope_and_rejects_profile_reuse(self):
        self.files['state/objects.sqlite']=self.input
        old=self.publish(object_block_bytes=repo.MAX_BLOCK)
        same=repo.unchanged(self.repository,self.owner,self.files,{},object_block_bytes=repo.MAX_BLOCK)
        self.assertEqual(same['snapshot_id'],old['snapshot_id']);self.assertTrue(same['noop'])
        self.assertIsNone(repo.unchanged(self.repository,self.owner,self.files,{}))
        current=self.publish()
        self.assertTrue(repo.unchanged(self.repository,self.owner,self.files,{})['noop'])
        self.assertIsNone(repo.unchanged(self.repository,self.owner,self.files,{},object_block_bytes=repo.MAX_BLOCK))
        with self.assertRaises(ValueError):
            repo.publish(self.repository,self.owner,self.files,{'object_leaf_bytes':repo.MAX_BLOCK})

    def test_stream_repartitioning_is_exact_and_failure_is_transactional(self):
        data=self.input.read_bytes()
        first=self.publish()
        with repo.session(self.repository) as (db,owner):
            db.execute('BEGIN IMMEDIATE')
            entry,_=repo.add_stream(db,(data[n:n+7777] for n in range(0,len(data),7777)),16384,
                expected=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
            self.assertEqual(b''.join(repo.Blocks(db).walk(entry['root'],entry['height'],entry['bytes'])),data)
            with self.assertRaises(ValueError):repo.add_stream(db,[b'short'],16384,expected=dict(bytes=1000,sha256='0'*64))
            db.rollback()
        self.assertEqual(repo.snapshots(self.repository)[0]['snapshot_id'],first['snapshot_id'])

    @unittest.skipUnless(os.name=='nt','Windows deny-write cold handles')
    def test_unchanged_guards_repository_and_owner_through_byte_verification(self):
        self.files['state/objects.sqlite']=self.input;self.publish()
        original=repo.verify_files
        def verify(db,value):
            for name in (repo.DATABASE,'OWNER.private.json'):
                with self.assertRaises(PermissionError):(self.repository/name).open('r+b')
            return original(db,value)
        with patch.object(repo,'verify_files',side_effect=verify):
            self.assertTrue(repo.unchanged(self.repository,self.owner,self.files,{})['noop'])
        for name in (repo.DATABASE,'OWNER.private.json'):
            with (self.repository/name).open('r+b'):pass


if __name__=='__main__':unittest.main()
