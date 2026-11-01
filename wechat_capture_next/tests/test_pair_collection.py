from pathlib import Path
import hashlib
import os
import random
import subprocess
import sys
import unittest
from unittest.mock import patch

from wechat_capture_next import pair_collection as collection, pair_repository as repository
from wechat_capture_next.tests import test_pair_repository as fixtures


def accepted_only(repo, owner, files, **kwargs):
    """Model the publisher's acceptance commit, before its collector runs."""
    with patch.object(collection, 'cleanup', return_value={}):
        return repository.publish(repo, owner, files, {}, **kwargs)


class PairCollectionTests(unittest.TestCase):
    setUp = fixtures.PairedTreeTests.setUp
    change = fixtures.PairedTreeTests.change
    restore = fixtures.PairedTreeTests.restore

    def accept(self, **kwargs):
        return accepted_only(self.repository, self.owner, self.files, **kwargs)

    def collect(self, **kwargs):
        with repository.session(self.repository) as (db, owner):
            return collection.cleanup(db, owner, self.repository, **kwargs)

    def three(self):
        first = self.accept()
        self.change(1)
        second = self.accept()
        middle = self.input.read_bytes()
        self.change(2)
        third = self.accept()
        return first, second, third, middle

    def test_publish_default_work_budget_is_300_with_original_small_batches(self):
        def collected(db,owner,path,**kwargs):
            self.assertFalse(db.in_transaction)
            self.assertEqual(db.execute('PRAGMA foreign_keys').fetchone()[0],1)
            self.assertEqual(kwargs['seconds'],300)
            self.assertNotIn('batch_row_limit',kwargs)
            self.assertNotIn('batch_payload_limit',kwargs)
            self.assertEqual(collection.DEFAULT_BATCH_ROWS,128)
            self.assertEqual(collection.DEFAULT_BATCH_PAYLOAD,16*1024*1024)
            return dict(cleanup_pending=False)
        with patch.object(repository,'verify_files',wraps=repository.verify_files) as verified, \
             patch.object(collection,'cleanup',side_effect=collected) as collector:
            result=repository.publish(self.repository,self.owner,self.files,{})
        self.assertEqual(verified.call_count,1)
        self.assertEqual(collector.call_count,1)
        self.assertTrue(result['verification']['verified'])
        self.assertFalse(result['governance']['cleanup_pending'])

    def test_after_commit_fault_follows_collection_start_and_preserves_accepted_points(self):
        first=self.accept();self.change(1);second=self.accept();middle=self.input.read_bytes()
        self.change(2);seen=[]
        def fail(phase,db):
            seen.append(phase)
            if phase=='after_commit':raise RuntimeError('post-commit interruption')
        with self.assertRaises(RuntimeError):
            repository.publish(self.repository,self.owner,self.files,{},fault=fail)
        self.assertLess(seen.index('collection_start'),seen.index('after_commit'))
        points=repository.snapshots(self.repository)
        self.assertEqual(len(points),3)
        self.assertEqual(middle,self.restore(second['snapshot_id'],'second-after-hook-failure'))
        self.assertEqual(self.input.read_bytes(),self.restore(points[0]['snapshot_id'],'accepted-after-hook-failure'))
        self.assertFalse(self.collect(seconds=30)['cleanup_pending'])

    def test_finite_cycles_bounded_slices_converge_with_pins_and_byte_restores(self):
        first=self.accept();old=self.input.read_bytes();repository.pin(self.repository,first['snapshot_id'],True)
        previous=first;previous_bytes=old
        def slice_once():
            clock=[0.0]
            def boundary(phase,db):
                if phase=='after_batch_commit':clock[0]=2.0
            with patch.object(collection.time,'monotonic',side_effect=lambda:clock[0]):
                return self.collect(seconds=1,batch_row_limit=3,fault=boundary)
        for number in range(1,5):
            self.change(number);current=self.accept()
            result=slice_once()
            self.assertNotIn('cleanup_error',result)
            self.assertEqual(self.input.read_bytes(),self.restore(current['snapshot_id'],'cycle-current-'+str(number)))
            self.assertEqual(previous_bytes,self.restore(previous['snapshot_id'],'cycle-previous-'+str(number)))
            self.assertEqual(old,self.restore(first['snapshot_id'],'cycle-pinned-'+str(number)))
            previous=current;previous_bytes=self.input.read_bytes()
        repository.pin(self.repository,first['snapshot_id'],False)
        for attempt in range(100):
            result=slice_once()
            self.assertNotIn('cleanup_error',result)
            if not result['cleanup_pending']:break
            self.assertTrue(result['deleted_blocks'] or result['file_bytes_reclaimed'])
        else:self.fail('stable finite graph failed to drain bounded slices')
        self.assertFalse(result['cleanup_pending'])
        self.assertEqual(len(repository.snapshots(self.repository)),2)

    def test_latest_two_restore_and_reclaim_without_full_temporary(self):
        first, second, third, middle = self.three()
        result = self.collect(seconds=30, batch_payload_limit=32 * 1024, batch_row_limit=3)
        self.assertNotIn('cleanup_error', result)
        self.assertIn(first['snapshot_id'], result['expired_snapshots'])
        self.assertEqual({item['snapshot_id'] for item in repository.snapshots(self.repository)},
                         {second['snapshot_id'], third['snapshot_id']})
        self.assertEqual(middle, self.restore(second['snapshot_id'], 'second'))
        self.assertEqual(self.input.read_bytes(), self.restore(third['snapshot_id'], 'third'))
        self.assertGreater(result['deleted_blocks'], 0)
        self.assertFalse(result['cleanup_pending'])
        self.assertTrue({item.name for item in self.repository.iterdir()}.issubset(
            {'OWNER.private.json', repository.DATABASE, 'repository.lock'}))

    def test_pinned_shared_graph_survives_and_unpin_collects(self):
        first = self.accept()
        original = self.input.read_bytes()
        repository.pin(self.repository, first['snapshot_id'], True)
        self.change(1)
        second = self.accept()
        self.change(2)
        third = self.accept()
        result = self.collect(seconds=30, batch_row_limit=1)
        self.assertNotIn('cleanup_error', result)
        self.assertEqual(len(repository.snapshots(self.repository)), 3)
        self.assertEqual(original, self.restore(first['snapshot_id'], 'pinned'))
        repository.pin(self.repository, first['snapshot_id'], False)
        result = self.collect(seconds=30, batch_row_limit=1)
        self.assertIn(first['snapshot_id'], result['expired_snapshots'])
        self.assertEqual({item['snapshot_id'] for item in repository.snapshots(self.repository)},
                         {second['snapshot_id'], third['snapshot_id']})

    def test_forged_retained_map_edges_fail_before_retirement(self):
        first, second, third, _ = self.three()
        before = {item['snapshot_id'] for item in repository.snapshots(self.repository)}
        with repository.session(self.repository) as (db, owner):
            key = repository.manifest(db, second['snapshot_id'], owner)['files']['state/catalog.sqlite']['root']
            db.execute('DELETE FROM edge WHERE parent=? AND ordinal=0', (key,))
            db.commit()
        result = self.collect(seconds=30)
        self.assertEqual(result['cleanup_error'], 'ValueError')
        self.assertFalse(result['retention_committed'])
        self.assertEqual(before, {item['snapshot_id'] for item in repository.snapshots(self.repository)})

    def test_failed_new_acceptance_does_not_retire_previous_points(self):
        first = self.accept()
        self.change(1)
        second = self.accept()
        self.change(2)

        def fail(phase, db):
            if phase == 'before_verify':
                raise RuntimeError('new readback rejected')

        with self.assertRaises(RuntimeError):
            self.accept(fault=fail)
        self.assertEqual({item['snapshot_id'] for item in repository.snapshots(self.repository)},
                         {first['snapshot_id'], second['snapshot_id']})

    def test_cleanup_failure_returns_pending_after_acceptance(self):
        first, second, third, middle = self.three()

        def fail(phase, db):
            if phase == 'after_batch_delete':
                raise RuntimeError('collector interrupted')

        result = self.collect(seconds=30, fault=fail)
        self.assertTrue(result['retention_committed'])
        self.assertTrue(result['cleanup_pending'])
        self.assertEqual(result['cleanup_error'], 'RuntimeError')
        self.assertEqual(middle, self.restore(second['snapshot_id'], 'failed-cleanup-second'))
        self.assertEqual(self.input.read_bytes(), self.restore(third['snapshot_id'], 'failed-cleanup-third'))
        resumed = self.collect(seconds=30)
        self.assertNotIn('cleanup_error', resumed)
        self.assertFalse(resumed['cleanup_pending'])

    def test_zero_budget_same_cut_resumes_and_clean_cut_bytes_do_not_change(self):
        self.three()
        paused = self.collect(seconds=0)
        self.assertTrue(paused['cleanup_pending'])
        self.assertGreater(paused['dead_blocks_remaining'], 0)
        self.assertEqual(paused['deleted_blocks'], 0)
        finished = self.collect(seconds=30)
        self.assertFalse(finished['cleanup_pending'])
        before = hashlib.sha256((self.repository / repository.DATABASE).read_bytes()).hexdigest()
        again = self.collect(seconds=30)
        after = hashlib.sha256((self.repository / repository.DATABASE).read_bytes()).hexdigest()
        self.assertFalse(again['cleanup_pending'])
        self.assertEqual(before, after)

    def test_low_space_defers_deletion_without_losing_accepted_points(self):
        _, second, third, middle = self.three()
        usage = type('Usage', (), {'free': 1})()
        with patch.object(collection.shutil, 'disk_usage', return_value=usage):
            result = self.collect(seconds=30)
        self.assertTrue(result['cleanup_pending'])
        self.assertEqual(result['cleanup_error'], 'ValueError')
        self.assertEqual(result['deleted_blocks'], 0)
        self.assertEqual(middle, self.restore(second['snapshot_id'], 'low-space-second'))
        self.assertEqual(self.input.read_bytes(), self.restore(third['snapshot_id'], 'low-space-third'))

    def test_journal_peak_is_batch_sized_not_total_retired_payload(self):
        # Distinct old payload far exceeds one 128 KiB deletion batch.
        self.files['state/objects.sqlite'] = self.input
        self.input.write_bytes(random.Random(41).randbytes(6 * 1024 * 1024 + 17))
        first = self.accept(object_block_bytes=repository.MAX_BLOCK)
        self.input.write_bytes(random.Random(42).randbytes(6 * 1024 * 1024 + 17))
        second = self.accept(object_block_bytes=repository.MAX_BLOCK)
        self.input.write_bytes(random.Random(43).randbytes(6 * 1024 * 1024 + 17))
        third = self.accept(object_block_bytes=repository.MAX_BLOCK)
        journals = []

        def sample(phase, db):
            if phase in ('after_batch_delete', 'after_batch_edges'):
                journals.append(collection._journal_bytes(self.repository))

        result = self.collect(seconds=30, batch_payload_limit=128 * 1024, batch_row_limit=8, fault=sample)
        self.assertNotIn('cleanup_error', result)
        self.assertGreater(result['collection_batches'], 4)
        self.assertGreater(result['deleted_payload_bytes'], 5 * 1024 * 1024)
        self.assertTrue(journals)
        self.assertLess(max(journals), 2 * 1024 * 1024)
        self.assertEqual({item['snapshot_id'] for item in repository.snapshots(self.repository)},
                         {second['snapshot_id'], third['snapshot_id']})

    def test_high_incoming_degree_is_collected_in_separate_edge_batches(self):
        self.accept()
        with repository.session(self.repository) as (db, owner):
            db.execute('BEGIN IMMEDIATE')
            child, _ = repository._put(db, 'D', b'orphan shared child')
            for number in range(19):
                # Valid map payloads, all sharing one dead child. The second
                # unique child makes parent hashes distinct without cycles.
                sibling, _ = repository._put(db, 'D', ('orphan-' + str(number)).encode())
                children = [[child, 19], [sibling, len(('orphan-' + str(number)).encode())]]
                from wechat_capture_v2.common import canonical
                repository._put(db, 'N', canonical(dict(height=1, children=children)).encode(), children)
            db.commit()
        result = self.collect(seconds=30, batch_row_limit=1)
        self.assertNotIn('cleanup_error', result)
        self.assertGreaterEqual(result['collection_edge_batches'], 38)
        self.assertGreaterEqual(result['deleted_blocks'], 39)
        self.assertFalse(result['cleanup_pending'])

    def test_pending_probe_is_readonly_and_detects_orphan_roots(self):
        self.accept()
        before = hashlib.sha256((self.repository / repository.DATABASE).read_bytes()).hexdigest()
        with repository.session(self.repository, readonly=True) as (db, _):
            hint = collection.pending(db)
        self.assertFalse(hint['cleanup_pending'])
        self.assertTrue(hint['orphan_root_probe_executed'])
        self.assertEqual(hint['probe_cost'], 'metadata_only_may_scan_all_blocks')
        self.assertFalse(hint['repository_block_payloads_read'])
        self.assertEqual(before, hashlib.sha256((self.repository / repository.DATABASE).read_bytes()).hexdigest())
        with repository.session(self.repository) as (db, _):
            repository._put(db, 'D', b'nonempty orphan')
            db.commit()
        with repository.session(self.repository, readonly=True) as (db, _):
            self.assertTrue(collection.pending(db)['cleanup_pending'])
        self.assertFalse(self.collect(seconds=30)['cleanup_pending'])

    def test_reclaim_multiple_real_rounds_aggregate_and_stop_when_done(self):
        self.three()
        original = repository._reclaim
        rounds = []

        def one_page(db, path, **kwargs):
            result = original(db, path, page_budget=1, seconds=kwargs['seconds'])
            rounds.append(result)
            return result

        with patch.object(repository, '_reclaim', side_effect=one_page):
            result = self.collect(seconds=30)
        self.assertNotIn('cleanup_error', result)
        self.assertGreaterEqual(len(rounds), 2)
        self.assertEqual(result['reclaim_rounds'], len(rounds))
        self.assertEqual(result['file_bytes_reclaimed'], sum(item['file_bytes_reclaimed'] for item in rounds))
        self.assertEqual(result['freelist_pages_before'], rounds[0]['freelist_pages_before'])
        self.assertEqual(result['freelist_pages_after'], rounds[-1]['freelist_pages_after'])
        self.assertEqual(result['freelist_pages_after'], 0)
        self.assertFalse(result['cleanup_pending'])

    def test_reclaim_stall_and_error_stop_after_one_round(self):
        self.three()
        for mode in ('stall', 'error'):
            with self.subTest(mode=mode):
                def stopped(db, path, **kwargs):
                    free = db.execute('PRAGMA freelist_count').fetchone()[0]
                    result = dict(freelist_pages_before=free, freelist_pages_after=free,
                                  file_bytes_reclaimed=0, cleanup_pending=True)
                    if mode == 'error':
                        result['cleanup_error'] = 'OperationalError'
                    return result
                with patch.object(repository, '_reclaim', side_effect=stopped) as reclaim:
                    result = self.collect(seconds=30)
                self.assertEqual(reclaim.call_count, 1)
                self.assertTrue(result['cleanup_pending'])
                if mode == 'stall':
                    self.assertTrue(result['reclaim_progress_stalled'])
                else:
                    self.assertEqual(result['cleanup_error'], 'OperationalError')
        self.assertFalse(self.collect(seconds=30)['cleanup_pending'])

    def test_nonfinite_duration_is_rejected_before_writes(self):
        self.accept()
        for duration in (float('nan'), float('inf'), float('-inf')):
            with self.subTest(duration=duration):
                with self.assertRaises(ValueError):
                    self.collect(seconds=duration)

    def test_real_process_exit_after_acceptance_retention_delete_and_commit(self):
        script = '''import os,sys
from pathlib import Path
from unittest.mock import patch
from wechat_capture_next import pair_repository as r, pair_collection as c
p=Path(sys.argv[1]);source=Path(sys.argv[2]);phase=sys.argv[3]
owner=dict(schema=r.SCHEMA,catalog_instance='synthetic-catalog',union_id='synthetic-union')
if phase=='after_acceptance':
    with patch.object(c,'cleanup',return_value={}):
        r.publish(p,owner,{'state/catalog.sqlite':source,'union/archive.wua.sqlite':source},{})
    os._exit(73)
def fault(event,db):
    if event==phase:os._exit(73)
with r.session(p) as (db,actual):
    c.cleanup(db,actual,p,seconds=30,batch_row_limit=1,fault=fault)
'''
        phases = ('after_acceptance', 'after_retention_commit', 'after_batch_edges',
                  'after_batch_delete', 'after_batch_commit')
        for index, phase in enumerate(phases):
            with self.subTest(phase=phase):
                self.repository = self.root / ('crash-' + str(index))
                self.input.write_bytes(random.Random(100 + index).randbytes(1024 * 1024 + 13))
                first = self.accept()
                self.change(1)
                second = self.accept()
                middle = self.input.read_bytes()
                self.change(2)
                if phase != 'after_acceptance':
                    self.accept()
                child = subprocess.run([sys.executable, '-c', script, str(self.repository), str(self.input), phase],
                                       capture_output=True)
                self.assertEqual(child.returncode, 73, child.stderr.decode(errors='replace'))
                resumed = self.collect(seconds=30, batch_row_limit=1)
                self.assertNotIn('cleanup_error', resumed)
                self.assertFalse(resumed['cleanup_pending'])
                points = repository.snapshots(self.repository)
                self.assertEqual(len(points), 2)
                self.assertNotIn(first['snapshot_id'], {point['snapshot_id'] for point in points})
                self.assertIn(second['snapshot_id'], {point['snapshot_id'] for point in points})
                self.assertEqual(middle, self.restore(second['snapshot_id'], 'crash-middle-' + str(index)))
                self.assertEqual(self.input.read_bytes(), self.restore(points[0]['snapshot_id'], 'crash-latest-' + str(index)))


if __name__ == '__main__':
    unittest.main()
