import hashlib
from pathlib import Path
import tempfile
import unittest
import zlib

from wechat_capture_next import benchmark_object_blocks as benchmark
from wechat_capture_next import pair_repository as repository
from wechat_capture_next.union_archive import cold_input


class LeafEstimateTests(unittest.TestCase):
    def estimate(self, a, b, chunks):
        with benchmark._memory_db() as db:
            first = benchmark.Leaves(db, 'A'); second = benchmark.Leaves(db, 'B')
            for offset in range(0, len(a), chunks):first.feed(a[offset:offset+chunks])
            first.finish(dict(bytes=len(a), sha256=hashlib.sha256(a).hexdigest()))
            for offset in range(0, len(b), chunks):second.feed(b[offset:offset+chunks])
            return second.finish(dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest()))

    def test_same_bytes_no_new_payload_with_arbitrary_source_boundaries(self):
        raw = (bytes(range(256))*5000)+b'partial tail'
        for chunk in (3001, 65537, 1048576):
            result = self.estimate(raw, raw, chunk)
            self.assertTrue(all(stats['new_unique_compressed_payload_bytes'] == 0 for stats in result['per_leaf_bytes'].values()))

    def test_new_repeated_leaves_count_compressed_payload_once(self):
        result = self.estimate(b'a'*4096, b'b'*8192, 2003)
        small = result['per_leaf_bytes']['4096']
        self.assertEqual(small['unique_inserted'], 1)
        self.assertEqual(small['new_in_b_repeat_occurrences'], 1)
        self.assertEqual(small['new_unique_compressed_payload_bytes'], len(zlib.compress(b'b'*4096, 1)))

    def test_coverage_and_digest_reject_omission_or_modified_bytes(self):
        with benchmark._memory_db() as db:
            leaves = benchmark.Leaves(db, 'A'); leaves.feed(b'cut short')
            with self.assertRaisesRegex(ValueError, 'SHA-256 or length'):
                leaves.finish(dict(bytes=1000, sha256='0'*64))

    def test_empty_stream_has_one_authentic_empty_leaf_for_each_size(self):
        result = self.estimate(b'', b'', 123)
        self.assertTrue(all(stats['leaf_occurrences'] == 1 and stats['new_unique_compressed_payload_bytes'] == 0
            for stats in result['per_leaf_bytes'].values()))

    def test_authenticated_A_tree_and_exact_B_file_and_released_guards(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); a = root/'a'; b = root/'b'; repo = root/'repo'
            a.write_bytes(b'a'*10000); b.write_bytes(b'a'*9999+b'b')
            owner = dict(schema=repository.SCHEMA, catalog_instance='test', union_id='test')
            one = repository.publish(repo, owner, {'state/objects.sqlite':a}, {}, block_bytes=4096)
            two = repository.publish(repo, owner, {'state/objects.sqlite':b}, {}, block_bytes=4096)
            result = benchmark.compare(repo, one['snapshot_id'], two['snapshot_id'], b)
            self.assertEqual(result['raw_input_bytes'], 20000)
            self.assertTrue(result['cold_guards_and_connections_released'])
            self.assertFalse(result['actual_repository_growth_measured'])
            with cold_input(repo/'repository.sqlite'):
                pass
            # Reopening a source for writing also proves its deny-write handle closed.
            with b.open('ab') as stream:
                stream.write(b'changed')
            with self.assertRaisesRegex(ValueError, 'length differs'):
                benchmark.compare(repo, one['snapshot_id'], two['snapshot_id'], b)


if __name__ == '__main__':
    unittest.main()
