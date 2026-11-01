import unittest
from wechat_capture_next import benchmark_collection as benchmark,pair_repository as repository
from wechat_capture_next.tests import test_pair_repository as fixtures


class FreePagesTests(unittest.TestCase):
    setUp=fixtures.PairedTreeTests.setUp
    publish=fixtures.PairedTreeTests.publish
    change=fixtures.PairedTreeTests.change

    def test_free_page_compaction_preserves_all_points_and_does_not_claim_deep_authentication(self):
        first=self.publish();self.change(1);self.publish()
        points=repository.snapshots(self.repository)
        result=benchmark.free_pages(self.repository.resolve())
        self.assertEqual(points,repository.snapshots(self.repository))
        self.assertEqual(result['blocks_deleted'],0)
        self.assertEqual(result['snapshots_retired'],0)
        self.assertFalse(result['full_payload_authentication_executed_now'])
        self.assertTrue(result['retained_manifests_and_block_count_unchanged'])
        repository.restore_files(self.repository,first['snapshot_id'],self.root/'old')


if __name__=='__main__':unittest.main()
