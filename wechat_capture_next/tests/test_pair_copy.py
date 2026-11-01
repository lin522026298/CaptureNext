from wechat_capture_next.tests import test_pair_repository as fixtures
from wechat_capture_next import pair_repository as repo,pair_copy
import unittest


class CopyTests(unittest.TestCase):
    setUp=fixtures.PairedTreeTests.setUp
    change=fixtures.PairedTreeTests.change
    publish=fixtures.PairedTreeTests.publish
    def test_selected_point_is_independent_and_source_unchanged(self):
        from wechat_capture_v2.common import digest_file
        first=self.publish();self.change(1);self.publish()
        before=digest_file(self.repository/repo.DATABASE)
        target=self.root/'one-point';result=pair_copy.copy_snapshot(self.repository,first['snapshot_id'],target)
        self.assertTrue(result['independent']);self.assertEqual(len(repo.snapshots(target)),1)
        self.assertEqual(digest_file(self.repository/repo.DATABASE),before)
        repo.restore_files(target,first['snapshot_id'],self.root/'restored-copy')
        self.assertNotEqual((self.root/'restored-copy/state/catalog.sqlite').read_bytes(),self.input.read_bytes())
    def test_corruption_cannot_publish_a_selected_point(self):
        first=self.publish()
        with repo.session(self.repository) as (db,_):db.execute("UPDATE block SET data=x'00' WHERE kind='D'");db.commit()
        target=self.root/'failed-copy'
        with self.assertRaises(ValueError):pair_copy.copy_snapshot(self.repository,first['snapshot_id'],target)
        self.assertFalse(repo.snapshots(target))
