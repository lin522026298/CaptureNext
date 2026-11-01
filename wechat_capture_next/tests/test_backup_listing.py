from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from wechat_capture_next.backup_listing import listing


class BackupListingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.core = SimpleNamespace(paired_repository=base/'rolling', union_repository=base/'legacy')
        self.core.paired_repository.mkdir(); self.core.union_repository.mkdir()

    def test_bad_rolling_still_lists_legacy_without_exception_details(self):
        with patch('wechat_capture_next.pair_repository.snapshots', side_effect=ValueError('private detail')), \
             patch('wechat_capture_next.backup_listing._legacy', return_value=[dict(snapshot_id='old', repository='legacy')]):
            result = listing(self.core)
        self.assertEqual(result['snapshots'][0]['snapshot_id'], 'old')
        self.assertEqual(result['repositories']['rolling']['error_type'], 'ValueError')
        self.assertNotIn('private detail', str(result))
        self.assertFalse(result['contents_verified'])

    def test_bad_legacy_does_not_discard_rolling_rows(self):
        with patch('wechat_capture_next.pair_repository.snapshots', return_value=[dict(snapshot_id='new', verified_at='now')]), \
             patch('wechat_capture_next.backup_listing._legacy', side_effect=OSError('private')):
            result = listing(self.core)
        self.assertEqual(result['snapshots'][0]['snapshot_id'], 'new')
        self.assertEqual(result['repositories']['legacy']['status'], 'unavailable')
        self.assertEqual(result['repositories']['rolling']['status'], 'listed')

    def test_both_failed_are_not_an_empty_success(self):
        with patch('wechat_capture_next.pair_repository.snapshots', side_effect=ValueError()), \
             patch('wechat_capture_next.backup_listing._legacy', side_effect=ValueError()):
            result = listing(self.core)
        self.assertEqual(result['snapshots'], [])
        self.assertTrue(all(row['status']=='unavailable' for row in result['repositories'].values()))

    def test_absent_repositories_are_distinct_from_failures(self):
        self.core.paired_repository = None
        self.core.union_repository = self.core.union_repository/'absent'
        result = listing(self.core)
        self.assertTrue(all(row['status']=='absent' for row in result['repositories'].values()))


if __name__ == '__main__':
    unittest.main()
