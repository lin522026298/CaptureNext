import json
import os
from pathlib import Path
import tempfile
import unittest

from wechat_capture_next.storage_ledger import inventory, verify_inventory


class StorageLedgerTests(unittest.TestCase):
    def test_exact_readonly_inventory_and_mutation_gate(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path/'nested').mkdir()
            (path/'nested'/'payload').write_bytes(b'abc')
            before = inventory(path)
            self.assertTrue(before['deletion_candidate_clean'])
            self.assertEqual((before['file_count'],before['logical_bytes']),(1,3))
            self.assertEqual(verify_inventory(json.loads(json.dumps(before)))['entries_sha256'],before['entries_sha256'])
            (path/'nested'/'payload').write_bytes(b'abcd')
            with self.assertRaisesRegex(ValueError,'changed'):
                verify_inventory(before)

    def test_hardlinks_count_storage_once_and_block_clean_flag(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path/'first').write_bytes(b'abc')
            try:
                os.link(path/'first',path/'second')
            except OSError as exc:
                self.skipTest(str(exc))
            report = inventory(path)
            self.assertFalse(report['deletion_candidate_clean'])
            self.assertEqual(report['hardlinked_files'],2)
            self.assertEqual(report['logical_bytes'],6)
            self.assertEqual(report['allocated_bytes'],report['files'][0]['allocated_bytes'])

    def test_no_follow_links_or_linked_ancestor(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path/'real').mkdir()
            (path/'real'/'payload').write_bytes(b'abc')
            try:
                os.symlink(path/'real',path/'link',target_is_directory=True)
            except OSError as exc:
                self.skipTest(str(exc))
            report = inventory(path)
            self.assertFalse(report['deletion_candidate_clean'])
            self.assertEqual(report['file_count'],1)
            with self.assertRaisesRegex(ValueError,'reparse'):
                inventory(path/'link')


if __name__ == '__main__':
    unittest.main()
