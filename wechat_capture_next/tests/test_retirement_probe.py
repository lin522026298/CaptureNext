import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from tools.wechat_retirement_probe import exclusive_probe
from wechat_capture_next.prepare_pair_restore_cleanup import _directory_identities
from wechat_capture_next.storage_ledger import inventory
from wechat_capture_next.union_archive import cold_input


@unittest.skipUnless(os.name == "nt", "Windows held-handle audit")
class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "nested").mkdir()
        (self.root / "nested/data").write_bytes(b"synthetic" * 100)
        self.evidence = inventory(self.root)
        self.hashes = {r["relative"]: hashlib.sha256((self.root / r["relative"]).read_bytes()).hexdigest() for r in self.evidence["files"]}
        self.dirs = _directory_identities(self.root, self.evidence)

    def tearDown(self):
        self.temp.cleanup()

    def test_success_is_non_mutating_and_closes_handles(self):
        result = exclusive_probe(self.root, self.evidence, self.hashes, self.dirs, lambda: {})
        self.assertTrue(result["all_owned_probe_handles_closed"])
        self.assertEqual(self.evidence["entries_sha256"], inventory(self.root)["entries_sha256"])
        self.assertEqual(b"synthetic" * 100, (self.root / "nested/data").read_bytes())

    def test_hash_failure_closes_handles(self):
        with self.assertRaisesRegex(ValueError, "SHA"):
            exclusive_probe(self.root, self.evidence, {"nested/data": "0" * 64}, self.dirs, lambda: {})
        self.assertEqual(b"synthetic" * 100, (self.root / "nested/data").read_bytes())

    def test_new_child_during_final_checks_is_rejected(self):
        def change():
            (self.root / "nested/new").write_bytes(b"synthetic")
            return {}
        with self.assertRaisesRegex(ValueError, "child set"):
            exclusive_probe(self.root, self.evidence, self.hashes, self.dirs, change)

    def test_preexisting_reader_is_rejected(self):
        with cold_input(self.root / "nested/data"):
            with self.assertRaises(OSError):
                exclusive_probe(self.root, self.evidence, self.hashes, self.dirs, lambda: {})
