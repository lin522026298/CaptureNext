from contextlib import closing
import json
from pathlib import Path
import tempfile
import unittest

from tests.test_wua_store import observation
from wua import ArchiveStore
from wua.bag import export_bag, verify_bag
from wua.viewer import format_detail


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "archive.sqlite"
        with ArchiveStore(self.path) as store:
            store.import_observations({"source_id": "fixture"}, {"snapshot_id": "snapshot"}, [observation()])

    def tearDown(self):
        self.temp.cleanup()

    def test_bag_hashes_backup_interchange_and_readonly_origin(self):
        before = self.path.read_bytes()
        output = self.root / "归档 bag"
        result = export_bag(self.path, output)
        self.assertTrue(result["pass"])
        self.assertEqual(before, self.path.read_bytes())
        self.assertFalse((output / "INCOMPLETE.txt").exists())
        self.assertTrue(verify_bag(output)["pass"])
        raw = (output / "data/interchange/message_observation.jsonl").read_text(encoding="utf-8")
        self.assertIn("raw_record_json", json.loads(raw))
        with ArchiveStore(output / "data/canonical/wua.sqlite", readonly=True) as store:
            self.assertEqual(store.stats()["observations"], 1)
            self.assertEqual(store.semantic_digest(), result["semantic_digest"])

    def test_existing_export_not_overwritten(self):
        output = self.root / "bag"
        output.mkdir()
        (output / "keep.txt").write_text("keep")
        with self.assertRaises(FileExistsError):
            export_bag(self.path, output)
        self.assertEqual((output / "keep.txt").read_text(), "keep")

    def test_corruption_and_extra_payload_detected(self):
        output = self.root / "bag"
        export_bag(self.path, output)
        extra = output / "data/extra.txt"
        extra.write_text("extra")
        with self.assertRaisesRegex(ValueError, "unlisted"):
            verify_bag(output)
        extra.unlink()
        (output / "data/provenance/coverage.json").write_text("corrupt")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify_bag(output)

    def test_manifest_traversal_is_rejected(self):
        output = self.root / "bag"
        export_bag(self.path, output)
        (output / "manifest-sha256.txt").write_text("0" * 64 + "  ../outside\n")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            verify_bag(output)

    def test_viewer_detail_preserves_provenance_without_rendering_payload(self):
        before = self.path.read_bytes()
        with ArchiveStore(self.path, readonly=True) as store:
            message = store.list_messages()[0]
            detail = json.loads(format_detail(store, message["logical_id"]))
            self.assertEqual(detail["observations"][0]["source_id"], "fixture")
            self.assertIn("raw_record", detail["observations"][0])
        self.assertEqual(before, self.path.read_bytes())


if __name__ == "__main__":
    unittest.main()
