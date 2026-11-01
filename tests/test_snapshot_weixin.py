from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.snapshot_weixin_source import snapshot


class SnapshotTests(unittest.TestCase):
    def test_copy_unicode_empty_directories_single_file_and_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "空目录").mkdir(parents=True)
            (source / "消息.bin").write_bytes(b"synthetic\x00\xff")
            single = root / "program.bin"
            single.write_bytes(b"program fixture")
            with patch("tools.snapshot_weixin_source.assert_stopped"):
                report = snapshot({"data": source, "program": single}, root / "copy")
            self.assertTrue(report["accepted"])
            self.assertEqual(report["file_count"], 2)
            self.assertEqual((root / "copy/10_RAW_SNAPSHOT/data/消息.bin").read_bytes(), b"synthetic\x00\xff")
            self.assertTrue((root / "copy/10_RAW_SNAPSHOT/data/空目录").is_dir())
            self.assertEqual((root / "copy/10_RAW_SNAPSHOT/program/program.bin").read_bytes(), b"program fixture")
            with patch("tools.snapshot_weixin_source.assert_stopped"):
                with self.assertRaises(FileExistsError):
                    snapshot({"data": source}, root / "copy")

    def test_source_destination_overlap_and_running_process_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with self.assertRaisesRegex(ValueError, "overlap"):
                snapshot({"data": source}, source / "copy")
            with patch("tools.snapshot_weixin_source.assert_stopped", side_effect=RuntimeError("running")):
                with self.assertRaisesRegex(RuntimeError, "running"):
                    snapshot({"data": source}, root / "copy")
            self.assertFalse((root / "copy").exists())


if __name__ == "__main__":
    unittest.main()
