import os
from pathlib import Path
import tempfile
import unittest

from wechat_capture_next.state_guard import state_preflight, writer_lock
from wechat_capture_next.service import CaptureService


class StateGuardTests(unittest.TestCase):
    def test_hardlinked_state_files_rejected_before_any_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root/'old'
            protected.write_bytes(b'protected old bytes')
            state = root/'next'
            state.mkdir()
            for name in ('catalog.sqlite', 'objects.sqlite-wal', 'writer.lock',
                         'config.private.json', 'cache/view.db', 'cache/view.pages.sqlite'):
                target = state/name
                target.parent.mkdir(exist_ok=True)
                os.link(protected, target)
                for operation in (state_preflight, CaptureService):
                    with self.assertRaisesRegex(ValueError, 'hardlinked'):
                        operation(state)
                with self.assertRaisesRegex(ValueError, 'hardlinked'):
                    with writer_lock(state):
                        self.fail('lock must not open')
                self.assertEqual(protected.read_bytes(), b'protected old bytes')
                self.assertFalse((state/'writer.lock').exists() and name != 'writer.lock')
                target.unlink()

    def test_normal_lock_compatible_and_missing_state_not_created(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'next'
            with self.assertRaises(FileNotFoundError):
                with writer_lock(state):
                    pass
            self.assertFalse(state.exists())
            state.mkdir()
            with writer_lock(state):
                self.assertTrue((state/'writer.lock').exists())
            self.assertEqual((state/'writer.lock').read_bytes(), b'0')
