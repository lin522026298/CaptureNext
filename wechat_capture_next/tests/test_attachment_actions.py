from contextlib import nullcontext
import json
import threading
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wechat_capture_next import attachment_actions as actions
from wechat_capture_next.tests import test_file_media as fixtures


class AttachmentActionsTests(unittest.TestCase):
    setUp=fixtures.FileMediaTests.setUp
    prepare=fixtures.FileMediaTests.prepare

    def test_live_shared_action_stream_export_and_original_account_guard(self):
        self.prepare(raw=b'actual synthetic original')
        separate=tempfile.TemporaryDirectory();self.addCleanup(separate.cleanup);output=Path(separate.name)
        (self.service.state/'config.private.json').write_text(json.dumps({'database_root':str(self.root/'account'/'db_storage')}))
        core=SimpleNamespace(reader_gate=threading.RLock(),offline_view=None,state=self.service.state,
            union_root=self.root/'union',service=self.service,output_root=output)
        params=dict(logical_id=self.logical,sha=self.sha,name='document.bin')
        with patch.object(actions,'CompactArchive',return_value=nullcontext(self.archive)):
            result=actions.perform(core,'export_attachment',params)
        self.assertTrue(result['export_readback_verified'])
        self.assertEqual((output/'document.bin').read_bytes(),self.data)
        self.assertFalse(result['automatically_opened'])
        self.archive._db.rollback()
        # Reusing a name never overwrites a prior successful deliverable.
        with patch.object(actions,'CompactArchive',return_value=nullcontext(self.archive)),self.assertRaises(FileExistsError):
            actions.perform(core,'export_attachment',params)
        self.archive._db.rollback()
        core.output_root=self.root/'account';core.output_root.mkdir()
        with patch.object(actions,'CompactArchive',return_value=nullcontext(self.archive)),self.assertRaisesRegex(ValueError,'protected'):
            actions.perform(core,'export_attachment',dict(params,name='must-not-write.bin'))
        self.assertFalse((core.output_root/'must-not-write.bin').exists())

    def test_unopened_offline_copy_and_unsafe_request_rejected(self):
        self.prepare(raw=b'x')
        core=SimpleNamespace(reader_gate=threading.RLock(),offline_view=None)
        with self.assertRaisesRegex(ValueError,'offline copy'):
            actions.perform(core,'verify_attachment',dict(logical_id=self.logical,sha=self.sha,view='restored'))
        for name in ('../escape','C:\\overwrite','evil.exe:stream','CON'):
            with self.assertRaises(ValueError):actions.validate(dict(logical_id=self.logical,sha=self.sha,name=name),export=True)


if __name__=='__main__':unittest.main()
