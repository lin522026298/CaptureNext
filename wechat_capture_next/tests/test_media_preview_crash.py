from contextlib import closing
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from wechat_capture_v2.objects import Objects
from wechat_capture_next import media_preview


@unittest.skipUnless(importlib.util.find_spec('pilk'),'optional native codec absent')
class PreviewCrashTests(unittest.TestCase):
    def crash(self,folder,phase):
        script='''import os,sys,sqlite3,struct,tempfile
from pathlib import Path
from contextlib import closing
from unittest.mock import patch
import pilk
from wechat_capture_next.tests import test_viewer_media as fixtures
from wechat_capture_next import media_preview,viewer_media
original=tempfile.TemporaryDirectory
with patch.object(fixtures.tempfile,'TemporaryDirectory',lambda:original(dir=sys.argv[1])):
    f=fixtures.MediaTests('test_wrong_source_or_dictionary_does_not_associate');f.setUp()
pcm=f.root/'tone.pcm';silk=f.root/'tone.silk';pcm.write_bytes(struct.pack('<h',1200)*24000)
pilk.encode(str(pcm),str(silk),pcm_rate=24000,tencent=True)
with closing(sqlite3.connect(f.path)) as db:db.execute('UPDATE VoiceInfo SET voice_data=?',(silk.read_bytes(),));db.commit()
f.ingest();message=next(m for m in f.archive.list_messages() if m['server_id']=='100')
item=viewer_media.for_message(f.archive,message['logical_id'])['rows'][0]
output=f.root/'output';output.mkdir()
if sys.argv[2]=='before_worker':
    media_preview.subprocess.Popen=lambda *a,**k:os._exit(73)
else:
    original_rename=os.rename
    def rename(first,second):
        if str(first).endswith('.pending.private.json'):os._exit(73)
        return original_rename(first,second)
    media_preview.os.rename=rename
media_preview.prepare(f.archive,f.service.objects.db,output,logical_id=message['logical_id'],snapshot_id=item['snapshot_id'],locator=item['locator'])
'''
        result=subprocess.run([sys.executable,'-c',script,str(folder),phase],capture_output=True)
        self.assertEqual(result.returncode,73,result.stderr.decode(errors='replace'))
        roots=[p for p in folder.iterdir() if p.is_dir()];self.assertEqual(len(roots),1)
        return roots[0]
    def test_real_exit_after_plaintext_copy_then_owned_recovery(self):
        with tempfile.TemporaryDirectory() as folder:
            root=self.crash(Path(folder),'before_worker');cache=root/'output/media-preview'
            self.assertTrue(list(cache.glob('decode-*')))
            with closing(Objects(root/'state/objects.sqlite')) as objects,patch('wechat_capture_next.media_preview.time.time',return_value=10**10):
                self.assertEqual(media_preview._recover(cache,objects.db),1)
            self.assertFalse(list(cache.glob('decode-*')))
    def test_real_exit_between_wav_rename_and_receipt_finishes_publication(self):
        with tempfile.TemporaryDirectory() as folder:
            root=self.crash(Path(folder),'before_receipt');cache=root/'output/media-preview'
            pending=list(cache.glob('*.pending.private.json'));self.assertEqual(len(pending),1)
            ident=pending[0].name.removesuffix('.pending.private.json')
            with closing(Objects(root/'state/objects.sqlite')) as objects,patch('wechat_capture_next.media_preview.time.time',return_value=10**10):
                media_preview._recover(cache,objects.db)
            self.assertFalse(list(cache.glob('decode-*')));self.assertFalse(list(cache.glob('*.pending.private.json')))
            self.assertEqual(media_preview.read(root/'output',ident).content_type,'audio/wav')


if __name__=='__main__':unittest.main()
