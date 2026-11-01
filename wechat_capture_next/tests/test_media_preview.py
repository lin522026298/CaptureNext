from contextlib import closing
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import struct
import unittest
from unittest.mock import patch
from wechat_capture_v2.common import write_json_new

from wechat_capture_next.tests import test_viewer_media as fixtures
from wechat_capture_next import media_preview
from wechat_capture_v2.common import canonical
from wechat_capture_next.cas_stream import publish


class PreviewIntegrityTests(unittest.TestCase):
    setUp=fixtures.MediaTests.setUp
    ingest=fixtures.MediaTests.ingest

    def cached(self,raw_sha,*,data=b'RIFF synthetic derivative'):
        root=media_preview._cache(self.output)
        ident=hashlib.sha256(canonical([media_preview.CODEC,raw_sha]).encode()).hexdigest()
        (root/(ident+'.wav')).write_bytes(data)
        write_json_new(root/(ident+'.private.json'),dict(schema=media_preview.SCHEMA,
            artifact_id=ident,raw_sha=raw_sha,codec=media_preview.CODEC,bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),mime='audio/wav',audio=dict(synthetic=True)))
        return root,ident

    def selected_voice(self):
        self.ingest();message=next(m for m in self.archive.list_messages() if m['server_id']=='100')
        item=media_preview.viewer_media.for_message(self.archive,message['logical_id'])['rows'][0]
        self.args=dict(logical_id=message['logical_id'],snapshot_id=item['snapshot_id'],locator=item['locator'])
        self.output=self.root/'output';self.output.mkdir();self.sha=item['file_sha']

    def test_hit_authenticates_current_binding_once_and_does_not_decode(self):
        self.selected_voice();root,ident=self.cached(self.sha)
        before={p:p.read_bytes() for p in root.iterdir()}
        other=sqlite3.connect(':memory:');self.addCleanup(other.close)
        self.service.objects.db.backup(other)
        for db in (self.service.objects.db,other):
            with patch.object(media_preview,'_blocks',wraps=media_preview._blocks) as authenticated,\
                 patch.object(media_preview.subprocess,'Popen',side_effect=AssertionError('no repeated decoding')):
                result=media_preview.prepare(self.archive,db,self.output,**self.args)
            self.assertEqual(authenticated.call_count,1)
            self.assertEqual(authenticated.call_args.args[0],db)
            self.assertTrue(result['reused']);self.assertTrue(result['sha256_original_bytes_verified'])
            self.assertEqual(result['artifact_id'],ident)
        self.assertEqual(before,{p:p.read_bytes() for p in root.iterdir()})

    def test_hit_missing_or_corrupt_bound_original_preserves_wav_and_rejects_ready(self):
        self.selected_voice();root,_=self.cached(self.sha)
        before={p:p.read_bytes() for p in root.iterdir()}
        for mutation in ('DELETE FROM file_chunk','DELETE FROM file_chunk; DELETE FROM file',
                "UPDATE chunk SET data=x'00'",'UPDATE file SET bytes=bytes+1'):
            other=sqlite3.connect(':memory:');self.addCleanup(other.close);self.service.objects.db.backup(other)
            other.executescript(mutation);other.commit()
            with self.subTest(mutation=mutation),self.assertRaises(Exception):
                media_preview.prepare(self.archive,other,self.output,**self.args)
            self.assertEqual(before,{p:p.read_bytes() for p in root.iterdir()})

    def test_prune_checks_all_originals_before_deleting_any_derivative(self):
        self.selected_voice();root,_=self.cached(self.sha)
        raw=b'another synthetic original';obj=publish(self.service.objects,io.BytesIO(raw),len(raw))
        self.cached(obj['sha256']);before={p:p.read_bytes() for p in root.iterdir()}
        self.service.objects.db.execute('DELETE FROM file_chunk WHERE file_hash=?',(obj['sha256'],))
        self.service.objects.db.execute('DELETE FROM file WHERE hash=?',(obj['sha256'],));self.service.objects.db.commit()
        with patch.object(media_preview,'BUDGET',1),self.assertRaisesRegex(ValueError,'preserve derived previews'):
            media_preview._prune(root,'',self.service.objects.db)
        self.assertEqual(before,{p:p.read_bytes() for p in root.iterdir()})
        publish(self.service.objects,io.BytesIO(raw),len(raw))
        with patch.object(media_preview,'BUDGET',(root/'OWNER.private.json').stat().st_size+1),\
             patch.object(media_preview,'_blocks',wraps=media_preview._blocks) as authenticated:
            result=media_preview._prune(root,'',self.service.objects.db)
        self.assertEqual(authenticated.call_count,2);self.assertEqual(result['removed_derivatives'],2)
        self.assertFalse(result['cleanup_pending']);self.assertEqual(len(list(root.iterdir())),1)

    def test_prune_corrupt_original_and_repeated_prepare_fail_without_growth(self):
        self.selected_voice();raw=b'irreconstructable original';obj=publish(self.service.objects,io.BytesIO(raw),len(raw))
        root,_=self.cached(obj['sha256']);before={p:p.read_bytes() for p in root.iterdir()}
        self.service.objects.db.execute("UPDATE chunk SET data=x'00' WHERE hash=?",(obj['sha256'],));self.service.objects.db.commit()
        with patch.object(media_preview,'BUDGET',1),patch.object(media_preview.subprocess,'Popen',side_effect=AssertionError('no decode or growth')):
            for _ in range(2):
                with self.assertRaisesRegex(ValueError,'preserve derived previews'):
                    media_preview.prepare(self.archive,self.service.objects.db,self.output,**self.args)
                self.assertEqual(before,{p:p.read_bytes() for p in root.iterdir()})

    def test_over_budget_hit_is_not_reported_ready_when_keep_cannot_be_pruned(self):
        self.selected_voice();root,_=self.cached(self.sha);before={p:p.read_bytes() for p in root.iterdir()}
        with patch.object(media_preview,'BUDGET',1),self.assertRaisesRegex(ValueError,'budget requires maintenance'):
            media_preview.prepare(self.archive,self.service.objects.db,self.output,**self.args)
        self.assertEqual(before,{p:p.read_bytes() for p in root.iterdir()})


@unittest.skipUnless(importlib.util.find_spec('pilk'),'optional native codec absent')
class PreviewTests(unittest.TestCase):
    setUp=fixtures.MediaTests.setUp
    ingest=fixtures.MediaTests.ingest
    def test_real_worker_cas_to_wave_reuse_and_corruption_fail_closed(self):
        import pilk
        pcm=self.root/'tone.pcm';silk=self.root/'tone.silk'
        pcm.write_bytes(struct.pack('<h',1200)*24000)
        pilk.encode(str(pcm),str(silk),pcm_rate=24000,tencent=True)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('UPDATE VoiceInfo SET voice_data=?',(silk.read_bytes(),));db.commit()
        self.ingest();row=next(m for m in self.archive.list_messages() if m['server_id']=='100')
        from wechat_capture_next.viewer_media import for_message
        item=for_message(self.archive,row['logical_id'])['rows'][0]
        output=self.root/'output';output.mkdir()
        args=dict(logical_id=row['logical_id'],snapshot_id=item['snapshot_id'],locator=item['locator'])
        with patch.object(media_preview,'_blocks',wraps=media_preview._blocks) as authenticated:
            result=media_preview.prepare(self.archive,self.service.objects.db,output,**args)
        self.assertEqual(authenticated.call_count,1)
        self.assertFalse(result['reused']);binary=media_preview.read(output,result['artifact_id'])
        self.assertEqual(binary.content_type,'audio/wav');self.assertTrue(binary.data.startswith(b'RIFF'))
        self.assertFalse(list((output/'media-preview').glob('decode-*')))
        before={p:p.read_bytes() for p in (output/'media-preview').iterdir()}
        self.assertTrue(media_preview.prepare(self.archive,self.service.objects.db,output,**args)['reused'])
        self.assertEqual(before,{p:p.read_bytes() for p in (output/'media-preview').iterdir()})
        target=output/'media-preview'/(result['artifact_id']+'.wav');target.write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError,'differs'):media_preview.read(output,result['artifact_id'])
        with self.assertRaisesRegex(ValueError,'differs'):media_preview.prepare(self.archive,self.service.objects.db,output,**args)
    def test_post_publication_maintenance_failure_preserves_bounded_outputs_and_blocks_growth(self):
        import pilk
        pcm=self.root/'tone.pcm';silk=self.root/'tone.silk'
        pcm.write_bytes(struct.pack('<h',1200)*24000);pilk.encode(str(pcm),str(silk),pcm_rate=24000,tencent=True)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('UPDATE VoiceInfo SET voice_data=?',(silk.read_bytes(),));db.commit()
        self.ingest();message=next(m for m in self.archive.list_messages() if m['server_id']=='100')
        item=media_preview.viewer_media.for_message(self.archive,message['logical_id'])['rows'][0]
        args=dict(logical_id=message['logical_id'],snapshot_id=item['snapshot_id'],locator=item['locator'])
        self.output=self.root/'output';self.output.mkdir()
        raw=b'missing old original';obj=publish(self.service.objects,io.BytesIO(raw),len(raw))
        root,_=PreviewIntegrityTests.cached(self,obj['sha256'])
        self.service.objects.db.execute('DELETE FROM file_chunk WHERE file_hash=?',(obj['sha256'],))
        self.service.objects.db.execute('DELETE FROM file WHERE hash=?',(obj['sha256'],));self.service.objects.db.commit()
        before={p:p.read_bytes() for p in root.iterdir()};budget=sum(len(data) for data in before.values())+1
        with patch.object(media_preview,'BUDGET',budget):
            with self.assertRaisesRegex(ValueError,'preserve derived previews'):
                media_preview.prepare(self.archive,self.service.objects.db,self.output,**args)
            after={p:p.read_bytes() for p in root.iterdir()}
            self.assertEqual({p:data for p,data in after.items() if p in before},before)
            self.assertEqual(len(after),len(before)+2)
            added=[p for p in after if p not in before]
            receipt=next(p for p in added if p.suffix=='.json')
            self.assertLessEqual(sum(len(data) for data in after.values()),budget+media_preview.MAX_WAV+len(after[receipt]))
            self.assertFalse(list(root.glob('decode-*')))
            with patch.object(media_preview.subprocess,'Popen',side_effect=AssertionError('no cache growth')):
                with self.assertRaisesRegex(ValueError,'preserve derived previews'):
                    media_preview.prepare(self.archive,self.service.objects.db,self.output,**args)
            self.assertEqual(after,{p:p.read_bytes() for p in root.iterdir()})
    def test_candidate_not_accepted_and_path_not_trusted(self):
        self.ingest();row=next(m for m in self.archive.list_messages() if m['server_id']=='102')
        from wechat_capture_next.viewer_media import for_message
        item=for_message(self.archive,row['logical_id'])['rows'][0]
        output=self.root/'output';output.mkdir()
        with self.assertRaisesRegex(ValueError,'confirmed'):
            media_preview.prepare(self.archive,self.service.objects.db,output,logical_id=row['logical_id'],snapshot_id=item['snapshot_id'],locator=item['locator'])
        with self.assertRaises(ValueError):media_preview.read(output,'../private')
    def test_recover_only_owned_dead_stages_and_count_unreceipted_files(self):
        self.ingest();output=self.root/'output';output.mkdir();cache=media_preview._cache(output)
        from wechat_capture_next.cas_stream import publish
        raw=b'recoverable original';obj=publish(self.service.objects,io.BytesIO(raw),len(raw))
        stage=cache/'decode-owned';stage.mkdir()
        write_json_new(stage/'STAGE.private.json',dict(schema=media_preview.STAGE,raw_sha=obj['sha256'],bytes=len(raw),
            pid=2147483647,created=0,stage_started=0))
        (stage/'input.silk').write_bytes(raw)
        self.assertEqual(media_preview._recover(cache,self.service.objects.db),1);self.assertFalse(stage.exists())
        orphan=cache/('0'*64+'.wav');orphan.write_bytes(b'diagnostic orphan, no trusted receipt')
        with patch.object(media_preview,'BUDGET',1):value=media_preview._prune(cache,'not-an-artifact')
        self.assertGreaterEqual(value['cache_bytes'],orphan.stat().st_size);self.assertTrue(value['cleanup_pending']);self.assertTrue(orphan.exists())
    def test_cache_junction_is_refused_for_read_and_prune(self):
        import os,subprocess
        if os.name!='nt':self.skipTest('Windows junction regression')
        output=self.root/'output';output.mkdir();outside=self.root/'outside';outside.mkdir()
        root=output/'media-preview'
        result=subprocess.run(['cmd','/c','mklink','/J',str(root),str(outside)],capture_output=True)
        if result.returncode:self.skipTest('cannot create local junction')
        try:
            keep=outside/'untouched';keep.write_bytes(b'not a cache')
            with self.assertRaises(ValueError):media_preview._cache(output)
            with self.assertRaises(ValueError):media_preview.read(output,'0'*64)
            with self.assertRaises(ValueError):media_preview._prune(root,'0'*64)
            self.assertEqual(keep.read_bytes(),b'not a cache')
        finally:root.rmdir()
