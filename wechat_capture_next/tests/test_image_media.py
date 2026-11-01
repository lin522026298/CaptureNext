import hashlib
import io
import json
import sqlite3
import struct
from contextlib import nullcontext,redirect_stdout
import unittest
from unittest.mock import patch
from PIL import Image
from tests.test_wua_store import observation
from wechat_capture_next import image_media
from wechat_capture_next import benchmark_images
from wechat_capture_next.cas_stream import publish
from wechat_capture_next.tests import test_viewer_media as fixtures


class ImageTests(unittest.TestCase):
    setUp=fixtures.MediaTests.setUp
    def prepare(self,*,count=1,raw=None):
        out=io.BytesIO();Image.new('RGB',(3,2),(10,20,30)).save(out,format='PNG');self.image=out.getvalue()
        self.md5=hashlib.md5(self.image).hexdigest()
        self.service.catalog.db.execute('CREATE TABLE asset_history(source_id,relative_path,file_sha,bytes,cycle_id)')
        self.archive.import_observations(dict(source_id='images'),dict(snapshot_id='images'),[
            observation(native_locator=i,server_id=str(5000+i),message_type='3',body_text='<msg><img md5="'+self.md5+'"/></msg>') for i in range(count)])
        value=raw if raw is not None else bytes(b^91 for b in self.image)
        obj=publish(self.service.objects,io.BytesIO(value),len(value));self.sha=obj['sha256']
        self.service.catalog.db.execute('INSERT INTO asset_history VALUES(?,?,?,?,?)',('current','Img/'+self.md5+'.dat',self.sha,len(value),'accepted'));self.service.catalog.db.commit()
        self.message=next(m for m in self.archive.list_messages() if m['message_type']=='3')
    def test_real_worker_pixel_validation_checksum_and_memory_only_reuse(self):
        self.prepare(count=2);cache=image_media.ImageCache(budget=1024)
        candidates=image_media.candidates(self.archive,self.service.catalog.db,self.message['logical_id'])
        self.assertEqual(candidates['status'],'candidate');self.assertFalse(candidates['rows'][0]['origin_link_confirmed'])
        before=[db.total_changes for db in (self.archive._db,self.service.catalog.db,self.service.objects.db)]
        args=dict(logical_id=self.message['logical_id'],sha=self.sha,expected_md5=self.md5)
        result=cache.prepare(self.archive,self.service.catalog.db,self.service.objects.db,**args)
        self.assertTrue(result['content_checksum_matches']);self.assertFalse(result['origin_link_confirmed'])
        self.assertEqual(cache.read(result['artifact_id']).data,self.image)
        self.assertTrue(cache.prepare(self.archive,self.service.catalog.db,self.service.objects.db,**args)['reused'])
        self.assertEqual(before,[db.total_changes for db in (self.archive._db,self.service.catalog.db,self.service.objects.db)])
        self.assertEqual(self.archive._db.execute("SELECT count(*) FROM logical_message WHERE message_type='3'").fetchone()[0],2)
        cache.clear();self.assertEqual(cache.bytes,0)
        with self.assertRaises(KeyError):cache.read(result['artifact_id'])
    def test_unsupported_original_and_tampered_claim_do_not_become_links(self):
        self.prepare(raw=b'not an image but an archived original');cache=image_media.ImageCache()
        result=cache.prepare(self.archive,self.service.catalog.db,self.service.objects.db,logical_id=self.message['logical_id'],sha=self.sha,expected_md5=self.md5)
        self.assertEqual(result['status'],'saved_unsupported');self.assertTrue(result['raw_preserved'])
        with self.assertRaises(ValueError):cache.prepare(self.archive,self.service.catalog.db,self.service.objects.db,
            logical_id=self.message['logical_id'],sha=self.sha,expected_md5='f'*32)
    def test_cache_hits_authenticate_bound_original_once_without_decoding_again(self):
        self.prepare();cache=image_media.ImageCache()
        args=dict(logical_id=self.message['logical_id'],sha=self.sha,expected_md5=self.md5)
        consumed=[];original=image_media._blocks
        def blocks(*args):
            for item in original(*args):
                consumed.append(len(item[-1]));yield item
        with patch.object(image_media,'_blocks',side_effect=blocks) as authenticated,\
             patch.object(image_media.subprocess,'run',wraps=image_media.subprocess.run) as decoded:
            first=cache.prepare(self.archive,self.service.catalog.db,self.service.objects.db,**args)
            second=cache.prepare(self.archive,self.service.catalog.db,self.service.objects.db,**args)
        self.assertEqual(authenticated.call_count,2)
        self.assertEqual(sum(consumed),2*len(self.image))
        self.assertEqual(decoded.call_count,1)
        self.assertEqual(first['artifact_id'],second['artifact_id'])
        self.assertTrue(second['reused']);self.assertTrue(second['sha256_original_bytes_verified'])
    def test_same_cache_cannot_conceal_missing_current_or_rebound_original(self):
        self.prepare();cache=image_media.ImageCache()
        args=dict(logical_id=self.message['logical_id'],sha=self.sha,expected_md5=self.md5)
        first=cache.prepare(self.archive,self.service.catalog.db,self.service.objects.db,**args)
        other=sqlite3.connect(':memory:');self.addCleanup(other.close)
        self.service.objects.db.backup(other)
        for db in (other,self.service.objects.db):
            db.execute('DELETE FROM file_chunk WHERE file_hash=?',(self.sha,))
            db.execute('DELETE FROM file WHERE hash=?',(self.sha,));db.commit()
            with patch.object(image_media.subprocess,'run',side_effect=AssertionError('must not decode cached pixels')):
                result=cache.prepare(self.archive,self.service.catalog.db,db,**args)
            self.assertEqual(result['status'],'file_missing');self.assertFalse(result['raw_preserved'])
            self.assertFalse(result['sha256_original_bytes_verified']);self.assertNotIn('artifact_id',result)
            self.assertIn('other_sources_not_claimed_absent',result['reason'])
        # Disposable pixels can remain in RAM, but never prove original retention.
        self.assertEqual(cache.read(first['artifact_id']).data,self.image)
    def test_same_cache_rebound_valid_original_reuses_pixels_but_corruption_is_rejected(self):
        self.prepare();cache=image_media.ImageCache()
        args=dict(logical_id=self.message['logical_id'],sha=self.sha,expected_md5=self.md5)
        cache.prepare(self.archive,self.service.catalog.db,self.service.objects.db,**args)
        for mutation in (None,"UPDATE chunk SET data=x'00'",'DELETE FROM file_chunk',
                'UPDATE file SET bytes=bytes+1','UPDATE chunk SET bytes=bytes+1'):
            other=sqlite3.connect(':memory:');self.addCleanup(other.close)
            self.service.objects.db.backup(other)
            if mutation:other.execute(mutation);other.commit()
            with self.subTest(mutation=mutation),patch.object(image_media.subprocess,'run',side_effect=AssertionError('must not decode')):
                if mutation:
                    with self.assertRaises(Exception):cache.prepare(self.archive,self.service.catalog.db,other,**args)
                else:
                    result=cache.prepare(self.archive,self.service.catalog.db,other,**args)
                    self.assertTrue(result['reused']);self.assertTrue(result['sha256_original_bytes_verified'])
        self.service.objects.db.execute("UPDATE chunk SET data=x'00'");self.service.objects.db.commit()
        with self.assertRaises(Exception):cache.prepare(self.archive,self.service.catalog.db,self.service.objects.db,**args)
    def test_preview_limits_authenticate_full_stream_without_decoding_or_retaining_pixels(self):
        self.prepare(raw=b'x'*700000);cache=image_media.ImageCache()
        args=dict(logical_id=self.message['logical_id'],sha=self.sha,expected_md5=self.md5)
        consumed=[];original=image_media._blocks
        def blocks(*args):
            for item in original(*args):
                consumed.append(len(item[-1]));yield item
        with patch.object(image_media,'MAX_IMAGE',1),patch.object(image_media,'_blocks',side_effect=blocks) as authenticated,\
             patch.object(image_media.subprocess,'run',side_effect=AssertionError('must not decode oversized original')):
            result=cache.prepare(self.archive,self.service.catalog.db,self.service.objects.db,**args)
        self.assertEqual(authenticated.call_count,1);self.assertEqual(sum(consumed),700000)
        self.assertEqual(result['reason'],'image_preview_size_limit_only')
        self.assertTrue(result['raw_preserved']);self.assertTrue(result['sha256_original_bytes_verified'])
        self.assertEqual(cache.bytes,0);self.assertNotIn('artifact_id',result)
        self.service.objects.db.execute("UPDATE chunk SET data=x'00'");self.service.objects.db.commit()
        with patch.object(image_media,'MAX_IMAGE',1),self.assertRaises(Exception):
            cache.prepare(self.archive,self.service.catalog.db,self.service.objects.db,**args)
    def test_memory_budget_limit_preserves_authenticated_raw_without_cache_entry(self):
        self.prepare();cache=image_media.ImageCache(budget=1)
        with patch.object(image_media,'_blocks',wraps=image_media._blocks) as authenticated:
            result=cache.prepare(self.archive,self.service.catalog.db,self.service.objects.db,
                logical_id=self.message['logical_id'],sha=self.sha,expected_md5=self.md5)
        self.assertEqual(authenticated.call_count,1)
        self.assertEqual(result['reason'],'image_memory_preview_budget_only')
        self.assertTrue(result['sha256_original_bytes_verified']);self.assertEqual(cache.bytes,0)
    def test_native_only_candidate_allows_preview_without_claiming_md5_verification(self):
        self.prepare();token='a1'*16
        self.service.catalog.db.execute('UPDATE asset_history SET relative_path=?',('cache/Img/'+token+'_h.dat',))
        self.archive.import_observations(dict(source_id='native-only'),dict(snapshot_id='native-only'),[
            observation(native_locator=500,server_id='9000',message_type='3',body_text='native image',
                raw_record=dict(packed_info_data=b'\x1a\x22\x22\x20'+token.encode()))])
        message=next(m for m in self.archive.list_messages() if m['server_id']=='9000')
        args=dict(logical_id=message['logical_id'],sha=self.sha,expected_md5=None)
        image_media.validate_request(args)
        listing=image_media.candidates(self.archive,self.service.catalog.db,message['logical_id'])
        self.assertEqual(listing['rows'][0]['md5s'],[])
        result=image_media.ImageCache().prepare(self.archive,self.service.catalog.db,self.service.objects.db,**args)
        self.assertEqual(result['status'],'ready');self.assertIsNone(result['content_checksum_matches'])
        self.assertFalse(result['content_checksum_matches_any_explicit_field'])
        self.assertEqual(result['association'],'candidate_content_checksum_unavailable_origin_unconfirmed')
        self.assertFalse(result['origin_link_confirmed']);self.assertTrue(result['sha256_original_bytes_verified'])
        self.service.catalog.db.execute('UPDATE asset_history SET relative_path=?',('cache/unrelated.dat',))
        with patch.object(image_media,'_blocks',side_effect=AssertionError('must not read without evidence')),self.assertRaisesRegex(ValueError,'not a retained candidate'):
            image_media.ImageCache().prepare(self.archive,self.service.catalog.db,self.service.objects.db,**args)
        for bad in ('f'*31,1,{},'A'*32):
            with self.subTest(bad=bad),self.assertRaises(ValueError):image_media.validate_request(dict(args,expected_md5=bad))
    def test_all_candidates_are_paginated_and_not_truncated(self):
        self.prepare()
        for i in range(3):
            obj=publish(self.service.objects,io.BytesIO(bytes([i])),1)
            self.service.catalog.db.execute('INSERT INTO asset_history VALUES(?,?,?,?,?)',('old','Img/'+self.md5+'-'+str(i)+'.dat',obj['sha256'],1,'historical'))
        self.service.catalog.db.commit();seen=[];after=''
        while True:
            page=image_media.candidates(self.archive,self.service.catalog.db,self.message['logical_id'],after=after,limit=1)
            seen.extend(r['file_sha'] for r in page['rows'])
            if page['next_after'] is None:break
            after=page['next_after']
        self.assertEqual(len(seen),4);self.assertEqual(len(set(seen)),4)
    def test_benchmark_prefers_images_and_deduplicates_original_objects(self):
        self.prepare(count=2)
        self.archive.import_observations(dict(source_id='stickers'),dict(snapshot_id='stickers'),[
            observation(native_locator=90,server_id='9090',message_type='47',body_text='<msg><emoji md5="'+self.md5+'"/></msg>')])
        self.assertEqual([kind for _,kind in benchmark_images.sample_messages(self.archive,10)],[3,3,47])
        target=self.root/'aggregate.private.json';stdout=io.StringIO()
        with patch.object(benchmark_images,'writer_lock',side_effect=lambda _:nullcontext()),\
             patch.object(benchmark_images,'_offline',return_value=nullcontext(self.service)),\
             patch.object(benchmark_images,'cold_input',side_effect=lambda _:nullcontext()),\
             patch.object(benchmark_images,'CompactArchive',return_value=nullcontext(self.archive)),redirect_stdout(stdout):
            benchmark_images.main(['--state',str(self.service.state),'--union',str(self.root/'union'),
                '--out',str(target),'--success-target','9'])
        receipt=json.loads(target.read_text())
        self.assertEqual(receipt['counts']['attempts'],1)
        self.assertEqual(receipt['counts']['duplicate_originals_skipped'],2)
        self.assertEqual(receipt['counts']['checksum_matches'],1)
        self.assertEqual(receipt['successes_private'][0]['mime'],'image/png')
        self.assertEqual(receipt['preview_RAM_bytes_after_clear'],0)
        self.assertNotIn('successes_private',json.loads(stdout.getvalue()))
        self.assertNotIn('diagnostic_private',json.loads(stdout.getvalue()))
    def test_benchmark_path_prefilter_never_truncates_on_budget_exhaustion(self):
        self.prepare()
        self.assertIn(self.md5,benchmark_images.retained_paths(self.archive,self.service.catalog.db))
        self.assertIsNone(benchmark_images.retained_paths(self.archive,self.service.catalog.db,budget=1))
        self.service.catalog.db.execute('UPDATE asset_history SET relative_path=?',('Img/'+'a'+self.md5+'b'+'.dat',))
        self.assertIn(self.md5,benchmark_images.retained_paths(self.archive,self.service.catalog.db))
    def test_v2_real_worker_full_image_and_content_checksum(self):
        from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
        from tools.decode_weixin_dat import Candidate,V2_MAGIC
        out=io.BytesIO();Image.new('RGB',(3,2),(10,20,30)).save(out,format='PNG');plain=out.getvalue()
        key=b'synthetic-key-16';prefix=plain[:16]+bytes([16])*16
        cipher=Cipher(algorithms.AES(key),modes.ECB()).encryptor()
        blob=V2_MAGIC+struct.pack('<II',16,len(plain)-16)+b'\x01'+cipher.update(prefix)+cipher.finalize()+bytes(b^91 for b in plain[16:])
        self.prepare(raw=blob);cache=image_media.ImageCache();cache.candidates=(Candidate(key,91),)
        result=cache.prepare(self.archive,self.service.catalog.db,self.service.objects.db,
            logical_id=self.message['logical_id'],sha=self.sha,expected_md5=self.md5)
        self.assertEqual(result['status'],'ready');self.assertTrue(result['content_checksum_matches'])
        self.assertEqual(result['image']['method'],'v2-aes-pkcs7-raw-xor')
        self.assertEqual(cache.read(result['artifact_id']).data,plain)
    def test_native_wire_layout_is_strict_and_does_not_infer_semantics(self):
        self.assertEqual(benchmark_images.wire_layout(b'\x08\x01\x12\x03abc'),[(1,0,0),(2,2,3)])
        for data in (b'\x00',b'\x08\x80',b'\x12\x03ab',b'\x0e',b'\x09abc'):
            with self.subTest(data=data),self.assertRaises(ValueError):benchmark_images.wire_layout(data)
    def test_native_layout_is_not_assumed_for_unobserved_message_types(self):
        self.prepare();token='a1'*16
        blob=b'\x1a\x22\x22\x20'+token.encode()
        self.archive.import_observations(dict(source_id='other-type'),dict(snapshot_id='other-type'),[
            observation(native_locator=900,server_id='19000',message_type='47',
                body_text='<msg><emoji md5="'+self.md5+'"/></msg>',raw_record=dict(packed_info_data=blob))])
        message=next(m for m in self.archive.list_messages() if m['server_id']=='19000')
        self.assertEqual(image_media.native_hints(self.archive,message['logical_id']),( [],0))
        self.assertEqual(image_media.hints(self.archive,message['logical_id'])[0][0]['md5'],self.md5)
    def test_native_filename_candidate_is_not_a_content_md5_or_time_link(self):
        self.prepare();token='a1'*16
        self.service.catalog.db.execute('UPDATE asset_history SET relative_path=?',('cache/Img/'+token+'_h.dat',))
        blob=b'\x08\x01\x10\x01\x1a\x22\x22\x20'+token.encode()+b'\x78\x01'+b'\x81\x01'+b'\0'*8+b'\x8d\x01'+b'\0'*4
        for index,md5 in enumerate((self.md5,'f'*32)):
            self.archive.import_observations(dict(source_id='native'),dict(snapshot_id='native-'+str(index)),[
                observation(native_locator=500+index,server_id=str(9000+index),message_type='3',event_time='1901-01-01T00:00:00Z',
                    body_text='<msg><img md5="'+md5+'"/></msg>',raw_record=dict(packed_info_data=blob))])
            message=next(m for m in self.archive.list_messages() if m['server_id']==str(9000+index))
            page=image_media.candidates(self.archive,self.service.catalog.db,message['logical_id'])
            self.assertEqual(page['rows'][0]['md5s'],[md5])
            self.assertEqual(page['native_filename_hints'][0]['token'],token)
            self.assertFalse(page['native_filename_hints'][0]['content_md5_claim'])
            self.assertEqual(page['rows'][0]['evidence'][0]['identifier_kind'],'native_filename_identifier_candidate')
            result=image_media.ImageCache().prepare(self.archive,self.service.catalog.db,self.service.objects.db,
                logical_id=message['logical_id'],sha=self.sha,expected_md5=md5)
            self.assertEqual(result['status'],'ready');self.assertFalse(result['origin_link_confirmed'])
            self.assertEqual(result['content_checksum_matches'],index==0)
            if index:self.assertEqual(result['association'],'candidate_checksum_mismatch_not_associated')
        self.service.catalog.db.execute('UPDATE asset_history SET relative_path=?',('cache/'+token+'/unrelated.dat',))
        self.assertEqual(image_media.candidates(self.archive,self.service.catalog.db,message['logical_id'])['rows'],[])
    def test_native_identifier_truncation_duplicates_and_wrong_shape_are_not_candidates(self):
        self.prepare();token='a1'*16;child=b'\x22\x20'+token.encode();parent=b'\x1a\x22'+child
        blobs=(parent[:-1],parent+parent,b'\x1a\x44'+child+child,b'\x1a\x21\x22\x1f'+token[:-1].encode(),
            b'\x18\x01',parent+b'\x7e',b'\x1a\x22\x22\x20'+b'0'*32)
        for index,blob in enumerate(blobs):
            self.archive.import_observations(dict(source_id='bad-native'),dict(snapshot_id='bad-native-'+str(index)),[
                observation(native_locator=800+index,server_id=str(9800+index),message_type='3',
                    body_text='<msg><img md5="'+self.md5+'"/></msg>',raw_record=dict(packed_info_data=blob))])
            message=next(m for m in self.archive.list_messages() if m['server_id']==str(9800+index))
            with self.subTest(index=index):
                hints,unsupported=image_media.native_hints(self.archive,message['logical_id'])
                self.assertEqual(hints,[]);self.assertEqual(unsupported,1)


if __name__=='__main__':unittest.main()
