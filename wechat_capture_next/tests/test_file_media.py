import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.test_wua_store import observation
from wechat_capture_next import file_media
from wechat_capture_next.cas_stream import publish
from wechat_capture_next.tests import test_viewer_media as fixtures


class FileMediaTests(unittest.TestCase):
    setUp = fixtures.MediaTests.setUp

    def prepare(self, body=None, *, count=1, raw=None, kind='file', path=None):
        self.data = b'raw original bytes'+b'x'*700000 if raw is None else raw
        self.md5 = hashlib.md5(self.data).hexdigest()
        if body is None:
            if kind == 'file':
                body = '<msg><appmsg><title>example.bin</title><type>6</type><appattach><totallen>'+str(len(self.data))+'</totallen><filemd5>'+self.md5+'</filemd5></appattach></appmsg></msg>'
            else:
                body = '<msg><videomsg md5="'+self.md5+'" length="'+str(len(self.data))+'"/></msg>'
        self.service.catalog.db.execute('CREATE TABLE asset_history(source_id,relative_path,file_sha,bytes,cycle_id)')
        self.archive.import_observations(dict(source_id='media-files'), dict(snapshot_id='media-files'),[
            observation(native_locator=1000+i, server_id=str(8000+i), message_type='49' if kind == 'file' else '43', body_text=body) for i in range(count)])
        obj = publish(self.service.objects, io.BytesIO(self.data), len(self.data)); self.sha = obj['sha256']
        self.service.catalog.db.execute('INSERT INTO asset_history VALUES(?,?,?,?,?)',
            ('current', path or ('File/example.bin' if kind == 'file' else 'Video/'+self.md5+'.mp4'), self.sha, len(self.data), 'accepted'))
        self.service.catalog.db.commit()
        self.messages = [m for m in self.archive.list_messages() if m['message_type'] in ('49', '43')]
        self.logical = self.messages[0]['logical_id']

    def test_full_original_hashes_not_message_deduplication_and_no_database_writes(self):
        self.prepare(count=2)
        before = [db.total_changes for db in (self.archive._db, self.service.catalog.db, self.service.objects.db)]
        for message in self.messages:
            result = file_media.verify(self.archive, self.service.catalog.db, self.service.objects.db,
                logical_id=message['logical_id'], sha=self.sha)
            self.assertEqual(result['status'], 'linked')
            self.assertTrue(result['sha256_original_bytes_verified'])
            self.assertFalse(result['origin_link_confirmed'])
            self.assertEqual(result['preview_status'], 'saved_unsupported')
        self.assertNotEqual(self.messages[0]['logical_id'], self.messages[1]['logical_id'])
        self.assertEqual(before, [db.total_changes for db in (self.archive._db, self.service.catalog.db, self.service.objects.db)])

    def test_real_file_shape_without_md5_is_only_candidate(self):
        self.prepare('<msg><appmsg><title>example.bin</title><type>6</type><appattach><totallen>1</totallen><aeskey>'+('a'*32)+'</aeskey><filekey>'+('b'*32)+'</filekey><cdnattachurl>https://invalid.local/</cdnattachurl></appattach></appmsg></msg>', raw=b'x')
        result = file_media.verify(self.archive, self.service.catalog.db, self.service.objects.db, logical_id=self.logical, sha=self.sha)
        self.assertEqual(result['status'], 'candidate')
        self.assertFalse(result['content_checksum_matches'])
        self.assertIsNone(file_media.hints(self.archive, self.logical)['claims'][0]['md5'])

    def test_wrong_checksum_or_size_never_becomes_link(self):
        self.prepare('<msg><appmsg><title>example.bin</title><type>6</type><appattach><totallen>1</totallen><md5>'+('a'*32)+'</md5></appattach></appmsg></msg>')
        result = file_media.verify(self.archive, self.service.catalog.db, self.service.objects.db, logical_id=self.logical, sha=self.sha)
        self.assertEqual(result['status'], 'candidate')
        claims = file_media.hints(self.archive, self.logical)['claims']; claims[0]['md5'] = self.md5
        self.assertEqual(file_media._result(dict(file_sha=self.sha), claims, self.md5, len(self.data))['status'], 'candidate')

    def test_video_raw_and_original_are_independent_claims_not_thumbnail(self):
        self.prepare(kind='video')
        result = file_media.verify(self.archive, self.service.catalog.db, self.service.objects.db, logical_id=self.logical, sha=self.sha, kind='video')
        self.assertEqual(result['status'], 'linked')
        self.assertEqual(result['matching_claims'][0]['field'], 'videomsg.md5')
        self.assertEqual(file_media.candidates(self.archive, self.service.catalog.db, self.logical, kind='file')['status'], 'unsupported')

    def test_malformed_entity_xml_and_non_file_type_are_unsupported(self):
        for body in ('<!DOCTYPE msg [<!ENTITY a SYSTEM "file:///invalid">]><msg><appmsg>&a;</appmsg></msg>',
                '<msg><appmsg><title>example.bin</title><type>5</type><appattach><filemd5>'+('a'*32)+'</filemd5></appattach></appmsg></msg>', '<msg>'):
            with self.subTest(body=body):
                self.archive.import_observations(dict(source_id=body), dict(snapshot_id=body),[
                    observation(native_locator=998, server_id=hashlib.md5(body.encode()).hexdigest(), message_type='49', body_text=body)])
                message = next(m for m in self.archive.list_messages() if m['body_text'] == body)
                self.assertEqual(file_media.candidates(self.archive, None, message['logical_id'])['status'], 'unsupported')

    def test_all_object_variants_paginate_and_history_scope_preserved(self):
        self.prepare()
        for i in range(4):
            obj = publish(self.service.objects, io.BytesIO(bytes([i])), 1)
            self.service.catalog.db.execute('INSERT INTO asset_history VALUES(?,?,?,?,?)', ('historical', 'File/example.bin', obj['sha256'], 1, 'old'))
        self.service.catalog.db.commit(); seen = []; after = ''
        while True:
            page = file_media.candidates(self.archive, self.service.catalog.db, self.logical, after=after, limit=1)
            seen.extend(row['file_sha'] for row in page['rows'])
            if page['next_after'] is None:
                break
            after = page['next_after']
        self.assertEqual(len(seen), 5)
        self.assertEqual(len(set(seen)), 5)
        with self.assertRaises(ValueError):
            file_media.candidates(self.archive, None, self.logical, limit=0)

    def test_explicit_stream_export_readback_no_overwrite_and_boundaries(self):
        self.prepare()
        with tempfile.TemporaryDirectory() as output:
            target = Path(output)/'explicit-original.bin'
            args = dict(logical_id=self.logical, sha=self.sha, destination=target, protected_roots=[self.root])
            result = file_media.export(self.archive, self.service.catalog.db, self.service.objects.db, **args)
            self.assertEqual(target.read_bytes(), self.data)
            self.assertTrue(result['export_readback_verified']); self.assertFalse(result['automatically_opened'])
            with self.assertRaises(FileExistsError):
                file_media.export(self.archive, self.service.catalog.db, self.service.objects.db, **args)
        with self.assertRaisesRegex(ValueError, 'protected'):
            file_media.export(self.archive, None, self.service.objects.db, logical_id=self.logical, sha=self.sha,
                destination=self.root/'forbidden', protected_roots=[self.root])

    def test_corrupt_original_or_failed_export_is_never_success_or_left_partial(self):
        self.prepare()
        self.service.objects.db.execute("UPDATE chunk SET data=x'00'"); self.service.objects.db.commit()
        with self.assertRaises(Exception):
            file_media.verify(self.archive, self.service.catalog.db, self.service.objects.db, logical_id=self.logical, sha=self.sha)
        with tempfile.TemporaryDirectory() as output:
            target = Path(output)/'broken.bin'
            with self.assertRaises(Exception):
                file_media.export(self.archive, self.service.catalog.db, self.service.objects.db,
                    logical_id=self.logical, sha=self.sha, destination=target, protected_roots=[self.root])
            self.assertFalse(target.exists())

    def test_missing_metadata_is_scoped_missing_not_claim_original_absent(self):
        self.prepare()
        self.service.catalog.db.execute('DELETE FROM asset_history'); self.service.catalog.db.commit()
        result = file_media.candidates(self.archive, self.service.catalog.db, self.logical)
        self.assertEqual(result['status'], 'association_unknown')
        self.assertIn('not_proof_original_absent', result['missing_scope'])
        with self.assertRaises(ValueError):
            file_media.verify(self.archive, None, self.service.objects.db, logical_id=self.logical, sha=self.sha)

    def test_selected_missing_object_is_distinct_from_unknown_association(self):
        self.prepare()
        self.service.objects.db.execute('DELETE FROM file_chunk WHERE file_hash=?', (self.sha,))
        self.service.objects.db.execute('DELETE FROM file WHERE hash=?', (self.sha,)); self.service.objects.db.commit()
        result = file_media.verify(self.archive, self.service.catalog.db, self.service.objects.db, logical_id=self.logical, sha=self.sha)
        self.assertEqual(result['status'], 'file_missing')
        self.assertFalse(result['sha256_original_bytes_verified'])

    def test_raw_video_length_and_checksum_no_thumbnail_evidence(self):
        raw = b'raw video original'; md5 = hashlib.md5(raw).hexdigest()
        self.prepare('<msg><videomsg md5="'+('a'*32)+'" length="2" rawmd5="'+md5+'" rawlength="'+str(len(raw))+'" cdnthumbmd5="'+('b'*32)+'"/></msg>',
            raw=raw, kind='video', path='Video/'+md5+'.mp4')
        result = file_media.verify(self.archive, self.service.catalog.db, self.service.objects.db,
            logical_id=self.logical, sha=self.sha)
        self.assertEqual(result['status'], 'linked')
        self.assertEqual([c['field'] for c in result['matching_claims']], ['videomsg.rawmd5'])

    def test_checksum_token_boundary_and_filename_are_not_fuzzy_guesses(self):
        claim = dict(md5='a'*32, filename='名字.pdf')
        self.assertFalse(file_media._path_basis('Video/0'+('a'*32)+'1.mp4', claim))
        self.assertFalse(file_media._path_basis('File/名字(1).pdf', claim))
        self.assertEqual(file_media._path_basis('File/名字.pdf', claim), ['explicit_filename_equal'])
        self.assertIn('explicit_checksum_token_in_retained_path', file_media._path_basis('Video/'+('a'*32)+'.mp4', claim))

    def test_empty_original_is_authenticatable_and_selection_is_required(self):
        self.prepare(raw=b'')
        result = file_media.verify(self.archive, self.service.catalog.db, self.service.objects.db,
            logical_id=self.logical, sha=self.sha)
        self.assertEqual(result['status'], 'linked'); self.assertEqual(result['bytes'], 0)
        with self.assertRaises(ValueError):
            file_media.verify(self.archive, self.service.catalog.db, self.service.objects.db,
                logical_id=self.logical, sha=None)

    def native_message(self,blob,*,native_type='43',md5=None):
        ident=hashlib.sha256(blob+native_type.encode()+str(md5).encode()).hexdigest()
        body='<msg><videomsg'+(' md5="'+md5+'" length="'+str(len(self.data))+'"' if md5 else '')+'/></msg>'
        self.archive.import_observations(dict(source_id='native-'+ident),dict(snapshot_id='native-'+ident),[
            observation(native_locator=1777,server_id=str(int(ident[:15],16)),message_type=native_type,
                event_time='1901-01-01T00:00:00Z',body_text=body,raw_record=dict(packed_info_data=blob))])
        return next(m for m in self.archive.list_messages() if m['server_id']==str(int(ident[:15],16)))['logical_id']

    def test_independently_observed_video_4_8_identifier_is_not_content_md5(self):
        token='d'*32;blob=b'\x22\x22\x42\x20'+token.encode()
        self.prepare(kind='video',path='Video/'+token+'.mp4')
        for md5,expected in ((None,'candidate'),(self.md5,'linked'),('f'*32,'candidate')):
            logical=self.native_message(blob,md5=md5)
            page=file_media.candidates(self.archive,self.service.catalog.db,logical,kind='video')
            self.assertEqual(len(page['rows']),1)
            self.assertFalse(page['native_filename_hints'][0]['content_md5_claim'])
            self.assertEqual(page['native_filename_hints'][0]['field'],'raw_record.packed_info_data.protobuf.4.8')
            result=file_media.verify(self.archive,self.service.catalog.db,self.service.objects.db,logical_id=logical,sha=self.sha,kind='video')
            self.assertEqual(result['status'],expected)
            self.assertFalse(result['origin_link_confirmed'])
            self.assertIn('native_video_basename_identifier_not_content_md5',result['selection_basis'])

    def test_video_identifier_is_not_inferred_from_image_layout_or_unobserved_62(self):
        token='d'*32;self.prepare(kind='video',path='Video/'+token+'.mp4')
        image_layout=b'\x1a\x22\x22\x20'+token.encode()
        self.assertEqual(file_media.native_video_hints(self.archive,self.native_message(image_layout)),([],0))
        video_layout=b'\x22\x22\x42\x20'+token.encode()
        self.assertEqual(file_media.native_video_hints(self.archive,self.native_message(video_layout,native_type='62')),([],0))

    def test_video_basename_token_is_not_directory_substring_or_thumbnail(self):
        token='d'*32;claim=dict(identifier_kind='native_video_filename_identifier_candidate',token=token)
        for name in ('Video/'+token+'/other.mp4','Video/0'+token+'.mp4','Video/'+token+'.jpg','Video/'+token+'.dat'):
            self.assertEqual(file_media._path_basis(name,claim),[])
        self.assertTrue(file_media._path_basis('Video/'+token+'_raw.mp4',claim))

    def test_truncated_duplicate_and_wrong_wire_video_layouts_are_unsupported(self):
        token='d'*32;self.prepare(kind='video',path='Video/'+token+'.mp4')
        nested=b'\x42\x20'+token.encode()
        for blob in (b'\x22\x22'+nested[:-1],b'\x22\x44'+nested+nested,b'\x20\x01',b'\x22\x02\x40\x01'):
            with self.subTest(blob=blob):
                hints,unsupported=file_media.native_video_hints(self.archive,self.native_message(blob))
                self.assertFalse(hints);self.assertEqual(unsupported,1)

    def test_unsupported_hint_skips_asset_metadata_scan(self):
        self.prepare('<msg><appmsg><type>5</type></appmsg></msg>')
        with patch.object(file_media, '_tables', side_effect=AssertionError('must not scan')):
            self.assertEqual(file_media.candidates(self.archive, self.service.catalog.db, self.logical)['status'], 'unsupported')


if __name__ == '__main__':
    unittest.main()
