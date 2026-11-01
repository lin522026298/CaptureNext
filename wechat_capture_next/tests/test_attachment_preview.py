import hashlib
import io
import unittest
from unittest.mock import patch

from tests.test_wua_store import observation
from wechat_capture_next import attachment_preview as preview
from wechat_capture_next import file_media
from wechat_capture_next.cas_stream import publish
from wechat_capture_next.media_preview import BinaryMedia
from wechat_capture_next.tests import test_file_media as file_fixtures
from wechat_capture_next.tests import test_viewer_media as media_fixtures


MP4 = b'\0\0\0\x18ftypmp42\0\0\0\0mp42isom' + b'\0\0\0\x08mdat'


class AttachmentPreviewTests(unittest.TestCase):
    setUp = media_fixtures.MediaTests.setUp
    fixture = file_fixtures.FileMediaTests.prepare

    def prepare(self, cache=None, **kwargs):
        return (cache or self.cache).prepare(self.archive, self.service.catalog.db,
            self.service.objects.db, logical_id=kwargs.pop('logical_id', self.logical),
            sha=kwargs.pop('sha', self.sha), **kwargs)

    def text(self, raw='safe 文本\n'.encode(), *, extension='txt', body=None):
        if body is None:
            body = '<msg><appmsg><title>sample.'+extension+'</title><type>6</type><appattach><totallen>'+str(len(raw))+'</totallen><filemd5>'+hashlib.md5(raw).hexdigest()+'</filemd5></appattach></appmsg></msg>'
        self.fixture(body, raw=raw, path='File/sample.'+extension)
        self.cache = preview.AttachmentCache()

    def test_authenticated_text_full_readback_and_no_writes_or_execution(self):
        self.text()
        dbs = (self.archive._db, self.service.catalog.db, self.service.objects.db)
        before = [db.total_changes for db in dbs]
        with patch('subprocess.run', side_effect=AssertionError('must not execute')):
            result = self.prepare()
            binary = self.cache.read(result['artifact_id'])
        self.assertIsInstance(binary, BinaryMedia)
        self.assertEqual(binary.data, self.data)
        self.assertEqual(binary.content_type, 'text/plain; charset=utf-8')
        self.assertEqual(result['status'], 'ready')
        self.assertEqual(result['media_kind'], 'text')
        self.assertEqual(result['association_status'], 'linked')
        self.assertTrue(result['sha256_original_bytes_verified'])
        self.assertTrue(result['content_checksum_matches'])
        self.assertFalse(result['origin_link_confirmed'])
        self.assertFalse(result['physical_origin_confirmed'])
        self.assertEqual(result['storage'], 'bounded_RAM_only_no_plaintext_temp_files')
        self.assertEqual(before, [db.total_changes for db in dbs])

    def test_mp4_container_is_not_playback_verification(self):
        self.fixture(raw=MP4, kind='video')
        self.cache = preview.AttachmentCache()
        result = self.prepare(kind='video')
        self.assertEqual(result['media_kind'], 'video')
        self.assertEqual(result['mime'], 'video/mp4')
        self.assertTrue(result['container_recognized'])
        self.assertFalse(result['browser_playback_verified'])
        self.assertEqual(self.cache.read(result['artifact_id']).data, MP4)

    def test_checksum_mismatch_candidate_can_be_seen_but_never_becomes_linked(self):
        body = '<msg><appmsg><title>sample.txt</title><type>6</type><appattach><totallen>1</totallen><filemd5>'+('a'*32)+'</filemd5></appattach></appmsg></msg>'
        self.text(raw=b'x', body=body)
        result = self.prepare()
        self.assertEqual(result['status'], 'ready')
        self.assertEqual(result['association_status'], 'candidate')
        self.assertEqual(result['association'], 'unconfirmed_candidate')
        self.assertFalse(result['content_checksum_matches'])
        self.assertFalse(result['origin_link_confirmed'])
        self.assertTrue(result['evidence_is_not_duplicate_message_identity'])

    def test_no_supported_message_hint_denies_object_access(self):
        self.text(body='<msg><appmsg><type>5</type></appmsg></msg>')
        with patch.object(file_media, '_blocks', side_effect=AssertionError('must not read')):
            with self.assertRaisesRegex(ValueError, 'not a retained candidate'):
                self.prepare()

    def test_malformed_unknown_webm_and_ogg_remain_preserved_without_artifact(self):
        self.fixture(kind='video', raw=b'bad header')
        self.cache = preview.AttachmentCache()
        for data in (b'bad header', b'\x1aE\xdf\xa3webm', b'OggS\0video',
                b'\0\0\0\x10ftypxxxx\0\0\0\0',
                b'\0\0\0\xffftypmp42\0\0\0\0',
                b'\0\0\0\x01ftypmp42\0\0\0\0'):
            with self.subTest(data=data):
                obj = publish(self.service.objects, io.BytesIO(data), len(data))
                md5 = hashlib.md5(data).hexdigest()
                self.service.catalog.db.execute('INSERT INTO asset_history VALUES(?,?,?,?,?)',
                    ('another', 'Video/'+self.md5+'.mp4', obj['sha256'], len(data), 'old'))
                self.service.catalog.db.commit()
                result = self.prepare(sha=obj['sha256'], kind='video')
                self.assertEqual(result['status'], 'saved_unsupported')
                self.assertEqual(result['md5'], md5)
                self.assertTrue(result['raw_preserved'])
                self.assertTrue(result['sha256_original_bytes_verified'])
                self.assertNotIn('artifact_id', result)

    def test_html_and_binary_extensions_are_not_rendered(self):
        for ext in ('html', 'htm', 'svg', 'exe', 'pdf', 'bin'):
            self.assertNotIn('.'+ext, preview.TEXT_EXTENSIONS)
        self.text(b'<script>alert(1)</script>', extension='html')
        result = self.prepare()
        self.assertEqual(result['status'], 'saved_unsupported')
        self.assertTrue(result['raw_preserved'])

    def test_text_extensions_only_plaintext_and_strict_utf8(self):
        self.text(b'\xff\xfe')
        result = self.prepare()
        self.assertEqual(result['preview_reason'], 'text_is_not_strict_utf8')
        self.assertTrue(result['raw_preserved'])
        self.assertEqual(self.cache.bytes, 0)
        self.assertEqual(preview._preview_type(b'x\0y', dict(evidence=[dict(claim=dict(filename='x.txt'))]), 'file')[2],
            'binary_control_characters_not_text')
        row = dict(evidence=[dict(claim=dict(filename='x.xml'))])
        self.assertEqual(preview._preview_type(b'<script>alert(1)</script>', row, 'file')[1],
            'text/plain; charset=utf-8')

    def test_preview_size_and_memory_limits_still_authenticate_all_original_bytes(self):
        self.text(b'x'*700000)
        original_blocks = file_media._blocks
        consumed = []

        def blocks(*args):
            for block in original_blocks(*args):
                consumed.append(len(block[-1]))
                yield block

        with patch.object(file_media, '_blocks', side_effect=blocks):
            result = self.prepare(preview.AttachmentCache(max_item=100))
        self.assertEqual(sum(consumed), len(self.data))
        self.assertEqual(result['preview_reason'], 'attachment_preview_size_limit_only')
        self.assertTrue(result['sha256_original_bytes_verified'])
        self.assertFalse(result['original_retention_limited'])
        result = self.prepare(preview.AttachmentCache(budget=100))
        self.assertEqual(result['preview_reason'], 'attachment_memory_preview_budget_only')
        self.assertTrue(result['raw_preserved'])

    def test_corruption_never_publishes_or_succeeds_even_when_oversized(self):
        self.text(b'original text')
        self.service.objects.db.execute("UPDATE chunk SET data=x'00'")
        self.service.objects.db.commit()
        for cache in (self.cache, preview.AttachmentCache(max_item=1)):
            with self.assertRaises(Exception):
                self.prepare(cache)
            self.assertEqual(cache.bytes, 0)

    def test_missing_bound_original_is_distinct(self):
        self.text()
        self.service.objects.db.execute('DELETE FROM file_chunk WHERE file_hash=?', (self.sha,))
        self.service.objects.db.execute('DELETE FROM file WHERE hash=?', (self.sha,))
        self.service.objects.db.commit()
        result = self.prepare()
        self.assertEqual(result['status'], 'file_missing')
        self.assertEqual(result['preview_status'], 'file_missing')
        self.assertFalse(result['sha256_original_bytes_verified'])
        self.assertIn('other_sources_not_claimed_absent', result['reason'])
        self.assertNotIn('artifact_id', result)

    def test_reuse_is_current_message_evidence_not_cached_association(self):
        self.text(b'x')
        first = self.prepare()
        wrong = '<msg><appmsg><title>sample.txt</title><type>6</type><appattach><totallen>1</totallen><filemd5>'+('a'*32)+'</filemd5></appattach></appmsg></msg>'
        self.archive.import_observations(dict(source_id='another-message'), dict(snapshot_id='another-message'),
            [observation(native_locator=9000, server_id='another-message', message_type='49', body_text=wrong)])
        other = next(m for m in self.archive.list_messages() if m['body_text'] == wrong)
        second = self.prepare(logical_id=other['logical_id'])
        self.assertEqual(first['artifact_id'], second['artifact_id'])
        self.assertTrue(second['reused'])
        self.assertEqual(second['association_status'], 'candidate')
        self.assertFalse(second['content_checksum_matches'])
        self.assertNotEqual(first['evidence'], second['evidence'])
        self.assertEqual(self.cache.bytes, 1)
        # A hit still reads the bound CAS instead of concealing later corruption.
        self.service.objects.db.execute("UPDATE chunk SET data=x'00'")
        self.service.objects.db.commit()
        with self.assertRaises(Exception):
            self.prepare()

    def test_lru_expiration_and_clear_are_disposable_only(self):
        self.text(b'one')
        cache = preview.AttachmentCache(budget=6)
        first = self.prepare(cache)
        objects = []
        for data in (b'two', b'new'):
            item = publish(self.service.objects, io.BytesIO(data), len(data))
            self.service.catalog.db.execute('INSERT INTO asset_history VALUES(?,?,?,?,?)',
                ('current', 'File/sample.txt', item['sha256'], len(data), 'accepted'))
            self.service.catalog.db.commit()
            objects.append(item['sha256'])
        second = self.prepare(cache, sha=objects[0])
        cache.read(first['artifact_id'])  # first becomes most recently used.
        third = self.prepare(cache, sha=objects[1])
        with self.assertRaises(KeyError):
            cache.read(second['artifact_id'])
        self.assertEqual(cache.read(first['artifact_id']).data, b'one')
        self.assertEqual(cache.read(third['artifact_id']).data, b'new')
        self.assertEqual(cache.bytes, 6)
        cache.clear()
        self.assertEqual(cache.bytes, 0)
        with self.assertRaises(KeyError):
            cache.read(first['artifact_id'])
        self.assertFalse(self.prepare(cache)['reused'])

    def test_read_rejects_paths_and_invalid_identifiers(self):
        self.cache = preview.AttachmentCache()
        for value in (None, '../secret.txt', 'C:\\private\\item.txt', 'a'*63, 'A'*64):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.cache.read(value)
        with self.assertRaises(KeyError):
            self.cache.read('a'*64)

    def test_empty_utf8_text_has_valid_readback_and_hard_entry_bound(self):
        self.text(b'')
        result = self.prepare()
        self.assertEqual(result['status'], 'ready')
        self.assertEqual(self.cache.read(result['artifact_id']).data, b'')
        self.assertEqual(self.cache.bytes, 0)
        self.assertEqual(preview.MAX_ENTRIES, 256)


if __name__ == '__main__':
    unittest.main()
