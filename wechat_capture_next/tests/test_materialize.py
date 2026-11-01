from pathlib import Path
from contextlib import closing
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from wechat_capture_v2.cipher import materialize
from wechat_capture_v2.common import digest_file
from wechat_capture_v2.tests.test_backend import KEY, TABLE, encrypt, make_plain, make_wal, empty_sqlite_page
from wechat_capture_v2.tests.test_integration import reserve80
from wechat_capture_next.materialize import update_view


class ChangedWriteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.plain = self.root/'plain.db'
        make_plain(self.plain, count=40)
        reserve80(self.plain)
        self.source = self.root/'encrypted.db'
        self.view = self.root/'views'/'decoded.db'
        self.wal = Path(str(self.source)+'-wal')
        self.publish()

    def tearDown(self):
        self.temp.cleanup()

    def pages(self):
        blob = self.plain.read_bytes()
        return [blob[i:i+4096] for i in range(0, len(blob), 4096)]

    def publish(self):
        self.source.write_bytes(b''.join(encrypt(page, i) for i, page in enumerate(self.pages(), 1)))

    def update(self, **kwargs):
        return update_view(self.source, self.view, KEY, scratch=self.root/'scratch', **kwargs)

    def assert_legacy(self):
        baseline = self.root/'baseline.db'
        if baseline.exists():
            baseline.unlink()
        materialize(self.source, baseline, KEY, self.wal if self.wal.exists() else None)
        self.assertEqual(digest_file(baseline), digest_file(self.view))
        self.assertFalse(list((self.root/'scratch').iterdir()))

    def test_initial_and_identical_write_zero(self):
        first = self.update()
        self.assertEqual(first['main_copy_bytes'], 0)
        self.assert_legacy()
        second = self.update()
        self.assertEqual(second['decrypted_pages'], 0)
        self.assertEqual(second['plaintext_write_bytes'], 0)
        self.assertEqual(second['reused_pages'], len(self.pages()))
        self.assert_legacy()

    def test_wal_proofs_match_full_prefix_hash_without_frozen_rereads_or_aes(self):
        import io
        from wechat_capture_next import materialize as current
        from wechat_capture_next.wal_memory import stream_wal_prefix, stream_prefix_hash
        from wechat_capture_v2.cipher import PageCipher, wal_prefix
        # Many overwritten and complete uncommitted frames must ALL authenticate.
        frames = [(1, len(self.pages()) if i % 7 == 0 else 0, encrypt(self.pages()[0], 1))
                  for i in range(256)]
        make_wal(self.wal, frames)
        blob = self.wal.read_bytes()
        cipher = PageCipher(KEY, self.source.read_bytes()[:16])
        expected = wal_prefix(self.wal, cipher)
        class CountingStream(io.BytesIO):
            bytes_read = 0
            def read(self, count=-1):
                value = super().read(count)
                self.bytes_read += len(value)
                return value
        stream, hashes = CountingStream(blob), {}
        with patch.object(cipher, 'decrypt', side_effect=AssertionError('audit decrypted discarded plaintext')):
            self.assertEqual(stream_wal_prefix(stream, len(blob), cipher,
                prefix_hashes=hashes, authentication_only=True), expected)
        self.assertEqual(stream.bytes_read, len(blob))
        committed = expected['committed_bytes']
        self.assertEqual(hashes['committed'], stream_prefix_hash(io.BytesIO(blob), committed))
        self.assertEqual(hashes['verification'], hashes['committed'])
        # Both live comparisons remain mandatory, but frozen proof costs zero rereads.
        with patch.object(current, 'prefix_hash', wraps=current.prefix_hash) as live_hash:
            current._verify_wal(self.wal, stream, expected, hashes['verification'])
            current._verify_wal(self.wal, stream, expected, hashes['verification'])
        self.assertEqual(live_hash.call_count, 2)
        self.assertEqual(stream.bytes_read, len(blob))
        with patch.object(current, 'stream_prefix_hash', side_effect=AssertionError('redundant frozen hash')):
            report = self.update()
        self.assertEqual(report['wal'], expected)
        self.assertEqual(report['wal_sha256'], hashes['committed'])
        self.assert_legacy()

    def test_hmac_only_audit_rejects_bad_uncommitted_hmac_and_preserves_empty_prefix(self):
        import io
        from wechat_capture_next.wal_memory import stream_wal_prefix, stream_prefix_hash
        from wechat_capture_v2.cipher import PageCipher, wal_prefix
        cipher = PageCipher(KEY, self.source.read_bytes()[:16])
        for frames in ([], [(1, 0, encrypt(self.pages()[0], 1))],
                       [(1, len(self.pages()), encrypt(self.pages()[0], 1))]):
            make_wal(self.wal, frames)
            blob, proof = self.wal.read_bytes(), {}
            audit = stream_wal_prefix(io.BytesIO(blob), len(blob), cipher,
                prefix_hashes=proof, authentication_only=True)
            self.assertEqual(audit, wal_prefix(self.wal, cipher))
            self.assertEqual(proof['committed'], stream_prefix_hash(io.BytesIO(blob), audit['committed_bytes']))
            self.assertEqual(proof['verification'], stream_prefix_hash(io.BytesIO(blob),
                audit['committed_bytes'] or min(32, len(blob))))
        proof = {'stale': 'must not survive'}
        self.assertEqual(stream_wal_prefix(io.BytesIO(b''), 0, cipher, prefix_hashes=proof)['tail_reason'], 'empty')
        self.assertNotIn('stale', proof)
        bad = bytearray(encrypt(self.pages()[0], 1))
        bad[-1] ^= 1
        # make_wal recalculates checksums: only cryptographic authentication fails.
        make_wal(self.wal, [(1, len(self.pages()), encrypt(self.pages()[0], 1)), (1, 0, bytes(bad))])
        for only in (False, True):
            with self.assertRaisesRegex(ValueError, 'HMAC'), self.wal.open('rb') as stream:
                stream_wal_prefix(stream, self.wal.stat().st_size, cipher,
                    prefix_hashes=proof, authentication_only=only)
            self.assertEqual(proof, {})

    def test_main_revision_old_sequence_delete_and_growth(self):
        self.update()
        with closing(sqlite3.connect(self.plain)) as db, db:
            db.execute(f'UPDATE "{TABLE}" SET message_content=? WHERE local_id=1', ('revised '*600,))
            db.execute(f'DELETE FROM "{TABLE}" WHERE local_id=2')
            db.execute(f'INSERT INTO "{TABLE}" VALUES(-1,555,1,7,1,?,NULL,NULL,-100)', ('late',))
        self.publish()
        report = self.update()
        self.assertGreater(report['changed_plain_pages'], 0)
        self.assert_legacy()

    def test_wal_commit_with_uncommitted_tail(self):
        self.update()
        page = bytearray(self.pages()[-1])
        # Mutate only reserved bytes so structural validity is unchanged.
        page[-1] = 1  # encryption intentionally normalizes reserved bytes
        frames = [(len(self.pages()), len(self.pages()), encrypt(bytes(page), len(self.pages()))),
                  (1, 0, encrypt(self.pages()[0], 1))]
        make_wal(self.wal, frames)
        report = self.update()
        self.assertEqual(report['wal']['last_commit_frame'], 1)
        self.assert_legacy()

    def test_wal_reset_and_checkpoint(self):
        self.update()
        make_wal(self.wal, [(1, len(self.pages()), encrypt(self.pages()[0], 1))])
        self.update()
        self.wal.write_bytes(b'')
        self.update()
        self.assert_legacy()

    def test_ram_wal_and_disk_spill_match_old_audit_and_full_plaintext(self):
        from wechat_capture_v2.cipher import wal_prefix, PageCipher
        from wechat_capture_next.wal_memory import freeze_wal, stream_wal_prefix
        make_wal(self.wal, [(1, len(self.pages()), encrypt(self.pages()[0], 1))])
        # Model the client's preallocated WAL tail; stale generation is not a
        # committed frame and must not be applied. Full physical bytes freeze.
        with self.wal.open('ab') as stream:
            stream.truncate(4*1024**2)
        cipher = PageCipher(KEY, self.source.read_bytes()[:16])
        expected = wal_prefix(self.wal, cipher)
        for memory in (64*1024**2, 0, 128):
            with self.subTest(memory=memory):
                with freeze_wal(self.wal, self.root, memory) as (stream, size, spilled):
                    self.assertEqual(size, 4*1024**2)
                    self.assertEqual(stream_wal_prefix(stream, size, cipher), expected)
                    self.assertEqual(spilled, memory < size)
                report = self.update(wal_memory_bytes=memory)
                self.assertEqual(report['wal'], expected)
                self.assertEqual(report['temporary_wal_bytes'], size if memory < size else 0)
                self.assertEqual(report['frozen_wal_bytes'], size)
                self.assert_legacy()

    def test_wal_stream_errors_and_valid_tail_match_legacy(self):
        from wechat_capture_v2.cipher import wal_prefix, PageCipher
        from wechat_capture_next.wal_memory import freeze_wal, stream_wal_prefix
        cipher = PageCipher(KEY, self.source.read_bytes()[:16])
        make_wal(self.wal, [(1, len(self.pages()), encrypt(self.pages()[0], 1)),
            (1, 0, encrypt(self.pages()[0], 1))])
        original = self.wal.read_bytes()
        for blob in (b'', b'bad header', original, original[:-1], original[:-1]+bytes([original[-1]^1]),
                     bytes([original[0]^1])+original[1:]):
            self.wal.write_bytes(blob)
            try:
                expected = wal_prefix(self.wal, cipher)
            except Exception as exc:
                with self.assertRaises(type(exc)), freeze_wal(self.wal, self.root) as (stream, size, spilled):
                    stream_wal_prefix(stream, size, cipher)
            else:
                with freeze_wal(self.wal, self.root) as (stream, size, spilled):
                    self.assertEqual(stream_wal_prefix(stream, size, cipher), expected)

    def test_live_wal_reset_after_ram_freeze_is_rejected_and_retry_recovers(self):
        make_wal(self.wal, [(1, len(self.pages()), encrypt(self.pages()[0], 1))])
        original = self.wal.read_bytes()

        def reset(phase):
            if phase == 'after_view_fsync':
                self.wal.write_bytes(b'')

        with self.assertRaises(RuntimeError):
            self.update(fault=reset)
        self.assertTrue(self.view.with_suffix('.dirty').exists())
        self.wal.write_bytes(original)
        self.assertTrue(self.update()['recovered_invalid_view'])
        self.assert_legacy()
        self.wal.unlink()
        self.update()
        self.assert_legacy()

    def test_shrink_then_expand_does_not_resurrect_old_pages(self):
        self.update()
        # A valid empty database, shrink to 1, then expand and shrink again.
        page = empty_sqlite_page()
        make_wal(self.wal, [(1, 1, encrypt(page, 1)), (2, 2, encrypt(bytes(4096), 2)),
                            (1, 1, encrypt(page, 1))])
        self.update()
        self.assert_legacy()

    def test_crash_markers_rebuild(self):
        self.update()
        for phase in ('after_view_fsync', 'after_index_commit'):
            def fail(current):
                if current == phase:
                    raise RuntimeError('synthetic crash')
            with self.assertRaises(RuntimeError):
                self.update(fault=fail)
            self.assertTrue(self.view.with_suffix('.dirty').exists())
            report = self.update()
            self.assertTrue(report['recovered_invalid_view'])
            self.assert_legacy()

    def test_hmac_torn_wal_and_live_race_reject(self):
        self.update()
        original = self.source.read_bytes()
        blob = bytearray(original)
        blob[-1] ^= 1
        self.source.write_bytes(blob)
        with self.assertRaises(ValueError):
            self.update()
        self.source.write_bytes(original)
        self.update()
        make_wal(self.wal, [(1, len(self.pages()), encrypt(self.pages()[0], 1))])
        wal = bytearray(self.wal.read_bytes())
        wal[-1] ^= 1
        self.wal.write_bytes(wal)
        with self.assertRaises(RuntimeError):
            self.update()
        self.wal.unlink()
        with patch('wechat_capture_next.materialize.digest_file', return_value='race'):
            with self.assertRaises(RuntimeError):
                self.update()
        self.assertTrue(self.update()['recovered_invalid_view'])

    def test_tampered_plain_page_is_repaired(self):
        self.update()
        with self.view.open('r+b') as stream:
            stream.seek(150)
            stream.write(b'wrong')
        report = self.update()
        self.assertEqual(report['decrypted_pages'], 1)
        self.assert_legacy()

    def test_corrupt_main_page_is_rejected_even_when_wal_overrides_it(self):
        self.update()
        pages = self.pages()
        make_wal(self.wal, [(len(pages), len(pages), encrypt(pages[-1], len(pages)))])
        blob = bytearray(self.source.read_bytes())
        blob[-1] ^= 1
        self.source.write_bytes(blob)
        with self.assertRaises(ValueError):
            self.update()


if __name__ == '__main__':
    unittest.main()
