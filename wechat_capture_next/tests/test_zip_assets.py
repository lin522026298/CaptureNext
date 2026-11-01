"""Synthetic ZIP -> existing CAS -> retained metadata -> formal union tests."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import struct
import subprocess
import sys
import warnings
import zipfile
import zlib
import unittest
from unittest.mock import patch

from wechat_capture_next.tests import test_union_assets as fixtures
from wechat_capture_next.tests.test_union_assets import OfflineService
from wechat_capture_next.zip_assets import import_zip_assets, decode_zip_info, zip_info_json
from wechat_capture_next.union_assets import import_asset_union, verify_union_assets
from wechat_capture_v2.objects import CHUNK_BYTES


PREFIX = 'source_C_xwechat_files/msg/'


class ZipAssetTests(unittest.TestCase):
    setUp = fixtures.UnionAssetTests.setUp
    tearDown = fixtures.UnionAssetTests.tearDown
    archive = fixtures.UnionAssetTests.archive

    def make_zip(self, entries, name='source.zip', compression=zipfile.ZIP_DEFLATED):
        path = self.root/name
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(path, 'w', compression=compression) as archive:
                archive.comment = b'original archive comment\x00\xff'
                for filename, content in entries:
                    info = zipfile.ZipInfo(filename, date_time=(2024, 2, 3, 4, 5, 6))
                    info.compress_type = compression
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o640) << 16
                    info.internal_attr = 1
                    info.extra = b'\xfe\xca\x03\x00xyz'
                    info.comment = b'raw member comment\x00\xff'
                    archive.writestr(info, content)
        return path

    def invoke(self, source, output='zip-metadata.sqlite', **kwargs):
        return import_zip_assets(self.service, source, self.root/output,
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), source_id='opaque-oldpc-zip', **kwargs)

    def test_stream_raw_bytes_info_fidelity_and_union_without_media_copy(self):
        binary = bytes(range(256)) * (CHUNK_BYTES // 256 + 17)
        entries = [(PREFIX+'attach/中文🙂.dat', binary), (PREFIX+'video/same-bytes.dat', binary),
                   (PREFIX+'file/empty.bin', b''), ('source_C_xwechat_files/db_storage/not-media.db', b'outside scope')]
        source = self.make_zip(entries)
        original = source.read_bytes()
        source_hashes = []
        from wechat_capture_next import zip_assets
        real_digest = zip_assets.digest_file
        def digest(path):
            source_hashes.append(Path(path))
            return real_digest(path)
        with patch.object(zip_assets, 'digest_file', side_effect=digest):
            result = self.invoke(source)
        self.assertEqual(1, source_hashes.count(source))
        self.assertEqual(3, result['members_verified'])
        self.assertEqual(2, result['unique_objects_verified'])
        self.assertEqual(2, result['added_cas_files'])
        output = Path(result['metadata_output'])
        with closing(sqlite3.connect(output)) as metadata, zipfile.ZipFile(source) as archive:
            self.assertEqual(0, metadata.execute('SELECT count(*) FROM file').fetchone()[0])
            self.assertEqual(0, metadata.execute('SELECT count(*) FROM chunk').fetchone()[0])
            self.assertEqual((3, 3), tuple(metadata.execute('SELECT (SELECT count(*) FROM asset),(SELECT count(*) FROM asset_history)').fetchone()))
            for filename, raw_name, encoded, cycle in metadata.execute('SELECT relative_path,zip_filename_raw,zip_info_json,cycle_id FROM asset'):
                info = archive.getinfo(filename)
                self.assertEqual(zip_info_json(info), encoded)
                restored = decode_zip_info(encoded)
                self.assertEqual(info.orig_filename, restored['orig_filename'])
                self.assertIsInstance(restored['date_time'], tuple)
                self.assertEqual(info.extra, restored['extra'])
                self.assertEqual(info.comment, restored['comment'])
                self.assertEqual(info.CRC, restored['CRC'])
                self.assertEqual(info.orig_filename.encode('utf-8' if info.flag_bits & 0x800 else 'cp437'), raw_name)
                self.assertEqual('zip:'+result['zip_sha256'], cycle)
        existing = self.service.objects.db.execute('SELECT count(*) FROM file').fetchone()[0]
        with self.archive() as union:
            imported = import_asset_union(union, self.service, output, 'oldpc-zip-media')
            self.assertEqual(0, imported['imported_files'])
            self.assertEqual(6, imported['added_metadata_observations'])
            self.assertTrue(verify_union_assets(union, self.service)['closure_complete'])
        self.assertEqual(existing, self.service.objects.db.execute('SELECT count(*) FROM file').fetchone()[0])
        self.assertEqual(original, source.read_bytes())
        self.assertFalse(list(self.root.glob('zip-metadata.sqlite.partial-*')))
        self.assertFalse(any(path.name == '中文🙂.dat' for path in self.root.rglob('*')))

    def test_reimport_to_fresh_metadata_is_deterministic_and_cas_has_no_writes(self):
        source = self.make_zip([(PREFIX+'a.dat', b'content' * 5000)])
        first = self.invoke(source)
        changes = self.service.objects.db.total_changes
        footprint = {p.name: (p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
                     for p in self.state.glob('objects.sqlite*')}
        second = self.invoke(source, 'second.sqlite')
        self.assertEqual(0, second['added_cas_files'])
        self.assertEqual(changes, self.service.objects.db.total_changes)
        self.assertEqual(footprint, {p.name: (p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
                                   for p in self.state.glob('objects.sqlite*')})
        self.assertEqual(first['metadata_sha256'], second['metadata_sha256'])
        with self.assertRaises(FileExistsError):
            self.invoke(source)

    def test_hash_mismatch_is_rejected_before_zip_parse_or_cas_writes(self):
        source = self.make_zip([(PREFIX+'a', b'data')])
        before = self.service.objects.db.total_changes
        with patch('wechat_capture_next.zip_assets.zipfile.ZipFile', side_effect=AssertionError('must hash first')):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                import_zip_assets(self.service, source, self.root/'out.sqlite',
                    expected_sha256='0'*64, source_id='opaque')
        self.assertEqual(before, self.service.objects.db.total_changes)

    def test_duplicate_unsafe_special_and_outside_only_members_fail_before_publication(self):
        cases = [([(PREFIX+'a', b'1'), (PREFIX+'a', b'2')], 'duplicate'),
                 ([(PREFIX+'A', b'1'), (PREFIX+'a', b'2')], 'aliased'),
                 ([(PREFIX+'../escape', b'1')], 'unsafe'),
                 ([(PREFIX+'folder\\escape', b'1')], 'unsafe'),
                 ([('/absolute', b'1')], 'unsafe'),
                 ([(PREFIX+'NUL.dat', b'1')], 'ambiguous'),
                 ([('outside/media.dat', b'1')], 'no file members')]
        before = self.service.objects.db.total_changes
        for index, (entries, message) in enumerate(cases):
            with self.subTest(entries=entries):
                source = self.make_zip(entries, f'bad-{index}.zip')
                for filename, _ in entries:
                    if '\\' in filename:
                        # ZipInfo's Windows writer normalizes separators; patch
                        # both equal-length header names to test an actual raw
                        # backslash-bearing container rather than its alias.
                        data = source.read_bytes().replace(filename.replace('\\', '/').encode(), filename.encode())
                        source.write_bytes(data)
                with self.assertRaisesRegex(ValueError, message):
                    self.invoke(source, f'bad-{index}.sqlite')
        special = self.root/'symlink.zip'
        with zipfile.ZipFile(special, 'w') as archive:
            info = zipfile.ZipInfo(PREFIX+'link')
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b'../../outside')
        with self.assertRaisesRegex(ValueError, 'linked or special'):
            self.invoke(special, 'symlink.sqlite')
        self.assertEqual(before, self.service.objects.db.total_changes)

    def test_crc_corruption_rolls_back_unpublished_chunks_and_maps(self):
        source = self.make_zip([(PREFIX+'one.dat', b'raw-bytes'*10000)], compression=zipfile.ZIP_STORED)
        payload = bytearray(source.read_bytes())
        central = payload.index(b'PK\x01\x02')
        crc = struct.unpack_from('<I', payload, central+16)[0]
        struct.pack_into('<I', payload, central+16, crc ^ 0x01010101)
        source.write_bytes(payload)
        before = [tuple(row) for row in self.service.objects.db.execute('SELECT * FROM file')]
        with self.assertRaises((zipfile.BadZipFile, ValueError)):
            self.invoke(source)
        self.assertEqual(before, [tuple(row) for row in self.service.objects.db.execute('SELECT * FROM file')])
        self.assertFalse((self.root/'zip-metadata.sqlite').exists())

    def test_actual_inflated_length_rejects_consistent_prefix_headers(self):
        before = [tuple(row) for row in self.service.objects.db.execute('SELECT * FROM file')]
        for compression in (zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            for declared in (0, 6, CHUNK_BYTES+7):
                with self.subTest(compression=compression, declared=declared):
                    content = b'prefix' + b'not silently discarded suffix' * (CHUNK_BYTES//8)
                    source = self.make_zip([(PREFIX+'underdeclared.dat', content)],
                        f'prefix-{compression}-{declared}.zip', compression=compression)
                    container = bytearray(source.read_bytes())
                    local, central = container.index(b'PK\x03\x04'), container.index(b'PK\x01\x02')
                    for offset, crc_field, size_field in ((local, 14, 22), (central, 16, 24)):
                        struct.pack_into('<I', container, offset+crc_field, zlib.crc32(content[:declared]))
                        struct.pack_into('<I', container, offset+size_field, declared)
                    source.write_bytes(container)
                    output = f'prefix-{compression}-{declared}.sqlite'
                    with self.assertRaises((ValueError, zipfile.BadZipFile)):
                        self.invoke(source, output)
                    self.assertFalse((self.root/output).exists())
                    self.assertEqual(before, [tuple(row) for row in self.service.objects.db.execute('SELECT * FROM file')])

    def test_supported_decoders_empty_small_and_multichunk_exact_output(self):
        contents = (b'', b'valid small content', os.urandom(3*CHUNK_BYTES+19))
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            with self.subTest(compression=compression):
                source = self.make_zip([(PREFIX+str(i)+'.dat', data) for i, data in enumerate(contents)],
                    f'valid-{compression}.zip', compression=compression)
                result = self.invoke(source, f'valid-{compression}.sqlite')
                self.assertEqual(3, result['members_verified'])
                self.assertEqual(sum(map(len, contents)), result['logical_bytes'])
                for data in contents:
                    sha = hashlib.sha256(data).hexdigest()
                    self.assertEqual(len(data), self.service.objects.db.execute('SELECT bytes FROM file WHERE hash=?', (sha,)).fetchone()[0])

    def test_low_space_and_existing_chunk_corruption_fail_closed(self):
        source = self.make_zip([(PREFIX+'shared.dat', self.shared.read_bytes())])
        usage = shutil_usage(0)
        before = self.service.objects.db.total_changes
        with patch('wechat_capture_next.zip_assets.shutil.disk_usage', return_value=usage):
            with self.assertRaisesRegex(OSError, 'free space'):
                self.invoke(source)
        self.assertEqual(before, self.service.objects.db.total_changes)
        key = self.service.objects.db.execute('SELECT hash FROM chunk LIMIT 1').fetchone()[0]
        self.service.objects.db.execute('UPDATE chunk SET data=? WHERE hash=?', (b'corrupt', key))
        self.service.objects.db.commit()
        with self.assertRaises((ValueError, __import__('zlib').error)):
            self.invoke(source)
        self.assertFalse((self.root/'zip-metadata.sqlite').exists())

    def test_linked_zip_and_lock_inputs_are_rejected_without_writing_protected_files(self):
        source = self.make_zip([(PREFIX+'a', b'data')])
        alias = self.root/'alias.zip'
        os.link(source, alias)
        try:
            with self.assertRaisesRegex(ValueError, 'linked'):
                self.invoke(alias)
        finally:
            alias.unlink()
        sentinel = self.root/'sentinel'; sentinel.write_bytes(b'')
        lock = self.state/'writer.lock'
        if lock.exists():
            lock.unlink()
        os.link(sentinel, lock)
        try:
            with self.assertRaisesRegex(ValueError, 'hardlinked'):
                self.invoke(source)
            self.assertEqual(b'', sentinel.read_bytes())
        finally:
            lock.unlink()

    def test_real_os_exit_cas_and_metadata_windows_retry_without_deleting_published_files(self):
        source = self.make_zip([(PREFIX+'a.dat', b'A'*10000), (PREFIX+'b.dat', b'B'*20000)])
        expected = hashlib.sha256(source.read_bytes()).hexdigest()
        original = source.read_bytes()
        for stage in ('after_cas_file_commit', 'before_metadata_publish'):
            with self.subTest(stage=stage):
                state = self.root/('state-'+stage); state.mkdir()
                with closing(sqlite3.connect(state/'catalog.sqlite')) as db:
                    db.execute('CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
                    db.execute("INSERT INTO meta VALUES('next_catalog_instance','synthetic-instance')")
                    db.commit()
                with closing(OfflineService(state)):
                    pass
                output = self.root/(stage+'.sqlite')
                code = '''import os,sys
from wechat_capture_next.tests.test_union_assets import OfflineService
from wechat_capture_next.zip_assets import import_zip_assets
service=OfflineService(sys.argv[1])
def fault(stage):
 if stage==sys.argv[5]:os._exit(81)
import_zip_assets(service,sys.argv[2],sys.argv[3],expected_sha256=sys.argv[4],source_id='oldpc',fault=fault)
'''
                child = subprocess.run([sys.executable, '-c', code, str(state), str(source), str(output), expected, stage],
                                       capture_output=True, text=True, timeout=30)
                self.assertEqual(81, child.returncode, child.stderr)
                self.assertFalse(output.exists())
                with closing(OfflineService(state)) as service:
                    retained = service.objects.db.execute('SELECT count(*) FROM file').fetchone()[0]
                    self.assertGreaterEqual(retained, 1)
                    result = import_zip_assets(service, source, output, expected_sha256=expected, source_id='oldpc')
                    self.assertEqual(2, result['members_verified'])
                    self.assertEqual(2, service.objects.db.execute('SELECT count(*) FROM file').fetchone()[0])
                with closing(sqlite3.connect(output)) as db:
                    self.assertEqual(2, db.execute('SELECT count(*) FROM asset').fetchone()[0])
        self.assertEqual(original, source.read_bytes())


def shutil_usage(free):
    from collections import namedtuple
    return namedtuple('usage', 'total used free')(2**40, 0, free)


if __name__ == '__main__':
    unittest.main()
