"""Synthetic ID-first regression and isolated-process logical-I/O benchmark.

Run tests normally, or:
 python -m wechat_capture_next.tests.test_union_id_first --benchmark --rows 1500
Only temporary fixtures are created. The frozen fc92ba5 baseline is evaluated in memory.
Logical process reads are not physical SSD reads; timing is cache-sensitive.
"""
import argparse
import ast
from contextlib import closing
import ctypes
from ctypes import wintypes
import hashlib
import inspect
import json
import os
from pathlib import Path
import random
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch
import zlib

from tests.test_wua_store import observation
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next import union_archive as current
from wechat_capture_v2.common import canonical, digest_file, encoded
from wechat_capture_v2.store import Catalog


def baseline(revision='fc92ba5'):
    frozen=Path(__file__).with_name('fixtures')/'union_archive_fc92ba5.py'
    source = (frozen.read_text(encoding='utf-8') if revision=='fc92ba5' else
        subprocess.check_output(['git', 'show', revision+':wechat_capture_next/union_archive.py'],
                                text=True, encoding='utf-8'))
    module = types.ModuleType('wechat_capture_next._id_first_baseline')
    module.__package__ = 'wechat_capture_next'
    module.__file__ = str(Path(current.__file__).absolute())
    exec(compile(source, module.__file__, 'exec'), module.__dict__)
    module._baseline_source = source
    return module


def payload_query(module):
    source = (module._baseline_source if hasattr(module, '_baseline_source')
              else inspect.getsource(module.import_catalog))
    for node in ast.walk(ast.parse(source)):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and 'v.raw_z' in node.value and 'union_catalog.interpretation' in node.value):
            return node.value
    raise AssertionError('catalog payload selection SQL not found')


def capture(db, identity):
    db.execute('INSERT INTO db_capture VALUES(?,?,?,?,?,?,?,?)',
        (identity, 'cycle', 'synthetic-wide', 'message.db', identity,
         canonical({'plaintext': {'sha256': '1'*64}}), 0, 'synthetic'))


def version(db, identity, index, raw_bytes, rng, capture_id='base'):
    raw = canonical(encoded({'ordinal': index, 'payload': rng.randbytes(raw_bytes)}))
    row = observation(native_locator=index, server_id=1000000+index, event_time=1700000000+index,
        body_text='synthetic body '+str(index), normalization_hint='wide-normalized-'*160)
    row.pop('raw_record')
    literal = canonical(row)
    db.execute('INSERT INTO version VALUES(?,?,?,?,?,?,?,?,?,?)',
        (identity, 'synthetic-wide', row['account_alias'], row['db_relative_path'], row['table_name'],
         canonical(row['native_locator']), hashlib.sha256(raw.encode()).hexdigest(),
         zlib.compress(raw.encode()), literal, capture_id))
    return literal


def fixture(root, count=240, raw_bytes=8192):
    source, target = root/'catalog.sqlite', root/'base.sqlite'
    rng = random.Random(719)
    with closing(Catalog(source)) as catalog:
        db = catalog.db
        db.execute("INSERT INTO cycle VALUES('cycle','synthetic',NULL,'synthetic','complete',NULL)")
        capture(db, 'base')
        capture(db, 'reinterpret-base')
        for index in range(count):
            identity = 'version-'+str(index).zfill(8)
            literal = version(db, identity, index, raw_bytes, rng)
            if index % 4 == 0:
                row = json.loads(literal)
                row['body_text'] = 'interpreted '+str(index)
                interpreted = canonical(row)
                db.execute('INSERT INTO interpretation VALUES(?,?,?,?)',
                    (identity, hashlib.sha256(interpreted.encode()).hexdigest(), interpreted, 'reinterpret-base'))
        db.commit()
    with CompactArchive(target, create=True) as archive:
        current.import_catalog(archive, source, origin_id='wide')
    return source, target


def process_reads():
    if os.name != 'nt':
        return None
    class Counters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in
                    ('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters)]
    kernel.GetProcessIoCounters.restype = wintypes.BOOL
    value = Counters()
    if not kernel.GetProcessIoCounters(kernel.GetCurrentProcess(), ctypes.byref(value)):
        raise ctypes.WinError(ctypes.get_last_error())
    return value.read_bytes


def worker(kind, source, target, revision='fc92ba5'):
    module = baseline(revision) if kind == 'baseline' else current
    source, target = Path(source), Path(target)
    before_hash, source_hash = digest_file(target), digest_file(source)
    with CompactArchive(target) as archive:
        steps, decodes = [0], [0]
        original = module.zlib_decompress

        def decode(value):
            decodes[0] += 1
            return original(value)

        def progress():
            steps[0] += 100
            return 0

        archive._db.set_progress_handler(progress, 100)
        with patch.object(module, 'zlib_decompress', side_effect=decode):
            logical_before = process_reads()
            cpu, started = time.process_time(), time.perf_counter()
            result = module.import_catalog(archive, source, origin_id='wide')
            elapsed, cpu = time.perf_counter()-started, time.process_time()-cpu
            logical_after = process_reads()
        archive._db.set_progress_handler(None, 0)
        semantic = archive.semantic_digest()
        archive._db.execute('ATTACH DATABASE ? AS union_catalog', (source.as_uri()+'?mode=ro',))
        try:
            plan = [row[3] for row in archive._db.execute('EXPLAIN QUERY PLAN '+payload_query(module), ('wide', 'wide'))]
        finally:
            archive._db.execute('DETACH DATABASE union_catalog')
    after_hash = digest_file(target)
    assert before_hash == after_hash and source_hash == digest_file(source)
    assert result['added_versions'] == result['added_interpretations'] == decodes[0] == 0
    return dict(kind=kind, seconds=elapsed, cpu_seconds=cpu, sqlite_VM_steps_approx=steps[0],
        logical_read_bytes=None if logical_before is None else logical_after-logical_before,
        raw_decodes=decodes[0], target_SHA256=after_hash, source_SHA256=source_hash,
        semantic_digest=semantic, target_bytes_unchanged=True, source_bytes_unchanged=True, plan=plan)


def benchmark(count=1500, raw_bytes=16384, revision='fc92ba5'):
    with tempfile.TemporaryDirectory(prefix='union-id-first-') as directory:
        root = Path(directory)
        source, template = fixture(root, count, raw_bytes)
        results = []
        for kind in ('baseline', 'optimized'):
            target = root/(kind+'.sqlite')
            shutil.copyfile(template, target)
            output = subprocess.check_output([sys.executable, '-m',
                'wechat_capture_next.tests.test_union_id_first', '--worker', kind,
                str(source), str(target), '--revision', revision], text=True, encoding='utf-8')
            results.append(json.loads(output))
        assert results[0]['target_SHA256'] == results[1]['target_SHA256']
        assert results[0]['source_SHA256'] == results[1]['source_SHA256']
        assert results[0]['semantic_digest'] == results[1]['semantic_digest']
        return dict(schema='synthetic-union-id-first-benchmark-1', baseline=revision,
            sqlite_version=sqlite3.sqlite_version, source_rows=count, interpretations=(count+3)//4,
            random_payload_bytes_per_raw=raw_bytes, source_bytes=source.stat().st_size,
            limitation='One cache-sensitive synthetic run; logical process reads, not physical-disk I/O.',
            results=results)


class IDFirstTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='union-id-first-test-')
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.source, self.template = fixture(self.root)

    def test_covering_id_scans_and_payload_point_lookups_only_for_unseen(self):
        source_hash, target_hash = digest_file(self.source), digest_file(self.template)
        with CompactArchive(self.template) as archive:
            archive._db.execute('ATTACH DATABASE ? AS union_catalog', (self.source.as_uri()+'?mode=ro',))
            try:
                plan = [r[3] for r in archive._db.execute('EXPLAIN QUERY PLAN '+payload_query(current), ('wide', 'wide'))]
            finally:
                archive._db.execute('DETACH DATABASE union_catalog')
            text = '\n'.join(plan)
            self.assertIn('MATERIALIZE unseen_version', text)
            self.assertIn('MATERIALIZE unseen_interpretation', text)
            self.assertIn('SCAN v USING COVERING INDEX sqlite_autoindex_version_1', text)
            self.assertIn('SCAN i USING COVERING INDEX sqlite_autoindex_interpretation_1', text)
            self.assertIn('SEARCH v USING INDEX sqlite_autoindex_version_1 (id=?)', text)
            self.assertIn('SEARCH i USING INDEX sqlite_autoindex_interpretation_1', text)
            with patch.object(current, 'zlib_decompress', side_effect=AssertionError('no seen raw should be decoded')):
                result = current.import_catalog(archive, self.source, origin_id='wide')
            self.assertEqual(result['added_versions'], 0)
            self.assertEqual(result['added_interpretations'], 0)
        self.assertEqual(source_hash, digest_file(self.source))
        self.assertEqual(target_hash, digest_file(self.template))

    def test_backfill_interpretation_regression_and_failure_match_frozen_baseline(self):
        old = baseline()
        old_target, new_target = self.root/'old.sqlite', self.root/'new.sqlite'
        for target in (old_target, new_target):
            shutil.copyfile(self.template, target)
        with closing(Catalog(self.source)) as catalog:
            db = catalog.db
            capture(db, 'backfill')
            capture(db, 'reinterpret-new')
            version(db, 'version--old-backlog', -999, 2048, random.Random(1), 'backfill')
            row = json.loads(db.execute('SELECT normalized_json FROM version WHERE id=?', ('version-00000000',)).fetchone()[0])
            row['body_text'] = 'a newly added interpretation of an old version'
            literal = canonical(row)
            db.execute('INSERT INTO interpretation VALUES(?,?,?,?)',
                ('version-00000000', hashlib.sha256(literal.encode()).hexdigest(), literal, 'reinterpret-new'))
            db.commit()
        with CompactArchive(old_target) as full, CompactArchive(new_target) as new:
            original_hash = digest_file(new_target)
            actual = new.insert_prepared

            def fail(*args, **kwargs):
                actual(*args, **kwargs)
                raise RuntimeError('synthetic unseen-row failure')

            with patch.object(new, 'insert_prepared', side_effect=fail):
                with self.assertRaisesRegex(RuntimeError, 'unseen-row failure'):
                    current.import_catalog(new, self.source, origin_id='wide')
            self.assertEqual(original_hash, digest_file(new_target))
            self.assertNotIn('union_catalog', [r[1] for r in new._db.execute('PRAGMA database_list')])
            with patch.object(current, 'zlib_decompress', wraps=current.zlib_decompress) as decoded:
                result = current.import_catalog(new, self.source, origin_id='wide')
            reference = old.import_catalog(full, self.source, origin_id='wide')
            self.assertEqual((result['added_versions'], result['added_interpretations'], decoded.call_count), (1, 1, 2))
            self.assertEqual(reference['added_observations'], result['added_observations'])
            self.assertEqual(full.semantic_digest(), new.semantic_digest())
            for table in ('message_observation', 'logical_message', 'message_link', 'conflict', 'dedupe_candidate'):
                self.assertEqual(sorted(map(tuple, full._db.execute('SELECT * FROM '+table))),
                                 sorted(map(tuple, new._db.execute('SELECT * FROM '+table))), table)
            new._db.execute("INSERT INTO next_union_version VALUES('wide','absent-from-source')")
            before = new.semantic_digest()
            with self.assertRaisesRegex(ValueError, 'regressed'):
                current.import_catalog(new, self.source, origin_id='wide')
            self.assertEqual(before, new.semantic_digest())
            self.assertNotIn('union_catalog', [r[1] for r in new._db.execute('PRAGMA database_list')])

    def test_null_ids_and_orphan_interpretations_fail_closed_without_silent_join_drops(self):
        for defect in ('null-version', 'null-interpretation', 'orphan-interpretation'):
            with self.subTest(defect=defect):
                root = self.root/defect
                root.mkdir()
                source, target = fixture(root, count=4, raw_bytes=512)
                with closing(sqlite3.connect(source)) as db, db:
                    if defect == 'null-version':
                        version(db, None, -777, 512, random.Random(1))
                    else:
                        row = db.execute('SELECT normalized_json FROM version ORDER BY id LIMIT 1').fetchone()[0]
                        if defect == 'null-interpretation':
                            # Historical retained subsets use CREATE TABLE AS
                            # and do not inherit the live schema's NOT NULLs.
                            db.execute('ALTER TABLE interpretation RENAME TO original_interpretation')
                            db.execute('CREATE TABLE interpretation AS SELECT * FROM original_interpretation')
                            db.execute('DROP TABLE original_interpretation')
                        # Deliberately malformed synthetic input, not a bypass
                        # of any production writer's immutable/FK guarantees.
                        db.execute('INSERT INTO interpretation VALUES(?,?,?,?)',
                            ('absent' if defect == 'orphan-interpretation' else 'version-00000000',
                             None if defect == 'null-interpretation' else hashlib.sha256(row.encode()).hexdigest(),
                             row, 'base'))
                target_hash, source_hash = digest_file(target), digest_file(source)
                with CompactArchive(target) as archive:
                    with self.assertRaisesRegex(ValueError, 'missing identities or orphan'):
                        current.import_catalog(archive, source, origin_id='wide')
                    self.assertNotIn('union_catalog', [r[1] for r in archive._db.execute('PRAGMA database_list')])
                self.assertEqual(target_hash, digest_file(target))
                self.assertEqual(source_hash, digest_file(source))


if __name__ == '__main__':
    if '--benchmark' in sys.argv or '--worker' in sys.argv:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--benchmark', action='store_true')
        parser.add_argument('--worker', nargs=3, metavar=('KIND', 'SOURCE', 'TARGET'))
        parser.add_argument('--rows', type=int, default=1500)
        parser.add_argument('--payload-bytes', type=int, default=16384)
        parser.add_argument('--revision', default='fc92ba5')
        args = parser.parse_args()
        value = worker(*args.worker, revision=args.revision) if args.worker else benchmark(args.rows, args.payload_bytes, args.revision)
        print(json.dumps(value, indent=2))
    else:
        unittest.main()
