"""Same-input, subprocess-isolated cache A/B; synthetic temporary files only.

Run: python -m wechat_capture_next.tests.benchmark_sqlite_cache --rows 6000
The fixture row count is an experiment size, never an acquisition/message cap.
Process logical I/O is not physical disk I/O. No OS page-cache flush is attempted.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

import psutil

from tests.test_wua_store import observation
from wua.store import ArchiveStore
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next import union_archive
from wechat_capture_v2.common import digest_file


def _worker(root, writer_mib, reader_mib):
    root = Path(root).resolve()
    if not root.name.startswith('next-sqlite-cache-synthetic-'):
        raise ValueError('worker requires its own synthetic temporary directory')
    source = root/'synthetic-source.sqlite'
    target = root/f'target-{writer_mib}-{reader_mib}.sqlite'
    if target.exists():
        raise FileExistsError(target)
    process = psutil.Process()
    stop = threading.Event()
    peaks = dict(sampled_rss_bytes=0, sampled_private_bytes=0)

    def sample():
        while not stop.is_set():
            memory = process.memory_info()
            peaks['sampled_rss_bytes'] = max(peaks['sampled_rss_bytes'], memory.rss)
            peaks['sampled_private_bytes'] = max(peaks['sampled_private_bytes'],
                getattr(memory, 'private', memory.vms))
            stop.wait(.01)

    observer = threading.Thread(target=sample, daemon=True)
    observer.start()
    original_reader = union_archive.cold_reader
    reader_settings = []

    def reader(path):
        db = original_reader(path)
        db.execute(f'PRAGMA cache_size=-{reader_mib*1024}')
        reader_settings.append(db.execute('PRAGMA cache_size').fetchone()[0])
        return db

    io0, cpu0 = process.io_counters(), process.cpu_times()
    started = time.perf_counter()
    try:
        with CompactArchive(target, create=True) as archive, \
                patch.object(union_archive, 'cold_reader', side_effect=reader):
            archive._db.execute(f'PRAGMA cache_size=-{writer_mib*1024}')
            writer_setting = archive._db.execute('PRAGMA cache_size').fetchone()[0]
            result = union_archive.import_archive(archive, source,
                origin_id='synthetic-cache-fixture', verify=True)
            semantic = result['semantic_digest']
            integrity = result['integrity']
        # All target handles are closed. No checkpoint/VACUUM/format changes.
        io1, cpu1 = process.io_counters(), process.cpu_times()
        elapsed = time.perf_counter()-started
    finally:
        stop.set()
        observer.join()
    memory = process.memory_info()
    return dict(writer_mib=writer_mib, reader_mib=reader_mib,
        effective_writer_cache_size=writer_setting, effective_reader_cache_sizes=reader_settings,
        elapsed_seconds=elapsed, cpu_seconds=cpu1.user+cpu1.system-cpu0.user-cpu0.system,
        logical_read_bytes=io1.read_bytes-io0.read_bytes,
        logical_write_bytes=io1.write_bytes-io0.write_bytes,
        settled_bytes=sum(p.stat().st_size for p in root.glob(target.name+'*')),
        target_bytes=target.stat().st_size, semantic_digest=semantic,
        source_sha256=result['artifact_sha256'], observations=result['totals']['observations'],
        full_verification=integrity,
        lifetime_peak_rss_bytes=getattr(memory, 'peak_wset', None),
        lifetime_peak_private_bytes=getattr(memory, 'peak_pagefile', None), **peaks)


def run(rows=6000, configs=((2, 2), (128, 2), (128, 128), (256, 256))):
    with tempfile.TemporaryDirectory(prefix='next-sqlite-cache-synthetic-') as root_text:
        root = Path(root_text)
        source = root/'synthetic-source.sqlite'
        prep_started = time.perf_counter()
        with ArchiveStore(source) as archive:
            archive._db.execute('PRAGMA cache_size=-131072')

            def fixture_rows():
                for number in range(rows):
                    opaque = base64.b85encode(hashlib.shake_256(
                        ('synthetic-'+str(number)).encode()).digest(2048)).decode('ascii')
                    yield observation(native_locator=number, server_id=number+1,
                        body_text='synthetic cache body '+str(number), opaque_extension=opaque,
                        raw_record={'sequence': number, 'opaque': opaque, 'binary': bytes(range(64))})

            archive.import_observations({'source_id': 'synthetic-cache-source'},
                {'source_id': 'synthetic-cache-source', 'snapshot_id': 'synthetic-cache-snapshot'}, fixture_rows())
            expected_semantic = archive.semantic_digest()
        expected_source = digest_file(source)
        prepared = dict(rows=rows, bytes=source.stat().st_size, sha256=expected_source,
            semantic_digest=expected_semantic, prep_seconds=time.perf_counter()-prep_started)
        results = []
        for writer_mib, reader_mib in configs:
            command = [sys.executable, '-m', 'wechat_capture_next.tests.benchmark_sqlite_cache', '--worker', root_text,
                       '--writer-mib', str(writer_mib), '--reader-mib', str(reader_mib)]
            result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8',
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), timeout=600)
            if result.returncode:
                raise RuntimeError(result.stdout+result.stderr)
            measured = json.loads(result.stdout)
            if measured['semantic_digest'] != expected_semantic or measured['source_sha256'] != expected_source:
                raise AssertionError('same-input semantic or source hash mismatch')
            if digest_file(source) != expected_source:
                raise AssertionError('synthetic source changed')
            results.append(measured)
            print(json.dumps(dict(event='configuration_complete', **measured)), file=sys.stderr, flush=True)
        return dict(synthetic_only=True, python=sys.version, sqlite=sqlite3.sqlite_version,
            fixture=prepared, results=results, all_semantics_equal=True, source_unchanged=True,
            limitations='Logical process I/O, not physical I/O; shared OS cache and concurrent external load were not controlled. '
                'One subprocess per configuration; fixture generation is excluded from worker metrics. '
                '128/256 MiB are connection-local suggested page-cache budgets, not preallocation.',
            source_sha256={name: digest_file(Path('wechat_capture_next')/(name+'.py'))
                for name in ('compact_archive', 'content_pool', 'compact_delta', 'union_archive')})


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--rows', type=int, default=6000)
    parser.add_argument('--worker')
    parser.add_argument('--writer-mib', type=int)
    parser.add_argument('--reader-mib', type=int)
    args = parser.parse_args()
    print(json.dumps(_worker(args.worker, args.writer_mib, args.reader_mib)
        if args.worker else run(args.rows), indent=2))
