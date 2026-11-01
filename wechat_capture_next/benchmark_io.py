"""Same frozen SQLCipher main + committed WAL, old vs changed-write collector.

Fixture preparation is outside measured workers. Warm changed capture includes
full row reconciliation, catalog commit and closing SQLite handles/checkpoints.
No source/corpus count is truncated; --mib controls synthetic fixture size only.
Physical disk writes require a separate trace and are deliberately null here.
"""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import threading
import time

import psutil

from wechat_capture_v2.common import canonical, digest_file, write_json_new
from wechat_capture_v2.tests.test_backend import KEY, TABLE, encrypt, make_plain, make_wal
from wechat_capture_v2.tests.test_integration import reserve80


def footprint(root):
    return sum(p.stat().st_size for p in Path(root).rglob('*') if p.is_file())


def worker(mode, root, state):
    if mode == 'v2':
        from wechat_capture_v2.service import CaptureService, initialize
    else:
        from .service import CaptureService, initialize
    from wechat_capture_v2.compare import compare_native
    initialize(state, root/'source', root/'fixture.keys.json', source_id='benchmark',
        account_alias='benchmark', self_username='wxid_synthetic_self')
    service = CaptureService(state)
    try:
        warm = service.capture(force=True)
        if warm['status'] != 'local_complete':
            raise ValueError('warm capture failed')
        print(canonical({'phase': 'warm_ready'}), flush=True)
        if sys.stdin.readline().strip() != 'changed':
            raise ValueError('expected controlled replay barrier')
        own = psutil.Process()
        initial_io, initial_cpu = own.io_counters(), own.cpu_times()
        state_before = footprint(state)
        stop = threading.Event()
        peaks = dict(private_bytes=0, rss_bytes=0, temporary_bytes=0)

        def sample():
            while not stop.is_set():
                try:
                    memory = own.memory_info()
                    peaks['private_bytes'] = max(peaks['private_bytes'], getattr(memory, 'private', memory.vms))
                    peaks['rss_bytes'] = max(peaks['rss_bytes'], memory.rss)
                    peaks['temporary_bytes'] = max(peaks['temporary_bytes'], footprint(state/'tmp'))
                except (OSError, psutil.Error):
                    pass
                stop.wait(.02)

        thread = threading.Thread(target=sample, daemon=True)
        thread.start()
        started = time.monotonic()
        report = service.capture(force=False)
        durable_capture_seconds = time.monotonic()-started
        # Finish writer/checkpoint work before counter end. Independent native
        # comparison and semantic digest below are excluded from perf totals.
        service.close()
        service = None
        elapsed = time.monotonic()-started
        end_io, end_cpu = own.io_counters(), own.cpu_times()
        stop.set()
        thread.join(5)
        with closing(CaptureService(state)) as verify:
            native = compare_native(verify.catalog, 'benchmark', 'message_0.db', root/'changed.plain.db')
            digest = hashlib.sha256()
            for row in verify.catalog.db.execute('''SELECT h.table_name,h.locator_json,v.row_hash,v.normalized_json
                FROM head h JOIN version v ON v.id=h.version_id WHERE h.active=1 ORDER BY h.table_name,h.locator_json'''):
                digest.update(canonical(list(row)).encode())
        result = dict(mode=mode, status=report['status'], capture_seconds=durable_capture_seconds,
            elapsed_with_close_seconds=elapsed, cpu_seconds=end_cpu.user+end_cpu.system-initial_cpu.user-initial_cpu.system,
            logical_read_bytes=end_io.read_bytes-initial_io.read_bytes,
            logical_write_bytes=end_io.write_bytes-initial_io.write_bytes,
            peaks=peaks, state_growth_bytes=footprint(state)-state_before,
            rows_scanned=sum(r.get('rows', 0) for r in report['databases']),
            new_versions=sum(r.get('new_versions', 0) for r in report['databases']),
            databases=report['databases'], native_comparison=native, active_semantic_sha256=digest.hexdigest(),
            physical_disk_write_bytes=None, sample_seconds=.02,
            caveat='temp/private peaks sampled; process logical writes include temp-sampler/report overhead, not physical/NAND writes')
        print(canonical(result), flush=True)
    finally:
        if service:
            service.close()


def fixture(root, mib, rows):
    root.mkdir(parents=True, exist_ok=False)
    source = root/'source'
    source.mkdir()
    plain = root/'base.plain.db'
    make_plain(plain, count=rows)
    with closing(sqlite3.connect(plain)) as db, db:
        db.execute('CREATE TABLE fixture_padding(body BLOB)')
        db.executemany('INSERT INTO fixture_padding VALUES(zeroblob(65536))', (() for _ in range(mib*16)))
    reserve80(plain)
    with plain.open('rb') as original, (source/'message_0.db').open('xb') as encrypted:
        number = 1
        while page := original.read(4096):
            encrypted.write(encrypt(page, number))
            number += 1
    changed = root/'changed.plain.db'
    shutil.copyfile(plain, changed)
    with closing(sqlite3.connect(changed)) as db, db:
        db.execute(f'UPDATE "{TABLE}" SET message_content=? WHERE local_id=1', ('synthetic revision',))
        db.execute(f'INSERT INTO "{TABLE}" VALUES(-9,999999999,1,7,1,?,NULL,NULL,-999)', ('old-sequence late message',))
    frames = []
    pages = changed.stat().st_size//4096
    with plain.open('rb') as before, changed.open('rb') as after:
        for number in range(1, pages+1):
            old, new = before.read(4096), after.read(4096)
            if old != new:
                frames.append((number, 0, encrypt(new, number)))
    number, _, data = frames[-1]
    frames[-1] = (number, pages, data)
    make_wal(root/'changed.wal', frames)
    write_json_new(root/'fixture.keys.json', {'databases': [{'relative_path': 'message_0.db',
        'verified': True, 'raw_encryption_key_hex': KEY.hex()}]})
    write_json_new(root/'INPUT.json', dict(main_sha256=digest_file(source/'message_0.db'),
        main_bytes=(source/'message_0.db').stat().st_size, wal_sha256=digest_file(root/'changed.wal'),
        wal_bytes=(root/'changed.wal').stat().st_size, committed_changed_pages=len(frames), baseline_rows=rows))


def benchmark(root, mib=64, rows=10000):
    fixture(root, mib, rows)
    results = []
    wal = root/'source'/'message_0.db-wal'
    for iteration, mode in enumerate(('v2', 'next', 'next', 'v2')):
        if wal.exists():
            wal.unlink()  # Only the benchmark's own synthetic source WAL.
        command = [sys.executable, '-u', '-m', 'wechat_capture_next.benchmark_io', '--worker', mode,
            '--out', str(root), '--state', str(root/f'state-{iteration}-{mode}')]
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding='utf-8',
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        ready = process.stdout.readline()
        if not ready or json.loads(ready).get('phase') != 'warm_ready':
            raise RuntimeError('benchmark warmup failed: '+process.stderr.read())
        shutil.copyfile(root/'changed.wal', wal)
        stdout, stderr = process.communicate('changed\n')
        if process.returncode:
            raise RuntimeError('benchmark failed: '+stderr)
        result = json.loads(stdout.strip())
        results.append(result)
        write_json_new(root/f'RESULT-{iteration}-{mode}.json', result)
        print(canonical({k: result[k] for k in ('mode', 'capture_seconds', 'logical_write_bytes', 'peaks')}), flush=True)
    equal = len({r['active_semantic_sha256'] for r in results}) == 1 and all(r['native_comparison']['pass'] for r in results)
    final = dict(results=results, same_input_result_equal=equal, physical_disk_write_bytes=None,
        source_hashes={p.name: digest_file(p) for p in Path(__file__).parent.glob('*.py')},
        scope='warm one-batch replay; not live locking/latency or long-term source influence')
    write_json_new(root/'RESULT.json', final)
    if not equal:
        raise ValueError('same-input correctness mismatch')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--mib', type=int, default=64)
    parser.add_argument('--rows', type=int, default=10000)
    parser.add_argument('--worker', choices=('v2', 'next'))
    parser.add_argument('--state', type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker, args.out, args.state)
    elif args.mib > 0 and args.rows > 1:
        benchmark(args.out, args.mib, args.rows)
    else:
        parser.error('positive fixture size and at least 2 synthetic rows required')
