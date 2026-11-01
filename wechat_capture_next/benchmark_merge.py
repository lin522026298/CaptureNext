"""Same-input one-message merge: frozen prior reducer vs differential reducer.

Both use MEMORY temporary storage. Preparation is unmeasured, and both file
measurements are taken after closing SQLite with DELETE journaling. No source
or old archive is modified. Synthetic fixture size is not a collector limit.
"""
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
import types

import psutil

from tests.test_wua_store import observation
from wechat_capture_v2.common import canonical, write_json_new
from .merge import LeanArchiveStore


def store_class(mode):
    if mode == 'delta':
        return LeanArchiveStore
    source = (Path(__file__).with_name('tests')/'fixtures'/'merge_capture_next_io_20261019.py').read_text(encoding='utf-8')
    module = types.ModuleType('frozen_prior_lean_merge')
    exec(compile(source, 'capture-next-io-20261019/merge.py', 'exec'), module.__dict__)
    return module.LeanArchiveStore


def size(path):
    return sum(p.stat().st_size for p in path.parent.glob(path.name+'*') if p.is_file())


def worker(mode, path, count):
    Store = store_class(mode)
    with Store(path) as store:
        store._db.execute('PRAGMA temp_store=MEMORY')
        store.import_observations({'source_id': 'benchmark'}, {'source_id': 'benchmark', 'snapshot_id': 'base'},
            (observation(native_locator=i, server_id=1000000+i, body_text=str(i)+':'+'x'*1024)
             for i in range(count)))
    before_bytes = size(path)
    own = psutil.Process()
    io0, cpu0 = own.io_counters(), own.cpu_times()
    stop = threading.Event()
    peak = {'private_bytes': 0, 'rss_bytes': 0}

    def sample():
        while not stop.is_set():
            m = own.memory_info()
            peak['private_bytes'] = max(peak['private_bytes'], getattr(m, 'private', m.vms))
            peak['rss_bytes'] = max(peak['rss_bytes'], m.rss)
            stop.wait(.02)

    thread = threading.Thread(target=sample, daemon=True)
    thread.start()
    start = time.monotonic()
    with Store(path) as store:
        store._db.execute('PRAGMA temp_store=MEMORY')
        trace_counts = {}

        def trace(sql):
            action = sql.lstrip().split(' ', 1)[0].upper()
            trace_counts[action] = trace_counts.get(action, 0)+1

        store._db.set_trace_callback(trace)
        result = store.import_observations({'source_id': 'benchmark'},
            {'source_id': 'benchmark', 'snapshot_id': 'one-more'},
            [observation(native_locator=-99, server_id=999999999, body_text='late message')])
        writes = getattr(store, 'last_rebuild_writes', None)
        store._db.set_trace_callback(None)
    elapsed = time.monotonic()-start
    io1, cpu1 = own.io_counters(), own.cpu_times()
    stop.set()
    thread.join(5)
    with Store(path, readonly=True) as check:
        digest = check.semantic_digest()
        fts = hashlib.sha256()
        for row in check._db.execute('SELECT logical_id,body_text FROM message_fts ORDER BY logical_id'):
            fts.update(canonical(list(row)).encode())
        integrity = check.integrity_check()
    result = dict(mode=mode, elapsed_seconds=elapsed, peaks=peak, derived_row_writes=writes,
        logical_write_bytes=io1.write_bytes-io0.write_bytes, logical_read_bytes=io1.read_bytes-io0.read_bytes,
        cpu_seconds=cpu1.user+cpu1.system-cpu0.user-cpu0.system,
        final_before_bytes=before_bytes, final_after_bytes=size(path), final_growth_bytes=size(path)-before_bytes,
        semantic_digest=digest, fts_digest=fts.hexdigest(), integrity=integrity, trace_counts=trace_counts,
        physical_write_bytes=None, temp_store='MEMORY', closure='all SQLite handles closed before before/after filesystem size')
    print(canonical(result))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rows', type=int, default=10000)
    parser.add_argument('--worker', choices=('full', 'delta'))
    parser.add_argument('--path', type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker, args.path, args.rows)
    else:
        args.out.mkdir(parents=True, exist_ok=False)
        results = []
        for i, mode in enumerate(('full', 'delta', 'delta', 'full')):
            run = subprocess.run([sys.executable, '-m', 'wechat_capture_next.benchmark_merge', '--worker', mode,
                '--path', str(args.out/f'{i}-{mode}.sqlite'), '--out', str(args.out), '--rows', str(args.rows)],
                text=True, encoding='utf-8', capture_output=True, check=True)
            result = json.loads(run.stdout)
            results.append(result)
            write_json_new(args.out/f'{i}-{mode}.json', result)
            print(canonical({k: result[k] for k in ('mode', 'elapsed_seconds', 'logical_write_bytes', 'final_growth_bytes')}), flush=True)
        passed = len({r['semantic_digest'] for r in results}) == len({r['fts_digest'] for r in results}) == 1
        write_json_new(args.out/'RESULT.json', {'pass': passed, 'results': results})
        if not passed:
            raise SystemExit(2)
