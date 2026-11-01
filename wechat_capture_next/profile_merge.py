"""Measure the unchanged WUA full rebuild on a read-only archive.

No memory cutoff, no copied archive, no writes to the input. A rebuild that
would alter derived state fails at SQLite's read-only boundary. --trace is a
separate, explicitly instrumented allocation run, not native performance.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import psutil

from wechat_capture_v2.common import canonical, write_json_new
from .paging import PagingSampler


def worker(path, trace=False, lean=False, temp_store='default'):
    from wua.store import ArchiveStore
    if lean:
        from .merge import LeanArchiveStore as ArchiveStore
    if trace:
        import tracemalloc
        tracemalloc.start(1)
    process = psutil.Process()
    began = time.monotonic()

    def event(phase):
        memory = process.memory_info()
        row = dict(phase=phase, elapsed=time.monotonic()-began,
                   private_bytes=getattr(memory, 'private', memory.vms), rss_bytes=memory.rss)
        if trace:
            row['python_current_bytes'], row['python_peak_bytes'] = tracemalloc.get_traced_memory()
        print(canonical(row), flush=True)

    with ArchiveStore(path, readonly=True) as archive:
        if temp_store != 'default':
            archive._db.execute('PRAGMA temp_store='+temp_store.upper())
        print(canonical({'temp_store': archive._db.execute('PRAGMA temp_store').fetchone()[0],
                         'sqlite_version': __import__('sqlite3').sqlite_version}), flush=True)
        desired = archive._desired_state
        candidates = archive._candidates

        def measured_candidates(rows):
            event('observations_and_groups_resident_before_candidates')
            result = candidates(rows)
            event('candidates_complete')
            return result

        def measured_desired():
            event('desired_start')
            result = desired()
            event('desired_complete')
            if trace:
                snapshot = tracemalloc.take_snapshot()
                print(canonical({'allocation_top': [
                    {'location': str(item.traceback[0]), 'bytes': item.size, 'count': item.count}
                    for item in snapshot.statistics('lineno')[:15]]}), flush=True)
            return result

        archive._candidates = measured_candidates
        archive._desired_state = measured_desired
        event('full_rebuild_start')
        result = archive._rebuild()
        event('full_rebuild_complete')
        print(canonical({'result': result, 'input_opened_readonly': True,
                         'instrumented': trace}), flush=True)


def profile(path, out, trace=False, lean=False, temp_store='default'):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    paging = PagingSampler(out/'system-paging.jsonl')
    process = subprocess.Popen([sys.executable, '-u', '-m', 'wechat_capture_next.profile_merge', '--worker',
        '--archive', str(path), '--temp-store', temp_store] + (['--trace'] if trace else []) + (['--lean'] if lean else []), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding='utf-8',
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    events = []

    def read_events():
        with (out/'events.jsonl').open('x', encoding='utf-8') as stream:
            for line in process.stdout:
                stream.write(line)
                stream.flush()
                events.append(json.loads(line))

    thread = threading.Thread(target=read_events, daemon=True)
    thread.start()
    own = psutil.Process(process.pid)
    counters = {}
    peaks = dict(private_bytes=0, rss_bytes=0, os_peak_wset=0, os_peak_pagefile=0)
    latest = {}
    start = time.monotonic()
    previous_time = start
    high_memory_seconds = {str(gib): 0.0 for gib in (1, 2, 4, 6, 8)}
    swap_min = swap_max = psutil.swap_memory().used
    with (out/'samples.jsonl').open('x', encoding='utf-8') as stream:
        while process.poll() is None:
            try:
                current = []
                for item in [own] + own.children(recursive=True):
                    try:
                        memory = item.memory_info()
                        io = item.io_counters()
                        cpu = item.cpu_times()
                        counters[item.pid] = dict(read=io.read_bytes, write=io.write_bytes, cpu=cpu.user+cpu.system,
                            peak_wset=getattr(memory, 'peak_wset', memory.rss),
                            peak_pagefile=getattr(memory, 'peak_pagefile', 0), faults=getattr(memory, 'num_page_faults', 0))
                        current.append((getattr(memory, 'private', memory.vms), memory.rss))
                    except psutil.Error:
                        pass
                latest = dict(elapsed=time.monotonic()-start,
                    private_bytes=sum(p for p, r in current), rss_bytes=sum(r for p, r in current),
                    os_peak_wset=sum(v['peak_wset'] for v in counters.values()),
                    os_peak_pagefile=sum(v['peak_pagefile'] for v in counters.values()),
                    page_faults=sum(v['faults'] for v in counters.values()),
                    logical_read_bytes=sum(v['read'] for v in counters.values()),
                    logical_write_bytes=sum(v['write'] for v in counters.values()),
                    cpu_seconds=sum(v['cpu'] for v in counters.values()),
                    system_available_bytes=psutil.virtual_memory().available,
                    system_swap_used_bytes=psutil.swap_memory().used)
                for key in peaks:
                    peaks[key] = max(peaks[key], latest[key])
                now = time.monotonic()
                for gib in high_memory_seconds:
                    if latest['private_bytes'] >= int(gib)*1024**3:
                        high_memory_seconds[gib] += now-previous_time
                previous_time = now
                swap_min = min(swap_min, latest['system_swap_used_bytes'])
                swap_max = max(swap_max, latest['system_swap_used_bytes'])
                stream.write(canonical(latest)+'\n')
                stream.flush()
            except psutil.Error:
                pass
            time.sleep(.2)
    thread.join(10)
    errors = process.stderr.read()
    paging_result = paging.finish()
    result = dict(returncode=process.returncode, elapsed_seconds=time.monotonic()-start,
        peaks=peaks, last_sample=latest, events=events, errors_private=errors,
        input_opened_readonly=True, instrumented=trace, lean_projection=lean, memory_cutoff=None,
        temp_store_requested=temp_store, high_private_GiB_seconds=high_memory_seconds,
        system_swap_used_min_bytes=swap_min, system_swap_used_max_bytes=swap_max,
        system_paging=paging_result,
        physical_disk_write_bytes=None, hard_fault_bytes=None,
        caveat='process logical I/O and page-fault count are not physical writes or hard-fault bytes')
    write_json_new(out/'RESULT.json', result)
    print(canonical({k: v for k, v in result.items() if k not in ('events', 'errors_private')}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--lean', action='store_true')
    parser.add_argument('--temp-store', choices=('default','file','memory'), default='default')
    args = parser.parse_args()
    if args.worker:
        worker(args.archive, args.trace, args.lean, args.temp_store)
    elif args.out:
        profile(args.archive, args.out, args.trace, args.lean, args.temp_store)
    else:
        parser.error('--out required')
