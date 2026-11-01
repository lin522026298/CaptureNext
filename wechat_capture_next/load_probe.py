"""Private phase-aware real-load evidence, separate observer and collector.

Only next-state databases are checkpointed, under their own writer lock.
No UI control, source writes, history limits, memory cap, or automatic cleanup.
The configured duration bounds observation time, not the messages acquired.
"""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

import psutil

from wechat_capture_v2.common import canonical, digest_file, directory, write_json_new
from .state_guard import writer_lock
from .paging import PagingSampler


def filesystem(state):
    buckets = {}
    for path in state.rglob('*'):
        if path.is_file():
            key = path.relative_to(state).parts[0]
            buckets[key] = buckets.get(key, 0)+path.stat().st_size
    return dict(bytes=sum(buckets.values()), buckets=buckets)


def settle(state):
    # Never checkpoint the client's DBs or any old archive. Caller holds the
    # new state's single-writer lock; all service handles are closed here.
    results = {}
    for name in ('catalog.sqlite', 'objects.sqlite'):
        path = state/name
        with closing(sqlite3.connect(path.as_uri()+'?mode=rw', uri=True)) as db:
            row = tuple(db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone())
            if row[0]:
                raise RuntimeError('measurement requires a settled owned database')
            results[name] = row
    return results


def emit(value):
    print(canonical(value), flush=True)


def worker(args):
    from .service import CaptureService
    from .sync_wua import sync_wua
    worker_began = time.monotonic()
    with writer_lock(args.state):
        settle(args.state)
        before = filesystem(args.state)
        target = args.managed/'archive.wua.sqlite' if args.managed else None
        target_before = target.stat().st_size if target and target.exists() else 0
        began = time.monotonic()
        emit(dict(event='start', unix=time.time(), action=args.action, settled_before=before))
        with closing(CaptureService(args.state)) as service:
            if args.action == 'sync':
                emit(dict(event='sync', result=sync_wua(service, args.managed, verify=args.verify)))
            else:
                last_full = None
                while True:
                    now = time.monotonic()
                    phase_path = args.out/'phase.txt'
                    phase = phase_path.read_text(encoding='utf-8').strip() if phase_path.exists() else 'natural_load'
                    full = args.action == 'capture' or last_full is None or now-last_full >= 300
                    own = psutil.Process()
                    io0, cpu0 = own.io_counters(), own.cpu_times()
                    report = service.capture(force=full, reuse_identical=args.action != 'capture')
                    io1, cpu1 = own.io_counters(), own.cpu_times()
                    if full:
                        last_full = now
                    emit(dict(event='cycle', unix=time.time(), phase=phase,
                        logical_write_bytes=io1.write_bytes-io0.write_bytes,
                        logical_read_bytes=io1.read_bytes-io0.read_bytes,
                        cpu_seconds=cpu1.user+cpu1.system-cpu0.user-cpu0.system, report=report))
                    if args.action == 'capture' or time.monotonic()-began >= args.seconds or (args.out/'stop').exists():
                        break
                    time.sleep(3)
        emit(dict(event='settling'))
        if getattr(args, 'worker', False):
            deadline = time.monotonic()+10
            while not (args.out/'observer-closed.json').exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError('observer did not release source reads for settled measurement')
                time.sleep(.02)
        settled = settle(args.state)
        after = filesystem(args.state)
        io, cpu = psutil.Process().io_counters(), psutil.Process().cpu_times()
        emit(dict(event='end', unix=time.time(), elapsed_seconds=time.monotonic()-began,
            whole_worker_seconds=time.monotonic()-worker_began,
            settled_before=before, settled_after=after, state_net_growth_bytes=after['bytes']-before['bytes'],
            target_before_bytes=target_before, target_after_bytes=target.stat().st_size if target and target.exists() else 0,
            checkpoint=settled, logical_read_bytes=io.read_bytes, logical_write_bytes=io.write_bytes,
            cpu_seconds=cpu.user+cpu.system, counter_scope='whole worker since process creation, including pipe logging and startup/closure; cycle counters capture-only',
            closure='all owned service handles closed, checkpoint TRUNCATE both ends'))


def validate_measurement_output(args):
    from wechat_capture_v2.service import load_config
    raw = args.out
    for parent in (raw, *raw.parents):
        if parent.exists() or parent.is_symlink():
            directory(parent)
    output = raw.resolve()
    config = load_config(args.state)
    roots = [args.state, Path(config['database_root']), args.managed]
    if config.get('asset_root'):
        roots.append(Path(config['asset_root']))
    for root in roots:
        if root and (output.is_relative_to(root.resolve()) or root.resolve().is_relative_to(output)):
            raise ValueError('measurement logs must not overlap state, managed output, or live sources')
    return output


def run(args):
    args.out = validate_measurement_output(args)
    args.out.mkdir(parents=True, exist_ok=False)
    source_hashes = {p.name: digest_file(p) for p in Path(__file__).parent.glob('*.py')}
    paging = PagingSampler(args.out/'paging.jsonl')
    command = [sys.executable, '-u', '-m', 'wechat_capture_next.load_probe', '--worker', '--state', str(args.state),
        '--out', str(args.out), '--action', args.action, '--seconds', str(args.seconds)]
    if args.managed:
        command += ['--managed', str(args.managed)]
    if args.verify:
        command += ['--verify']
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8',
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except BaseException:
        paging.finish()
        raise
    try:
        write_json_new(args.out/'RUN.private.json', dict(pid=process.pid, action=args.action, seconds=args.seconds,
            state=str(args.state), managed=str(args.managed) if args.managed else None,
            started_unix=time.time(), source_hashes=source_hashes))
        return observe(args, process, paging, source_hashes)
    finally:
        if process.poll() is None:
            try:
                with (args.out/'stop').open('x') as stream:
                    stream.write('observer ending; stop after current capture')
            except OSError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # Only descendants of our newly spawned worker, never WeChat.
                try:
                    children = psutil.Process(process.pid).children(recursive=True)
                except psutil.Error:
                    children = []
                for child in reversed(children):
                    try:
                        child.terminate()
                    except psutil.Error:
                        pass
                process.terminate()
                process.wait(timeout=10)
        paging.finish()


def observe(args, process, paging, source_hashes):
    events = dict(cycles=0, partial=0, idle=0, temporary_wal_bytes=0, frozen_wal_bytes=0,
        memory_wal_bytes=0, changed_plain_pages=0, new_versions=0)
    phases, endpoints = {}, {}
    reader_errors = []
    settling = threading.Event()
    marker_lock = threading.Lock()
    reader_failed = threading.Event()

    def fail(exc):
        if not reader_failed.is_set():
            reader_errors.append(type(exc).__name__+': '+str(exc))
        reader_failed.set()

    def read():
        with (args.out/'cycles.private.jsonl').open('x', encoding='utf-8') as stream:
            for line in process.stdout:
                stream.write(line)
                stream.flush()
                try:
                    row = json.loads(line)
                except ValueError as exc:
                    fail(exc)
                    continue
                if row['event'] == 'cycle':
                    report = row['report']
                    events['cycles'] += 1
                    events['partial'] += report['status'] == 'partial'
                    events['idle'] += report['status'] == 'idle'
                    for entry in report['databases']:
                        for key in ('temporary_wal_bytes', 'frozen_wal_bytes', 'memory_wal_bytes', 'changed_plain_pages', 'new_versions'):
                            events[key] += entry.get(key, 0)
                    label = row['phase']+'/'+('idle' if report['status'] == 'idle' else report['mode'])
                    stats = phases.setdefault(label, dict(cycles=0, elapsed_seconds=0, changed_cycles=0,
                        logical_write_bytes=0, logical_read_bytes=0, cpu_seconds=0))
                    stats['cycles'] += 1
                    stats['elapsed_seconds'] += report['elapsed_seconds']
                    stats['changed_cycles'] += report['status'] != 'idle'
                    for key in ('logical_write_bytes','logical_read_bytes','cpu_seconds'):
                        stats[key] += row[key]
                else:
                    endpoints[row['event']] = row
                    if row['event'] == 'settling':
                        settling.set()
                        with marker_lock:
                            write_json_new(args.out/'observer-closed.json', {'source_read_connections_closed': True})

    def guarded_read():
        try:
            read()
        except Exception as exc:
            fail(exc)
            for line in process.stdout:  # Drain even if the evidence disk fails.
                pass

    def drain_errors():
        try:
            with (args.out/'stderr.private.txt').open('x', encoding='utf-8') as stream:
                for line in process.stderr:
                    stream.write(line)
                    stream.flush()
        except Exception as exc:
            fail(exc)
            for line in process.stderr:
                pass

    thread = threading.Thread(target=guarded_read, daemon=True)
    thread.start()
    error_thread = threading.Thread(target=drain_errors, daemon=True)
    error_thread.start()
    own = psutil.Process(process.pid)
    start = previous_time = time.monotonic()
    previous_write = None
    peaks = dict(private_bytes=0, rss_bytes=0, temporary_bytes=0, managed_sidecar_bytes=0, logical_write_bytes_per_second=0)
    high = {str(gib): 0.0 for gib in (1, 2, 4, 8)}
    counters = {}
    wechat = {}
    markers = {}
    source = (args.state/'catalog.sqlite').as_uri()+'?mode=ro'
    with closing(sqlite3.connect(source, uri=True)) as db:
        last_row = db.execute('SELECT coalesce(max(rowid),0) FROM version').fetchone()[0]
    with (args.out/'samples.jsonl').open('x', encoding='utf-8') as stream:
        while process.poll() is None:
            if reader_failed.is_set():
                raise RuntimeError('evidence reader failed: '+repr(reader_errors))
            private = rss = 0
            try:
                tree = [own]+own.children(recursive=True)
            except psutil.Error:
                tree = []
            for item in tree:
                try:
                    memory, io, cpu = item.memory_info(), item.io_counters(), item.cpu_times()
                    counters[item.pid] = dict(read=io.read_bytes, write=io.write_bytes, cpu=cpu.user+cpu.system)
                    private += getattr(memory, 'private', memory.vms)
                    rss += memory.rss
                except psutil.Error:
                    pass
            for item in psutil.process_iter(['name']):
                if (item.info['name'] or '').lower() in ('weixin.exe', 'weixinappex.exe'):
                    try:
                        io, cpu = item.io_counters(), item.cpu_times()
                        current = dict(read=io.read_bytes, write=io.write_bytes, cpu=cpu.user+cpu.system)
                        key = (item.pid, item.create_time())
                        if key not in wechat:
                            wechat[key] = dict(first=current, last=current)
                        wechat[key]['last'] = current
                    except psutil.Error:
                        pass
            # Observer reads only new rows to timestamp synthetic markers; this
            # is NOT how collection decides completeness (it scans all rows).
            try:
                with marker_lock:
                    if not settling.is_set():
                        with closing(sqlite3.connect(source, uri=True, timeout=.1)) as db:
                            for rowid, normalized in db.execute('SELECT rowid,normalized_json FROM version WHERE rowid>? ORDER BY rowid', (last_row,)):
                                body = json.loads(normalized).get('body_text')
                                if isinstance(body, str) and body.startswith('归档测试-负载-'):
                                    markers[body] = dict(observed_unix=time.time(), elapsed=time.monotonic()-start)
                                last_row = rowid
            except sqlite3.Error:
                pass
            try:
                temporary = sum(p.stat().st_size for p in (args.state/'tmp').rglob('*') if p.is_file())
                sidecars = sum(p.stat().st_size for p in args.managed.glob('archive.wua.sqlite-*') if p.is_file()) if args.managed else 0
            except OSError:
                temporary = sidecars = 0
            now = time.monotonic()
            total_write = sum(c['write'] for c in counters.values())
            row = dict(elapsed=now-start, private_bytes=private, rss_bytes=rss, temporary_bytes=temporary, managed_sidecar_bytes=sidecars,
                logical_write_bytes=total_write, logical_read_bytes=sum(c['read'] for c in counters.values()),
                cpu_seconds=sum(c['cpu'] for c in counters.values()),
                logical_write_bytes_per_second=(total_write-previous_write)/(now-previous_time) if previous_write is not None else 0,
                first_counter_baseline=previous_write is None,
                system_swap_used_bytes=psutil.swap_memory().used,
                system_available_bytes=psutil.virtual_memory().available)
            for key in peaks:
                peaks[key] = max(peaks[key], row[key])
            for gib in high:
                if private >= int(gib)*1024**3:
                    high[gib] += now-previous_time
            previous_time, previous_write = now, total_write
            stream.write(canonical(row)+'\n')
            stream.flush()
            time.sleep(.5)
    thread.join(10)
    error_thread.join(10)
    returncode = process.returncode or (1 if reader_errors or 'end' not in endpoints else 0)
    result = dict(returncode=returncode, reader_errors=reader_errors, elapsed_seconds=time.monotonic()-start, peaks=peaks,
        high_private_GiB_seconds=high, events=events, phases=phases, endpoints=endpoints, test_markers=markers,
        system_paging=paging.finish(), source_hashes=source_hashes,
        wechat_observed_delta={key: sum(v['last'][key]-v['first'][key] for v in wechat.values()) for key in ('read','write','cpu')},
        physical_write_bytes=None, process_hard_fault_bytes=None, stderr_file='stderr.private.txt',
        caveat='logical process I/O is not physical writes; WeChat observations lack a no-collector counterfactual; memory duration sampled at 0.5 sec')
    write_json_new(args.out/'RESULT.json', result)
    emit({k: v for k, v in result.items() if k not in ('errors_private', 'source_hashes', 'test_markers')})
    if returncode:
        raise SystemExit(returncode)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--action', choices=('capture', 'watch', 'sync'), default='watch')
    parser.add_argument('--seconds', type=float, default=3600)
    parser.add_argument('--managed', type=Path)
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    args.state = args.state.resolve(strict=True)
    if args.action == 'sync' and not args.managed:
        parser.error('--managed required for sync')
    args.managed = args.managed.resolve() if args.managed else None
    worker(args) if args.worker else run(args)
