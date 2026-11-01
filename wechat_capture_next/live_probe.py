"""Owned bounded-duration live observation; no UI input or memory limit.

Logs only test-marker arrival metadata, never emits unrelated message bodies.
The current decoded archive remains private in the explicit new state.
"""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

import psutil

from wechat_capture_v2.common import canonical, write_json_new, digest_file


def run(state, out, seconds):
    state, out = Path(state).resolve(), Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    source_hashes = {p.name: digest_file(p) for p in Path(__file__).parent.glob('*.py')}
    with sqlite3.connect((state/'catalog.sqlite').as_uri()+'?mode=ro', uri=True) as db:
        last_row = db.execute('SELECT coalesce(max(rowid),0) FROM version').fetchone()[0]
    command = [sys.executable, '-u', '-m', 'wechat_capture_next', 'watch', '--state', str(state),
        '--run-seconds', str(seconds), '--stop-file', str(out/'stop'), '--interval', '3', '--reconcile-seconds', '300']
    start = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8',
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    cycles = []

    def read():
        with (out/'cycles.private.jsonl').open('x', encoding='utf-8') as stream:
            for line in process.stdout:
                stream.write(line)
                stream.flush()
                cycles.append(json.loads(line))

    thread = threading.Thread(target=read, daemon=True)
    thread.start()
    own = psutil.Process(process.pid)
    counters, source_counters, found, samples = {}, {}, {}, 0
    peaks = dict(private_bytes=0, rss_bytes=0, temporary_bytes=0)

    def update(item, ledger):
        io, cpu = item.io_counters(), item.cpu_times()
        current = dict(read=io.read_bytes, write=io.write_bytes, cpu=cpu.user+cpu.system)
        if item.pid not in ledger:
            ledger[item.pid] = {'initial': current, 'latest': current}
        else:
            ledger[item.pid]['latest'] = current

    def totals(ledger):
        return {key: sum(v['latest'][key]-v['initial'][key] for v in ledger.values()) for key in ('read', 'write', 'cpu')}

    with (out/'samples.jsonl').open('x', encoding='utf-8') as stream:
        while process.poll() is None:
            private = rss = 0
            try:
                for item in [own]+own.children(recursive=True):
                    try:
                        update(item, counters)
                        memory = item.memory_info()
                        private += getattr(memory, 'private', memory.vms)
                        rss += memory.rss
                    except psutil.Error:
                        pass
            except psutil.Error:
                pass
            for item in psutil.process_iter(['name']):
                if (item.info['name'] or '').lower() in ('weixin.exe', 'weixinappex.exe'):
                    try:
                        update(item, source_counters)
                    except psutil.Error:
                        pass
            try:
                with sqlite3.connect((state/'catalog.sqlite').as_uri()+'?mode=ro', uri=True, timeout=.1) as db:
                    for rowid, normalized in db.execute('SELECT rowid,normalized_json FROM version WHERE rowid>? ORDER BY rowid', (last_row,)):
                        last_row = rowid
                        body = json.loads(normalized).get('body_text')
                        if isinstance(body, str) and body.startswith('归档测试-增量IO-'):
                            found[body] = dict(observed_elapsed=time.monotonic()-start, observed_unix=time.time())
            except sqlite3.Error:
                pass
            try:
                temporary = sum(p.stat().st_size for p in (state/'tmp').rglob('*') if p.is_file())
            except OSError:
                temporary = 0
            for key, value in dict(private_bytes=private, rss_bytes=rss, temporary_bytes=temporary).items():
                peaks[key] = max(peaks[key], value)
            sample = dict(elapsed=time.monotonic()-start, private_bytes=private, rss_bytes=rss,
                logical=totals(counters), wechat_observation=totals(source_counters),
                temporary_bytes=temporary, test_markers_seen=len(found))
            stream.write(canonical(sample)+'\n')
            stream.flush()
            samples += 1
            time.sleep(.5)
    thread.join(10)
    errors = process.stderr.read()
    result = dict(returncode=process.returncode, elapsed_seconds=time.monotonic()-start, peaks=peaks,
        logical=totals(counters), wechat_observation=totals(source_counters), test_markers=found,
        cycles=len(cycles), partial_cycles=sum(c['status'] == 'partial' for c in cycles), errors_private=errors,
        samples=samples, physical_disk_write_bytes=None, source_hashes=source_hashes,
        caveat='Wechat CPU/IO are observations without a no-collector counterfactual; not a causal impact estimate')
    write_json_new(out/'RESULT.json', result)
    print(canonical({k: v for k, v in result.items() if k != 'errors_private'}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--seconds', type=float, default=120)
    args = parser.parse_args()
    run(args.state, args.out, args.seconds)
