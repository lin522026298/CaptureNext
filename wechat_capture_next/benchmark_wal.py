"""Same frozen synthetic WAL, RAM/FILE storage ABBA; no retained fixture DBs."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

import psutil

from wechat_capture_v2.cipher import materialize
from wechat_capture_v2.common import canonical, digest_file, write_json_new
from wechat_capture_v2.tests.test_backend import KEY, encrypt, make_plain, make_wal
from wechat_capture_v2.tests.test_integration import reserve80
from .materialize import update_view


def worker(mode, count, mib):
    with tempfile.TemporaryDirectory(prefix='next-wal-bench-') as folder:
        root = Path(folder)
        plain, source, view, wal = (root/name for name in ('plain.db','encrypted.db','decoded.db','encrypted.db-wal'))
        make_plain(plain, count=1000)
        reserve80(plain)
        blob = plain.read_bytes()
        pages = [blob[i:i+4096] for i in range(0,len(blob),4096)]
        source.write_bytes(b''.join(encrypt(page, i) for i,page in enumerate(pages,1)))
        make_wal(wal, [(1,len(pages),encrypt(pages[0],1))])
        with wal.open('ab') as stream:
            stream.truncate(max(wal.stat().st_size, mib*1024**2))
        baseline = root/'baseline.db'
        materialize(source, baseline, KEY, wal)
        expected = digest_file(baseline)
        budget = 0 if mode == 'file' else 64*1024**2
        def cycle():
            return update_view(source, view, KEY, scratch=root/'scratch', wal_memory_bytes=budget)
        first = cycle()  # Initial view/index creation excluded in BOTH arms.
        process = psutil.Process()
        io0, cpu0 = process.io_counters(), process.cpu_times()
        stop = threading.Event()
        peaks = dict(private_bytes=0, rss_bytes=0)
        def sample():
            while not stop.is_set():
                memory = process.memory_info()
                peaks['private_bytes'] = max(peaks['private_bytes'], getattr(memory,'private',memory.vms))
                peaks['rss_bytes'] = max(peaks['rss_bytes'], memory.rss)
                stop.wait(.01)
        thread = threading.Thread(target=sample, daemon=True)
        thread.start()
        began = time.monotonic()
        disk = memory = changed = frozen = 0
        for _ in range(count):
            result = cycle()
            if result['wal'] != first['wal'] or result['plaintext_sha256'] != expected:
                raise ValueError('same-input WAL audit/plaintext mismatch')
            disk += result['temporary_wal_bytes']
            memory += result['memory_wal_bytes']
            frozen += result['frozen_wal_bytes']
            changed += result['plaintext_write_bytes']
        elapsed = time.monotonic()-began
        io1, cpu1 = process.io_counters(), process.cpu_times()
        stop.set()
        thread.join(5)
        result = dict(mode=mode, cycles=count, wal_physical_bytes=wal.stat().st_size,
            input_main_sha256=digest_file(source), input_wal_sha256=digest_file(wal),
            plaintext_sha256=digest_file(view), equals_legacy_plaintext=digest_file(view)==expected,
            elapsed_seconds=elapsed, cpu_seconds=cpu1.user+cpu1.system-cpu0.user-cpu0.system,
            logical_write_bytes=io1.write_bytes-io0.write_bytes, logical_read_bytes=io1.read_bytes-io0.read_bytes,
            frozen_wal_bytes=frozen, disk_wal_bytes=disk, ram_wal_bytes=memory, changed_plaintext_bytes=changed,
            peak_frozen_wal_disk_bytes=wal.stat().st_size if mode=='file' else 0,
            final_view_bytes=view.stat().st_size, final_index_bytes=view.with_suffix('.pages.sqlite').stat().st_size,
            peaks=peaks, physical_write_bytes=None, memory_cap=None, wal_ram_buffer_before_spill_bytes=budget,
            caveat='synthetic stable preallocated WAL; storage selection only, not a production arrival-rate benchmark')
        print(canonical(result))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cycles', type=int, default=16)
    parser.add_argument('--wal-mib', type=int, default=4)
    parser.add_argument('--worker', choices=('file','memory'))
    args = parser.parse_args()
    if args.cycles < 1 or args.wal_mib < 1:
        parser.error('positive fixture size and repetitions required')
    if args.worker:
        worker(args.worker,args.cycles,args.wal_mib)
    else:
        args.out.mkdir(parents=True,exist_ok=False)
        results = []
        for i, mode in enumerate(('file','memory','memory','file')):
            run = subprocess.run([sys.executable,'-m','wechat_capture_next.benchmark_wal','--worker',mode,
                '--cycles',str(args.cycles),'--wal-mib',str(args.wal_mib),'--out',str(args.out)],
                text=True,encoding='utf-8',capture_output=True,check=True)
            result = json.loads(run.stdout)
            results.append(result)
            write_json_new(args.out/f'{i}-{mode}.json',result)
            print(canonical({key:result[key] for key in ('mode','logical_write_bytes','elapsed_seconds','peaks')}),flush=True)
        same = all(len({r[key] for r in results})==1 for key in ('input_main_sha256','input_wal_sha256','plaintext_sha256'))
        write_json_new(args.out/'RESULT.json',dict(pass_all=same and all(r['equals_legacy_plaintext'] for r in results),results=results))
        if not same:
            raise SystemExit(2)
