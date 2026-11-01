"""Supplementary resource evidence: owned process observation and large assets."""
import argparse
import hashlib
import os
from pathlib import Path
import statistics
import sys
import time
import psutil
from .common import canonical,write_json_new
from .objects import Objects,PendingImport


def observe(pid,seconds,out):
    process=psutil.Process(pid);rows=[];start=time.monotonic();last_cpu=None;last_time=start
    while time.monotonic()-start<seconds:
        try:
            with process.oneshot():
                memory=process.memory_info();cpu=process.cpu_times();io=process.io_counters()
                total=cpu.user+cpu.system;now=time.monotonic()
                rows.append({'elapsed':now-start,'cpu_machine_percent':(total-last_cpu)/(now-last_time)*100/(os.cpu_count() or 1) if last_cpu is not None else 0,
                    'private_bytes':getattr(memory,'private',memory.rss),'rss_bytes':memory.rss,
                    'handles':process.num_handles() if os.name=='nt' else process.num_fds(),'read':io.read_bytes,'write':io.write_bytes})
                last_cpu=total;last_time=now
        except psutil.Error:break
        time.sleep(1)
    result={'sampled_seconds':time.monotonic()-start,'samples':len(rows),'cpu_machine_mean_percent':statistics.mean(r['cpu_machine_percent'] for r in rows),
        'private_peak_bytes':max(r['private_bytes'] for r in rows),'rss_peak_bytes':max(r['rss_bytes'] for r in rows),
        'private_start':rows[0]['private_bytes'],'private_end':rows[-1]['private_bytes'],
        'handles_start':rows[0]['handles'],'handles_end':rows[-1]['handles'],
        'logical_reads':rows[-1]['read']-rows[0]['read'],'logical_writes':rows[-1]['write']-rows[0]['write'],
        'scope':'selected_server_process_only_browser_and_workers_excluded'}
    write_json_new(out,result);print(canonical(result))


def assets(out,mib):
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    source=out/'synthetic-random.bin';digest=hashlib.sha256()
    with source.open('xb') as stream:
        for _ in range(mib):
            block=os.urandom(1024**2);stream.write(block);digest.update(block)
    objects=Objects(out/'objects.sqlite');pending=PendingImport(objects,source)
    rows=[];start=time.monotonic();process=psutil.Process();cpu0=process.cpu_times()
    try:
        while pending.result is None:
            before=time.monotonic();phase=pending.phase
            pending.advance(before+.25)
            memory=process.memory_info()
            rows.append({'phase':phase,'seconds':time.monotonic()-before,'private_bytes':getattr(memory,'private',memory.rss)})
        if pending.result['sha256']!=digest.hexdigest():raise ValueError('synthetic digest mismatch')
        objects.restore(digest.hexdigest(),out/'restored.bin')
        verification=objects.verify_all()
        cpu=process.cpu_times()
        result={'source_bytes':source.stat().st_size,'pass':verification['pass'],'elapsed_seconds':time.monotonic()-start,
            'cpu_seconds':cpu.user+cpu.system-cpu0.user-cpu0.system,'time_slice_target_seconds':.25,
            'longest_slice_seconds':max(r['seconds'] for r in rows),'slices':len(rows),
            'private_peak_bytes':max(r['private_bytes'] for r in rows),'pending_chunk_count':len(pending.chunks),
            'pending_chunk_list_shallow_bytes':sys.getsizeof(pending.chunks)+sum(sys.getsizeof(c) for c in pending.chunks),
            'slice_samples':rows,'not_a_hard_realtime_guarantee':True}
        write_json_new(out/'RESULT.json',result)
        print(canonical({k:v for k,v in result.items() if k!='slice_samples'}))
    finally:objects.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--pid',type=int);parser.add_argument('--seconds',type=float,default=300);parser.add_argument('--asset-mib',type=int)
    args=parser.parse_args()
    if args.asset_mib:assets(args.out,args.asset_mib)
    else:observe(args.pid,args.seconds,args.out)
