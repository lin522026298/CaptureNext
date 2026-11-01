"""Owned backup/restore measurement; all detailed outputs stay private/local."""
import argparse
import hashlib
import json
from pathlib import Path
import threading
import time
import traceback

import psutil
from wechat_capture_v2.common import write_json_new,utcnow
from .product_settings import atomic_json
from . import pair_repository,rolling_delivery


def footprint(root):
    root=Path(root)
    return sum(p.stat().st_size for p in root.rglob('*') if p.is_file()) if root.exists() else 0


def measure(operation,space_root,*,samples_path=None):
    own=psutil.Process();start=time.monotonic();cpu0=own.cpu_times();io0=own.io_counters()
    before=footprint(space_root);done=threading.Event();peak=dict(private_bytes=0,rss_bytes=0,high_memory_seconds=0,ephemeral_sqlite_sidecar_bytes=0)
    def sample():
        previous=time.monotonic()
        stream=samples_path.open('x',encoding='utf-8',buffering=1) if samples_path is not None else None
        try:
            while not done.is_set():
                now=time.monotonic();memory=own.memory_info();private=getattr(memory,'private',memory.vms)
                peak['private_bytes']=max(peak['private_bytes'],private);peak['rss_bytes']=max(peak['rss_bytes'],memory.rss)
                try:
                    sidecars=sum(p.stat().st_size for p in Path(space_root).rglob('*')
                        if p.is_file() and p.name.endswith(('-journal','-wal','-shm')))
                    peak['ephemeral_sqlite_sidecar_bytes']=max(peak['ephemeral_sqlite_sidecar_bytes'],sidecars)
                except FileNotFoundError:pass
                if private>1024**3:peak['high_memory_seconds']+=now-previous
                if stream:
                    io=own.io_counters();cpu=own.cpu_times()
                    stream.write(json.dumps(dict(elapsed_seconds=now-start,private_bytes=private,rss_bytes=memory.rss,
                        read_bytes=io.read_bytes-io0.read_bytes,write_bytes=io.write_bytes-io0.write_bytes,
                        cpu_seconds=cpu.user+cpu.system-cpu0.user-cpu0.system))+'\n')
                previous=now;done.wait(.5)
        finally:
            if stream:stream.close()
    thread=threading.Thread(target=sample,daemon=True);thread.start()
    result=None;error=None;error_trace=None
    try:result=operation()
    except Exception as exc:error=type(exc).__name__;error_trace=traceback.format_exc()
    finally:done.set();thread.join()
    io1=own.io_counters();cpu1=own.cpu_times()
    value=dict(schema='next-paired-backup-measurement-1',partial=error is not None,error_type=error,error_trace_private=error_trace,result=result,
        elapsed_seconds=time.monotonic()-start,cpu_seconds=cpu1.user+cpu1.system-cpu0.user-cpu0.system,
        process_logical_read_bytes=io1.read_bytes-io0.read_bytes,process_logical_write_bytes=io1.write_bytes-io0.write_bytes,
        physical_disk_write_bytes=None,process_hard_fault_bytes=None,memory_sample_seconds=.5,peak=peak,
        temporary_peak_scope='sampled_SQLite_sidecars_inside_space_scope_not_all_system_temp',
        settled_before_bytes=before,settled_after_bytes=footprint(space_root),
        includes_output_receipt_writes=False,includes_sampling_overhead=True,
        harness_sample_bytes=samples_path.stat().st_size if samples_path is not None else 0,space_scope=str(space_root))
    value['settled_net_bytes']=value['settled_after_bytes']-before
    return value


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    b=sub.add_parser('backup')
    for name in ('state','union','repo','out'):b.add_argument('--'+name,type=Path,required=True)
    b.add_argument('--provenance',type=Path);b.add_argument('--block-bytes',type=int,default=pair_repository.DEFAULT_BLOCK)
    b.add_argument('--object-block-bytes',type=int,choices=pair_repository.ALLOWED_BLOCKS,default=pair_repository.DEFAULT_OBJECT_BLOCK)
    r=sub.add_parser('restore')
    for name in ('repo','target','out'):r.add_argument('--'+name,type=Path,required=True)
    r.add_argument('--snapshot',required=True)
    args=p.parse_args(argv)
    if args.out.exists():raise FileExistsError('fresh measurement receipt required')
    paths=[Path(__file__).with_name(n+'.py') for n in ('benchmark_pair','pair_repository','pair_collection','pair_readback_memo','rolling_delivery','backup','operation_objects','union_assets','assets','service','compact_archive','viewer_identity','viewer_media','cas_stream')]
    hashes=lambda:{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    before_hashes=hashes();own=psutil.Process()
    run=dict(pid=own.pid,process_created=own.create_time(),started=utcnow(),action=args.action,source_hashes=before_hashes)
    write_json_new(args.out.with_name(args.out.stem+'.RUN.private.json'),run)
    samples=args.out.with_name(args.out.stem+'.samples.private.jsonl')
    phase_path=args.out.with_name(args.out.stem+'.PHASE.private.json')
    last_phase=[None]
    def phase(name,db):
        from .pair_collection import progress_phase
        name=progress_phase(name)
        if name!=last_phase[0]:
            atomic_json(phase_path,dict(phase=name,at=utcnow(),pid=own.pid));last_phase[0]=name
    if args.action=='backup':
        value=measure(lambda:rolling_delivery.backup(args.state,args.union,args.repo,provenance=args.provenance,
            block_bytes=args.block_bytes,object_block_bytes=args.object_block_bytes,fault=phase),args.repo,samples_path=samples)
    else:value=measure(lambda:rolling_delivery.restore(args.repo,args.snapshot,args.target),args.target,samples_path=samples)
    value.update(run=run,source_hashes_after=hashes(),code_changed_during_run=before_hashes!=hashes())
    write_json_new(args.out,value)
    print(json.dumps(dict(partial=value['partial'],error_type=value['error_type'],elapsed_seconds=value['elapsed_seconds'],
        settled_net_bytes=value['settled_net_bytes'])),flush=True)
    return 1 if value['partial'] else 0


if __name__=='__main__':raise SystemExit(main())
