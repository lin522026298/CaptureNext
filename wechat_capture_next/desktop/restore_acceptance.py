"""Restore the latest paired snapshot through the running product queue."""
import argparse
import json
from pathlib import Path
import time
import psutil
from .probe import connect


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--name',required=True)
    args=parser.parse_args();root=args.root.resolve()
    args.out.mkdir(parents=True,exist_ok=False)
    api=connect(root)
    rows=api('/api/union-backups')['snapshots']
    if not rows:raise ValueError('no paired snapshot')
    snapshot=rows[0]['snapshot_id']
    shell=json.loads((root/'archives/wechat-next/product/shell.private.json').read_text(encoding='utf-8'))
    process=psutil.Process(shell['backend_pid']);created=process.create_time()
    before=process.io_counters();cpu=process.cpu_times()
    start=time.monotonic();peak=0
    job=api('/api/jobs',dict(action='restore_pair',snapshot_id=snapshot,name=args.name))
    while True:
        if process.create_time()!=created:raise RuntimeError('backend process identity changed')
        peak=max(peak,process.memory_info().private)
        current=next(j for j in api('/api/jobs')['jobs'] if j['id']==job['id'])
        if current['status'] not in ('queued','running'):
            break
        time.sleep(.5)
    after=process.io_counters();end_cpu=process.cpu_times()
    result=dict(status=current['status'],result=current.get('result'),error_type=current.get('error_type'),
        snapshot_id=snapshot,peak_private=peak,seconds=time.monotonic()-start,
        cpu_seconds=end_cpu.user+end_cpu.system-cpu.user-cpu.system,
        logical_read_bytes=after.read_bytes-before.read_bytes,logical_write_bytes=after.write_bytes-before.write_bytes,
        physical_disk_write_bytes=None,process_hard_fault_bytes=None,
        measurement_scope='backend_process_only',full_process_tree=False,
        sampling_seconds=.5,peak_kind='sampled_not_kernel_peak',
        timing_scope='submit_to_observed_completion_includes_queue_and_final_poll',
        restore_name=args.name,cleanup_performed=False)
    (args.out/'RESULT.private.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='result'}),flush=True)
    if current['status']!='completed' or current['result'].get('attachments_closed') is not True:
        raise RuntimeError('full restoration not verified; preserve incomplete outputs')


if __name__=='__main__':main()
