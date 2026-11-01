"""Authorized real-instance maintenance acceptance; summaries only.

Requires an already-running exact owned native shell. Does not launch another
collector, switch sources, enter auth, or publish/export chat content.
"""
import argparse
import json
from pathlib import Path
import time

import psutil
from .probe import connect


def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    api=connect(a.root)
    identity=json.loads((a.root/'archives/wechat-next/product/shell.private.json').read_text(encoding='utf-8'))
    backend=psutil.Process(identity['backend_pid']);created=backend.create_time()
    records=[]

    def run(action):
        before=backend.io_counters();cpu=backend.cpu_times();start=time.monotonic()
        job=api('/api/jobs',dict(action=action));peak=0;peak_rss=0
        while True:
            if backend.create_time()!=created:raise RuntimeError('process identity changed')
            memory=backend.memory_info();peak=max(peak,memory.private);peak_rss=max(peak_rss,memory.rss)
            current=next(j for j in api('/api/jobs')['jobs'] if j['id']==job['id'])
            if current['status'] not in ('queued','running') and not api('/api/product')['busy']:
                break
            time.sleep(.5)
        after=backend.io_counters();cpu_after=backend.cpu_times()
        record=dict(action=action,status=current['status'],seconds=time.monotonic()-start,
            peak_private=peak,peak_rss=peak_rss,
            cpu_seconds=cpu_after.user+cpu_after.system-cpu.user-cpu.system,
            logical_read_bytes=after.read_bytes-before.read_bytes,
            logical_write_bytes=after.write_bytes-before.write_bytes,
            physical_disk_write_bytes=None,process_hard_fault_bytes=None,result=current.get('result'),
            error_type=current.get('error_type'))
        records.append(record)
        (a.out/'RESULT.partial.private.json').write_text(json.dumps(records,indent=2),encoding='utf-8')
        print(json.dumps({k:v for k,v in record.items() if k!='result'}),flush=True)
        if current['status']!='completed':raise RuntimeError('maintenance stage did not complete')
        return current

    stopped=run('stop_watch')
    try:
        first=run('backup_pair')
        second=run('backup_pair')
        if second['result'].get('reused_exact_authenticated_cut') is not True:
            raise RuntimeError('unchanged cut did not establish real reuse')
        validated=run('validate')
        if validated['result'].get('pass_all') is not True:
            raise RuntimeError('same-cut validator did not pass')
        # Toggle only our borrowed WebUI listener; no external browser needed.
        for enabled in (True,False,True,False):
            job=api('/api/jobs',dict(action='webui',enabled=enabled))
            while True:
                state=next(j for j in api('/api/jobs')['jobs'] if j['id']==job['id'])
                if state['status'] not in ('queued','running'):break
                time.sleep(.1)
            if state['status']!='completed':raise RuntimeError('WebUI toggle failed')
        run('start_watch')
        result=dict(stages=records,physical_disk_write_bytes=None,process_hard_fault_bytes=None,
            measurement_scope='backend_process_only',full_process_tree=False,
            sampling_seconds=.5,peak_kind='sampled_not_kernel_peak',
            timing_scope='submit_to_observed_completion_includes_queue_and_safe_boundary',
            paired_backup_reused=True,same_cut_validation=True,webui_toggle_core_survived=True,
            restore_scope='synthetic integration + previously verified formal backend; no new full-size restore here')
        (a.out/'RESULT.private.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    finally:
        # Queue resume even on a failed maintenance stage, unless the core has
        # already failed closed. Reconciliation then repairs only local backlog.
        try:
            state=api('/api/product')
            if not state['closing'] and not state['watching']:
                api('/api/jobs',dict(action='start_watch'))
        except Exception:pass


if __name__=='__main__':main()
