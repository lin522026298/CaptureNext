"""Sample an owned collector process tree, without touching the desktop."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import threading
import time

import psutil
from .common import canonical,digest_file,utcnow,write_json_new


def footprint(root):
    groups={}
    for path in Path(root).rglob('*'):
        if path.is_file():
            key=path.relative_to(root).parts[0] if len(path.relative_to(root).parts)>1 else path.name
            groups[key]=groups.get(key,0)+path.stat().st_size
    return groups


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',required=True,type=Path)
    parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--seconds',type=float,default=900)
    parser.add_argument('--assets',action='store_true')
    args=parser.parse_args()
    output=args.out.resolve()
    output.mkdir(parents=True,exist_ok=False)
    before=footprint(args.state)
    report_count_before=len(list((args.state/'reports').glob('*.json')))
    code={str(p.relative_to(Path(__file__).parent)):digest_file(p) for p in Path(__file__).parent.rglob('*.py')}
    command=[sys.executable,'-u','-m','wechat_capture_v2','watch','--state',str(args.state),
             '--interval','3','--reconcile-seconds','300','--run-seconds',str(args.seconds)]
    if args.assets:
        command+=['--assets']
    began=time.monotonic()
    process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',
                             creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    cycles=[];warm_footprint={}
    def reader():
        with (output/'cycles.jsonl').open('x',encoding='utf-8') as stream:
            for line in process.stdout:
                data=json.loads(line)
                event={'elapsed':time.monotonic()-began,'result':data}
                cycles.append(event)
                if not warm_footprint and 'cycle_id' in data:
                    warm_footprint.update(footprint(args.state))
                stream.write(canonical(event)+'\n');stream.flush()
    thread=threading.Thread(target=reader,daemon=True);thread.start()
    samples=[];counters={};last_cpu=None;last_time=began
    with (output/'samples.jsonl').open('x',encoding='utf-8') as stream:
        while process.poll() is None:
            now=time.monotonic();rss=private=handles=threads=0
            try:
                parent=psutil.Process(process.pid)
                processes=[parent]+parent.children(recursive=True)
            except psutil.Error:
                processes=[]
            for item in processes:
                try:
                    with item.oneshot():
                        cpu=item.cpu_times();memory=item.memory_info();io=item.io_counters()
                        counters[item.pid]={'cpu':cpu.user+cpu.system,'read':io.read_bytes,'write':io.write_bytes}
                        rss+=memory.rss;private+=getattr(memory,'private',memory.vms)
                        handles+=item.num_handles() if os.name=='nt' else item.num_fds()
                        threads+=item.num_threads()
                except psutil.Error:
                    pass
            total=sum(v['cpu'] for v in counters.values())
            single=max(0,total-last_cpu)/max(now-last_time,0.001)*100 if last_cpu is not None else 0.0
            sample={'elapsed':now-began,'cpu_machine_percent':single/(os.cpu_count() or 1),
                    'cpu_single_core_percent':single,'rss_bytes':rss,'private_bytes':private,
                    'handles':handles,'threads':threads,'process_count':len(processes),
                    'logical_read_bytes':sum(v['read'] for v in counters.values()),
                    'logical_write_bytes':sum(v['write'] for v in counters.values())}
            samples.append(sample);stream.write(canonical(sample)+'\n');stream.flush()
            last_cpu=total;last_time=now
            time.sleep(1)
    thread.join(timeout=10)
    errors=process.stderr.read()
    duration=time.monotonic()-began
    active=[];first_end=None
    for event in cycles:
        row=event['result']
        if 'elapsed_seconds' in row:
            if first_end is None:first_end=event['elapsed']
            if row['elapsed_seconds']>0.3:
                active.append((event['elapsed']-row['elapsed_seconds'],event['elapsed']))
    warm=[s for s in samples if first_end is not None and s['elapsed']>first_end+10]
    idle=[s for s in warm if not any(a-1<=s['elapsed']<=b+1 for a,b in active)]
    def stats(rows):
        if not rows:return {'samples':0}
        return {'samples':len(rows),'cpu_machine_mean_percent':statistics.mean(r['cpu_machine_percent'] for r in rows),
            'cpu_machine_peak_percent':max(r['cpu_machine_percent'] for r in rows),
            'private_peak_bytes':max(r['private_bytes'] for r in rows),'rss_peak_bytes':max(r['rss_bytes'] for r in rows),
            'private_first_window_bytes':statistics.median(r['private_bytes'] for r in rows[:min(30,len(rows))]),
            'private_last_window_bytes':statistics.median(r['private_bytes'] for r in rows[-min(30,len(rows)):]),
            'handles_first':rows[0]['handles'],'handles_last':rows[-1]['handles']}
    after=footprint(args.state)
    report={'schema':'wechat-resident-benchmark-1','finished':utcnow(),'duration_seconds':duration,
        'returncode':process.returncode,'errors_private':errors,'assets_enabled':args.assets,
        'host':{'logical_cpus':os.cpu_count(),'memory_bytes':psutil.virtual_memory().total,'python':platform.python_version()},
        'source_hashes':code,'all':stats(samples),'warm':stats(warm),'idle':stats(idle),
        'cpu_seconds':sum(v['cpu'] for v in counters.values()),
        'logical_read_bytes':sum(v['read'] for v in counters.values()),'logical_write_bytes':sum(v['write'] for v in counters.values()),
        'state_before':before,'state_after':after,'state_growth_bytes':sum(after.values())-sum(before.values()),
        'warm_state_before':warm_footprint,'warm_state_growth_bytes':sum(after.values())-sum(warm_footprint.values()),
        'cycle_count':sum('cycle_id' in e['result'] for e in cycles),
        'cycle_seconds':[e['result']['elapsed_seconds'] for e in cycles if 'elapsed_seconds' in e['result']],
        'report_count_before':report_count_before,'report_count_after':len(list((args.state/'reports').glob('*.json')))}
    write_json_new(output/'RESULT.json',report)
    print(canonical({key:report[key] for key in ('duration_seconds','returncode','all','warm','idle','state_growth_bytes','logical_write_bytes')}),flush=True)


if __name__=='__main__':main()
