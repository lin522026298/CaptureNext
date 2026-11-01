"""Opt-in packaged-shell exercise and process-tree measurement (no chat text).

This launches only our new application. --synthetic creates disposable small
fixtures; without it, use only an explicitly authorized formal workspace.
Logical process I/O is NOT physical disk I/O. CPU is summed CPU seconds, not a
machine-wide counter. Sample every .5s, including WebView descendants.
"""
import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import statistics
import subprocess
import time

import psutil


def inventory(root):
    return sum(p.stat().st_size for p in root.rglob('*') if p.is_file()) if root.exists() else 0


def browser_metrics(root):
    directory=root/'archives'/'wechat-next'/'product'/'webview-cache'/'EBWebView'/'BrowserMetrics'
    files=list(directory.glob('BrowserMetrics-*.pma')) if directory.exists() else []
    return dict(files=len(files),bytes=sum(p.stat().st_size for p in files))


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--exe',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--synthetic',action='store_true')
    a=p.parse_args()
    fixture=None
    root=a.root.resolve()
    if a.synthetic:
        from wechat_capture_next.tests.test_product import ProductTests
        fixture=ProductTests('test_schedule_windows_and_settings_types')
        fixture.setUp();fixture.prepared()
        root=fixture.root
        base=root/'archives'/'wechat-next';base.mkdir(parents=True)
        fixture.state.rename(base/'state');fixture.formal.rename(base/'unified')
    a.out.mkdir(parents=True,exist_ok=False)
    state_file=root/'archives'/'wechat-next'/'product'/'shell.private.json'
    before=inventory(root/'archives'/'wechat-next'/'product')
    metrics_before=browser_metrics(root)
    start=time.monotonic()
    proc=subprocess.Popen([str(a.exe.resolve()),'--root',str(root),'--exercise'],creationflags=subprocess.CREATE_NO_WINDOW)
    samples=[];counters={};last_seen={};seen=set()
    try:
        with (a.out/'samples.private.jsonl').open('x',encoding='utf-8') as stream:
            while proc.poll() is None and time.monotonic()-start<600:
                phase='startup'
                try:
                    state=json.loads(state_file.read_text(encoding='utf-8'))
                    if state['pid']==proc.pid:phase=state['phase']
                except (OSError,ValueError):pass
                rss=private=cpu=reads=writes=0
                processes=[]
                try:processes=[psutil.Process(proc.pid),*psutil.Process(proc.pid).children(recursive=True)]
                except psutil.Error:pass
                for item in processes:
                    try:
                        identity=(item.pid,item.create_time());seen.add(identity)
                        m=item.memory_info();i=item.io_counters();c=item.cpu_times()
                        rss+=m.rss;private+=getattr(m,'private',m.vms)
                        now=(c.user+c.system,i.read_bytes,i.write_bytes)
                        old=last_seen.get(identity,(0,0,0))
                        delta=tuple(max(0,x-y) for x,y in zip(now,old))
                        cpu+=delta[0];reads+=delta[1];writes+=delta[2]
                        last_seen[identity]=now
                    except psutil.Error:pass
                elapsed=round(time.monotonic()-start,3)
                duration=elapsed-samples[-1]['seconds'] if samples else .5
                sample=dict(seconds=elapsed,duration_seconds=duration,phase=phase,
                    rss=rss,private=private,cpu_seconds_delta=cpu,
                    logical_read_delta=reads,logical_write_delta=writes,processes=len(processes))
                stream.write(json.dumps(sample)+'\n');stream.flush();samples.append(sample)
                time.sleep(.5)
        if proc.poll() is None:
            raise RuntimeError('shell exercise did not exit within safe deadline; no forced termination issued')
        groups=defaultdict(list)
        for sample in samples:groups[sample['phase']].append(sample)
        results={}
        for phase,rows in groups.items():
            seconds=sum(r['duration_seconds'] for r in rows)
            results[phase]=dict(sample_seconds=seconds,samples=len(rows),
                peak_private=max(r['private'] for r in rows),median_private=statistics.median(r['private'] for r in rows),
                peak_rss=max(r['rss'] for r in rows),median_rss=statistics.median(r['rss'] for r in rows),
                cpu_seconds=sum(r['cpu_seconds_delta'] for r in rows),
                one_core_cpu_percent=100*sum(r['cpu_seconds_delta'] for r in rows)/seconds,
                logical_reads=sum(r['logical_read_delta'] for r in rows),
                logical_writes=sum(r['logical_write_delta'] for r in rows))
        result=dict(returncode=proc.returncode,seconds=time.monotonic()-start,phases=results,
            synthetic=a.synthetic,physical_disk_write_bytes=None,process_hard_fault_bytes=None,
            sampling_seconds=.5,full_process_tree=True,process_identities=len(seen),
            package_bytes=inventory(a.exe.parent),
            runtime_before=before,runtime_after=inventory(root/'archives'/'wechat-next'/'product'),
            browser_metrics_before=metrics_before,browser_metrics_after=browser_metrics(root),
            limits='short packaged lifecycle exercise, not long throughput/phone-history completeness',
            backend_survivors=[pid for pid,created in seen if pid!=proc.pid and psutil.pid_exists(pid)
                and abs(psutil.Process(pid).create_time()-created)<.01])
        (a.out/'RESULT.private.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(json.dumps(result))
    finally:
        if fixture is not None and proc.poll() is not None:
            fixture.tearDown()


if __name__=='__main__':main()
