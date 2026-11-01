"""Bounded read-only measurement of the exact already-running formal tray."""
import argparse
import json
from pathlib import Path
import statistics
import time

import psutil
from .probe import connect


def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--seconds',type=int,default=60)
    args=p.parse_args();root=args.root.resolve();api=connect(root)
    state_path=root/'archives/wechat-next/product/shell.private.json'
    shell=json.loads(state_path.read_text(encoding='utf-8'));process=psutil.Process(shell['pid'])
    created=process.create_time();start_state=api('/api/product')
    args.out.mkdir(parents=True,exist_ok=False);rows=[];previous={};start=time.monotonic()
    with (args.out/'samples.private.jsonl').open('x',encoding='utf-8') as stream:
        while time.monotonic()-start<args.seconds:
            if process.create_time()!=created:raise RuntimeError('shell identity changed')
            s=json.loads(state_path.read_text(encoding='utf-8'))
            if s['pid']!=process.pid or s['window_open']:raise RuntimeError('not a tray-only window')
            private=rss=cpu=reads=writes=0
            for child in [process,*process.children(recursive=True)]:
                try:
                    key=(child.pid,child.create_time());m=child.memory_info();io=child.io_counters();c=child.cpu_times()
                    now=(c.user+c.system,io.read_bytes,io.write_bytes);old=previous.get(key,now)
                    if rows and key not in previous:old=(0,0,0)
                    delta=[max(0,x-y) for x,y in zip(now,old)];previous[key]=now
                    private+=m.private;rss+=m.rss;cpu+=delta[0];reads+=delta[1];writes+=delta[2]
                except psutil.NoSuchProcess:continue
            row=dict(seconds=time.monotonic()-start,private=private,rss=rss,cpu=cpu,reads=reads,writes=writes)
            rows.append(row);stream.write(json.dumps(row)+'\n');stream.flush();time.sleep(.5)
    seconds=time.monotonic()-start;end_state=api('/api/product')
    result=dict(seconds=seconds,sampling_seconds=.5,full_process_tree=True,
        median_private=statistics.median(x['private'] for x in rows),peak_private=max(x['private'] for x in rows),
        cpu_seconds=sum(x['cpu'] for x in rows),logical_reads=sum(x['reads'] for x in rows),
        logical_writes=sum(x['writes'] for x in rows),physical_disk_write_bytes=None,process_hard_fault_bytes=None,
        core_pid=shell['backend_pid'],watching_before=start_state['watching'],watching_after=end_state['watching'],
        summary_before=start_state['summary'],summary_after=end_state['summary'],
        watch_error=end_state['watch_error'],schedule_error=end_state['product']['schedule_error'],
        scope='short formal tray observation; not a long-run or throughput test')
    result['one_core_cpu_percent']=100*result['cpu_seconds']/seconds
    with (args.out/'RESULT.private.json').open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps(result))


if __name__=='__main__':main()
