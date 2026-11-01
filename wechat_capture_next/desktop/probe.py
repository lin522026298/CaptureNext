"""Local acceptance helper; exact task shell identity, token kept in memory."""
import argparse
import json
from pathlib import Path
import re
import urllib.request

import psutil


def connect(root):
    root=Path(root).resolve()
    state=json.loads((root/'archives'/'wechat-next'/'product'/'shell.private.json').read_text(encoding='utf-8'))
    shell=psutil.Process(state['pid']);backend=psutil.Process(state['backend_pid'])
    if backend.ppid()!=shell.pid or Path(shell.exe()).name!='CaptureNext.exe':
        raise ValueError('not the exact owned shell/backend process tree')
    args=shell.cmdline()
    if '--root' not in args or Path(args[args.index('--root')+1]).resolve()!=root:
        raise ValueError('shell workspace identity differs')
    sockets=[c for c in backend.net_connections(kind='tcp')
        if c.status==psutil.CONN_LISTEN and c.laddr.ip=='127.0.0.1']
    if not sockets:
        raise ValueError('private endpoint not yet ready')
    # Desktop is first listener created; choose its actual HTML/bootstrap.
    # Multiple UI listeners share one core, so any still-live token is scoped
    # to this exact owned process and not printed/persisted by this helper.
    base='http://127.0.0.1:'+str(sockets[0].laddr.port)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(base,timeout=10) as response:html=response.read().decode('utf-8')
    match=re.search(r'window\.__BOOTSTRAP__=(.*?);</script>',html)
    if match is None:raise ValueError('bootstrap unavailable')
    token=json.loads(match.group(1))['token']
    def api(path,body=None):
        headers={'X-Capture-Token':token,'Origin':base}
        if body is not None:headers['Content-Type']='application/json'
        request=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,headers=headers)
        with opener.open(request,timeout=15) as response:return json.load(response)
    return api


def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True)
    p.add_argument('--action');a=p.parse_args()
    api=connect(a.root)
    if a.action:
        print(json.dumps(api('/api/jobs',dict(action=a.action))))
    else:
        s=api('/api/product')
        print(json.dumps(dict(watching=s['watching'],busy=s['busy'],closing=s['closing'],
            watch_error=s['watch_error'],summary=s.get('summary'),current_job=s['current_job'],
            union=s['product']['union'],schedule_error=s['product']['schedule_error'])))


if __name__=='__main__':main()
