"""Loopback-only control plane. Status never constructs a writer service."""
from __future__ import annotations

import argparse
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
import webbrowser

import psutil
from fastapi import FastAPI,HTTPException,Request
from fastapi.responses import FileResponse,JSONResponse
import uvicorn

from .common import canonical,directory,regular,utcnow,writer_lock
from .service import load_config

KINDS={'reconcile','backup','restore','compare','verify','jsonl','wua','extract_assets','verify_assets'}
LABELS={'reconcile':'完整补采','backup':'创建备份','restore':'恢复到独立目录','compare':'同源逐字段比对',
        'verify':'对象完整性校验','jsonl':'完整原始导出','wua':'去重归档导出','extract_assets':'提取附件','verify_assets':'附件读回校验'}


def atomic_json(path,value):
    for parent in (path.parent,*path.parent.parents):
        directory(parent)
    if path.exists():regular(path)
    temp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.new')
    try:
        with temp.open('x',encoding='utf-8') as stream:
            stream.write(canonical(value)+'\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temp,path)
    finally:
        # Only this attempt's owned temporary file; historical evidence untouched.
        if temp.exists():temp.unlink()


def checked_runtime(state,runtime):
    """Validate before even creating a lock file. Reject linked ancestors."""
    state=Path(state).absolute()
    runtime=Path(runtime).absolute()
    for path in (state,runtime,runtime/'jobs'):
        for part in (path,*path.parents):
            if part.exists():directory(part)
    state=state.resolve(strict=True)
    config=load_config(state)
    runtime=runtime.resolve()
    for root in (state,Path(config['database_root']),Path(config['asset_root']) if config.get('asset_root') else None):
        if root and (runtime.is_relative_to(root.resolve()) or root.resolve().is_relative_to(runtime)):
            raise ValueError('console output must not overlap source or state')
    return state,runtime,config


class Projection:
    def __init__(self,state):
        self.state=Path(state)
        self.lock=threading.Lock()
        self.cached=None
        self.until=0

    def read(self):
        with self.lock:
            if self.cached is not None and time.monotonic()<self.until:
                return self.cached
            result={'available':False,'phone_completeness':'unverified','source_scope':'本机已落盘数据'}
            try:
                # Not immutable: the collector may have an active WAL.
                db=sqlite3.connect((self.state/'catalog.sqlite').as_uri()+'?mode=ro',uri=True,timeout=0.5)
                db.execute('PRAGMA query_only=ON');db.execute('PRAGMA trusted_schema=OFF')
                try:
                    row=db.execute('SELECT finished,status,mode,report_json FROM cycle WHERE finished IS NOT NULL ORDER BY rowid DESC LIMIT 1').fetchone()
                    report=json.loads(row[3]) if row and row[3] else {}
                    summary=report.get('summary')
                    # Count projections are already committed in each completed
                    # cycle. Avoid rereading large indexes every UI poll.
                    if summary is not None:
                        counts={'active_observations':summary['active_messages'],'raw_versions':summary['versions'],
                            'asset_paths':summary['assets']}
                    else:
                        counts={key:db.execute(sql).fetchone()[0] for key,sql in {
                            'active_observations':'SELECT count(*) FROM head WHERE active=1',
                            'raw_versions':'SELECT count(*) FROM version','asset_paths':'SELECT count(*) FROM asset'}.items()}
                    counts['database_paths']=db.execute('SELECT count(*) FROM checkpoint').fetchone()[0]
                    asset_row=db.execute('SELECT finished,report_json FROM cycle WHERE finished IS NOT NULL AND report_json LIKE ? ORDER BY rowid DESC LIMIT 1',('%"assets":%',)).fetchone()
                    full=db.execute("SELECT finished FROM cycle WHERE mode='full_reconciliation' AND status IN ('local_complete','local_complete_assets_pending') ORDER BY rowid DESC LIMIT 1").fetchone()
                    result.update(available=True,**counts,last_successful_reconciliation=full[0] if full else None)
                    if row:
                        assets=report.get('assets',{})
                        result['last_cycle']={'finished':row[0],'status':row[1],'mode':row[2],
                            'errors':len(report.get('errors',[])),'asset_scan_complete':assets.get('complete'),
                            'asset_enabled':assets.get('enabled',False)}
                    if asset_row:
                        info=json.loads(asset_row[1]).get('assets',{})
                        result['last_asset_scan']={'finished':asset_row[0],'complete':info.get('complete',False),
                            'errors':len(info.get('errors',[])),'enabled':info.get('enabled',False)}
                finally:db.close()
            except (sqlite3.Error,OSError,ValueError):
                result['error_code']='catalog_temporarily_unavailable'
            result['checked_at']=utcnow()
            result['free_bytes']=shutil.disk_usage(self.state).free
            result['state_database_bytes']=sum(p.stat().st_size for p in self.state.glob('*.sqlite*') if p.is_file())
            self.cached=result;self.until=time.monotonic()+10
            return result


class Coordinator:
    """One owned watch or one owned job. Never kills an external collector."""
    def __init__(self,state,runtime):
        self.state,self.runtime,self.config=checked_runtime(state,runtime)
        self.runtime.mkdir(parents=True,exist_ok=True)
        directory(self.runtime)
        self.jobs_root=self.runtime/'jobs';self.jobs_root.mkdir(exist_ok=True);directory(self.jobs_root)
        self.guard=threading.RLock()
        self.jobs=[]
        for path in sorted(self.jobs_root.glob('*/job.json')):
            try:
                directory(path.parent);regular(path)
                job=json.loads(path.read_text(encoding='utf-8'))
                if not re.fullmatch('[0-9a-f]{32}',job['id']) or path.parent.name!=job['id'] or job['kind'] not in KINDS:
                    raise ValueError('invalid persisted task identity')
                if job['status'] in ('queued','running','waiting_safe_boundary'):
                    job.update(status='interrupted',error_code='console_restarted',finished=utcnow())
                    atomic_json(path,job)
                self.jobs.append(job)
            except (OSError,ValueError,KeyError):pass
        self.desired_watch=False
        self.jobs.sort(key=lambda j:(j['created'],j['id']))
        self.watch_assets=False
        self.watch=None
        self.watch_reader=None
        self.watch_latest=None
        self.watch_error=None
        self.watch_stop=None
        self.watch_started=None
        self.watch_updated=None
        self.watch_last_persist=0
        self.closing=False
        self.wake=threading.Event()
        self.thread=threading.Thread(target=self._loop,name='capture-job-coordinator',daemon=False)
        self.projection=Projection(self.state)
        self.thread.start()

    def _save(self,job):
        directory(self.jobs_root)
        directory(self.jobs_root/job['id'])
        atomic_json(self.jobs_root/job['id']/'job.json',job)

    def enqueue(self,payload):
        if not isinstance(payload,dict):raise ValueError('object required')
        if set(payload)-{'kind','acknowledge','include_secrets','assets','input_job','request_id'}:
            raise ValueError('unsupported parameter')
        kind=payload.get('kind')
        if kind not in KINDS:raise ValueError('unsupported task')
        for key in ('acknowledge','include_secrets','assets'):
            if key in payload and type(payload[key]) is not bool:raise ValueError('boolean required')
        if not payload.get('acknowledge'):raise ValueError('explicit task confirmation required')
        if payload.get('include_secrets') and kind!='backup':raise ValueError('keys only supported for private backup')
        with self.guard:
            if self.closing:raise ValueError('console shutting down')
            request_id=payload.get('request_id')
            if request_id is not None and (not isinstance(request_id,str) or not re.fullmatch('[0-9a-f-]{32,36}',request_id)):
                raise ValueError('invalid request identity')
            existing=next((j for j in self.jobs if request_id and j.get('request_id')==request_id),None)
            if existing:
                if existing['kind']!=kind or existing.get('include_secrets',False)!=payload.get('include_secrets',False) or existing.get('input_job')!=payload.get('input_job') or existing.get('assets',False)!=payload.get('assets',False):
                    raise ValueError('request identity reused with different parameters')
                return dict(existing)
            if sum(j['status']=='queued' for j in self.jobs)>=8:raise ValueError('wait for queued tasks to finish')
            input_job=payload.get('input_job')
            if kind in ('restore','verify_assets'):
                expected='backup' if kind=='restore' else 'extract_assets'
                source=next((j for j in self.jobs if j['id']==input_job and j['kind']==expected and j['status']=='completed'),None)
                if not source:raise ValueError('select a successfully completed input task')
            elif input_job:raise ValueError('input task not allowed')
            if kind=='wua' and psutil.virtual_memory().available<6*1024**3:
                raise ValueError('dedup export requires at least 6 GiB available memory')
            job={'id':uuid.uuid4().hex,'kind':kind,'status':'queued','created':utcnow(),
                'include_secrets':payload.get('include_secrets',False),'assets':payload.get('assets',False),
                'input_job':input_job,'phase':'等待后台队列','result':None,'error_code':None}
            job['request_id']=request_id
            directory(self.jobs_root)
            (self.jobs_root/job['id']).mkdir()
            self.jobs.append(job);self._save(job);self.wake.set()
            return dict(job)

    def watch_control(self,enabled,assets=False):
        if type(enabled) is not bool or type(assets) is not bool:raise ValueError('boolean required')
        with self.guard:
            if self.closing:raise ValueError('console shutting down')
            if self.watch and self.watch_assets!=assets:self._request_watch_stop()
            self.desired_watch=enabled;self.watch_assets=assets
            self.watch_error=None
            if not enabled:self._request_watch_stop()
        self.wake.set()

    def cancel(self,ident):
        with self.guard:
            job=next((j for j in self.jobs if j['id']==ident),None)
            if not job or job['status']!='queued':raise ValueError('only queued tasks can be cancelled')
            job.update(status='cancelled',finished=utcnow(),phase='已取消');self._save(job)
        return True

    def _spawn(self,args):
        return subprocess.Popen([sys.executable,'-u','-m','wechat_capture_v2',*map(str,args)],
            cwd=Path(__file__).resolve().parent.parent,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace',shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)

    def _request_watch_stop(self):
        if self.watch and self.watch_stop and not self.watch_stop.exists():
            self.watch_stop.touch(exist_ok=False)

    def _start_watch(self):
        try:
            with writer_lock(self.state):pass
        except OSError:
            self.watch_error='external_writer_busy';self.desired_watch=False;return
        self.watch_stop=self.runtime/('stop-'+uuid.uuid4().hex)
        args=['watch','--state',self.state,'--interval','3','--reconcile-seconds','300','--stop-file',self.watch_stop]
        if self.watch_assets:args.append('--assets')
        self.watch=self._spawn(args);self.watch_started=utcnow();self.watch_latest=None
        self.watch_reader=threading.Thread(target=self._read_watch,args=(self.watch,),daemon=True)
        self.watch_reader.start()

    def _read_watch(self,process):
        for line in process.stdout:
            try:
                report=json.loads(line)
                if 'elapsed_seconds' not in report:continue
                with self.guard:
                    self.watch_latest=report;self.watch_updated=utcnow()
                    # Idle UI telemetry is not an immutable message observation.
                    if report.get('cycle_id') or time.monotonic()-self.watch_last_persist>=60:
                        atomic_json(self.runtime/'watch.private.json',{'at':self.watch_updated,'report':report})
                        self.watch_last_persist=time.monotonic()
            except (ValueError,OSError):pass
        process.stdout.close()

    def _call(self,args,log):
        process=self._spawn(args)
        last=None
        for line in process.stdout:
            log.write(line)
            if len(line)<1024*1024:
                try:last=json.loads(line)
                except ValueError:pass
        process.stdout.close()
        code=process.wait();log.flush()
        if code!=0 or not isinstance(last,dict) or last.get('pass') is False or last.get('status')=='partial':
            raise RuntimeError('task_failed_check_private_log')
        return last

    def _execute(self,job):
        folder=self.jobs_root/job['id'];kind=job['kind'];output=None
        commands={'reconcile':'capture','compare':'compare-legacy','verify':'verify-state',
                  'jsonl':'export-jsonl','wua':'export-wua','extract_assets':'extract-assets'}
        args=[commands.get(kind,kind),'--state',self.state]
        if kind=='reconcile':
            args+=['--full']
            if job['assets']:args+=['--assets']
        elif kind in ('backup','compare','jsonl','wua','extract_assets','verify'):
            output=folder/({'jsonl':'messages.private.jsonl','wua':'deduplicated.wua.sqlite','verify':'VERIFY.json'}.get(kind,kind))
            args+=['--out',output]
            if job['include_secrets']:args+=['--include-secrets']
        elif kind in ('restore','verify_assets'):
            source=next(j for j in self.jobs if j['id']==job['input_job'])
            source_path=self.jobs_root/source['id']/('backup' if kind=='restore' else 'extract_assets')
            if kind=='restore':
                output=folder/'restored-state'
                args=['restore-backup','--backup',source_path,'--out',output]
            else:args=['verify-assets','--state',self.state,'--assets-root',source_path,'--out',folder/'VERIFY.json']
        # Conservative capacity guard; output estimates are not acquisition caps.
        state_bytes=sum((self.state/name).stat().st_size for name in ('catalog.sqlite','objects.sqlite') if (self.state/name).exists())
        need=64*1024**2
        if kind in ('backup','restore','extract_assets'):need+=state_bytes*1.2
        if kind=='wua':need+=max(state_bytes, self.projection.read().get('raw_versions',0)*24000)
        if shutil.disk_usage(folder).free<need:raise RuntimeError('insufficient_free_space')
        with (folder/'worker.private.log').open('x',encoding='utf-8') as log:
            result=self._call(args,log)
            if kind=='restore':
                with self.guard:job['phase']='已恢复，正在逐对象读回校验';self._save(job)
                result['verification']=self._call(['verify-state','--state',output],log)
        # Expose only numeric/boolean summaries, never raw bodies or key metadata.
        safe={k:v for k,v in result.items() if isinstance(v,(int,float,bool)) or v is None}
        if isinstance(result.get('stats'),dict):
            safe['logical_messages']=result['stats'].get('logical_messages')
        if isinstance(result.get('summary'),dict):
            safe['active_observations']=result['summary'].get('active_messages')
        if kind=='restore':safe['readback_verified']=result.get('verification',{}).get('pass',False)
        return safe,str(output) if output else None

    def _loop(self):
        while True:
            with self.guard:
                if self.watch and self.watch.poll() is not None:
                    code=self.watch.returncode
                    self.watch_reader.join(timeout=1)
                    self.watch=None
                    if code!=0:
                        self.watch_error='watch_exited';self.desired_watch=False
                queued=next((j for j in self.jobs if j['status']=='queued'),None)
                if self.watch and (queued or self.closing or not self.desired_watch):self._request_watch_stop()
                if self.watch and queued:
                    if queued['phase']!='等待采集器完成当前安全边界':
                        queued['phase']='等待采集器完成当前安全边界';self._save(queued)
                ready=queued is not None and self.watch is None and not self.closing
                if ready:
                    queued.update(status='running',started=utcnow(),phase='执行中 · 输出到新目录');self._save(queued)
                elif self.closing and self.watch is None:break
                elif not self.watch and not queued and self.desired_watch:self._start_watch()
            if ready:
                try:
                    # Fail cleanly when an unrelated CLI owns the writer.
                    with writer_lock(self.state):pass
                    result,output=self._execute(queued)
                    with self.guard:queued.update(status='completed',result=result,output=output,phase='已完成并生成独立结果')
                except Exception as exc:
                    with self.guard:queued.update(status='failed',error_code='writer_busy' if isinstance(exc,OSError) else str(exc) if str(exc) in ('insufficient_free_space','task_failed_check_private_log') else 'task_failed',phase='未完成 · 不作为有效交付',diagnostic_directory=str(self.jobs_root/queued['id']))
                with self.guard:
                    queued['finished']=utcnow();self._save(queued);self.projection.until=0
            self.wake.wait(0.5);self.wake.clear()
        with self.guard:
            for job in self.jobs:
                if job['status']=='queued':job.update(status='interrupted',finished=utcnow(),error_code='console_stopped');self._save(job)

    def status(self):
        with self.guard:
            watching=self.watch is not None and self.watch.poll() is None
            processes=[psutil.Process(os.getpid())]
            if watching:
                try:processes+=psutil.Process(self.watch.pid).children(recursive=True)+[psutil.Process(self.watch.pid)]
                except psutil.Error:pass
            memory=0
            for p in processes:
                try:memory+=getattr(p.memory_info(),'private',p.memory_info().rss)
                except psutil.Error:pass
            return {'schema':'capture-console-1','now':utcnow(),'closing':self.closing,'catalog':self.projection.read(),
                'watch':{'running':watching,'desired':self.desired_watch,'assets':self.watch_assets,
                    'stopping':bool(watching and self.watch_stop.exists()),'started':self.watch_started,
                    'updated':self.watch_updated,'latest':self.watch_latest,'error_code':self.watch_error},
                'jobs':[dict(j) for j in reversed(self.jobs[-100:])],
                'inputs':[{k:j[k] for k in ('id','kind','status','created','finished','include_secrets')}
                    for j in reversed(self.jobs) if j['status']=='completed' and j['kind'] in ('backup','extract_assets')],
                'resources':{'private_bytes':memory,'free_bytes':shutil.disk_usage(self.runtime).free},
                'policy':{'local_only':True,'history_count_limit':None,'message_count_limit':None,
                    'originals_modified':False,'dedup_destructive':False,'phone_completeness':'unverified'}}

    def close(self):
        with self.guard:self.closing=True;self.desired_watch=False;self._request_watch_stop()
        self.wake.set();self.thread.join()  # current operation completes; never force kill


def create_app(coordinator,port,shutdown=None):
    token=secrets.token_urlsafe(32)
    hosts={f'127.0.0.1:{port}',f'localhost:{port}'}
    origins={'http://'+h for h in hosts}
    app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    web=Path(__file__).parent/'web'

    @app.middleware('http')
    async def boundary(request,call_next):
        if request.headers.get('host') not in hosts:return JSONResponse({'error':'invalid_host'},400)
        origin=request.headers.get('origin')
        if origin and origin not in origins:return JSONResponse({'error':'invalid_origin'},403)
        if request.method not in ('GET','HEAD'):
            if origin not in origins:return JSONResponse({'error':'origin_required'},403)
            if request.headers.get('content-type','').split(';')[0]!='application/json':return JSONResponse({'error':'json_required'},415)
            body=b''
            async for chunk in request.stream():
                body+=chunk
                if len(body)>16384:return JSONResponse({'error':'body_too_large'},413)
            request._body=body
        if request.url.path.startswith('/api/') and request.url.path!='/api/session':
            if request.cookies.get('capture_session')!=token or request.headers.get('x-capture-token')!=token:
                return JSONResponse({'error':'session_required'},403)
        try:response=await call_next(request)
        except Exception:return JSONResponse({'error':'internal_error_check_local_logs'},500)
        response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
            'Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        return response

    @app.get('/api/session')
    def session(request:Request):
        if request.headers.get('x-capture-bootstrap')!='1':raise HTTPException(403,'bootstrap required')
        response=JSONResponse({'token':token})
        response.set_cookie('capture_session',token,httponly=True,samesite='strict')
        return response

    @app.get('/api/status')
    def status():return coordinator.status()

    @app.post('/api/watch')
    async def watch(request:Request):
        try:
            payload=await request.json()
            if not isinstance(payload,dict) or set(payload)-{'enabled','assets'}:raise ValueError('invalid watch settings')
            coordinator.watch_control(payload.get('enabled'),payload.get('assets',False));return {'accepted':True}
        except (ValueError,TypeError):raise HTTPException(400,'invalid watch settings')

    @app.post('/api/jobs')
    async def jobs(request:Request):
        try:return coordinator.enqueue(await request.json())
        except (ValueError,TypeError,KeyError):raise HTTPException(400,'参数无效、资源不足或输入任务未完成，请检查后重试')

    @app.post('/api/jobs/{ident}/cancel')
    def cancel(ident:str):
        try:coordinator.cancel(ident);return {'cancelled':True}
        except ValueError:raise HTTPException(409,'只有排队中的任务可以取消')

    @app.post('/api/shutdown')
    async def stop_console(request:Request):
        payload=await request.json()
        if payload!={'acknowledge':True} or shutdown is None:raise HTTPException(400,'explicit shutdown confirmation required')
        with coordinator.guard:
            coordinator.closing=True;coordinator.desired_watch=False;coordinator._request_watch_stop()
        coordinator.wake.set()
        threading.Thread(target=shutdown,name='console-safe-shutdown',daemon=False).start()
        return {'accepted':True,'policy':'finish_current_job_then_exit'}

    @app.get('/health')
    def health():return {'service':'wechat-capture-v2-console','local_only':True}

    @app.get('/')
    def index():return FileResponse(web/'index.html')

    @app.get('/{asset}')
    def static(asset:str):
        if asset not in ('app.js','app.css','favicon.svg'):raise HTTPException(404)
        return FileResponse(web/asset)
    return app


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--port',type=int,default=0)
    parser.add_argument('--open-browser',action='store_true')
    args=parser.parse_args()
    args.state,args.runtime,_=checked_runtime(args.state,args.runtime)
    args.runtime.mkdir(parents=True,exist_ok=True)
    with writer_lock(args.runtime):
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.bind(('127.0.0.1',args.port));sock.listen(128)
        port=sock.getsockname()[1]
        coordinator=None
        try:
            coordinator=Coordinator(args.state,args.runtime)
            server=None
            def finish_then_exit():
                coordinator.thread.join()
                server.should_exit=True
            app=create_app(coordinator,port,finish_then_exit)
            ready={'url':f'http://127.0.0.1:{port}','pid':os.getpid(),'started':utcnow()}
            atomic_json(args.runtime/'console.private.json',ready)
            if args.open_browser:webbrowser.open(ready['url'])
            server=uvicorn.Server(uvicorn.Config(app,access_log=False,log_level='warning'))
            server.run(sockets=[sock])
        finally:
            if coordinator:coordinator.close()
            sock.close()


if __name__=='__main__':main()
