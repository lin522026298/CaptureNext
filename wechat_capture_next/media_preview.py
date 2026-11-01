"""Bounded disposable derivatives; original CAS remains the only authority."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import psutil

from wechat_capture_v2.common import canonical,digest_file,write_json_new
from .backup import _file,_parents
from .union_assets import _blocks
from . import viewer_media

SCHEMA='next-media-preview-1'
CODEC='pilk-0.2.4-wave24k-1'
BUDGET=256*1024**2
MAX_WAV=100*1024**2
STAGE='next-media-decode-stage-1'


@dataclass(frozen=True)
class BinaryMedia:
    data:bytes
    content_type:str


def _cache(output,*,create=True):
    root=_parents(Path(output)/'media-preview')
    owner=dict(schema=SCHEMA)
    if root.exists():
        _file(root/'OWNER.private.json')
        if json.loads((root/'OWNER.private.json').read_text(encoding='utf-8'))!=owner:raise ValueError('foreign media preview directory')
    else:
        if not create:raise FileNotFoundError('media preview cache absent')
        root.mkdir();write_json_new(root/'OWNER.private.json',owner)
    return root


def _record(root,ident,*,pending=False):
    root=_parents(root)
    if not isinstance(ident,str) or not re.fullmatch('[0-9a-f]{64}',ident):raise ValueError('preview identity invalid')
    receipt=root/(ident+('.pending.private.json' if pending else '.private.json'));_file(receipt);record=json.loads(receipt.read_text(encoding='utf-8'))
    if set(record)!={'schema','artifact_id','raw_sha','codec','bytes','sha256','mime','audio'} or record['schema']!=SCHEMA or record['artifact_id']!=ident:
        raise ValueError('preview receipt invalid')
    if record['codec']!=CODEC or hashlib.sha256(canonical([CODEC,record['raw_sha']]).encode()).hexdigest()!=ident:
        raise ValueError('preview original binding differs')
    path=root/(ident+'.wav');_file(path)
    if path.stat().st_size!=record['bytes'] or digest_file(path)!=record['sha256']:raise ValueError('preview readback differs')
    return path,record


def _alive(pid,created):
    try:return psutil.Process(pid).create_time()==created
    except psutil.NoSuchProcess:return False
    except psutil.Error:raise ValueError('cannot verify media worker ownership')


def _recover(root,objects):
    """Only known, independently reconstructable derivatives are removable.

    No recursive deletion. Reject links and unknown files. A parent killed in
    the Popen/receipt gap gets a grace period before touching its own temporary
    data; a recorded live decoder is never collected.
    """
    from .state_guard import state_preflight
    from .union_assets import verify_published_object
    state_preflight(root);removed=0
    for folder in root.iterdir():
        if not folder.is_dir() or not folder.name.startswith('decode-'):continue
        marker=folder/'STAGE.private.json';_file(marker)
        owner=json.loads(marker.read_text(encoding='utf-8'))
        if (owner.get('schema')!=STAGE or not re.fullmatch('[0-9a-f]{64}',owner.get('raw_sha','')) or
            type(owner.get('bytes')) is not int or owner['bytes']<0 or type(owner.get('pid')) is not int or
            type(owner.get('created')) not in (int,float)):raise ValueError('foreign decode stage preserved')
        if _alive(owner['pid'],owner['created']):continue
        worker=owner.get('worker')
        if worker and _alive(worker['pid'],worker['created']):continue
        if not worker and time.time()-owner.get('stage_started',owner['created'])<120:continue
        allowed={'STAGE.private.json','input.silk','output.wav','output.wav.decode.pcm'}
        if any(not p.is_file() or p.name not in allowed for p in folder.iterdir()):raise ValueError('unknown decode stage entry preserved')
        verify_published_object(objects,owner['raw_sha'],owner['bytes'])
        for path in folder.iterdir():_file(path);path.unlink()
        folder.rmdir();removed+=1
    for pending in root.glob('*.pending.private.json'):
        ident=pending.name.removesuffix('.pending.private.json')
        # The pending receipt is published BEFORE the WAV rename. It either
        # completes authenticated publication, or can be safely regenerated.
        if (root/(ident+'.wav')).exists():
            _,record=_record(root,ident,pending=True)
            verify_published_object(objects,record['raw_sha'],objects.execute('SELECT bytes FROM file WHERE hash=?',(record['raw_sha'],)).fetchone()[0])
            final=root/(ident+'.private.json')
            if final.exists():
                if _record(root,ident)[1]!=record:raise ValueError('preview publication receipts conflict')
                pending.unlink()
            else:os.rename(pending,final)
        else:
            _file(pending);record=json.loads(pending.read_text(encoding='utf-8'))
            if record.get('schema')!=SCHEMA or record.get('artifact_id')!=ident:raise ValueError('unknown preview pending receipt')
            expected=hashlib.sha256(canonical([CODEC,record['raw_sha']]).encode()).hexdigest()
            if ident!=expected:raise ValueError('preview pending identity differs')
            row=objects.execute('SELECT bytes FROM file WHERE hash=?',(record['raw_sha'],)).fetchone()
            if row is None:raise ValueError('original missing; preserve pending preview')
            verify_published_object(objects,record['raw_sha'],row[0]);pending.unlink()
    return removed


def read(output,ident):
    if not isinstance(ident,str) or not re.fullmatch('[0-9a-f]{64}',ident):raise ValueError('preview identity invalid')
    root=_cache(output,create=False)
    path,record=_record(root,ident)
    if not 0<record['bytes']<=100*1024**2 or record['mime']!='audio/wav':raise ValueError('preview type or length unsupported')
    data=path.read_bytes()
    if len(data)!=record['bytes'] or hashlib.sha256(data).hexdigest()!=record['sha256']:raise ValueError('preview changed during serving')
    return BinaryMedia(data,record['mime'])


def _prune(root,keep,objects=None):
    root=_parents(root)
    from .state_guard import state_preflight
    state_preflight(root)
    entries=[];total=sum(path.stat().st_size for path in root.rglob('*') if path.is_file())
    for receipt in root.glob('*.private.json'):
        ident=receipt.name.removesuffix('.private.json')
        if not re.fullmatch('[0-9a-f]{64}',ident):continue
        path,record=_record(root,ident)
        entries.append((receipt.stat().st_mtime_ns,ident,path,receipt,record['bytes']))
    planned=[];remaining=total
    for _,ident,path,receipt,size in sorted(entries):
        if remaining<=BUDGET:break
        if ident==keep:continue
        planned.append((ident,path,receipt));remaining-=size+receipt.stat().st_size
    # Authenticate every eviction's current original before deleting any of
    # this batch. Derived receipts alone do not prove reconstructability.
    for ident,_,_ in planned:
        _,record=_record(root,ident)
        row=None if objects is None else objects.execute('SELECT bytes FROM file WHERE hash=?',(record['raw_sha'],)).fetchone()
        if row is None:raise ValueError('original unavailable; preserve derived previews; cache maintenance required')
        try:
            for _ in _blocks(objects,record['raw_sha'],row[0]):pass
        except Exception as exc:
            raise ValueError('original authentication failed; preserve derived previews; cache maintenance required') from exc
    removed=0
    for _,path,receipt in planned:
        total-=path.stat().st_size+receipt.stat().st_size;path.unlink();receipt.unlink();removed+=1
    return dict(cache_bytes=total,removed_derivatives=removed,budget_bytes=BUDGET,cleanup_pending=total>BUDGET,
        includes_pending_and_stage_bytes=True)


def prepare(archive,objects_db,output,*,logical_id,snapshot_id,locator):
    matches=[r for r in viewer_media.for_message(archive,logical_id)['rows']
        if r['snapshot_id']==snapshot_id and r['locator']==locator and r['status']=='linked']
    if not matches:raise ValueError('confirmed native voice association required')
    row=matches[0];raw_sha=row['file_sha'];root=_cache(output)
    recovered=_recover(root,objects_db)
    ident=hashlib.sha256(canonical([CODEC,raw_sha]).encode()).hexdigest()
    if (root/(ident+'.private.json')).exists():
        _,record=_record(root,ident)
        for _ in _blocks(objects_db,raw_sha,row['bytes']):pass
        cache=_prune(root,ident,objects_db)
        if cache['cleanup_pending']:raise ValueError('preview cache budget requires maintenance; original and derivatives preserved')
        return dict(status='ready',artifact_id=ident,reused=True,raw_sha=raw_sha,audio=record['audio'],
            raw_preserved=True,sha256_original_bytes_verified=True,cache=cache)
    if _prune(root,ident,objects_db)['cleanup_pending']:raise ValueError('preview cache contains pending/foreign data; original preserved')
    # All plaintext intermediates are private, unique and short-lived. Native
    # codec failure/timeout cannot crash the single capture process.
    with tempfile.TemporaryDirectory(prefix='decode-',dir=root) as temporary:
        temporary=Path(temporary);source=temporary/'input.silk';target=temporary/'output.wav'
        own=psutil.Process();stage=dict(schema=STAGE,raw_sha=raw_sha,bytes=row['bytes'],pid=own.pid,created=own.create_time(),stage_started=time.time())
        write_json_new(temporary/'STAGE.private.json',stage)
        with source.open('xb') as stream:
            for *_,block in _blocks(objects_db,raw_sha,row['bytes']):stream.write(block)
        command=([sys.executable,'--media-worker'] if getattr(sys,'frozen',False) else
                 [sys.executable,'-m','wechat_capture_next.media_decode'])
        with subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)) as worker:
            from .product_settings import atomic_json
            stage['worker']=dict(pid=worker.pid,created=psutil.Process(worker.pid).create_time())
            atomic_json(temporary/'STAGE.private.json',stage)
            try:stdout,stderr=worker.communicate(json.dumps(dict(source=str(source),target=str(target))),timeout=60)
            except BaseException:worker.kill();worker.wait();raise
            if worker.returncode:raise ValueError('saved voice cannot be decoded; original preserved')
        audio=json.loads(stdout)
        size=target.stat().st_size
        if not 0<size<=MAX_WAV:raise ValueError('decoded preview length unsupported')
        record=dict(schema=SCHEMA,artifact_id=ident,raw_sha=raw_sha,codec=CODEC,bytes=size,
            sha256=digest_file(target),mime='audio/wav',audio=audio)
        final=root/(ident+'.wav')
        pending=root/(ident+'.pending.private.json');write_json_new(pending,record)
        if final.exists():
            _file(final)
            if digest_file(final)!=record['sha256']:raise ValueError('unreceipted preview differs; preserved for diagnosis')
        else:os.rename(target,final)
        os.rename(pending,root/(ident+'.private.json'))
        _record(root,ident)
    # A failed post-publication prune preserves derivatives, not false success.
    # The preflight rejects further growth: at most one MAX_WAV plus its small
    # receipt can remain above BUDGET after this bounded decode attempt.
    cache=_prune(root,ident,objects_db)
    if cache['cleanup_pending']:raise ValueError('preview cache budget requires maintenance; original and derivatives preserved')
    return dict(status='ready',artifact_id=ident,reused=False,raw_sha=raw_sha,audio=audio,cache=cache,
        raw_preserved=True,sha256_original_bytes_verified=True)
