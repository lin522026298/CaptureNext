"""Retained raw originals, independent of message association and live keys.

Lists both captured history and externally retained WUA observations. Content
rows may share a SHA, but provenance and message identities are never merged.
Only explicit exports authenticate bytes; metadata listing makes no such claim.
"""
from contextlib import ExitStack,closing,contextmanager
import hashlib
import heapq
import itertools
import json
import os
import re
import sqlite3

from .console import _file,_name,_page
from .compact_archive import CompactArchive
from .file_media import _tables
from .paths import local_absolute
from .union_assets import _blocks

_SHA=re.compile('[0-9a-f]{64}')
EXAMPLES=8


def validate(params):
    if (not isinstance(params.get('sha'),str) or not _SHA.fullmatch(params['sha']) or
            params.get('view','current') not in ('current','restored')):
        raise ValueError('invalid retained original selection')
    _name(params.get('name'))


def _pagination(limit,offset):
    if type(limit) is not int or not 1<=limit<=200 or type(offset) is not int or not 0<=offset<=2**63-1:
        raise ValueError('invalid retained original page')


def _observations(archive,catalog,*,sha=None):
    """Ordered bounded-memory metadata streams; never read original bytes."""
    if sha is not None and (not isinstance(sha,str) or not _SHA.fullmatch(sha)):
        raise ValueError('invalid retained original hash')
    streams=[]
    for db,table,scope in _tables(archive,catalog):
        columns={r[1] for r in db.execute('PRAGMA table_info('+table+')')}
        fields=['file_sha','bytes','source_id','relative_path']
        fields.extend(k for k in ('observation_id','origin_id','source_table','cycle_id') if k in columns)
        cursor=db.execute('SELECT '+','.join(fields)+' FROM '+table+
            (' WHERE file_sha=?' if sha is not None else '')+' ORDER BY file_sha,source_id,relative_path'+
            (',observation_id' if 'observation_id' in columns else ',cycle_id' if 'cycle_id' in columns else ''),
            (sha,) if sha is not None else ())
        def stream(cursor=cursor,fields=fields,scope=scope,table=table):
            for record in cursor:
                item=dict(zip(fields,record))
                if (not isinstance(item['file_sha'],str) or not _SHA.fullmatch(item['file_sha']) or
                        type(item['bytes']) is not int or item['bytes']<0 or
                        any(not isinstance(item[k],str) or not item[k] for k in ('source_id','relative_path'))):
                    raise ValueError('invalid retained original metadata')
                yield dict(item,scope=scope,metadata_table=table)
        streams.append(stream())
    return heapq.merge(*streams,key=lambda row:(row['file_sha'],row['source_id'],row['relative_path']))


def listing(archive,catalog,objects,*,limit=50,offset=0):
    _pagination(limit,offset)
    rows=[];total=0
    for sha,group in itertools.groupby(_observations(archive,catalog),key=lambda item:item['file_sha']):
        size=None;count=0;examples=[]
        selected=offset<=total<offset+limit
        for evidence in group:
            if size is not None and evidence['bytes']!=size:
                raise ValueError('retained original lengths conflict')
            size=evidence['bytes'];count+=1
            if selected and len(examples)<EXAMPLES:examples.append(evidence)
        if selected:
            stored=objects.execute('SELECT bytes FROM file WHERE hash=?',(sha,)).fetchone()
            available=stored is not None and stored[0]==size
            first=examples[0]
            rows.append(dict(file_sha=sha,bytes=size,relative_path=first['relative_path'],source_id=first['source_id'],
                evidence=examples,evidence_count=count,evidence_examples_truncated=count>len(examples),
                evidence_query_id=sha,available_in_cas=available,
                status='retained_original' if available else 'file_missing',
                origin_link_confirmed=False,message_association='unknown',sha256_original_bytes_verified=False))
        total+=1
    return dict(rows=rows,total=total,next_offset=offset+len(rows) if offset+len(rows)<total else None,
        scope='all_retained_raw_original_metadata',message_association='unknown',
        content_rows_are_not_message_identities=True,contents_verified=False)


def evidence_page(archive,catalog,sha,*,limit=50,offset=0):
    _pagination(limit,offset)
    rows=[];total=0;size=None
    for item in _observations(archive,catalog,sha=sha):
        if size is not None and size!=item['bytes']:raise ValueError('retained original lengths conflict')
        size=item['bytes']
        if offset<=total<offset+limit:rows.append(item)
        total+=1
    return dict(file_sha=sha,rows=rows,total=total,next_offset=offset+len(rows) if offset+len(rows)<total else None,
        scope='retained_raw_original_provenance',origin_link_confirmed=False,message_association='unknown')


@contextmanager
def _view(core,view):
    if view not in ('current','restored'):raise ValueError('unknown original view')
    restored=view=='restored'
    if restored and core.offline_view is None:raise ValueError('open a completed offline copy first')
    if not restored and not getattr(core,'capture_capable',False):raise ValueError('offline original view required')
    state=core.offline_view.state if restored else core.state
    union=core.offline_view.union if restored else core.union_root
    with ExitStack() as stack:
        archive=stack.enter_context(CompactArchive(union/'archive.wua.sqlite',readonly=True,immutable=restored))
        archive._db.execute('BEGIN')
        databases=[]
        for name in ('catalog.sqlite','objects.sqlite'):
            path=local_absolute(state/name);_file(path)
            for suffix in ('-wal','-shm','-journal'):
                sidecar=path.with_name(path.name+suffix)
                if os.path.lexists(sidecar):_file(sidecar)
            db=stack.enter_context(closing(sqlite3.connect(path.as_uri()+'?mode=ro'+('&immutable=1' if restored else ''),uri=True)))
            db.execute('PRAGMA query_only=ON');db.execute('PRAGMA temp_store=MEMORY');db.execute('BEGIN')
            databases.append(db)
        yield archive,*databases,state,union


def read(core,query):
    limit,offset=_page(query)
    with _view(core,query.get('view',['current'])[0]) as (archive,catalog,objects,_,__):
        sha=query.get('id',[''])[0]
        if sha:return evidence_page(archive,catalog,sha,limit=limit,offset=offset)
        return listing(archive,catalog,objects,limit=limit,offset=offset)


def export(archive,catalog,objects,*,sha,destination,protected_roots):
    if not protected_roots:raise ValueError('explicit protected source roots required')
    target=local_absolute(destination)
    # Stored source boundaries are lexical: offline export must not connect or
    # probe a source drive simply to compare its already recorded paths.
    roots=[local_absolute(root,lexical=True) for root in protected_roots]
    for db in (archive._db,catalog,objects):
        for _,name,path in db.execute('PRAGMA database_list'):
            if name=='main' and path:roots.append(local_absolute(path).parent)
    if any(target==root or target.is_relative_to(root) for root in roots):
        raise ValueError('export overlaps protected archive, CAS, or source root')
    if not target.parent.is_dir():raise ValueError('explicit existing output directory required')
    page=evidence_page(archive,catalog,sha,limit=EXAMPLES)
    if not page['rows']:raise ValueError('object has no retained raw original provenance')
    size=page['rows'][0]['bytes']
    if objects.execute('SELECT 1 FROM file WHERE hash=?',(sha,)).fetchone() is None:
        raise FileNotFoundError('retained original is not in the bound CAS')
    created=None
    try:
        with target.open('xb') as stream:
            created=os.fstat(stream.fileno())
            if created.st_nlink!=1:raise ValueError('hardlinked output is outside export scope')
            for *_,block in _blocks(objects,sha,size):stream.write(block)
            stream.flush();os.fsync(stream.fileno())
        before=_file(local_absolute(target))
        if (before.st_dev,before.st_ino)!=(created.st_dev,created.st_ino):raise ValueError('export destination changed')
        digest=hashlib.sha256();length=0
        with target.open('rb') as stream:
            for block in iter(lambda:stream.read(1024**2),b''):
                digest.update(block);length+=len(block)
        after=_file(local_absolute(target))
        if (digest.hexdigest()!=sha or length!=size or
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)!=(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)):
            raise ValueError('export readback differs from authenticated original')
        return dict(status='completed',exported=True,destination=str(target),file_sha=sha,bytes=size,
            sha256_original_bytes_verified=True,export_readback_verified=True,raw_preserved=True,
            automatically_opened=False,origin_link_confirmed=False,message_association='unknown',
            evidence_count=page['total'],evidence=page['rows'],evidence_examples_truncated=page['total']>len(page['rows']))
    except BaseException:
        if created is not None:
            try:
                current=target.lstat()
                if (current.st_dev,current.st_ino,current.st_nlink)==(created.st_dev,created.st_ino,1):target.unlink()
            except FileNotFoundError:pass
        raise


def perform(core,params):
    validate(params)
    with core.reader_gate,_view(core,params.get('view','current')) as (archive,catalog,objects,state,union):
        config_path=local_absolute(state/'config.private.json');_file(config_path)
        config=json.loads(config_path.read_text(encoding='utf-8'))
        protected=[state,union]
        for key in ('database_root','asset_root'):
            if config.get(key):protected.append(local_absolute(config[key],lexical=True))
        if config.get('database_root'):protected.append(local_absolute(config['database_root'],lexical=True).parent)
        protected.extend(root for root in (core.state,core.union_root,core.repository_root,core.union_repository,
            getattr(core,'paired_repository',None)) if root is not None)
        return export(archive,catalog,objects,sha=params['sha'],destination=core.output_root/_name(params['name']),
            protected_roots=protected)
