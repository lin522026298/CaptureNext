"""V2 atomic paired restore points with shared, authenticated map trees.

This repository NEVER adopts or collects v1 repositories. Both state and union
roots commit in one SQLite transaction. Map nodes are content addressed too;
small blocks do not imply a repeated multi-hundred-MB manifest per snapshot.
"""
from collections import OrderedDict
from contextlib import contextmanager,ExitStack
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import zlib

from wechat_capture_v2.common import canonical, stamp, utcnow, write_json_new
from . import backup as legacy
from .paths import local_absolute

SCHEMA='next-paired-tree-backup-2'
DATABASE='repository.sqlite'
FANOUT=32
DEFAULT_BLOCK=4096
DEFAULT_OBJECT_BLOCK=16384
MAX_BLOCK=1024*1024
ALLOWED_BLOCKS=(4096,16384,65536,1048576)


def require(value,message):
    if not value:raise ValueError(message)


def identifier(value):
    require(isinstance(value,str) and legacy._HASH.fullmatch(value),'invalid digest')
    return value


def file_name(value):
    require(isinstance(value,str),'invalid paired file name')
    if value.startswith('state/'):
        legacy._manifest_path(value[6:])
    else:
        require(value in ('union/archive.wua.sqlite','union/OWNER.private.json',
            'provenance/pre-evidence-catalog.sqlite.zst','provenance/legacy-bag-derived.tar.zst'),
            'file outside paired restore scope')
    return value


def location(path,owner=None,create=False):
    path=legacy._parents(path)
    if not path.exists():
        require(create and owner is not None,'paired repository does not exist')
        path.mkdir(parents=True,exist_ok=False)
        write_json_new(path/'OWNER.private.json',owner)
    legacy._file(path/'OWNER.private.json')
    actual=json.loads((path/'OWNER.private.json').read_text(encoding='utf-8'))
    require(set(actual)=={'schema','catalog_instance','union_id'} and actual['schema']==SCHEMA,
            'unknown paired repository owner')
    require(all(isinstance(actual[k],str) and actual[k] for k in ('catalog_instance','union_id')),'missing paired identity')
    require(owner is None or actual==owner,'foreign paired repository; adoption forbidden')
    for child in path.iterdir():
        legacy._file(child)
        require(child.name in ('OWNER.private.json',DATABASE,DATABASE+'-journal','repository.lock'),
                'unexpected paired repository entry')
    return path,actual


_TABLES={'meta','block','edge','snapshot','snapshot_file','generation','pin'}


def _schema(db):
    objects={(r[0],r[1]) for r in db.execute("SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
    require(objects=={(n,'table') for n in _TABLES}|{('edge_child','index')},
            'unsupported paired repository schema')
    columns=dict(meta=('key','value'),block=('hash','kind','bytes','data'),edge=('parent','ordinal','child'),
        snapshot=('id','manifest','verified_at'),snapshot_file=('snapshot_id','name','root'),
        generation=('seq','snapshot_id','accepted_at'),pin=('snapshot_id','created'))
    for name,expected in columns.items():
        require(tuple(r[1] for r in db.execute('PRAGMA table_info('+name+')'))==expected,
                'unsupported paired repository columns')


@contextmanager
def session(path,owner=None,create=False,readonly=False,fault=None):
    path,owner=location(path,owner,create)
    target=path/DATABASE
    if not target.exists():
        require(create and not readonly,'paired database missing')
        with target.open('xb'):pass
    legacy._file(target)
    if readonly:
        require(not (path/(DATABASE+'-journal')).exists(),'explicit writer recovery required')
        db=legacy._readonly(target,immutable=False);db.row_factory=sqlite3.Row
        try:
            require(dict(db.execute('SELECT key,value FROM meta'))==owner,'paired database identity differs')
            _schema(db)
            yield db,owner
        finally:db.close()
        return
    with legacy._repository_lock(path):
        legacy._single_database_journal(path/(DATABASE+'-journal'))
        db=sqlite3.connect(target.as_uri()+'?mode=rw',uri=True,timeout=0)
        db.row_factory=sqlite3.Row
        try:
            db.execute('PRAGMA foreign_keys=ON');db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA temp_store=MEMORY')
            empty=db.execute('SELECT 1 FROM sqlite_master LIMIT 1').fetchone() is None
            if empty:
                require(create and not readonly,'empty repository is not a published backup')
                db.execute('PRAGMA auto_vacuum=INCREMENTAL')
                db.executescript('''BEGIN IMMEDIATE;
                    CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                    CREATE TABLE block(hash TEXT PRIMARY KEY,kind TEXT NOT NULL,bytes INTEGER NOT NULL,data BLOB NOT NULL);
                    CREATE TABLE edge(parent TEXT NOT NULL REFERENCES block(hash),ordinal INTEGER NOT NULL,
                        child TEXT NOT NULL REFERENCES block(hash),PRIMARY KEY(parent,ordinal));
                    CREATE INDEX edge_child ON edge(child);
                    CREATE TABLE snapshot(id TEXT PRIMARY KEY,manifest TEXT NOT NULL,verified_at TEXT NOT NULL);
                    CREATE TABLE snapshot_file(snapshot_id TEXT NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
                        name TEXT NOT NULL,root TEXT NOT NULL REFERENCES block(hash),PRIMARY KEY(snapshot_id,name));
                    CREATE TABLE generation(seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        snapshot_id TEXT NOT NULL REFERENCES snapshot(id),accepted_at TEXT NOT NULL);
                    CREATE TABLE pin(snapshot_id TEXT PRIMARY KEY REFERENCES snapshot(id),created TEXT NOT NULL);
                ''')
                db.executemany('INSERT INTO meta VALUES(?,?)',owner.items())
                if fault:fault('schema_before_commit',db)
                db.commit()
            require(dict(db.execute('SELECT key,value FROM meta'))==owner,'paired database identity differs')
            _schema(db)
            require(db.execute('PRAGMA journal_mode').fetchone()[0]=='delete','unexpected journal mode')
            if readonly:db.execute('PRAGMA query_only=ON')
            yield db,owner
        finally:
            if db.in_transaction:db.rollback()
            db.close()


def _put(db,kind,raw,children=()):
    key=hashlib.sha256(kind.encode('ascii')+raw).hexdigest()
    exists=db.execute('SELECT kind,bytes FROM block WHERE hash=?',(key,)).fetchone()
    if exists:
        require(tuple(exists)==(kind,len(raw)),'CAS node collision')
        return key,False
    db.execute('INSERT INTO block VALUES(?,?,?,?)',(key,kind,len(raw),zlib.compress(raw,1)))
    if kind=='N':
        db.executemany('INSERT INTO edge VALUES(?,?,?)',((key,i,c[0]) for i,c in enumerate(children)))
    return key,True


class Blocks:
    def __init__(self,db):self.db=db;self.cache=OrderedDict();self.cached=0
    def get(self,key):
        identifier(key)
        if key in self.cache:
            result=self.cache.pop(key);self.cache[key]=result;return result
        row=self.db.execute('SELECT kind,bytes,data FROM block WHERE hash=?',(key,)).fetchone()
        require(row is not None,'missing paired block')
        kind,size,payload=row
        require(kind in ('D','N') and type(size) is int and 0<=size<=MAX_BLOCK,'invalid block shape')
        decoder=zlib.decompressobj()
        try:raw=decoder.decompress(payload,MAX_BLOCK+1)
        except zlib.error as error:raise ValueError('paired compression corrupt') from error
        require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and len(raw)==size and
                hashlib.sha256(kind.encode('ascii')+raw).hexdigest()==key,'paired block authentication failed')
        if kind=='N':
            node=json.loads(raw)
            require(set(node)=={'height','children'} and type(node['height']) is int and 1<=node['height']<=16 and
                    1<=len(node['children'])<=FANOUT,'invalid map node')
            for item in node['children']:
                require(isinstance(item,list) and len(item)==2 and type(item[1]) is int and item[1]>=0,'invalid map entry')
                identifier(item[0])
            edges=[(r[0],r[1]) for r in self.db.execute('SELECT ordinal,child FROM edge WHERE parent=? ORDER BY ordinal',(key,))]
            require(edges==[(i,c[0]) for i,c in enumerate(node['children'])],'map edge/payload mismatch')
        result=(kind,raw)
        self.cache[key]=result;self.cached+=len(raw)
        while self.cached>8*MAX_BLOCK:
            _,(_,old)=self.cache.popitem(last=False);self.cached-=len(old)
        return result
    def walk(self,key,height,expected):
        kind,raw=self.get(key)
        if height==0:
            require(kind=='D' and len(raw)==expected,'leaf shape mismatch')
            yield raw;return
        require(kind=='N','expected a map node')
        node=json.loads(raw)
        require(node['height']==height and sum(c[1] for c in node['children'])==expected,'map length/height mismatch')
        for child,size in node['children']:yield from self.walk(child,height-1,size)


def _leaf_size(name,block_bytes,object_block_bytes):
    require(block_bytes in ALLOWED_BLOCKS and object_block_bytes in ALLOWED_BLOCKS,'unsupported leaf size')
    if name=='state/objects.sqlite':return object_block_bytes
    return MAX_BLOCK if name.startswith('provenance/') else block_bytes


def _profile(context,object_block_bytes):
    require(object_block_bytes in ALLOWED_BLOCKS,'unsupported object leaf size')
    result=dict(context)
    if 'object_leaf_bytes' in result:
        require(result['object_leaf_bytes']==object_block_bytes,'object leaf profile conflicts with context')
    # Missing means the historical 1MiB profile. Explicit old-profile probes
    # must not create a new context field and turn a no-change into migration.
    if object_block_bytes!=MAX_BLOCK:result['object_leaf_bytes']=object_block_bytes
    return result


def rechunk(chunks,block_bytes):
    """Bounded stream repartitioning; no reconstructed whole-file temporary."""
    require(block_bytes in ALLOWED_BLOCKS,'unsupported leaf size')
    pending=bytearray()
    for chunk in chunks:
        view=memoryview(chunk);offset=0
        if pending:
            length=min(block_bytes-len(pending),len(view));pending.extend(view[:length]);offset=length
            if len(pending)==block_bytes:yield bytes(pending);pending.clear()
        while offset+block_bytes<=len(view):
            yield view[offset:offset+block_bytes];offset+=block_bytes
        if offset<len(view):pending.extend(view[offset:])
    if pending:yield bytes(pending)


def add_stream(db,chunks,block_bytes,*,expected=None):
    require(block_bytes in ALLOWED_BLOCKS,'unsupported leaf size')
    digest=hashlib.sha256();total=added=0;levels=[]
    def emit(height,key,size):
        nonlocal added
        while len(levels)<=height:levels.append([])
        levels[height].append([key,size])
        if len(levels[height])==FANOUT:
            children=levels[height];levels[height]=[]
            raw=canonical(dict(height=height+1,children=children)).encode()
            parent,new=_put(db,'N',raw,children);added+=new
            emit(height+1,parent,sum(c[1] for c in children))
    for block in rechunk(chunks,block_bytes):
        # _put hashes kind || bytes; keep this bounded even for memoryview slices.
        block=bytes(block)
        key,new=_put(db,'D',block);added+=new;digest.update(block);total+=len(block)
        emit(0,key,len(block))
    if not total:
        key,new=_put(db,'D',b'');added+=new;emit(0,key,0)
    height=0
    while True:
        if height>=len(levels):raise ValueError('tree finalization failed')
        children=levels[height]
        above=any(levels[height+1:])
        if children and len(children)==1 and not above:
            root=children[0][0];break
        if children:
            levels[height]=[];raw=canonical(dict(height=height+1,children=children)).encode()
            parent,new=_put(db,'N',raw,children);added+=new
            emit(height+1,parent,sum(c[1] for c in children))
        height+=1
    entry=dict(root=root,height=height,bytes=total,sha256=digest.hexdigest(),leaf_bytes=block_bytes)
    if expected is not None:
        require(entry['bytes']==expected['bytes'] and entry['sha256']==expected['sha256'],'reblocked original SHA/length differs')
    return entry,added


def add_file(db,path,block_bytes):
    before=stamp(path)
    with path.open('rb') as stream:
        result=add_stream(db,iter(lambda:stream.read(block_bytes),b''),block_bytes)
    require(stamp(path)==before,'source changed during paired snapshot')
    return result


def manifest(db,snapshot,owner):
    identifier(snapshot)
    row=db.execute('SELECT manifest FROM snapshot WHERE id=?',(snapshot,)).fetchone()
    require(row is not None,'paired snapshot missing')
    literal=row[0];value=json.loads(literal)
    require(canonical(value)==literal and hashlib.sha256(literal.encode()).hexdigest()==snapshot and
            set(value)=={'schema','owner','files','context'} and value['schema']==SCHEMA and value['owner']==owner,
            'paired manifest authentication failed')
    require(isinstance(value['files'],dict) and value['files'],'empty paired file map')
    require(len({n.casefold() for n in value['files']})==len(value['files']),'aliased paired file names')
    for name,entry in value['files'].items():
        file_name(name)
        require(set(entry)=={'root','height','bytes','sha256','leaf_bytes'} and type(entry['height']) is int and
                0<=entry['height']<=16 and type(entry['bytes']) is int and entry['bytes']>=0 and
                entry['leaf_bytes'] in ALLOWED_BLOCKS,'invalid file tree')
        identifier(entry['root']);identifier(entry['sha256'])
    refs={r[0]:r[1] for r in db.execute('SELECT name,root FROM snapshot_file WHERE snapshot_id=?',(snapshot,))}
    require(refs=={n:e['root'] for n,e in value['files'].items()},'paired root references differ')
    return value


def verify_files(db,value):
    blocks=Blocks(db);count=total=0
    for entry in value['files'].values():
        digest=hashlib.sha256();size=0
        for raw in blocks.walk(entry['root'],entry['height'],entry['bytes']):digest.update(raw);size+=len(raw)
        require(size==entry['bytes'] and digest.hexdigest()==entry['sha256'],'paired file content differs')
        count+=1;total+=size
    require(not list(db.execute('PRAGMA foreign_key_check')),'paired foreign key failure')
    return dict(files=count,bytes=total,verified=True)


def unchanged(repository,owner,files,scope,*,block_bytes=DEFAULT_BLOCK,object_block_bytes=DEFAULT_OBJECT_BLOCK,_memo=None):
    """Full-content proof reuse, never an mtime shortcut or a new snapshot.

    Caller keeps cold guards on ALL input files. Old semantic checks are reused
    only after exact input equality AND independent repository byte readback.
    """
    from .pair_readback_memo import PairReadbackMemo,_inventory
    if _memo is not None and not isinstance(_memo,PairReadbackMemo):raise TypeError('private paired readback memo required')
    # Non-Windows guards cannot deny concurrent raw writes. Keep the ordinary
    # full authentication path there; never silently export a Windows proof.
    if _memo is not None and os.name!='nt':_memo.reset();_memo=None
    def miss():
        if _memo is not None:_memo.reset()
        return None
    scope=_profile(scope,object_block_bytes)
    if not Path(repository).exists():return miss()
    from .union_archive import cold_input
    try:
        with ExitStack() as stack:
            names=_inventory(Path(repository)) if _memo is not None else (DATABASE,'OWNER.private.json')
            for name in names:stack.enter_context(cold_input(Path(repository)/name))
            if _memo is not None:require(_inventory(Path(repository))==names,'repository inventory changed before guard')
            db,_=stack.enter_context(session(repository,owner,readonly=True))
            db.execute('BEGIN')
            latest=db.execute('SELECT snapshot_id FROM generation ORDER BY seq DESC LIMIT 1').fetchone()
            if latest is None:return miss()
            value=manifest(db,latest[0],owner)
            if value['context'].get('object_leaf_bytes',MAX_BLOCK)!=object_block_bytes:return miss()
            if set(value['files'])!=set(files) or any(value['context'].get(k)!=v for k,v in scope.items()):return miss()
            hashed=0
            for name,path in sorted(files.items()):
                entry=value['files'][name];size=_leaf_size(name,block_bytes,object_block_bytes)
                if entry['leaf_bytes']!=size or path.stat().st_size!=entry['bytes']:return miss()
                if legacy.digest_file(path)!=entry['sha256']:return miss()
                hashed+=entry['bytes']
            bindings=dict(owner=owner,snapshot_id=latest[0],scope=scope,input_files=files,file_map=value['files'],
                profile=dict(block_bytes=block_bytes,object_leaf_bytes=object_block_bytes,
                    verification_profile=scope.get('verification_profile')))
            proof=_memo.lookup(Path(repository),**bindings) if _memo is not None else None
            reused=proof is not None
            if proof is None:
                proof=verify_files(db,value)
                if _memo is not None:_memo.remember_verified(Path(repository),verification=proof,**bindings)
            return dict(snapshot_id=latest[0],noop=True,new_blocks=0,verification=proof,
                reused_exact_authenticated_cut=True,hashed_input_bytes=hashed,
                semantic_verification_executed_now=False,repository_bytes_verified_now=True,
                repository_full_file_sha_executed_now=_memo is not None,
                repository_block_authentication_executed_now=not reused,
                reused_same_process_authenticated_repository_cut=reused,
                reuse_scope='exact_full_input_and_repository_file_hashes_private_process_proof' if reused else
                    'exact_full_input_hashes_and_authenticated_repository_readback')
    except BaseException:
        miss();raise


def publish(repository,owner,files,context,*,block_bytes=DEFAULT_BLOCK,object_block_bytes=DEFAULT_OBJECT_BLOCK,keep=2,fault=None):
    context=_profile(context,object_block_bytes)
    require(len({n.casefold() for n in files})==len(files),'aliased paired file names')
    for name,path in files.items():file_name(name);legacy._file(path)
    with session(repository,owner,create=True,fault=fault) as (db,owner):
        db.execute('BEGIN IMMEDIATE');entries={};added=0
        for name,path in sorted(files.items()):
            # SQLite object metadata can change inside otherwise immutable CAS.
            # Objects use independent 16KiB leaves; provenance stays at 1MiB.
            size=_leaf_size(name,block_bytes,object_block_bytes)
            entry,new=add_file(db,path,size);entries[name]=entry;added+=new
        value=dict(schema=SCHEMA,owner=owner,files=entries,context=context)
        literal=canonical(value);identity=hashlib.sha256(literal.encode()).hexdigest()
        if fault:fault('before_verify',db)
        proof=verify_files(db,value)  # Always, including non-Windows and new blocks.
        latest=db.execute('SELECT snapshot_id FROM generation ORDER BY seq DESC LIMIT 1').fetchone()
        if latest and latest[0]==identity:
            db.rollback();return dict(snapshot_id=identity,noop=True,new_blocks=0,verification=proof)
        if not db.execute('SELECT 1 FROM snapshot WHERE id=?',(identity,)).fetchone():
            db.execute('INSERT INTO snapshot VALUES(?,?,?)',(identity,literal,utcnow()))
            db.executemany('INSERT INTO snapshot_file VALUES(?,?,?)',((identity,n,e['root']) for n,e in entries.items()))
        manifest(db,identity,owner)
        db.execute('INSERT INTO generation(snapshot_id,accepted_at) VALUES(?,?)',(identity,utcnow()))
        # Only this transaction's fully read-back new pair grants acceptance.
        # Keep large retired payloads OUT of its rollback journal: collection
        # starts after this durable commit, under the same repository lock.
        if fault:fault('before_commit',db)
        db.commit()
        # Acceptance is durable. Persist the collection-stage boundary before
        # any post-commit callback/authentication can fail or be interrupted.
        if fault:fault('collection_start',db)
        if fault:fault('after_commit',db)
        from .pair_collection import cleanup
        # Acceptance is already durable; retain this same writer session and
        # bounded transactions, allowing useful collection instead of 5s churn.
        # 300s is a between-batch work budget, NOT an end-to-end timeout.
        governance=cleanup(db,owner,Path(repository),keep=keep,seconds=300,fault=fault)
        return dict(snapshot_id=identity,noop=False,new_blocks=added,verification=proof,
                    manifest_bytes=len(literal.encode()),files=entries,governance=governance)


def snapshots(repository):
    with session(repository,readonly=True) as (db,owner):
        db.execute('BEGIN');rows=[]
        for row in db.execute('''SELECT s.id,s.verified_at,max(g.seq) seq,p.snapshot_id IS NOT NULL pinned
            FROM snapshot s LEFT JOIN generation g ON g.snapshot_id=s.id LEFT JOIN pin p ON p.snapshot_id=s.id
            GROUP BY s.id ORDER BY coalesce(max(g.seq),0) DESC,s.verified_at DESC'''):
            value=manifest(db,row[0],owner)
            names=set(value['files'])
            rows.append(dict(snapshot_id=row[0],verified_at=row[1],sequence=row[2],pinned=bool(row[3]),
                bytes=sum(e['bytes'] for e in value['files'].values()),format=SCHEMA,
                includes_secrets='state/'+legacy.SECRETS in names,
                provenance_included={'provenance/pre-evidence-catalog.sqlite.zst',
                    'provenance/legacy-bag-derived.tar.zst'}.issubset(names),
                materials_scope='manifest_file_members_only_not_payload_or_live_source_verification'))
        return rows


def pin(repository,snapshot,enabled):
    require(type(enabled) is bool,'pin must be boolean')
    with session(repository) as (db,owner):
        db.execute('BEGIN IMMEDIATE');manifest(db,snapshot,owner)
        if enabled:db.execute('INSERT OR IGNORE INTO pin VALUES(?,?)',(snapshot,utcnow()))
        else:db.execute('DELETE FROM pin WHERE snapshot_id=?',(snapshot,))
        db.commit()
    return dict(snapshot_id=snapshot,pinned=enabled)


def _govern_transaction(db,owner,keep,fault=None):
    require(type(keep) is int and keep>=2,'keep at least two successful generations')
    for row in db.execute('SELECT id FROM snapshot'):manifest(db,row[0],owner)
    require(not list(db.execute('PRAGMA foreign_key_check')),'cannot govern a broken repository')
    db.execute('DELETE FROM generation WHERE seq NOT IN (SELECT seq FROM generation ORDER BY seq DESC LIMIT ?)',(keep,))
    victims=[r[0] for r in db.execute('''SELECT id FROM snapshot WHERE id NOT IN
        (SELECT snapshot_id FROM generation UNION SELECT snapshot_id FROM pin)''')]
    db.executemany('DELETE FROM snapshot WHERE id=?',((s,) for s in victims))
    db.execute('CREATE TEMP TABLE IF NOT EXISTS gc_live(hash TEXT PRIMARY KEY,height INTEGER,bytes INTEGER) WITHOUT ROWID')
    db.execute('DELETE FROM gc_live')
    # Old/pinned trees are not covered by the new pair's leaf-byte proof. The
    # authenticated map payload, never an unchecked mutable edge table, is the
    # authority for reachability. A missing/extra edge must fail before deleting.
    require(db.execute("SELECT 1 FROM edge e JOIN block b ON b.hash=e.parent WHERE b.kind!='N' LIMIT 1").fetchone() is None,
            'data leaf has unexpected graph edges')
    maps=Blocks(db)
    def mark(key,height,size):
        previous=db.execute('SELECT height,bytes FROM gc_live WHERE hash=?',(key,)).fetchone()
        if previous is not None:
            require(tuple(previous)==(height,size),'inconsistent shared tree shape')
            return
        db.execute('INSERT INTO gc_live VALUES(?,?,?)',(key,height,size))
        if height:
            kind,raw=maps.get(key)
            require(kind=='N','expected authenticated map for GC')
            node=json.loads(raw)
            require(node['height']==height and sum(c[1] for c in node['children'])==size,
                    'GC map length/height differs')
            for child,length in node['children']:mark(child,height-1,length)
    # Manifest heights, not mutable SQL kind/edge fields, determine traversal.
    # Reading every old data byte is unnecessary to protect its reachability:
    # authenticated maps already supply its hash; leaf shape is checked below.
    for row in db.execute('SELECT id FROM snapshot').fetchall():
        for entry in manifest(db,row[0],owner)['files'].values():
            mark(entry['root'],entry['height'],entry['bytes'])
    require(db.execute('''SELECT 1 FROM gc_live l LEFT JOIN block b ON b.hash=l.hash
        WHERE b.hash IS NULL OR (l.height=0 AND (b.kind!='D' OR b.bytes!=l.bytes)) LIMIT 1''').fetchone() is None,
        'missing or invalid retained leaf')
    dead=db.execute('SELECT coalesce(sum(length(data)),0),count(*) FROM block WHERE hash NOT IN (SELECT hash FROM gc_live)').fetchone()
    db.execute('DELETE FROM edge WHERE parent NOT IN (SELECT hash FROM gc_live)')
    db.execute('DELETE FROM block WHERE hash NOT IN (SELECT hash FROM gc_live)')
    if fault:fault('before_gc_commit',db)
    require(not list(db.execute('PRAGMA foreign_key_check')),'GC broke a paired dependency')
    return dict(expired_snapshots=victims,deleted_payload_bytes=dead[0],deleted_blocks=dead[1],legacy_repositories_touched=False)


def _reclaim(db,path,*,page_budget=8192,seconds=2.0):
    before=(path/DATABASE).stat().st_size
    free=db.execute('PRAGMA freelist_count').fetchone()[0]
    try:
        if free:
            # Connection-local, nonpersistent pager-cache hint, not preallocation
            # or a process-memory cap. Keep it across maintenance batches; the
            # owning session's explicit finally/close releases it on every exit.
            db.execute('PRAGMA cache_size=-131072')
        db.execute('BEGIN IMMEDIATE');remaining=free;deadline=time.monotonic()+seconds
        while remaining and free-remaining<page_budget and time.monotonic()<deadline:
            db.execute('PRAGMA incremental_vacuum(1024)').fetchall()
            current=db.execute('PRAGMA freelist_count').fetchone()[0]
            require(current<remaining,'incremental reclaim made no progress')
            remaining=current
        db.commit()
        return dict(freelist_pages_before=free,freelist_pages_after=remaining,
                    file_bytes_reclaimed=max(0,before-(path/DATABASE).stat().st_size),
                    repository_bytes=(path/DATABASE).stat().st_size,cleanup_pending=remaining>0)
    except (sqlite3.Error,ValueError) as error:
        if db.in_transaction:db.rollback()
        return dict(cleanup_pending=True,cleanup_error=type(error).__name__,repository_bytes=(path/DATABASE).stat().st_size)


def govern(repository,*,keep=2,seconds=5.0,fault=None):
    path=local_absolute(repository)
    with session(path) as (db,owner):
        db.execute('BEGIN IMMEDIATE')
        latest=db.execute('SELECT snapshot_id FROM generation ORDER BY seq DESC LIMIT 1').fetchone()
        require(latest is not None,'no successfully accepted pair')
        verify_files(db,manifest(db,latest[0],owner))
        db.commit()
        from .pair_collection import cleanup
        result=cleanup(db,owner,path,keep=keep,seconds=seconds,fault=fault)
    return result


def maintenance_pending(repository):
    """Read-only metadata hint; not a replacement for file authentication."""
    from .pair_collection import pending
    with session(repository,readonly=True) as (db,_):
        db.execute('BEGIN')
        return pending(db)


def restore_files(repository,snapshot,output):
    output=legacy._parents(output);repo=legacy._parents(repository)
    require(not output.exists() and not legacy._overlap(output,repo),'fresh independent target required')
    with session(repo,readonly=True) as (db,owner):
        db.execute('BEGIN');value=manifest(db,snapshot,owner);blocks=Blocks(db)
        for root in value['context'].get('protected_roots',[]):
            require(not legacy._overlap(output,legacy._external_root(root)),'restore overlaps protected original')
        parent=output.parent
        while not parent.exists():parent=parent.parent
        import shutil
        require(shutil.disk_usage(parent).free>=sum(e['bytes'] for e in value['files'].values())+legacy.RESTORE_MARGIN_BYTES,
                'insufficient complete restore space')
        output.mkdir(parents=True,exist_ok=False)
        write_json_new(output/'DELIVERY.partial.private.json',dict(schema=SCHEMA,snapshot_id=snapshot,status='partial'))
        if 'state/config.private.json' in value['files']:
            (output/'state').mkdir()
            write_json_new(output/'state/RESTORE.partial.private.json',dict(schema=SCHEMA,snapshot_id=snapshot,status='partial'))
        for name,entry in value['files'].items():
            path=output/file_name(name);path.parent.mkdir(parents=True,exist_ok=True)
            digest=hashlib.sha256();size=0
            with path.open('xb') as stream:
                for raw in blocks.walk(entry['root'],entry['height'],entry['bytes']):
                    stream.write(raw);digest.update(raw);size+=len(raw)
                stream.flush();os.fsync(stream.fileno())
            require(size==entry['bytes'] and digest.hexdigest()==entry['sha256'] and
                    legacy.digest_file(path)==entry['sha256'],'restore readback failed')
        return value
