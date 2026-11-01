"""Evidence-backed native voice observations in the existing shared CAS.

No contact-name identity inference, timestamp proximity, or network requests.
Raw unknown fields and SQLite types are retained. Matching is a read-only
projection so subsequently imported message observations need no relinking.
"""
from contextlib import closing
from datetime import datetime,timezone
import hashlib
import json
import re
import uuid

from wechat_capture_v2.common import canonical,digest_file,encoded,decoded
from .backup import _file
from .cas_stream import publish
from .union_archive import cold_input,cold_reader
from .union_assets import _bind,verify_published_object

SCHEMA='next-viewer-media-1'


def validate_request(params):
    if (not isinstance(params.get('logical_id'),str) or not 1<=len(params['logical_id'])<=200 or
        not isinstance(params.get('snapshot_id'),str) or not re.fullmatch('media_[0-9a-f]{64}',params['snapshot_id']) or
        type(params.get('locator')) is not int or not -(2**63)<=params['locator']<2**63 or
        params.get('view','current') not in ('current','restored')):raise ValueError('invalid media selection')


def _quote(value):return '"'+value.replace('"','""')+'"'


def _extension(archive,cas_id):
    db=archive._db
    row=db.execute("SELECT value FROM archive_meta WHERE key='next_viewer_media_schema'").fetchone()
    if row:
        if row[0]!=SCHEMA:raise ValueError('unsupported media evidence schema')
        if db.execute("SELECT value FROM archive_meta WHERE key='next_viewer_media_cas'").fetchone()[0]!=cas_id:
            raise ValueError('media CAS binding differs')
        return
    for sql in (
        '''CREATE TABLE next_media_snapshot(snapshot_id TEXT PRIMARY KEY,source_id TEXT NOT NULL,
            account_alias TEXT NOT NULL,relative_path TEXT NOT NULL,db_sha TEXT NOT NULL,capture_id TEXT NOT NULL,
            evidence_id INTEGER NOT NULL REFERENCES content_payload(id),schema_id INTEGER NOT NULL REFERENCES content_payload(id),
            row_counts_id INTEGER NOT NULL REFERENCES content_payload(id),
            status TEXT NOT NULL CHECK(status IN ('pending','active')))''',
        '''CREATE TABLE next_media_row(snapshot_id TEXT NOT NULL REFERENCES next_media_snapshot(snapshot_id),
            table_name TEXT NOT NULL,locator INTEGER NOT NULL,row_sha TEXT NOT NULL,
            payload_id INTEGER NOT NULL REFERENCES content_payload(id),PRIMARY KEY(snapshot_id,table_name,locator))''',
        '''CREATE TABLE next_media_voice(snapshot_id TEXT NOT NULL,locator INTEGER NOT NULL,
            conversation_id TEXT,server_id TEXT,create_time INTEGER,file_sha TEXT,bytes INTEGER,
            PRIMARY KEY(snapshot_id,locator),FOREIGN KEY(snapshot_id,locator) REFERENCES next_media_voice_key(snapshot_id,locator))''',
        # A stable parent key also makes malformed/missing raw voice rows visible
        # to the independent verifier; no synthetic asset acquisition cycle.
        '''CREATE TABLE next_media_voice_key(snapshot_id TEXT NOT NULL,locator INTEGER NOT NULL,
            PRIMARY KEY(snapshot_id,locator))''',
        'CREATE INDEX next_media_voice_lookup ON next_media_voice(conversation_id,server_id)',
    ):db.execute(sql)
    union=db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()
    if union is None:raise ValueError('formal union identity required for media ownership')
    owner=uuid.uuid5(uuid.NAMESPACE_URL,'capture-next-media:'+union[0]).hex
    db.executemany('INSERT INTO archive_meta VALUES(?,?)',[
        ('next_viewer_media_schema',SCHEMA),('next_viewer_media_cas',cas_id),('next_viewer_media_owner',owner)])


def _pin(service,archive,sha,size,cas_id):
    owner=archive._db.execute("SELECT value FROM archive_meta WHERE key='next_viewer_media_owner'").fetchone()[0]
    db=service.catalog.db
    with db:
        db.execute('''CREATE TABLE IF NOT EXISTS external_asset_owner(owner_id TEXT PRIMARY KEY,cas_id TEXT NOT NULL,schema TEXT NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS external_asset_ref(owner_id TEXT NOT NULL,file_sha TEXT NOT NULL,
            bytes INTEGER NOT NULL,cas_id TEXT NOT NULL,PRIMARY KEY(owner_id,file_sha),
            FOREIGN KEY(owner_id) REFERENCES external_asset_owner(owner_id))''')
        expected=(owner,cas_id,SCHEMA)
        old=db.execute('SELECT owner_id,cas_id,schema FROM external_asset_owner WHERE owner_id=?',(owner,)).fetchone()
        if old is not None and tuple(old)!=expected:raise ValueError('media owner differs')
        db.execute('INSERT OR IGNORE INTO external_asset_owner VALUES(?,?,?)',expected)
        old=db.execute('SELECT bytes,cas_id FROM external_asset_ref WHERE owner_id=? AND file_sha=?',(owner,sha)).fetchone()
        if old is not None and tuple(old)!=(size,cas_id):raise ValueError('media pin differs')
        db.execute('INSERT OR IGNORE INTO external_asset_ref VALUES(?,?,?,?)',(owner,sha,size,cas_id))


def _rows(view,table,service,archive,cas_id):
    columns=[r[1] for r in view.execute('PRAGMA table_info('+_quote(table)+')')]
    if not columns or any(c.lower() in ('rowid','oid','_rowid_') for c in columns):
        raise ValueError('native rowid shadow or missing table')
    select=','.join('CASE WHEN typeof('+_quote(c)+")='blob' THEN NULL ELSE "+_quote(c)+' END' for c in columns)
    kinds=','.join('typeof('+_quote(c)+')' for c in columns)
    for row in view.execute('SELECT _rowid_,'+select+','+kinds+' FROM '+_quote(table)+' ORDER BY _rowid_'):
        locator=row[0];manifest=[];values={}
        for i,name in enumerate(columns):
            value=row[1+i]
            if row[1+len(columns)+i]=='blob':
                with view.blobopen(table,name,locator,readonly=True) as blob:
                    obj=publish(service.objects,blob,len(blob))
                _pin(service,archive,obj['sha256'],obj['bytes'],cas_id)
                value=['cas_blob',obj['sha256'],obj['bytes']]
                manifest.append([name,value]);values[name]=value
            else:manifest.append([name,encoded(value)]);values[name]=value
        yield locator,canonical(manifest),values


def _decode(text):
    raw={}
    for name,value in json.loads(text):
        if name in raw:raise ValueError('duplicate native media field')
        if value[0]=='cas_blob':
            if len(value)!=3 or not re.fullmatch('[0-9a-f]{64}',value[1]) or type(value[2]) is not int or value[2]<0:
                raise ValueError('invalid native media CAS reference')
            raw[name]=value
        else:raw[name]=decoded(value)
    return raw


def _projection(raw,names):
    blob=raw.get('voice_data');blob=blob if isinstance(blob,list) and blob[0]=='cas_blob' else None
    chat_id=raw.get('chat_name_id');chat=names.get(chat_id) if type(chat_id) is int else None
    server=raw.get('svr_id');created=raw.get('create_time')
    return (chat if isinstance(chat,str) and chat else None,
            str(server) if type(server) is int and server!=0 else None,
            created if type(created) is int else None,blob[1] if blob else None,blob[2] if blob else None)


def import_voice(archive,service,*,source_id,account_alias,relative,capture_id,evidence,path,fault=None):
    if not re.fullmatch(r'message/media_\d+\.db',relative):raise ValueError('unsupported native media path')
    cas_id,_=_bind(archive,service);expected=evidence['plaintext']['sha256']
    identity='media_'+hashlib.sha256(canonical([SCHEMA,source_id,account_alias,relative,expected]).encode()).hexdigest()
    with archive.transaction():_extension(archive,cas_id)
    old=archive._db.execute('SELECT status FROM next_media_snapshot WHERE snapshot_id=?',(identity,)).fetchone()
    if old and old[0]=='active':return dict(noop=True,rows_added=0,snapshot_id=identity)
    _file(path)
    with cold_input(path),closing(cold_reader(path)) as view:
        if digest_file(path)!=expected:raise ValueError('media cache differs from accepted cut')
        shapes={table:[r[1] for r in view.execute('PRAGMA table_info('+table+')')] for table in ('Name2Id','VoiceInfo')}
        if not {'chat_name_id','svr_id','create_time','voice_data'}.issubset(shapes['VoiceInfo']) or 'user_name' not in shapes['Name2Id']:
            raise ValueError('unsupported native voice profile')
        schema={table:view.execute("SELECT sql FROM sqlite_master WHERE name=? AND type='table'",(table,)).fetchone()[0] for table in shapes}
        counts={table:view.execute('SELECT count(*) FROM '+table).fetchone()[0] for table in shapes}
        with archive.transaction():
            archive._db.execute('INSERT OR IGNORE INTO next_media_snapshot VALUES(?,?,?,?,?,?,?,?,?,?)',
                (identity,source_id,account_alias,relative,expected,capture_id,
                 archive.pool.intern_json(canonical(evidence)),archive.pool.intern_json(canonical(schema)),archive.pool.intern_json(canonical(counts)),'pending'))
        if fault:fault('after_pending')
        names={};added=0
        # Commit raw rows only after CAS target readback and catalog pins. A
        # crash leaves a visible pending receipt and replay resumes idempotently.
        for table in ('Name2Id','VoiceInfo'):
            for locator,text,raw in _rows(view,table,service,archive,cas_id):
                sha=hashlib.sha256(text.encode()).hexdigest()
                with archive.transaction():
                    old=archive._db.execute('SELECT row_sha FROM next_media_row WHERE snapshot_id=? AND table_name=? AND locator=?',(identity,table,locator)).fetchone()
                    if old and old[0]!=sha:raise ValueError('immutable native media row differs')
                    if old is None:
                        archive._db.execute('INSERT INTO next_media_row VALUES(?,?,?,?,?)',(identity,table,locator,sha,archive.pool.intern_json(text)));added+=1
                    if table=='Name2Id':names[locator]=raw.get('user_name')
                    else:
                        archive._db.execute('INSERT OR IGNORE INTO next_media_voice_key VALUES(?,?)',(identity,locator))
                        archive._db.execute('INSERT OR IGNORE INTO next_media_voice VALUES(?,?,?,?,?,?,?)',(identity,locator,*_projection(raw,names)))
                if fault:fault('after_row')
        if digest_file(path)!=expected:raise ValueError('accepted native media changed during import')
        with archive.transaction():archive._db.execute("UPDATE next_media_snapshot SET status='active' WHERE snapshot_id=?",(identity,))
    return dict(noop=False,rows_added=added,snapshot_id=identity,scope='native_voice_only',other_media_association='not_indexed')


def _exists(archive):
    return archive._db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='next_media_snapshot'").fetchone() is not None


def sync(service,union):
    from .compact_archive import CompactArchive
    from .state_guard import writer_lock
    results=[]
    rows=list(service.catalog.db.execute('''SELECT c.relative_path,d.id,d.evidence_json FROM checkpoint c
        JOIN db_capture d ON d.id=c.capture_id WHERE c.source_id=?''',(service.config['source_id'],)))
    with writer_lock(union),CompactArchive(union/'archive.wua.sqlite') as archive:
        from .media_pending import resume,clear_completed
        results.extend(resume(archive,service))
        for relative,capture_id,evidence in rows:
            if re.fullmatch(r'message/media_\d+\.db',relative):
                result=import_voice(archive,service,source_id=service.config['source_id'],account_alias=service.config['account_alias'],
                    relative=relative,capture_id=capture_id,evidence=json.loads(evidence),path=service.view_path(relative))
                results.append(result)
                clear_completed(archive,service,result['snapshot_id'])
    return dict(status='completed' if results else 'source_unavailable',native_voice_snapshots=len(results),
        rows_added=sum(r['rows_added'] for r in results),scope='native_voice_only',other_media='association_not_indexed',
        decode_status='on_demand_not_all_decoded')


def _epoch(value):
    try:
        value=datetime.fromisoformat(value.replace('Z','+00:00'))
        return int(value.timestamp()) if value.tzinfo is not None else None
    except (ValueError,TypeError,AttributeError,OverflowError):return None


def for_message(archive,logical_id):
    if not _exists(archive):return dict(status='association_unknown',rows=[],scope='native_voice_not_indexed')
    observations=archive._db.execute('''SELECT o.*,s.source_id FROM message_link l JOIN observation_record o
        ON o.observation_id=l.observation_id JOIN source_snapshot s ON s.snapshot_id=o.snapshot_id WHERE l.logical_id=?''',(logical_id,))
    result=[];seen=set()
    for obs in observations:
        try:voice=int(obs['message_type'])&4294967295==34
        except (ValueError,TypeError):voice=False
        if not voice or not obs['server_id'] or str(obs['server_id'])=='0':continue
        for row in archive._db.execute('''SELECT v.*,s.source_id,s.account_alias,s.relative_path,s.db_sha FROM next_media_voice v
            JOIN next_media_snapshot s ON s.snapshot_id=v.snapshot_id WHERE s.status='active' AND s.source_id=? AND s.account_alias=?
            AND v.conversation_id=? AND v.server_id=?''',(obs['source_id'],obs['account_alias'],obs['conversation_id'],str(obs['server_id']))):
            key=(row['snapshot_id'],row['locator'],obs['observation_id'])
            if key in seen:continue
            seen.add(key)
            matches={r[0] for r in archive._db.execute('''SELECT DISTINCT l.logical_id FROM observation_record o
                JOIN source_snapshot s ON s.snapshot_id=o.snapshot_id JOIN message_link l ON l.observation_id=o.observation_id
                WHERE s.source_id=? AND o.account_alias=? AND o.conversation_id=? AND o.server_id=?
                AND (CAST(o.message_type AS INTEGER)&4294967295)=34''',
                (row['source_id'],row['account_alias'],row['conversation_id'],row['server_id']))}
            linked=matches=={logical_id} and _epoch(obs['event_time'])==row['create_time'] and row['create_time'] is not None
            variants={r[0] for r in archive._db.execute('''SELECT DISTINCT v.file_sha FROM next_media_voice v
                JOIN next_media_snapshot s ON s.snapshot_id=v.snapshot_id WHERE s.status='active'
                AND s.source_id=? AND s.account_alias=? AND v.conversation_id=? AND v.server_id=? AND v.file_sha IS NOT NULL''',
                (row['source_id'],row['account_alias'],row['conversation_id'],row['server_id']))}
            conflict=len(variants)>1
            linked=linked and not conflict
            item=dict(row);item.update(observation_id=obs['observation_id'],status='linked' if linked and row['file_sha'] else 'candidate',
                reason='native_content_conflict_all_observations_retained' if conflict else 'same_source_account_native_dictionary_server_id_type_and_time' if linked else 'native_id_match_requires_review',
                native_content_conflict=conflict,native_distinct_contents=len(variants),
                original_status='saved_undecoded' if row['file_sha'] else 'original_missing',kind='voice',
                evidence_is_not_duplicate_message_identity=True)
            result.append(item)
    return dict(status='linked' if any(r['status']=='linked' for r in result) else 'candidate' if result else 'association_unknown',
        rows=result,scope='retained_native_voice_observations',other_media_association='not_indexed')


def verify(archive,service,*,deep=True,object_proof=None):
    if not _exists(archive):return dict(status='not_indexed',rows_verified=0)
    cas_id,_=_bind(archive,service)
    meta=dict(archive._db.execute("SELECT key,value FROM archive_meta WHERE key LIKE 'next_viewer_media_%'"))
    if meta.get('next_viewer_media_schema')!=SCHEMA or meta.get('next_viewer_media_cas')!=cas_id:
        raise ValueError('media store identity differs')
    owner=meta['next_viewer_media_owner'];db=archive._db;references={};count=0
    for snap in db.execute('SELECT * FROM next_media_snapshot'):
        if snap['status']!='active':raise ValueError('native media import pending; retry required')
        expected='media_'+hashlib.sha256(canonical([SCHEMA,snap['source_id'],snap['account_alias'],snap['relative_path'],snap['db_sha']]).encode()).hexdigest()
        evidence=json.loads(archive.pool.get_text(snap['evidence_id']));json.loads(archive.pool.get_text(snap['schema_id']))
        counts=json.loads(archive.pool.get_text(snap['row_counts_id']))
        if set(counts)!={'Name2Id','VoiceInfo'} or any(type(v) is not int or v<0 for v in counts.values()):raise ValueError('native media row count receipt differs')
        if snap['snapshot_id']!=expected or evidence['plaintext']['sha256']!=snap['db_sha']:raise ValueError('media snapshot differs')
        names={};voice_rows=set()
        for table in ('Name2Id','VoiceInfo'):
            if db.execute('SELECT count(*) FROM next_media_row WHERE snapshot_id=? AND table_name=?',(snap['snapshot_id'],table)).fetchone()[0]!=counts[table]:
                raise ValueError('native media raw row coverage differs')
            for row in db.execute('SELECT * FROM next_media_row WHERE snapshot_id=? AND table_name=? ORDER BY locator',(snap['snapshot_id'],table)):
                text=archive.pool.get_text(row['payload_id']);raw=_decode(text)
                if hashlib.sha256(text.encode()).hexdigest()!=row['row_sha']:raise ValueError('media raw row digest differs')
                for value in raw.values():
                    if isinstance(value,list) and value[0]=='cas_blob':
                        old=references.setdefault(value[1],value[2])
                        if old!=value[2]:raise ValueError('media BLOB size conflict')
                if table=='Name2Id':names[row['locator']]=raw.get('user_name')
                else:
                    voice_rows.add(row['locator'])
                    projected=db.execute('SELECT conversation_id,server_id,create_time,file_sha,bytes FROM next_media_voice WHERE snapshot_id=? AND locator=?',(snap['snapshot_id'],row['locator'])).fetchone()
                    if projected is None or tuple(projected)!=_projection(raw,names):raise ValueError('native voice projection differs')
                count+=1
        if voice_rows!={r[0] for r in db.execute('SELECT locator FROM next_media_voice WHERE snapshot_id=?',(snap['snapshot_id'],))}:
            raise ValueError('media projection has extra rows')
    if db.execute("SELECT 1 FROM next_media_row WHERE table_name NOT IN ('Name2Id','VoiceInfo') LIMIT 1").fetchone():raise ValueError('unknown raw media table')
    registered=service.catalog.db.execute('SELECT cas_id,schema FROM external_asset_owner WHERE owner_id=?',(owner,)).fetchone() if references else None
    if references and (registered is None or tuple(registered)!=(cas_id,SCHEMA)):raise ValueError('media owner registration differs')
    if object_proof:object_proof.assert_for(service.objects.db,cas_id=cas_id)
    for sha,size in references.items():
        pin=service.catalog.db.execute('SELECT bytes,cas_id FROM external_asset_ref WHERE owner_id=? AND file_sha=?',(owner,sha)).fetchone()
        file=service.objects.db.execute('SELECT bytes FROM file WHERE hash=?',(sha,)).fetchone()
        if pin is None or tuple(pin)!=(size,cas_id) or file is None or file[0]!=size:raise ValueError('media object or pin missing')
        if deep:
            if object_proof:object_proof.covers(sha,size)
            else:verify_published_object(service.objects.db,sha,size)
    if object_proof:object_proof.assert_for(service.objects.db,cas_id=cas_id)
    if list(db.execute('PRAGMA foreign_key_check')):raise ValueError('media foreign key failure')
    return dict(status='verified',rows_verified=count,unique_objects=len(references),logical_bytes=sum(references.values()),byte_verified=deep)
