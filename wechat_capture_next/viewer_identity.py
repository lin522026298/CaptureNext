"""Exact accepted-contact observations, separate from message identity/merge.

Unknown contact columns and SQLite types remain reconstructable. Contact BLOBs
are interned once, not base64-copied into every row. This parser deliberately
does not infer group membership or media ID namespaces.
"""
from contextlib import closing
import hashlib
import json
import sqlite3

from wechat_capture_v2.common import canonical,digest_file,encoded,decoded
from .backup import _file
from .compact_archive import CompactArchive
from .state_guard import writer_lock
from .union_archive import cold_input,cold_reader

SCHEMA='next-contact-evidence-1'
FIELDS=('remark','nick_name','alias')


def _extension(archive):
    db=archive._db
    row=db.execute("SELECT value FROM archive_meta WHERE key='next_viewer_schema'").fetchone()
    if row:
        if row[0]!=SCHEMA:raise ValueError('unsupported identity evidence schema')
        return
    for sql in (
        '''CREATE TABLE next_viewer_aux_snapshot(snapshot_id TEXT PRIMARY KEY,source_id TEXT NOT NULL,
            account_alias TEXT NOT NULL,relative_path TEXT NOT NULL,db_sha TEXT NOT NULL,capture_id TEXT NOT NULL,
            evidence_id INTEGER NOT NULL REFERENCES content_payload(id),schema_id INTEGER NOT NULL REFERENCES content_payload(id))''',
        '''CREATE TABLE next_viewer_aux_row(snapshot_id TEXT NOT NULL REFERENCES next_viewer_aux_snapshot(snapshot_id),
            locator INTEGER NOT NULL,row_sha TEXT NOT NULL,payload_id INTEGER NOT NULL REFERENCES content_payload(id),
            PRIMARY KEY(snapshot_id,locator))''',
        '''CREATE TABLE next_viewer_identity(snapshot_id TEXT NOT NULL,locator INTEGER NOT NULL,source_id TEXT NOT NULL,
            account_alias TEXT NOT NULL,username TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,
            PRIMARY KEY(snapshot_id,locator,kind),
            FOREIGN KEY(snapshot_id,locator) REFERENCES next_viewer_aux_row(snapshot_id,locator))''',
        'CREATE INDEX next_viewer_name_lookup ON next_viewer_identity(account_alias,username)',
        'CREATE INDEX next_viewer_conversation_time ON observation_record(account_alias,conversation_id,event_time,observation_id)',
    ):db.execute(sql)
    db.execute("INSERT INTO archive_meta VALUES('next_viewer_schema',?)",(SCHEMA,))


def _row_manifest(archive,values):
    result=[]
    for name,value in values.items():
        if isinstance(value,bytes):
            identity=archive.pool.intern_bytes(value)
            result.append([name,['content_blob',identity,hashlib.sha256(value).hexdigest(),len(value)]])
        else:result.append([name,encoded(value)])
    return canonical(result)


def _decode(archive,text):
    values={}
    for name,value in json.loads(text):
        if name in values:raise ValueError('duplicate exact contact field')
        if value[0]=='content_blob':
            blob=archive.pool.get_bytes(value[1])
            if len(blob)!=value[3] or hashlib.sha256(blob).hexdigest()!=value[2]:raise ValueError('contact blob binding differs')
            values[name]=blob
        else:values[name]=decoded(value)
    return values


def import_contact(archive,*,source_id,account_alias,relative,capture_id,evidence,path):
    expected=evidence['plaintext']['sha256']
    identity='aux_'+hashlib.sha256(canonical([SCHEMA,source_id,account_alias,relative,expected]).encode()).hexdigest()
    with archive.transaction():
        _extension(archive)
        if archive._db.execute('SELECT 1 FROM next_viewer_aux_snapshot WHERE snapshot_id=?',(identity,)).fetchone():
            return dict(noop=True,rows_added=0,names_added=0)
        _file(path)
        with cold_input(path),closing(cold_reader(path)) as view:
            if digest_file(path)!=expected:raise ValueError('contact cache is not the accepted database cut')
            sql=view.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='contact'").fetchone()
            if sql is None:raise ValueError('confirmed contact table missing')
            columns=[r[1] for r in view.execute('PRAGMA table_info(contact)')]
            if not {'username',*FIELDS}.issubset(columns) or '_viewer_rowid' in columns:
                raise ValueError('unsupported contact field profile')
            archive._db.execute('INSERT INTO next_viewer_aux_snapshot VALUES(?,?,?,?,?,?,?,?)',
                (identity,source_id,account_alias,relative,expected,capture_id,
                 archive.pool.intern_json(canonical(evidence)),archive.pool.intern_text(sql[0])))
            rows=names=0
            for raw in view.execute('SELECT _rowid_ AS _viewer_rowid,* FROM contact ORDER BY _rowid_'):
                values=dict(raw);locator=values.pop('_viewer_rowid');text=_row_manifest(archive,values)
                archive._db.execute('INSERT INTO next_viewer_aux_row VALUES(?,?,?,?)',
                    (identity,locator,hashlib.sha256(text.encode()).hexdigest(),archive.pool.intern_json(text)))
                rows+=1;username=values.get('username')
                if not isinstance(username,str) or not username:continue
                for kind in FIELDS:
                    name=values.get(kind)
                    if isinstance(name,str) and name:
                        archive._db.execute('INSERT INTO next_viewer_identity VALUES(?,?,?,?,?,?,?)',
                            (identity,locator,source_id,account_alias,username,kind,name));names+=1
            if digest_file(path)!=expected:raise ValueError('accepted contact cut changed during indexing')
        return dict(noop=False,rows_added=rows,names_added=names,snapshot_id=identity,
            names_are_identity_keys=False,names_at_message_time_proven=False)


def sync_names(service,union):
    from .viewer_access import ensure
    # One-time narrow index upgrade, even when the accepted contacts are idle.
    # This changes no provenance/identity fields and is never done by readers.
    with writer_lock(union),CompactArchive(union/'archive.wua.sqlite') as archive:ensure(archive)
    # Called only by the state's owned worker, after capture/sync at a boundary.
    relative='contact/contact.db'
    row=service.catalog.db.execute('''SELECT d.id,d.evidence_json FROM checkpoint c
        JOIN db_capture d ON d.id=c.capture_id WHERE c.source_id=? AND c.relative_path=?''',
        (service.config['source_id'],relative)).fetchone()
    if row is None:return dict(status='source_unavailable',reason='accepted_contact_database_absent')
    with writer_lock(union),CompactArchive(union/'archive.wua.sqlite') as archive:
        return import_contact(archive,source_id=service.config['source_id'],account_alias=service.config['account_alias'],
            relative=relative,capture_id=row[0],evidence=json.loads(row[1]),path=service.view_path(relative))


def verify(archive):
    db=archive._db
    marker=db.execute("SELECT value FROM archive_meta WHERE key='next_viewer_schema'").fetchone()
    if marker is None:return dict(status='not_indexed',rows_verified=0)
    if marker[0]!=SCHEMA:raise ValueError('unsupported identity evidence schema')
    count=0
    for snapshot in db.execute('SELECT * FROM next_viewer_aux_snapshot'):
        evidence=json.loads(archive.pool.get_text(snapshot['evidence_id']))
        archive.pool.get_text(snapshot['schema_id'])
        expected='aux_'+hashlib.sha256(canonical([SCHEMA,snapshot['source_id'],snapshot['account_alias'],
            snapshot['relative_path'],snapshot['db_sha']]).encode()).hexdigest()
        if expected!=snapshot['snapshot_id'] or evidence['plaintext']['sha256']!=snapshot['db_sha']:
            raise ValueError('identity snapshot binding differs')
        for row in db.execute('SELECT * FROM next_viewer_aux_row WHERE snapshot_id=?',(snapshot['snapshot_id'],)):
            text=archive.pool.get_text(row['payload_id'])
            if hashlib.sha256(text.encode()).hexdigest()!=row['row_sha']:raise ValueError('identity row binding differs')
            raw=_decode(archive,text)
            projected={(r[0],r[1],r[2],r[3],r[4]) for r in db.execute('''SELECT source_id,account_alias,username,kind,name
                FROM next_viewer_identity WHERE snapshot_id=? AND locator=?''',(snapshot['snapshot_id'],row['locator']))}
            needed={(snapshot['source_id'],snapshot['account_alias'],raw['username'],k,raw[k]) for k in FIELDS
                if isinstance(raw.get('username'),str) and raw['username'] and isinstance(raw.get(k),str) and raw[k]}
            if projected!=needed:raise ValueError('identity projection differs from original fields')
            count+=1
    if list(db.execute('PRAGMA foreign_key_check')):raise ValueError('identity evidence foreign key failure')
    return dict(status='verified',rows_verified=count,scope='retained_accepted_contact_observations')
