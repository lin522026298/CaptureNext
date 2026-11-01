"""Explicit fresh union, immutable legacy inputs, exact replay and delta merge.

This never adopts an old archive as a capture catalog. Full deep verification
is explicit; a normal replay still authenticates the cold input artifact once,
then reuses its already committed import receipt rather than decoding all rows.
"""
from contextlib import closing, contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from wechat_capture_v2.common import canonical, decoded, digest_file, directory, regular, stamp, write_json_new
from .compact_archive import CompactArchive, HEAVY_CACHE_KIB
from .content_pool import register_codec
from .compare import _input
from .compact_delta import rebuild_delta
from .paths import local_absolute

OWNER_SCHEMA = 'next-formal-union-1'


@contextmanager
def cold_input(path):
    """Refuse dirty inputs; on Windows deny concurrent writes/delete by handle.

    No immutable=1 on a live catalog. Cold WUA inputs only. The OS guard lets
    one artifact hash serve this operation; SQLite's read transaction supplies
    its consistent semantic rows. Metadata is not used as content proof.
    """
    path = _input(path)
    handle = None
    if os.name == 'nt':
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,
            ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.CreateFileW(str(path),0x80000000,1,None,3,0,None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
    try:
        before = stamp(path)
        _input(path)
        yield path
        if stamp(path) != before:
            raise RuntimeError('cold archive changed during import')
    finally:
        if handle is not None:
            kernel.CloseHandle(handle)


def union_path(output, *, catalog_instance, create=False):
    root = local_absolute(output)
    for parent in (root, *root.parents):
        if os.path.lexists(parent):
            directory(parent)
    owner = dict(schema=OWNER_SCHEMA,catalog_instance=catalog_instance)
    if root.exists():
        regular(root/'OWNER.private.json')
        if json.loads((root/'OWNER.private.json').read_text(encoding='utf-8')) != owner:
            raise ValueError('foreign union owner; cannot adopt historical data')
        allowed = {'OWNER.private.json','archive.wua.sqlite','archive.wua.sqlite-journal',
                   'archive.wua.sqlite-wal','archive.wua.sqlite-shm','writer.lock'}
        for child in root.iterdir():
            if child.name not in allowed or regular(child).st_nlink != 1:
                raise ValueError('unexpected or linked union entry')
    elif create:
        root.mkdir(parents=True,exist_ok=False)
        write_json_new(root/'OWNER.private.json',owner)
    else:
        raise FileNotFoundError(root)
    return root/'archive.wua.sqlite'


def _receipts(db):
    db.execute('''CREATE TABLE IF NOT EXISTS next_union_artifact(
        origin_id TEXT NOT NULL,sha256 TEXT NOT NULL,bytes INTEGER NOT NULL,
        input_observations INTEGER NOT NULL,added_observations INTEGER NOT NULL,
        PRIMARY KEY(origin_id,sha256))''')


def cold_reader(path):
    """Only inside cold_input; immutable prevents SQLite creating WAL/SHM.

    Never use for the live capture catalog. Its WAL is handled by the source
    writer lock and ordinary read transactions in import_catalog instead.
    """
    db=sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro&immutable=1',uri=True,isolation_level=None)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA query_only=ON')
    db.execute('PRAGMA temp_store=MEMORY')
    db.execute(f'PRAGMA cache_size=-{HEAVY_CACHE_KIB}')
    register_codec(db)
    return db


@contextmanager
def _catalog_attachment(db,catalog):
    db.execute('ATTACH DATABASE ? AS union_catalog',(Path(catalog).resolve().as_uri()+'?mode=ro',))
    try:
        yield
    finally:
        db.execute('DETACH DATABASE union_catalog')


def import_archive(archive, source, *, origin_id, verify=False):
    if not isinstance(origin_id,str) or not origin_id or len(origin_id)>200:
        raise ValueError('explicit stable import origin required')
    source = local_absolute(source)
    if archive.path != ':memory:' and source == Path(archive.path).resolve():
        raise ValueError('cannot import union into itself')
    with cold_input(source):
        sha = digest_file(source)
        byte_length = source.stat().st_size
        with archive.transaction():
            _receipts(archive._db)
            previous = archive._db.execute('''SELECT input_observations,added_observations,bytes
                FROM next_union_artifact WHERE origin_id=? AND sha256=?''',(origin_id,sha)).fetchone()
            if previous:
                if previous['bytes'] != byte_length:
                    raise ValueError('artifact identity collision')
                result = dict(input_rows=previous['input_observations'],added_observations=0,
                    replayed_observations=previous['input_observations'],artifact_reused=True,
                    artifact_sha256=sha,raw_rows_decoded=0,rebuild_changed=False)
            else:
                with closing(cold_reader(source)) as incoming:
                    incoming.execute('BEGIN')
                    if [r[0] for r in incoming.execute('PRAGMA quick_check')] != ['ok'] or list(incoming.execute('PRAGMA foreign_key_check')):
                        raise ValueError('input archive integrity failed')
                    before = len(archive.new_observation_ids)
                    result = archive.import_legacy_rows(incoming,origin=dict(origin_id=origin_id))
                    new_ids = archive.new_observation_ids[before:]
                    result.update(rebuild_delta(archive,new_ids))
                    archive._db.execute('INSERT INTO next_union_artifact VALUES(?,?,?,?,?)',
                        (origin_id,sha,byte_length,result['input_rows'],result['added_observations']))
                    result.update(artifact_reused=False,artifact_sha256=sha,raw_rows_decoded=result['input_rows'])
            if verify:
                result['integrity']=archive.integrity_check()
                result['semantic_digest']=archive.semantic_digest()
        return result


def import_catalog(archive, catalog, *, origin_id, verify=False):
    """Import all unseen version AND interpretation IDs, not a time watermark.

    Caller owns capture's single-writer lock. Source is a read transaction and
    must be append-only; regression is detected before changing the target.
    The retained two-row old-v2 subset uses the same schema here.
    """
    if not isinstance(origin_id,str) or not origin_id or len(origin_id)>200:
        raise ValueError('explicit stable import origin required')
    with closing(sqlite3.connect(Path(catalog).resolve().as_uri()+'?mode=ro',uri=True)) as source, _catalog_attachment(archive._db,catalog):
        source.row_factory=sqlite3.Row
        source.execute('BEGIN')
        with archive.transaction():
            db=archive._db
            db.execute('''CREATE TABLE IF NOT EXISTS next_union_version(
                origin_id TEXT,id TEXT,PRIMARY KEY(origin_id,id))''')
            db.execute('''CREATE TABLE IF NOT EXISTS next_union_interpretation(
                origin_id TEXT,version_id TEXT,normalization_hash TEXT,
                PRIMARY KEY(origin_id,version_id,normalization_hash))''')
            old = db.execute('SELECT metadata_json FROM next_import_origin WHERE origin_id=?',(origin_id,)).fetchone()
            origin=canonical(dict(origin_id=origin_id,kind='capture-catalog'))
            if old and old[0]!=origin:raise ValueError('origin collision')
            if not old:db.execute('INSERT INTO next_import_origin VALUES(?,?)',(origin_id,origin))
            # ID membership is checked through an attached read-only source;
            # SQL temp/index sets never load all raw records into Python.
            rows=None
            try:
                if db.execute('''SELECT 1 FROM union_catalog.version WHERE id IS NULL LIMIT 1''').fetchone() or db.execute('''SELECT 1
                    FROM union_catalog.interpretation i LEFT JOIN union_catalog.version v ON v.id=i.version_id
                    WHERE i.version_id IS NULL OR i.normalization_hash IS NULL OR v.id IS NULL LIMIT 1''').fetchone():
                    raise ValueError('catalog has missing identities or orphan interpretations')
                if db.execute('''SELECT 1 FROM next_union_version t LEFT JOIN union_catalog.version v
                    ON v.id=t.id WHERE t.origin_id=? AND v.id IS NULL LIMIT 1''',(origin_id,)).fetchone() or db.execute('''SELECT 1 FROM next_union_interpretation t LEFT JOIN union_catalog.interpretation i ON i.version_id=t.version_id AND i.normalization_hash=t.normalization_hash
                    WHERE t.origin_id=? AND i.version_id IS NULL LIMIT 1''',(origin_id,)).fetchone():
                    raise ValueError('catalog regressed; retained history cannot be discarded')
                rows=db.execute('''WITH unseen_version AS MATERIALIZED (
                    SELECT v.id FROM union_catalog.version v
                    WHERE NOT EXISTS(SELECT 1 FROM next_union_version t WHERE t.origin_id=? AND t.id=v.id)
                    ), unseen_interpretation AS MATERIALIZED (
                    SELECT i.version_id,i.normalization_hash FROM union_catalog.interpretation i
                    WHERE NOT EXISTS(SELECT 1 FROM next_union_interpretation t WHERE t.origin_id=? AND t.version_id=i.version_id AND t.normalization_hash=i.normalization_hash)
                    )
                    SELECT v.id,NULL AS nh,v.raw_z,v.normalized_json,v.first_capture
                    FROM unseen_version u CROSS JOIN union_catalog.version v ON v.id=u.id
                    UNION ALL SELECT i.version_id,i.normalization_hash,v.raw_z,i.normalized_json,i.first_capture
                    FROM unseen_interpretation u CROSS JOIN union_catalog.interpretation i
                    ON i.version_id=u.version_id AND i.normalization_hash=u.normalization_hash
                    JOIN union_catalog.version v ON v.id=i.version_id''',(origin_id,origin_id))
                added=versions=interpretations=0;seen_captures=set()
                before=len(archive.new_observation_ids)
                for ident,nh,raw_z,normalized,capture_id in rows:
                    capture=source.execute('SELECT * FROM db_capture WHERE id=?',(capture_id,)).fetchone()
                    if capture is None:raise ValueError('capture provenance missing')
                    evidence=json.loads(capture['evidence_json'])
                    if capture_id not in seen_captures:
                        source_meta=dict(source_id=capture['source_id'],platform='windows',kind='capture-v2-raw-observations')
                        snapshot=dict(snapshot_id=capture_id,source_id=capture['source_id'],basis='authenticated-source-cut' if evidence.get('authentication') else 'explicit-frozen-plaintext-import',evidence_sha256=hashlib.sha256(capture['evidence_json'].encode()).hexdigest())
                        archive.insert_source_exact(capture['source_id'],canonical(source_meta))
                        archive.insert_snapshot_exact(capture_id,capture['source_id'],canonical(snapshot))
                        seen_captures.add(capture_id)
                    item=json.loads(normalized)
                    item['raw_record']=decoded(json.loads(zlib_decompress(raw_z)))
                    item['input_database_sha256']=evidence['plaintext']['sha256']
                    if evidence.get('reader',{}).get('schema_sha256'):
                        item['input_schema_sha256']=evidence['reader']['schema_sha256']
                    prepared=archive.prepared_observation(capture_id,item)
                    added+=int(archive.insert_prepared(prepared,origin=origin_id))
                    if nh is None:
                        versions+=1;db.execute('INSERT INTO next_union_version VALUES(?,?)',(origin_id,ident))
                    else:
                        interpretations+=1;db.execute('INSERT INTO next_union_interpretation VALUES(?,?,?)',(origin_id,ident,nh))
                result=dict(added_observations=added,added_versions=versions,added_interpretations=interpretations,
                    complete_history_scan=True,raw_or_history_limit=None)
                result.update(rebuild_delta(archive,archive.new_observation_ids[before:]))
            finally:
                # Exhausted cursors are harmless on success, but an interrupted
                # source iterator otherwise keeps its ATTACH read lock alive
                # even after ROLLBACK. Close it before leaving this transaction.
                if rows is not None:rows.close()
            if verify:
                result['integrity']=archive.integrity_check()
                result['semantic_digest']=archive.semantic_digest()
        return result


def zlib_decompress(value):
    import zlib
    return zlib.decompress(value)


def sync_union(service, output, *, inputs=(), verify=False):
    """Fresh union or append to our own union; caller owns state's writer lock.

    ``inputs`` contains explicit (stable_origin, cold_WUA_path) pairs. Current
    catalog is always imported, so this is a merge, not just a comparison.
    An independent union lock excludes other union writers.
    """
    from .sync_wua import catalog_identity
    from .state_guard import writer_lock
    output=local_absolute(output)
    protected=[service.state,service.root]
    if service.config.get('asset_root'):protected.append(Path(service.config['asset_root']))
    for root in protected:
        root=local_absolute(root)
        if output.is_relative_to(root) or root.is_relative_to(output):
            raise ValueError('union overlaps capture state or a live source')
    inputs=list(inputs)
    for _,path in inputs:
        source=_input(path)
        if output.is_relative_to(source.parent) or source.is_relative_to(output):
            raise ValueError('union output overlaps a historical input directory')
    identity=catalog_identity(service)
    path=union_path(output,catalog_instance=identity,create=True)
    with writer_lock(output), CompactArchive(path,create=True) as archive:
        results=[]
        for origin,source in inputs:
            results.append(import_archive(archive,source,origin_id=origin))
        current=import_catalog(archive,service.state/'catalog.sqlite',origin_id='capture-'+identity)
        result=dict(schema=OWNER_SCHEMA,inputs=results,current=current,stats=archive.stats(),
            storage=archive.storage_stats(),source_archives_modified=False,
            phone_completeness=False,attachments_included=False)
        if verify:
            result['integrity']=archive.integrity_check()
            result['semantic_digest']=archive.semantic_digest()
        return result
