"""Recoverable attachment references for a formal union and one existing CAS.

No acquisition, media-message inference, plaintext temporary files, automatic
pruning, or backup/restore policy is hidden here. Three independent databases
are deliberately NOT described as one atomic transaction. Durable pending
metadata -> published CAS objects -> catalog pins -> active receipt is resumable.
"""
from contextlib import closing, contextmanager, nullcontext
import base64
import hashlib
import json
from pathlib import Path
import os
import re
import sqlite3
import uuid
import zlib

from wechat_capture_v2.common import directory, regular, digest_file
from wechat_capture_v2.objects import CHUNK_BYTES
from .union_archive import cold_input, cold_reader
from .paths import local_absolute
from .state_guard import writer_lock, state_preflight
from wua.store import _json

SCHEMA = 'next-union-assets-1'
CAS_KIND = 'capture-next-objects-1'
_HASH = re.compile(r'[0-9a-f]{64}')
_TABLES = ('asset', 'asset_history')


def _hit(fault, stage):
    if fault:
        fault(stage)


def _origin(value):
    if not isinstance(value, str) or not value or len(value) > 200:
        raise ValueError('explicit stable asset origin required')
    return value


def _exists(db, table):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def _bind(archive, service):
    # local_absolute checks every lexical ancestor BEFORE resolving aliases.
    state = local_absolute(service.state)
    directory(state)
    for obj, name in ((service.catalog, 'catalog.sqlite'), (service.objects, 'objects.sqlite')):
        expected = state / name
        if regular(expected).st_nlink != 1:
            raise ValueError('linked asset store is outside write scope')
        actual = next(row[2] for row in obj.db.execute('PRAGMA database_list') if row[1] == 'main')
        if local_absolute(actual) != expected or local_absolute(obj.path) != expected:
            raise ValueError('asset connection is not the exact owned state database')
        for suffix in ('-wal', '-shm', '-journal'):
            candidate = Path(str(expected)+suffix)
            if os.path.lexists(candidate) and regular(candidate).st_nlink != 1:
                raise ValueError('linked asset store sidecar is outside write scope')
    row = service.catalog.db.execute("SELECT value FROM meta WHERE key='next_catalog_instance'").fetchone()
    if row is None or not isinstance(row[0], str) or not row[0]:
        raise ValueError('current catalog requires an existing stable instance identity')
    union_actual = next(row[2] for row in archive._db.execute('PRAGMA database_list') if row[1] == 'main')
    if str(archive.path) == ':memory:':
        if union_actual != '':
            raise ValueError('union connection is not the declared in-memory archive')
    else:
        target = local_absolute(archive.path)
        if not union_actual or local_absolute(union_actual) != target:
            raise ValueError('union connection is not the exact owned archive database')
        if regular(target).st_nlink != 1 or target.is_relative_to(state):
            raise ValueError('formal union must be independent of the current state')
        for suffix in ('-wal', '-shm', '-journal'):
            candidate = Path(str(target)+suffix)
            if os.path.lexists(candidate) and regular(candidate).st_nlink != 1:
                raise ValueError('linked union sidecar is outside write scope')
    return 'capture-next-objects:' + row[0], row[0]


@contextmanager
def _locks(archive, service, held):
    state = state_preflight(service.state)
    union = (None if str(archive.path) == ':memory:' else
             state_preflight(local_absolute(archive.path).parent))
    if held:
        yield
        return
    # Same ordering must be used by callers that pass locks_held=True.
    with writer_lock(state):
        lock = nullcontext() if union is None else writer_lock(union)
        with lock:
            yield


def _boundary(archive, service):
    if archive.readonly:
        raise PermissionError('attachment union requires an owned writable union')
    if any(db.in_transaction for db in (archive._db, service.catalog.db, service.objects.db)):
        raise ValueError('attachment union requires transaction boundaries')
    if getattr(service, '_pending_asset', None) is not None:
        raise ValueError('finish pending capture asset publication before attachment union')


def _typed(value):
    if value is None:
        return ['null', None]
    if isinstance(value, int):
        return ['integer', value]
    if isinstance(value, float):
        return ['real', value.hex()]
    if isinstance(value, str):
        return ['text', value]
    if isinstance(value, bytes):
        return ['blob', base64.b64encode(value).decode('ascii')]
    raise TypeError('unsupported SQLite asset field type')


def decode_asset_row(text):
    """Recover all original columns and SQLite value types, including unknowns."""
    document = json.loads(text)
    result = {}
    for name, (kind, value) in zip(document['columns'], document['values'], strict=True):
        if name in result:
            raise ValueError('duplicate original asset column')
        if kind == 'null':
            value = None
        elif kind == 'blob':
            value = base64.b64decode(value, validate=True)
        elif kind == 'real':
            value = float.fromhex(value)
        elif kind not in ('text', 'integer'):
            raise ValueError('unknown original asset value type')
        result[name] = value
    return result


def _rows(source, table):
    columns = [r[1] for r in source.execute(f'PRAGMA table_info({table})')]
    required = {'source_id', 'relative_path', 'file_sha', 'bytes', 'cycle_id'}
    if table == 'asset':
        required.add('stamp_json')
    if not required.issubset(columns):
        raise ValueError('unsupported retained asset columns')
    keys = ['source_id', 'relative_path'] + (['file_sha'] if table == 'asset_history' else [])
    previous = None
    for values in source.execute(f'SELECT * FROM {table} ORDER BY ' + ','.join(name+' COLLATE BINARY' for name in keys)):
        row = dict(zip(columns, values))
        if not all(isinstance(row[name], str) and row[name] for name in ('source_id', 'relative_path', 'cycle_id')):
            raise ValueError('invalid original asset provenance fields')
        sha, size = row['file_sha'], row['bytes']
        if not isinstance(sha, str) or not _HASH.fullmatch(sha) or type(size) is not int or size < 0:
            raise ValueError('invalid retained asset hash or length')
        key = tuple(row[name] for name in keys)
        if key == previous:
            raise ValueError('duplicate logical original asset key')
        previous = key
        payload = _json({'columns': columns, 'values': [_typed(value) for value in values]})
        yield row, _json(list(key)), hashlib.sha256(payload.encode()).hexdigest(), payload


def _inspect(source, objects):
    if [r[0] for r in source.execute('PRAGMA quick_check')] != ['ok']:
        raise ValueError('retained asset SQLite integrity failed')
    for table in (*_TABLES, 'file', 'chunk', 'file_chunk'):
        if not _exists(source, table):
            raise ValueError('retained asset tables are incomplete')
    for table, expected in (('file', ('hash', 'bytes', 'chunk_count')),
            ('chunk', ('hash', 'bytes', 'data')), ('file_chunk', ('file_hash', 'ordinal', 'chunk_hash'))):
        if tuple(r[1] for r in source.execute(f'PRAGMA table_info({table})')) != expected:
            raise ValueError('unsupported retained CAS schema')
    digest, references, counts = hashlib.sha256(), {}, {}
    shapes = {}
    for table in _TABLES:
        shapes[table] = [list(r) for r in source.execute(f'PRAGMA table_info({table})')]
        digest.update((_json([table, shapes[table]]) + '\n').encode())
        counts[table] = 0
        for row, key, sha, payload in _rows(source, table):
            digest.update((_json([key, sha]) + '\n').encode())
            counts[table] += 1
            old = references.setdefault(row['file_sha'], row['bytes'])
            if old != row['bytes']:
                raise ValueError('asset hash has conflicting original lengths')
    existing = missing = missing_bytes = 0
    unavailable = []
    for sha, size in references.items():
        target = objects.execute('SELECT bytes FROM file WHERE hash=?', (sha,)).fetchone()
        if target:
            if target[0] != size:
                raise ValueError('current CAS file length collision')
            existing += 1
        else:
            retained = source.execute('SELECT bytes FROM file WHERE hash=?', (sha,)).fetchone()
            if retained is None:
                unavailable.append(sha)
            elif retained[0] != size:
                raise ValueError('retained CAS file length differs from original metadata')
            else:
                missing += 1
                missing_bytes += size
    return dict(references=references, source_rows=counts, metadata_sha256=digest.hexdigest(),
        shapes=shapes, existing_files=existing, missing_files=missing, missing_logical_bytes=missing_bytes,
        unavailable_hashes=sorted(unavailable))


def _check_source_path(archive, service, path):
    path = local_absolute(path)
    targets = [local_absolute(service.objects.path), local_absolute(service.catalog.path)]
    if str(archive.path) != ':memory:':
        targets.append(local_absolute(archive.path))
    if path in targets:
        raise ValueError('retained input overlaps a writable union target')
    return path


def plan_asset_union(archive, service, retained_path, origin_id, *, source_receipt=None):
    """Read-only advisory inventory; it does not authenticate object bytes yet."""
    _origin(origin_id)
    cas_id, instance = _bind(archive, service)
    path = _check_source_path(archive, service, retained_path)
    with cold_input(path), closing(cold_reader(path)) as source:
        source.execute('BEGIN')
        result = _inspect(source, service.objects.db)
        result.pop('references')
        result.pop('shapes')
        result.update(schema=SCHEMA, origin_id=origin_id, cas_id=cas_id,
            catalog_instance=instance, artifact_sha256=digest_file(path),
            ready=not result['unavailable_hashes'], snapshot_atomic=False,
            object_bytes_verified=False, message_media_association='not_implemented',
            source_receipt=source_receipt)
        return result


def _union_schema(archive, cas_id, instance):
    db = archive._db
    identity = db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()
    if identity is None:
        owner = uuid.uuid4().hex
        db.execute("INSERT INTO archive_meta VALUES('next_union_id',?)", (owner,))
    else:
        owner = identity[0]
    try:
        valid_identity = isinstance(owner, str) and owner in (uuid.UUID(owner).hex, str(uuid.UUID(owner)))
    except (ValueError, AttributeError):
        valid_identity = False
    if not valid_identity:
        raise ValueError('invalid stable union identity')
    if _exists(db, 'next_union_asset_meta'):
        meta = dict(db.execute('SELECT key,value FROM next_union_asset_meta'))
        if meta.get('schema') != SCHEMA or meta.get('owner_id') != owner:
            raise ValueError('unsupported union asset extension')
    else:
        for statement in (
            'CREATE TABLE next_union_asset_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)',
            '''CREATE TABLE next_union_asset_store(cas_id TEXT PRIMARY KEY,catalog_instance TEXT NOT NULL,
                kind TEXT NOT NULL)''',
            '''CREATE TABLE next_union_asset_receipt(origin_id TEXT NOT NULL,artifact_sha TEXT NOT NULL,
                cas_id TEXT NOT NULL REFERENCES next_union_asset_store(cas_id),metadata_sha TEXT NOT NULL,
                schema_payload_id INTEGER NOT NULL REFERENCES content_payload(id),
                source_receipt_id INTEGER NOT NULL REFERENCES content_payload(id),
                expected_rows INTEGER NOT NULL,expected_files INTEGER NOT NULL,status TEXT NOT NULL
                CHECK(status IN ('pending','active')),PRIMARY KEY(origin_id,artifact_sha))''',
            '''CREATE TABLE next_union_asset_observation(observation_id TEXT PRIMARY KEY,origin_id TEXT NOT NULL,
                source_table TEXT NOT NULL,row_key TEXT NOT NULL,row_sha TEXT NOT NULL,source_id TEXT NOT NULL,
                relative_path TEXT NOT NULL,file_sha TEXT NOT NULL,bytes INTEGER NOT NULL,
                payload_id INTEGER NOT NULL REFERENCES content_payload(id),
                UNIQUE(origin_id,source_table,row_key,row_sha))''',
            '''CREATE TABLE next_union_asset_member(origin_id TEXT NOT NULL,artifact_sha TEXT NOT NULL,
                observation_id TEXT NOT NULL REFERENCES next_union_asset_observation(observation_id),
                PRIMARY KEY(origin_id,artifact_sha,observation_id),
                FOREIGN KEY(origin_id,artifact_sha) REFERENCES next_union_asset_receipt(origin_id,artifact_sha))'''):
            db.execute(statement)
        db.executemany('INSERT INTO next_union_asset_meta VALUES(?,?)', [('schema', SCHEMA), ('owner_id', owner)])
        for table in ('next_union_asset_meta', 'next_union_asset_store',
                      'next_union_asset_observation', 'next_union_asset_member'):
            for operation in ('UPDATE', 'DELETE'):
                db.execute(f'''CREATE TRIGGER {table}_no_{operation.lower()} BEFORE {operation} ON {table}
                    BEGIN SELECT RAISE(ABORT,'union asset evidence is immutable'); END''')
        db.execute('''CREATE TRIGGER next_union_asset_receipt_no_delete BEFORE DELETE ON next_union_asset_receipt
            BEGIN SELECT RAISE(ABORT,'union asset receipt is retained'); END''')
        db.execute('''CREATE TRIGGER next_union_asset_receipt_update BEFORE UPDATE ON next_union_asset_receipt
            WHEN OLD.status!='pending' OR NEW.status!='active' OR OLD.origin_id!=NEW.origin_id
            OR OLD.artifact_sha!=NEW.artifact_sha OR OLD.cas_id!=NEW.cas_id OR OLD.metadata_sha!=NEW.metadata_sha
            OR OLD.schema_payload_id!=NEW.schema_payload_id OR OLD.source_receipt_id!=NEW.source_receipt_id
            OR OLD.expected_rows!=NEW.expected_rows OR OLD.expected_files!=NEW.expected_files
            BEGIN SELECT RAISE(ABORT,'only pending receipt activation is permitted'); END''')
    stores = list(db.execute('SELECT cas_id,catalog_instance,kind FROM next_union_asset_store'))
    if stores and [tuple(r) for r in stores] != [(cas_id, instance, CAS_KIND)]:
        raise ValueError('union asset CAS identity mismatch')
    if not stores:
        db.execute('INSERT INTO next_union_asset_store VALUES(?,?,?)', (cas_id, instance, CAS_KIND))
    # The anti-join verifier starts with an observation, not an artifact. The
    # provenance PK starts (origin,artifact), so it cannot serve this lookup.
    # Explicit owned extension creation/import is the only schema write path.
    db.execute('''CREATE INDEX IF NOT EXISTS next_union_asset_member_observation
        ON next_union_asset_member(observation_id,origin_id,artifact_sha)''')
    return owner


def _catalog_schema(db, owner, cas_id):
    db.execute('''CREATE TABLE IF NOT EXISTS external_asset_owner(owner_id TEXT PRIMARY KEY,
        cas_id TEXT NOT NULL,schema TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS external_asset_ref(owner_id TEXT NOT NULL,
        file_sha TEXT NOT NULL,bytes INTEGER NOT NULL,cas_id TEXT NOT NULL,
        PRIMARY KEY(owner_id,file_sha),FOREIGN KEY(owner_id) REFERENCES external_asset_owner(owner_id))''')
    expected = (owner, cas_id, SCHEMA)
    previous = db.execute('SELECT owner_id,cas_id,schema FROM external_asset_owner WHERE owner_id=?', (owner,)).fetchone()
    if previous and tuple(previous) != expected:
        raise ValueError('external asset owner identity mismatch')
    if not previous:
        db.execute('INSERT INTO external_asset_owner VALUES(?,?,?)', expected)


def _blocks(db, sha, expected_size):
    file_row = db.execute('SELECT bytes,chunk_count FROM file WHERE hash=?', (sha,)).fetchone()
    if file_row is None or tuple(file_row) != (expected_size, (expected_size + CHUNK_BYTES - 1) // CHUNK_BYTES):
        raise ValueError('published asset file shape/length mismatch')
    count = total = 0
    digest = hashlib.sha256()
    for ordinal, key, size, payload in db.execute('''SELECT f.ordinal,f.chunk_hash,c.bytes,c.data
            FROM file_chunk f LEFT JOIN chunk c ON c.hash=f.chunk_hash
            WHERE f.file_hash=? ORDER BY f.ordinal''', (sha,)):
        if (ordinal != count or not isinstance(key, str) or not _HASH.fullmatch(key)
            or type(size) is not int or size != min(CHUNK_BYTES, expected_size-total) or size <= 0):
            raise ValueError('published asset chunk sequence/size mismatch')
        decoder = zlib.decompressobj()
        block = decoder.decompress(payload, CHUNK_BYTES + 1)
        if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or len(block) != size or hashlib.sha256(block).hexdigest() != key):
            raise ValueError('published asset chunk authentication failed')
        digest.update(block)
        total += size
        count += 1
        yield ordinal, key, size, payload, block
    if total != expected_size or count != file_row[1] or digest.hexdigest() != sha:
        raise ValueError('published asset file hash/length mismatch')


def verify_published_object(db, sha, size):
    """Full streaming authentication of one published object, including empty files."""
    for _ in _blocks(db, sha, size):
        pass


def _copy_object(source, target, sha, size, fault):
    target.execute('BEGIN IMMEDIATE')
    try:
        count = 0
        for ordinal, key, length, payload, block in _blocks(source, sha, size):
            previous = target.execute('SELECT bytes,data FROM chunk WHERE hash=?', (key,)).fetchone()
            if previous is None:
                target.execute('INSERT INTO chunk VALUES(?,?,?)', (key, length, payload))
            else:
                decoder = zlib.decompressobj()
                old = decoder.decompress(previous[1], CHUNK_BYTES + 1)
                if (previous[0] != length or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
                    or hashlib.sha256(old).hexdigest() != key or old != block):
                    raise ValueError('existing CAS chunk collision or corruption')
            mapping = target.execute('SELECT chunk_hash FROM file_chunk WHERE file_hash=? AND ordinal=?', (sha, ordinal)).fetchone()
            if mapping and mapping[0] != key:
                raise ValueError('existing unpublished CAS mapping collision')
            if not mapping:
                target.execute('INSERT INTO file_chunk VALUES(?,?,?)', (sha, ordinal, key))
            count += 1
        if target.execute('SELECT count(*) FROM file_chunk WHERE file_hash=?', (sha,)).fetchone()[0] != count:
            raise ValueError('unpublished CAS mapping has excess chunks')
        # Publication is deliberately last, after authenticating all source bytes.
        target.execute('INSERT INTO file VALUES(?,?,?)', (sha, size, count))
        _hit(fault, 'before_object_commit')
        target.commit()
    except BaseException:
        target.rollback()
        raise
    _hit(fault, 'after_object_commit')
    verify_published_object(target, sha, size)  # Target readback, not source-memory proof.


def _pending(archive, source, origin, artifact, cas_id, instance, inspected, source_receipt):
    with archive.transaction():
        owner = _union_schema(archive, cas_id, instance)
        db = archive._db
        schema_id = archive.pool.intern_json(_json(inspected['shapes']))
        receipt_id = archive.pool.intern_json(_json(source_receipt))
        expected = (origin, artifact, cas_id, inspected['metadata_sha256'], schema_id, receipt_id,
                    sum(inspected['source_rows'].values()), len(inspected['references']))
        old = db.execute('SELECT * FROM next_union_asset_receipt WHERE origin_id=? AND artifact_sha=?', (origin, artifact)).fetchone()
        if old and tuple(old)[:-1] != expected:
            raise ValueError('immutable asset import receipt mismatch')
        if not old:
            db.execute('INSERT INTO next_union_asset_receipt VALUES(?,?,?,?,?,?,?,?,\'pending\')', expected)
        added = 0
        for table in _TABLES:
            for row, key, sha, payload in _rows(source, table):
                observation = 'asset_' + hashlib.sha256(_json([origin, table, key, sha]).encode()).hexdigest()
                payload_id = archive.pool.intern_json(payload)
                values = (observation, origin, table, key, sha, row['source_id'], row['relative_path'], row['file_sha'], row['bytes'], payload_id)
                previous = db.execute('SELECT * FROM next_union_asset_observation WHERE observation_id=?', (observation,)).fetchone()
                if previous and tuple(previous) != values:
                    raise ValueError('asset observation identity collision')
                if not previous:
                    db.execute('INSERT INTO next_union_asset_observation VALUES(?,?,?,?,?,?,?,?,?,?)', values)
                    added += 1
                if not db.execute('SELECT 1 FROM next_union_asset_member WHERE origin_id=? AND artifact_sha=? AND observation_id=?',
                                  (origin, artifact, observation)).fetchone():
                    db.execute('INSERT INTO next_union_asset_member VALUES(?,?,?)', (origin, artifact, observation))
        return owner, added, old['status'] if old else None


def import_asset_union(archive, service, retained_path, origin_id, *, source_receipt=None,
                       fault=None, locks_held=False):
    """Import retained metadata and missing bytes into the existing current CAS.

    locks_held=True is only for a caller already holding BOTH OS writer locks in
    current-state -> union order. Published files intentionally survive failure;
    the pending receipt is resumed, never rolled back by deleting durable bytes.
    """
    origin = _origin(origin_id)
    _boundary(archive, service)
    with _locks(archive, service, locks_held):
        cas_id, instance = _bind(archive, service)
        path = _check_source_path(archive, service, retained_path)
        with cold_input(path), closing(cold_reader(path)) as source:
            source.execute('BEGIN')
            artifact = digest_file(path)
            inspected = _inspect(source, service.objects.db)
            if inspected['unavailable_hashes']:
                raise ValueError('retained metadata references unavailable attachment bytes')
            owner, added, old_status = _pending(archive, source, origin, artifact,
                cas_id, instance, inspected, source_receipt)
            _hit(fault, 'after_pending_commit')
            imported = existing = 0
            for sha, size in sorted(inspected['references'].items()):
                if service.objects.db.execute('SELECT 1 FROM file WHERE hash=?', (sha,)).fetchone():
                    verify_published_object(service.objects.db, sha, size)
                    existing += 1
                else:
                    _copy_object(source, service.objects.db, sha, size, fault)
                    imported += 1
            catalog = service.catalog.db
            catalog.execute('BEGIN IMMEDIATE')
            try:
                _catalog_schema(catalog, owner, cas_id)
                for sha, size in sorted(inspected['references'].items()):
                    previous = catalog.execute('SELECT bytes,cas_id FROM external_asset_ref WHERE owner_id=? AND file_sha=?', (owner, sha)).fetchone()
                    if previous and tuple(previous) != (size, cas_id):
                        raise ValueError('external asset pin collision')
                    if not previous:
                        catalog.execute('INSERT INTO external_asset_ref VALUES(?,?,?,?)', (owner, sha, size, cas_id))
                _hit(fault, 'before_pins_commit')
                catalog.commit()
            except BaseException:
                catalog.rollback()
                raise
            _hit(fault, 'after_pins_commit')
            with archive.transaction():
                row = archive._db.execute('SELECT status FROM next_union_asset_receipt WHERE origin_id=? AND artifact_sha=?', (origin, artifact)).fetchone()
                if row[0] == 'pending':
                    archive._db.execute("UPDATE next_union_asset_receipt SET status='active' WHERE origin_id=? AND artifact_sha=?", (origin, artifact))
                _hit(fault, 'before_union_commit')
            _hit(fault, 'after_union_commit')
            return dict(schema=SCHEMA, origin_id=origin, artifact_sha256=artifact, owner_id=owner, cas_id=cas_id,
                union_id=owner, catalog_instance=instance,
                source_rows=inspected['source_rows'], metadata_sha256=inspected['metadata_sha256'],
                added_metadata_observations=added, imported_files=imported,
                existing_files_verified=existing, unique_files_verified=existing+imported,
                resumed_pending=old_status == 'pending', replay=old_status == 'active',
                receipt_status='active', runtime_cas_copies=1,
                message_media_association='not_implemented', portable_restore_verified=False)


def initialize_standalone_assets(archive, service):
    """Receipt for a genuinely new install with no imported legacy asset tree.

    Current native assets remain in catalog/CAS and are verified separately.
    This does NOT attest that the client downloaded every historical medium.
    Existing imported extensions are never reset or treated as empty. The
    pending -> catalog binding -> active sequence is retryable after a crash.
    Caller owns state/union writer locks and is outside SQL transactions.
    """
    if service.config.get('standalone_install') is not True:
        raise ValueError('explicit fresh standalone installation required')
    _boundary(archive,service)
    cas_id,instance=_bind(archive,service)
    origin='standalone-no-legacy-assets:'+instance
    if _exists(archive._db,'next_union_asset_meta'):
        row=archive._db.execute('SELECT status FROM next_union_asset_receipt WHERE origin_id=?',(origin,)).fetchone()
        if row is None or row[0]=='active':return
    receipt=dict(schema='standalone-assets-bootstrap-1',catalog_instance=instance,
        scope='no_imported_legacy_asset_tree',native_source_completeness=False)
    with closing(sqlite3.connect(':memory:')) as source:
        shapes={}
        for table in _TABLES:
            source.execute(f'CREATE TABLE {table}(source_id TEXT,relative_path TEXT,file_sha TEXT,bytes INTEGER,stamp_json TEXT,cycle_id TEXT)')
            shapes[table]=[list(row) for row in source.execute(f'PRAGMA table_info({table})')]
        digest=hashlib.sha256()
        for table in _TABLES:digest.update((_json([table,shapes[table]])+'\n').encode())
        inspected=dict(shapes=shapes,source_rows={table:0 for table in _TABLES},
            references={},metadata_sha256=digest.hexdigest())
        artifact=hashlib.sha256(_json([receipt,shapes]).encode()).hexdigest()
        owner,_,_=_pending(archive,source,origin,artifact,cas_id,instance,inspected,receipt)
    with service.catalog.db:
        _catalog_schema(service.catalog.db,owner,cas_id)
    with archive.transaction():
        archive._db.execute("UPDATE next_union_asset_receipt SET status='active' WHERE origin_id=? AND artifact_sha=? AND status='pending'",(origin,artifact))


def verify_union_assets(archive, service, *, origin_id=None, deep=True,object_proof=None):
    """Verify immutable metadata, pin bindings, receipt closure and unique objects.

    This is read-only. deep=False explicitly omits byte authentication; it is
    suitable for UI status, not acceptance or backup/restore verification.
    """
    if origin_id is not None:
        _origin(origin_id)
    cas_id, instance = _bind(archive, service)
    if object_proof is not None:
        from .operation_objects import FrozenObjectProof
        if not deep or not isinstance(object_proof,FrozenObjectProof):raise ValueError('scoped full byte proof required')
        object_proof.assert_for(service.objects.db,cas_id=cas_id)
    db, catalog = archive._db, service.catalog.db
    if not _exists(db, 'next_union_asset_meta'):
        raise ValueError('union attachment extension is absent')
    meta = dict(db.execute('SELECT key,value FROM next_union_asset_meta'))
    if meta.get('schema') != SCHEMA:
        raise ValueError('unsupported union attachment extension')
    owner = meta['owner_id']
    union_id = db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()
    if union_id is None or union_id[0] != owner:
        raise ValueError('union attachment owner differs from stable union identity')
    stores = [tuple(r) for r in db.execute('SELECT cas_id,catalog_instance,kind FROM next_union_asset_store')]
    if stores != [(cas_id, instance, CAS_KIND)]:
        raise ValueError('union attachment CAS identity mismatch')
    external = catalog.execute('SELECT cas_id,schema FROM external_asset_owner WHERE owner_id=?', (owner,)).fetchone()
    if external is None or tuple(external) != (cas_id, SCHEMA):
        raise ValueError('external asset owner registration missing or mismatched')
    where, parameters = (' WHERE origin_id=?', (origin_id,)) if origin_id else ('', ())
    receipts = list(db.execute('SELECT * FROM next_union_asset_receipt' + where, parameters))
    if not receipts or any(row['status'] != 'active' for row in receipts):
        raise ValueError('attachment import is absent or still pending')
    scope = 'o.origin_id=? AND ' if origin_id is not None else ''
    if db.execute('''SELECT 1 FROM next_union_asset_observation o WHERE ''' + scope + '''NOT EXISTS(
            SELECT 1 FROM next_union_asset_member m INDEXED BY next_union_asset_member_observation
            JOIN next_union_asset_receipt r
            ON r.origin_id=m.origin_id AND r.artifact_sha=m.artifact_sha
            WHERE m.observation_id=o.observation_id AND m.origin_id=o.origin_id
            AND r.status='active') LIMIT 1''', parameters).fetchone():
        raise ValueError('union asset observation lacks same-origin active receipt coverage')
    references, observations, metadata_identity = {}, 0, []
    for row in db.execute('SELECT * FROM next_union_asset_observation' + where, parameters):
        if row['source_table'] not in _TABLES:
            raise ValueError('unsupported union asset source table')
        payload = archive.pool.get_text(row['payload_id'])
        if hashlib.sha256(payload.encode()).hexdigest() != row['row_sha']:
            raise ValueError('asset metadata payload digest mismatch')
        original = decode_asset_row(payload)
        keys = ['source_id', 'relative_path'] + (['file_sha'] if row['source_table'] == 'asset_history' else [])
        key = _json([original[name] for name in keys])
        identity = 'asset_' + hashlib.sha256(_json([row['origin_id'], row['source_table'], key, row['row_sha']]).encode()).hexdigest()
        if (key != row['row_key'] or identity != row['observation_id'] or any(
                original[name] != row[name] for name in ('source_id', 'relative_path', 'file_sha', 'bytes'))):
            raise ValueError('asset metadata projection or identity mismatch')
        previous = references.setdefault(row['file_sha'], row['bytes'])
        if previous != row['bytes']:
            raise ValueError('union attachment lengths conflict')
        observations += 1
        metadata_identity.append([row['origin_id'], row['source_table'], row['row_key'],
                                  row['row_sha'], row['observation_id']])
    for receipt in receipts:
        rows = list(db.execute('''SELECT o.* FROM next_union_asset_member m
            LEFT JOIN next_union_asset_observation o ON o.observation_id=m.observation_id
            WHERE m.origin_id=? AND m.artifact_sha=?''', (receipt['origin_id'], receipt['artifact_sha'])))
        if (len(rows) != receipt['expected_rows'] or any(r['observation_id'] is None for r in rows)
                or any(r['origin_id'] != receipt['origin_id'] for r in rows)
                or len({r['file_sha'] for r in rows}) != receipt['expected_files']):
            raise ValueError('union attachment receipt membership is incomplete')
        payloads = []
        for identity in (receipt['schema_payload_id'], receipt['source_receipt_id']):
            # Decode retained schema and opaque receipt too, without opening paths.
            text = archive.pool.get_text(identity)
            binding = db.execute('SELECT kind,sha256 FROM content_payload WHERE id=?', (identity,)).fetchone()
            if tuple(binding) != ('text', hashlib.sha256(text.encode()).hexdigest()):
                raise ValueError('union asset receipt payload digest mismatch')
            payloads.append(text)
        shapes = json.loads(payloads[0])
        digest = hashlib.sha256()
        for table in _TABLES:
            digest.update((_json([table, shapes[table]])+'\n').encode())
            selected = [row for row in rows if row['source_table'] == table]
            selected.sort(key=lambda row: (row['source_id'], row['relative_path'],
                          row['file_sha'] if table == 'asset_history' else ''))
            for row in selected:
                digest.update((_json([row['row_key'], row['row_sha']])+'\n').encode())
        if digest.hexdigest() != receipt['metadata_sha']:
            raise ValueError('union attachment receipt metadata digest mismatch')
    for sha, size in sorted(references.items()):
        pin = catalog.execute('SELECT bytes,cas_id FROM external_asset_ref WHERE owner_id=? AND file_sha=?', (owner, sha)).fetchone()
        if pin is None or tuple(pin) != (size, cas_id):
            raise ValueError('union attachment external pin missing or mismatched')
        published = service.objects.db.execute('SELECT bytes FROM file WHERE hash=?', (sha,)).fetchone()
        if published is None or published[0] != size:
            raise ValueError('union attachment published object missing or mismatched')
        if deep:
            if object_proof is None:verify_published_object(service.objects.db, sha, size)
            else:object_proof.covers(sha,size)
    if object_proof is not None:object_proof.assert_for(service.objects.db,cas_id=cas_id)
    reference_sha = hashlib.sha256(_json(sorted(map(list, references.items()))).encode()).hexdigest()
    metadata_sha = hashlib.sha256(_json(sorted(metadata_identity)).encode()).hexdigest()
    return dict(schema=SCHEMA, owner_id=owner, union_id=owner, cas_id=cas_id, catalog_instance=instance,
        references=len(references), reference_sha256=reference_sha, metadata_rows=observations,
        metadata_sha256=metadata_sha, available=len(references), missing=0,
        deep_verified=len(references) if deep else 0, closure_complete=bool(deep and origin_id is None),
        verification_scope='whole_union' if origin_id is None else 'origin_subset', origin_id=origin_id,
        integrity_scope='metadata+pins+published_CAS_full_bytes' if deep else 'metadata+pins+published_CAS_metadata_only',
        metadata_observations_verified=observations,
        active_receipts_verified=len(receipts), unique_file_references_verified=len(references),
        unique_objects_bytes_verified=sum(references.values()) if deep else 0,
        unique_objects_verified=len(references) if deep else 0, object_bytes_verified=bool(deep),
        object_byte_proof_scope='same_operation_frozen_state_verification' if object_proof is not None else 'direct_readback' if deep else None,
        objects_reused_from_state_verification=len(references) if object_proof is not None else 0,
        unique_object_bytes_read_this_verifier=sum(references.values()) if deep and object_proof is None else 0,
        object_bytes_covered_by_same_operation_proof=sum(references.values()) if object_proof is not None else 0,
        message_media_association='not_implemented', portable_restore_verified=False)
