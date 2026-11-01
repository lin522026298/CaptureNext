"""One explicitly owned WUA materialization, incrementally synchronized.

Never adopts an old export. Caller owns the next state's writer lock. Durable
imported IDs, not maximum sequence/rowid/time, determine unseen observations.
All intermediate todo sets are MEMORY TEMP tables. The catalog stays read-only
on this connection; its immutable records remain the authoritative source.
"""
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import uuid
import zlib

from wechat_capture_v2.common import decoded, directory, regular, write_json_new
from wua.store import _json
from .merge import LeanArchiveStore


def catalog_identity(service):
    with service.catalog.db:
        service.catalog.db.execute("INSERT OR IGNORE INTO meta VALUES('next_catalog_instance',?)", (uuid.uuid4().hex,))
    return service.catalog.db.execute("SELECT value FROM meta WHERE key='next_catalog_instance'").fetchone()[0]


def owned_directory(service, output, identity):
    raw = Path(output)
    for parent in (raw, *raw.parents):
        if os.path.lexists(parent):
            directory(parent)
    output = raw.resolve()
    for root in (service.root, Path(service.config['asset_root']) if service.config.get('asset_root') else None):
        if root and (output.is_relative_to(root) or root.is_relative_to(output)):
            raise ValueError('managed output overlaps a live source')
    if service.state == output or service.state.is_relative_to(output):
        raise ValueError('managed output must not contain the source state')
    owner = {'schema': 'next-managed-wua-1', 'catalog_instance': identity}
    if output.exists():
        marker = output/'OWNER.private.json'
        regular(marker)
        if json.loads(marker.read_text(encoding='utf-8')) != owner:
            raise ValueError('refusing to adopt a foreign or historical output')
    else:
        output.mkdir(parents=True, exist_ok=False)
        write_json_new(output/'OWNER.private.json', owner)
    path = output/'archive.wua.sqlite'
    # exists() follows links and misses dangling links. Never let SQLite
    # create/write through one, including its journal and WAL companions.
    for candidate in (path, *(path.with_name(path.name+s) for s in ('-journal', '-wal', '-shm'))):
        if os.path.lexists(candidate):
            if regular(candidate).st_nlink != 1:
                raise ValueError('linked managed archive file is outside write scope')
    if not os.path.lexists(path):
        with path.open('xb'):
            pass
    return path


def sync_wua(service, output, *, verify=False):
    identity = catalog_identity(service)
    path = owned_directory(service, output, identity)
    with LeanArchiveStore(path) as archive:
        # The legacy constructor does not enable SQLite URI filenames for a
        # writable archive. Reopen ONLY this owned target with URI support so
        # mode=ro on ATTACH is enforced, rather than treated as a literal name.
        archive._db.close()
        archive._db = sqlite3.connect(path.as_uri()+'?mode=rw', uri=True, isolation_level=None)
        archive._db.row_factory = sqlite3.Row
        archive._db.execute('PRAGMA foreign_keys=ON')
        archive._db.execute('PRAGMA temp_store=MEMORY')
        db = archive._db
        db.execute('ATTACH DATABASE ? AS capture_source',
            ((service.state/'catalog.sqlite').as_uri()+'?mode=ro',))
        try:
            db.execute('BEGIN')
            db.execute('CREATE TABLE IF NOT EXISTS next_sync_owner(catalog_instance TEXT PRIMARY KEY)')
            owners = [r[0] for r in db.execute('SELECT catalog_instance FROM next_sync_owner')]
            if owners and owners != [identity]:
                raise ValueError('managed archive identity mismatch')
            if not owners:
                if db.execute('SELECT count(*) FROM message_observation').fetchone()[0]:
                    raise ValueError('refusing to claim a populated unmanaged archive')
                db.execute('INSERT INTO next_sync_owner VALUES(?)', (identity,))
            db.execute('CREATE TABLE IF NOT EXISTS next_imported_version(id TEXT PRIMARY KEY)')
            db.execute('''CREATE TABLE IF NOT EXISTS next_imported_interpretation(
                version_id TEXT,normalization_hash TEXT,PRIMARY KEY(version_id,normalization_hash))''')
            if db.execute('''SELECT 1 FROM next_imported_version i LEFT JOIN capture_source.version v ON v.id=i.id
                WHERE v.id IS NULL LIMIT 1''').fetchone() or db.execute('''SELECT 1 FROM next_imported_interpretation i
                LEFT JOIN capture_source.interpretation v ON v.version_id=i.version_id AND v.normalization_hash=i.normalization_hash
                WHERE v.version_id IS NULL LIMIT 1''').fetchone():
                raise ValueError('source catalog regressed; retained target history must not be silently discarded')
            db.execute('CREATE TEMP TABLE todo_version(id TEXT PRIMARY KEY)')
            db.execute('CREATE TEMP TABLE todo_interpretation(version_id TEXT,normalization_hash TEXT,PRIMARY KEY(version_id,normalization_hash))')
            db.execute('''INSERT INTO todo_version SELECT v.id FROM capture_source.version v
                LEFT JOIN next_imported_version i ON i.id=v.id WHERE i.id IS NULL''')
            db.execute('''INSERT INTO todo_interpretation SELECT v.version_id,v.normalization_hash
                FROM capture_source.interpretation v LEFT JOIN next_imported_interpretation i
                ON i.version_id=v.version_id AND i.normalization_hash=v.normalization_hash WHERE i.version_id IS NULL''')
            versions = db.execute('SELECT count(*) FROM todo_version').fetchone()[0]
            interpretations = db.execute('SELECT count(*) FROM todo_interpretation').fetchone()[0]
            captures = set()

            @lru_cache(maxsize=256)  # Cache bound only, never an acquisition limit.
            def capture_metadata(capture_id):
                capture = db.execute('SELECT * FROM capture_source.db_capture WHERE id=?', (capture_id,)).fetchone()
                return capture, json.loads(capture['evidence_json'])

            rows = db.execute('''SELECT v.raw_z,v.normalized_json,v.first_capture FROM capture_source.version v
                JOIN todo_version t ON t.id=v.id
                UNION ALL SELECT v.raw_z,i.normalized_json,i.first_capture FROM capture_source.interpretation i
                JOIN todo_interpretation t ON t.version_id=i.version_id AND t.normalization_hash=i.normalization_hash
                JOIN capture_source.version v ON v.id=i.version_id''')
            for raw_z, normalized, capture_id in rows:
                capture, evidence = capture_metadata(capture_id)
                if capture_id not in captures:
                    source = dict(source_id=capture['source_id'], platform='windows', kind='capture-v2-raw-observations')
                    snapshot = dict(snapshot_id=capture_id, source_id=capture['source_id'],
                        basis='authenticated-source-cut' if evidence.get('authentication') else 'explicit-frozen-plaintext-import',
                        evidence_sha256=hashlib.sha256(capture['evidence_json'].encode()).hexdigest())
                    for table, key, value in (('source_device', 'source_id', _json(source)),
                                              ('source_snapshot', 'snapshot_id', _json(snapshot))):
                        expected_id = capture['source_id'] if table == 'source_device' else capture_id
                        old = db.execute(f'SELECT metadata_json FROM {table} WHERE {key}=?', (expected_id,)).fetchone()
                        if old and old[0] != value:
                            raise ValueError('immutable source/snapshot metadata mismatch')
                    db.execute('INSERT OR IGNORE INTO source_device VALUES(?,?)', (capture['source_id'], _json(source)))
                    db.execute('INSERT OR IGNORE INTO source_snapshot VALUES(?,?,?)', (capture_id, capture['source_id'], _json(snapshot)))
                    captures.add(capture_id)
                item = json.loads(normalized)
                item['raw_record'] = decoded(json.loads(zlib.decompress(raw_z)))
                item['input_database_sha256'] = evidence['plaintext']['sha256']
                if evidence.get('reader', {}).get('schema_sha256'):
                    item['input_schema_sha256'] = evidence['reader']['schema_sha256']
                prepared = archive._prepare_row(capture_id, item)
                db.execute('INSERT INTO message_observation ('+','.join(prepared)+') VALUES ('+
                    ','.join('?' for _ in prepared)+')', tuple(prepared.values()))
            if versions or interpretations:
                rebuild = archive._rebuild()
                db.execute('INSERT INTO next_imported_version SELECT id FROM todo_version')
                db.execute('INSERT INTO next_imported_interpretation SELECT version_id,normalization_hash FROM todo_interpretation')
            else:
                rebuild = {'rebuild_changed': False, 'added_logical_messages': 0, 'totals': archive.stats()}
            db.execute('COMMIT')
        except BaseException:
            if db.in_transaction:
                db.execute('ROLLBACK')
            raise
        finally:
            db.execute('DETACH DATABASE capture_source')
        result = dict(added_observations=versions+interpretations, added_versions=versions,
            added_interpretations=interpretations, rebuild_changed=rebuild['rebuild_changed'],
            stats=rebuild['totals'], derived_row_writes=archive.last_rebuild_writes,
            complete_history_scan=True, raw_or_history_limit=None, managed_output=True)
        if verify:
            result['integrity'] = archive.integrity_check()
            result['semantic_digest'] = archive.semantic_digest()
    return result
