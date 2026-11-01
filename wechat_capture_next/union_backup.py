"""Independent compact-union CAS snapshots, bound to an exact state companion.

Caller holds current-state then union writer locks. No acquisition, login, live
source probing, adoption of old backups, or automatic cleanup is performed.
An archive alone is metadata, NOT an offline attachment closure.
"""
from collections import OrderedDict
from contextlib import ExitStack, closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
from types import SimpleNamespace
import uuid

from wechat_capture_v2.common import canonical, digest_file, stamp, utcnow, write_json_new
from . import backup as state_backup
from .compact_archive import CompactArchive, SCHEMA_VERSION
from .union_archive import cold_input, cold_reader, OWNER_SCHEMA

SCHEMA = 'next-union-cas-backup-1'
DATABASE = 'repository.sqlite'
CHUNK_BYTES = state_backup.CHUNK_BYTES
_HASH = state_backup._HASH
_EXPECTED = {'meta': ('key', 'value'), 'chunk': ('hash', 'bytes', 'data'),
    'snapshot': ('id', 'created', 'manifest_json'), 'snapshot_chunk': ('snapshot_id', 'chunk_hash')}
_ASSET_FIELDS = ('schema', 'union_id', 'owner_id', 'cas_id', 'catalog_instance',
    'references', 'reference_sha256', 'metadata_rows', 'metadata_sha256', 'available',
    'missing', 'deep_verified', 'closure_complete', 'integrity_scope',
    'message_media_association', 'portable_restore_verified', 'verification_scope', 'origin_id')


def _identifier(value, name):
    if not isinstance(value, str) or not value or len(value) > 200 or any(ord(c) < 32 for c in value):
        raise ValueError('invalid '+name)
    return value


def _uuid(value):
    try:
        if not isinstance(value, str) or value not in (str(uuid.UUID(value)), uuid.UUID(value).hex):
            raise ValueError()
    except (ValueError, AttributeError) as error:
        raise ValueError('invalid stable union identity') from error
    return value


def _union_owner(path):
    state_backup._parents(path.parent)
    state_backup._file(path)
    state_backup._sidecars(path)
    marker = path.parent/'OWNER.private.json'
    state_backup._file(marker)
    value = json.loads(marker.read_text(encoding='utf-8'))
    if (not isinstance(value, dict) or set(value) != {'schema', 'catalog_instance'}
            or value['schema'] != OWNER_SCHEMA):
        raise ValueError('formal union ownership required')
    _identifier(value['catalog_instance'], 'catalog instance')
    return value


def ensure_union_id(path):
    """Explicit owned-union write; caller MUST already hold its writer lock."""
    path = state_backup._absolute(path)
    _union_owner(path)
    # Do not recover or checkpoint a dirty union implicitly.
    from .compare import _input
    _input(path)
    with CompactArchive(path) as archive, archive.transaction():
        row = archive._db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()
        if row:
            return _uuid(row[0])
        identity = str(uuid.uuid4())
        archive._db.execute("INSERT INTO archive_meta VALUES('next_union_id',?)", (identity,))
        return identity


def _repository(path, owner=None, *, create=False):
    path = state_backup._parents(path)
    if not os.path.lexists(path):
        if not create or owner is None:
            raise FileNotFoundError('union backup repository missing')
        path.mkdir(parents=True, exist_ok=False)
        write_json_new(path/'OWNER.private.json', owner)
    state_backup._file(path/'OWNER.private.json')
    actual = json.loads((path/'OWNER.private.json').read_text(encoding='utf-8'))
    if (not isinstance(actual, dict) or set(actual) != {'schema', 'catalog_instance', 'union_id'}
            or actual.get('schema') != SCHEMA or (owner is not None and actual != owner)):
        raise ValueError('foreign union backup owner; adoption forbidden')
    _identifier(actual['catalog_instance'], 'catalog instance')
    _uuid(actual['union_id'])
    allowed = {'OWNER.private.json', DATABASE, DATABASE+'-journal', 'repository.lock'}
    for child in path.iterdir():
        state_backup._file(child)
        if child.name not in allowed:
            raise ValueError('unexpected union backup entry or sidecar')
    target = path/DATABASE
    if create and not os.path.lexists(target):
        with target.open('xb'):
            pass
    state_backup._file(target)
    return path, actual


def _check(db, owner):
    actual = dict(db.execute("SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
    if actual != {table: 'table' for table in _EXPECTED} or any(
            tuple(r[1] for r in db.execute(f'PRAGMA table_info({table})')) != columns
            for table, columns in _EXPECTED.items()):
        raise ValueError('unknown or incomplete union backup schema')
    if dict(db.execute('SELECT key,value FROM meta')) != owner:
        raise ValueError('union backup database identity mismatch')


@contextmanager
def _session(path, owner=None, *, create=False, fault=None):
    path, owner = _repository(path, owner, create=create)
    with state_backup._repository_lock(path):
        _repository(path, owner)
        state_backup._single_database_journal(path/(DATABASE+'-journal'))
        db = sqlite3.connect((path/DATABASE).as_uri()+'?mode=rw', uri=True, timeout=0)
        try:
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA synchronous=FULL')
            # Native read triggers owned hot-journal recovery. Never manually
            # remove journals, disable foreign keys, or ignore WAL.
            empty = db.execute('SELECT 1 FROM sqlite_master LIMIT 1').fetchone() is None
            if db.execute('PRAGMA journal_mode').fetchone()[0].lower() != 'delete':
                raise ValueError('union repository must use rollback-journal mode')
            if empty:
                db.execute('BEGIN IMMEDIATE')
                for statement in (
                    'CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)',
                    'CREATE TABLE chunk(hash TEXT PRIMARY KEY,bytes INTEGER NOT NULL,data BLOB NOT NULL)',
                    'CREATE TABLE snapshot(id TEXT PRIMARY KEY,created TEXT NOT NULL,manifest_json TEXT NOT NULL)',
                    '''CREATE TABLE snapshot_chunk(snapshot_id TEXT NOT NULL REFERENCES snapshot(id),
                        chunk_hash TEXT NOT NULL REFERENCES chunk(hash),PRIMARY KEY(snapshot_id,chunk_hash))'''):
                    db.execute(statement)
                    if fault:
                        fault('schema_statement', db)
                db.executemany('INSERT INTO meta VALUES(?,?)', owner.items())
                db.commit()
            _check(db, owner)
            yield path, owner, db
        finally:
            if db.in_transaction:
                db.rollback()
            db.close()


@contextmanager
def _state_snapshot(repository, snapshot_id):
    """Read only a published state manifest: no lock creation or recovery."""
    repository, owner = state_backup._repository(repository)
    if os.path.lexists(repository/(state_backup.DATABASE+'-journal')):
        raise ValueError('state backup needs explicit writer recovery first')
    with cold_input(repository/state_backup.DATABASE), closing(state_backup._readonly(
            repository/state_backup.DATABASE)) as db:
        state_backup._check_repository(db, owner, verify_integrity=False)
        yield repository, owner, state_backup._manifest(db, snapshot_id, owner)


def _binding(value, catalog_instance, union_id):
    # Binding means exact declared summary, not an invented availability proof.
    if not isinstance(value, dict):
        raise ValueError('explicit canonical asset binding summary required')
    if any(key not in value for key in _ASSET_FIELDS):
        raise ValueError('incomplete canonical asset binding')
    value = {key: value[key] for key in _ASSET_FIELDS}
    literal = canonical(value)
    # The archive file always contains the whole union. A valid receipt for one
    # origin is NOT a proof for that file's other origins, even if its selected
    # references happen to be deep-verified and closure_complete was supplied.
    if value['verification_scope'] != 'whole_union' or value['origin_id'] is not None:
        raise ValueError('whole-union asset verification scope required')
    if value.get('catalog_instance') != catalog_instance or value.get('union_id') != union_id:
        raise ValueError('asset binding identity mismatch')
    if (value['schema'] != 'next-union-assets-1' or value['owner_id'] != union_id
            or value['cas_id'] != 'capture-next-objects:'+catalog_instance
            or any(type(value[key]) is not int or value[key] < 0 for key in
                   ('references', 'metadata_rows', 'available', 'missing', 'deep_verified'))
            or any(not isinstance(value[key], str) or not _HASH.fullmatch(value[key])
                   for key in ('reference_sha256', 'metadata_sha256'))
            or type(value['closure_complete']) is not bool
            or type(value['portable_restore_verified']) is not bool
            or value['integrity_scope'] not in ('metadata+pins+published_CAS_full_bytes',
                                               'metadata+pins+published_CAS_metadata_only')
            or value['message_media_association'] != 'not_implemented'):
        raise ValueError('invalid canonical asset binding summary')
    if (value['available']+value['missing'] != value['references']
            or value['deep_verified'] > value['available']
            or (value['closure_complete'] and (value['missing'] != 0
                or value['available'] != value['references']
                or value['deep_verified'] != value['references']
                or value['integrity_scope'] != 'metadata+pins+published_CAS_full_bytes'))):
        raise ValueError('inconsistent declared asset closure')
    return json.loads(literal), hashlib.sha256(literal.encode()).hexdigest()


def _file_map(entry):
    if (not isinstance(entry, dict) or set(entry) != {'sha256', 'bytes', 'chunks'}
            or not isinstance(entry['sha256'], str) or not _HASH.fullmatch(entry['sha256'])
            or type(entry['bytes']) is not int or entry['bytes'] < 1
            or not isinstance(entry['chunks'], list)
            or len(entry['chunks']) != (entry['bytes']+CHUNK_BYTES-1)//CHUNK_BYTES
            or any(not isinstance(key, str) or not _HASH.fullmatch(key) for key in entry['chunks'])):
        raise ValueError('invalid union file chunk map')


def _manifest(db, snapshot_id, owner):
    if not isinstance(snapshot_id, str) or not _HASH.fullmatch(snapshot_id):
        raise ValueError('invalid union snapshot ID')
    row = db.execute('SELECT manifest_json FROM snapshot WHERE id=?', (snapshot_id,)).fetchone()
    if not row:
        raise KeyError(snapshot_id)
    literal = row[0]
    if hashlib.sha256(literal.encode()).hexdigest() != snapshot_id:
        raise ValueError('union snapshot manifest authentication failed')
    value = json.loads(literal)
    keys = {'schema', 'catalog_instance', 'union_id', 'chunk_bytes', 'archive',
            'semantic_digest', 'state_companion', 'asset_binding', 'asset_binding_sha256', 'origin_archive',
            'protected_roots'}
    if (not isinstance(value, dict) or set(value) != keys or canonical(value) != literal
            or value['schema'] != SCHEMA or value['chunk_bytes'] != CHUNK_BYTES
            or value['catalog_instance'] != owner['catalog_instance'] or value['union_id'] != owner['union_id']
            or not isinstance(value['semantic_digest'], str) or not _HASH.fullmatch(value['semantic_digest'])):
        raise ValueError('invalid union snapshot manifest')
    state_backup._external_root(value['origin_archive'])
    if not isinstance(value['protected_roots'], list):
        raise ValueError('protected input roots missing')
    for root in value['protected_roots']:
        state_backup._external_root(root)
    _file_map(value['archive'])
    companion = value['state_companion']
    if (not isinstance(companion, dict) or set(companion) != {'schema', 'snapshot_id', 'catalog_instance',
            'catalog_sha256', 'objects_sha256'} or companion['schema'] != state_backup.SCHEMA
            or companion['catalog_instance'] != owner['catalog_instance']
            or any(not isinstance(companion[key], str) or not _HASH.fullmatch(companion[key])
                   for key in ('snapshot_id', 'catalog_sha256', 'objects_sha256'))):
        raise ValueError('invalid state companion binding')
    _, digest = _binding(value['asset_binding'], owner['catalog_instance'], owner['union_id'])
    if digest != value['asset_binding_sha256']:
        raise ValueError('asset summary digest mismatch')
    actual = {r[0] for r in db.execute('SELECT chunk_hash FROM snapshot_chunk WHERE snapshot_id=?', (snapshot_id,))}
    if actual != set(value['archive']['chunks']):
        raise ValueError('union snapshot chunk references mismatch')
    if db.execute('''SELECT 1 FROM snapshot_chunk r LEFT JOIN chunk c ON c.hash=r.chunk_hash
            WHERE r.snapshot_id=? AND c.hash IS NULL LIMIT 1''', (snapshot_id,)).fetchone():
        raise ValueError('union snapshot chunk missing')
    return value


def _freeze_state_inputs(stack, paths):
    """Reuse one byte proof ONLY under a successful mandatory Windows guard.

    Owned services may retain write-capable SQLite handles while idle. Windows
    then rejects the share-read-only guard; only that sharing conflict falls
    back to the original two full hashes. Other failures remain fail-closed.
    Guards that succeeded stay held through publication, including when another
    file falls back. No proof/cache escapes this ExitStack/backup operation.
    """
    from .compare import _input
    proofs = {}
    for path in paths:
        _input(path)
        proofs[path] = None
        if os.name != 'nt':
            continue
        try:
            stack.enter_context(cold_input(path))
        except OSError as error:
            if getattr(error, 'winerror', None) not in (32, 33):
                raise
        else:
            proofs[path] = stamp(path)
    return proofs


def backup_archive(union_path, state_repository, state_snapshot_id, out, *,
                   state_catalog, state_objects, asset_binding, fault=None):
    """Snapshot cold union; state bytes MUST equal the post-pin companion cut.

    Creates only a new-format union repository, never touches the state backup.
    Readback proofs/cache live for one repository transaction only. Cold Windows
    state files held against writes/delete need one full hash; a retained writer
    handle or non-Windows platform preserves the two-full-hash fallback.
    """
    source = state_backup._absolute(union_path)
    output = state_backup._parents(out)
    owner = _union_owner(source)
    state_paths = [state_backup._absolute(p) for p in (state_catalog, state_objects)]
    state_repo = state_backup._absolute(state_repository)
    for protected in (source.parent, state_repo, *(p.parent for p in state_paths)):
        if state_backup._overlap(output, protected):
            raise ValueError('union backup output overlaps an input tree')
    with ExitStack() as stack:
        stack.enter_context(cold_input(source))
        from .compare import _input
        state_proofs = _freeze_state_inputs(stack, state_paths)
        _, state_owner, companion_manifest = stack.enter_context(_state_snapshot(state_repo, state_snapshot_id))
        if state_owner['catalog_instance'] != owner['catalog_instance']:
            raise ValueError('state/union catalog identity mismatch')
        protected_roots = {str(source.parent), str(state_repo), companion_manifest['origin_state'],
                           *companion_manifest['source_roots'], *(str(p.parent) for p in state_paths)}
        if companion_manifest['source_roots']:
            protected_roots.add(str(state_backup._external_root(companion_manifest['source_roots'][0]).parent))
        for root in protected_roots:
            if state_backup._overlap(output, state_backup._external_root(root)):
                raise ValueError('union backup output overlaps a state or live-source tree')
        for name, path in zip(('catalog.sqlite', 'objects.sqlite'), state_paths):
            if digest_file(path) != companion_manifest['files'][name]['sha256']:
                raise ValueError('state snapshot is not the exact post-pin catalog/CAS cut')
        reader = stack.enter_context(closing(cold_reader(source)))
        metadata = dict(reader.execute('SELECT key,value FROM archive_meta'))
        if metadata.get('schema_version') != SCHEMA_VERSION:
            raise ValueError('compact formal union required')
        union_id = _uuid(metadata.get('next_union_id'))
        binding, binding_sha = _binding(asset_binding, owner['catalog_instance'], union_id)
        repo_owner = dict(schema=SCHEMA, catalog_instance=owner['catalog_instance'], union_id=union_id)
        companion = dict(schema=state_backup.SCHEMA, snapshot_id=state_snapshot_id,
            catalog_instance=owner['catalog_instance'],
            catalog_sha256=companion_manifest['files']['catalog.sqlite']['sha256'],
            objects_sha256=companion_manifest['files']['objects.sqlite']['sha256'])
        with _session(output, repo_owner, create=True, fault=fault) as (_, _, db):
            db.execute('BEGIN IMMEDIATE')
            entry, _, added = state_backup._add_file(db, source, verified_blocks=OrderedDict())
            if fault:
                fault('chunks', db)
            # A prior snapshot with the identical authenticated archive bytes is
            # already a semantic proof for those exact bytes, independent of the
            # state snapshot/attachment availability changing around it.
            previous = db.execute("SELECT manifest_json FROM snapshot WHERE json_extract(manifest_json,'$.archive.sha256')=? LIMIT 1",
                                  (entry['sha256'],)).fetchone()
            if previous:
                prior_id = hashlib.sha256(previous[0].encode()).hexdigest()
                semantic = _manifest(db, prior_id, repo_owner)['semantic_digest']
            else:
                semantic = CompactArchive.semantic_digest(SimpleNamespace(_db=reader))
            manifest = dict(schema=SCHEMA, catalog_instance=owner['catalog_instance'], union_id=union_id,
                chunk_bytes=CHUNK_BYTES, archive=entry, semantic_digest=semantic, state_companion=companion,
                asset_binding=binding, asset_binding_sha256=binding_sha, origin_archive=str(source),
                protected_roots=sorted(protected_roots))
            literal = canonical(manifest)
            identity = hashlib.sha256(literal.encode()).hexdigest()
            noop = db.execute('SELECT 1 FROM snapshot WHERE id=?', (identity,)).fetchone() is not None
            for name, path in zip(('catalog.sqlite', 'objects.sqlite'), state_paths):
                _input(path)
                if state_proofs[path] is not None:
                    # The prior full SHA authenticates bytes that the OS still
                    # forbids anyone from changing. Stamp is only the final path
                    # identity check, never a substitute for an unguarded hash.
                    unchanged = stamp(path) == state_proofs[path]
                else:
                    unchanged = digest_file(path) == companion_manifest['files'][name]['sha256']
                if not unchanged:
                    raise ValueError('state companion changed during union backup')
            if noop:
                db.rollback()
            else:
                db.execute('INSERT INTO snapshot VALUES(?,?,?)', (identity, utcnow(), literal))
                db.executemany('INSERT INTO snapshot_chunk VALUES(?,?)',
                               ((identity, key) for key in sorted(set(entry['chunks']))))
                if fault:
                    fault('snapshot', db)
                _manifest(db, identity, repo_owner)
                db.commit()
            return dict(schema=SCHEMA, snapshot_id=identity, noop=noop, new_chunks=0 if noop else added,
                archive_sha256=entry['sha256'], archive_bytes=entry['bytes'], state_companion=companion,
                asset_binding_sha256=binding_sha, metadata_only=True, attachments_closed=False)


def inspect_snapshot(repository, snapshot_id):
    with _session(repository) as (_, owner, db):
        return _manifest(db, snapshot_id, owner)


def _offline_companion(offline_state, companion):
    root = state_backup._parents(offline_state.state)
    from .compare import _input
    for name, key in (('catalog.sqlite', 'catalog_sha256'), ('objects.sqlite', 'objects_sha256')):
        path = _input(root/name)
        if digest_file(path) != companion[key]:
            raise ValueError('offline state is not the exact companion snapshot')


def restore_archive(repository, snapshot_id, out, *, as_file=False,
                    offline_state=None, asset_verifier=None, fault=None):
    """Fresh offline restoration with explicit metadata/attachment scope.

    Partial outputs are retained on failure. Full attachment closure requires a
    caller-supplied offline state plus verifier; no live state is constructed.
    """
    if type(as_file) is not bool or (offline_state is None) != (asset_verifier is None):
        raise ValueError('offline state and asset verifier must be supplied together')
    repository = state_backup._parents(repository)
    output = state_backup._absolute(out)
    state_backup._parents(output.parent)
    if os.path.lexists(output) or state_backup._overlap(output, repository):
        raise ValueError('restore requires a fresh non-overlapping output')
    with _session(repository) as (_, owner, db):
        db.execute('BEGIN')
        manifest = _manifest(db, snapshot_id, owner)
        origin = state_backup._external_root(manifest['origin_archive'])
        if state_backup._overlap(output, origin.parent):
            raise ValueError('restore overlaps original union tree')
        for root in manifest['protected_roots']:
            if state_backup._overlap(output, state_backup._external_root(root)):
                raise ValueError('restore overlaps a protected state, repository or live-source tree')
        ancestor = output.parent
        while not ancestor.exists():
            ancestor = ancestor.parent
        if shutil.disk_usage(ancestor).free < manifest['archive']['bytes']+state_backup.RESTORE_MARGIN_BYTES:
            raise state_backup.InsufficientRestoreSpace('insufficient space for union restore')
        if as_file:
            output.parent.mkdir(parents=True, exist_ok=True)
            target = output
            partial = output.with_name(output.name+'.RESTORE.partial.private.json')
            complete = output.with_name(output.name+'.RESTORE.complete.private.json')
            if os.path.lexists(partial) or os.path.lexists(complete):
                raise ValueError('restore markers already exist')
            for suffix in ('-journal', '-wal', '-shm'):
                if os.path.lexists(target.with_name(target.name+suffix)):
                    raise ValueError('restore target has an existing SQLite sidecar')
        else:
            output.mkdir(parents=True, exist_ok=False)
            target = output/'archive.wua.sqlite'
            partial, complete = output/'RESTORE.partial.private.json', output/'RESTORE.complete.private.json'
        write_json_new(partial, dict(schema=SCHEMA, snapshot_id=snapshot_id, status='partial'))
        state_backup._restore_file(db, target, manifest['archive'])
        if fault:
            fault('file_restored', target)
        with CompactArchive(target) as archive:
            identity = archive._db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()
            if identity is None or identity[0] != owner['union_id']:
                raise ValueError('restored union identity mismatch')
            integrity = archive.integrity_check()  # Writable SAVEPOINT checks FTS.
            if integrity['quick_check'] != ['ok'] or integrity['foreign_key_check']:
                raise ValueError('restored union integrity failed')
            if archive.semantic_digest() != manifest['semantic_digest']:
                raise ValueError('restored union semantic digest mismatch')
            attachments_closed = False
            attachment_result = None
            if asset_verifier is not None:
                _offline_companion(offline_state, manifest['state_companion'])
                attachment_result = asset_verifier(archive, offline_state)
                # Equality authenticates the declared binding only. The callback
                # must explicitly assert closure; counts are never guessed here.
                actual, actual_sha = _binding(attachment_result, owner['catalog_instance'], owner['union_id'])
                if actual_sha != manifest['asset_binding_sha256']:
                    raise ValueError('offline asset binding differs from snapshot')
                attachments_closed = actual['closure_complete'] is True
                if not attachments_closed:
                    raise ValueError('offline verifier did not establish attachment closure')
                _offline_companion(offline_state, manifest['state_companion'])
        if digest_file(target) != manifest['archive']['sha256']:
            raise ValueError('verification changed restored archive bytes')
        result = dict(schema=SCHEMA, snapshot_id=snapshot_id, archive=str(target), integrity=integrity,
            semantic_digest=manifest['semantic_digest'], state_companion=manifest['state_companion'],
            asset_binding=manifest['asset_binding'], metadata_only=not attachments_closed,
            attachments_closed=attachments_closed, attachment_verification=attachment_result,
            capture_started=False, login_started=False)
        write_json_new(complete, result)
        # Preserve the partial receipt as history; a completion receipt is the
        # sole success marker. No automatic deletion, including on failure.
        return result
