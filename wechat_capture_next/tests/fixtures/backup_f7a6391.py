"""Independent, offline-restorable CAS snapshots for capture-next.

The caller MUST hold the state's OS writer_lock for backup(), before opening
the service. Only owned state databases are checkpointed; live sources are
never opened here. A snapshot contains complete file chunk maps, not deltas or
parent dependencies. Repositories and restore directories are never adopted.
"""
from contextlib import ExitStack, closing, contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import sqlite3
import stat
import zlib

from wechat_capture_v2.common import canonical, digest_file, regular, directory, stamp, utcnow, write_json_new
from .service import CaptureService, MODE
from .catalog import Catalog, FORMAT
from .sync_wua import catalog_identity
from wechat_capture_v2.objects import Objects
from .paths import local_absolute

SCHEMA = 'next-cas-backup-1'
CHUNK_BYTES = 1024 * 1024
DATABASE = 'repository.sqlite'
SECRETS = '90_SECRETS_PLAINTEXT_RESTRICTED/keyring.json'
_HASH = re.compile(r'[0-9a-f]{64}\Z')
_REQUIRED = {'config.private.json', 'next.private.json', 'catalog.sqlite', 'objects.sqlite'}
RESTORE_MARGIN_BYTES = 64 * 1024 * 1024


class InsufficientRestoreSpace(OSError):
    """A fresh restore was refused before creating any output directory."""


def _absolute(path):
    # abspath is lexical: unlike resolve(), it must not follow source links.
    return local_absolute(path, allow_relative=True)


def _parents(path):
    path = _absolute(path)
    for part in reversed((path, *path.parents)):
        if os.path.lexists(part):
            directory(part)
    return path


def _file(path):
    info = regular(path)
    if info.st_nlink != 1:
        raise ValueError('hardlinked files are outside backup/restore scope')
    return info


def _overlap(a, b):
    return a.is_relative_to(b) or b.is_relative_to(a)


def _external_root(value):
    if not isinstance(value, str):
        raise ValueError('source roots must be absolute local paths')
    return local_absolute(value, lexical=True)


def _source_roots(config):
    return [str(_external_root(config[key])) for key in ('database_root', 'asset_root') if config.get(key)]


def _guard_location(path, state, roots):
    path = _parents(path)
    protected = [state, *map(_external_root, roots)]
    if roots:
        # database_root is usually the account's db_storage subtree. Media,
        # configuration and other account files beside it are live source too.
        protected.append(_external_root(roots[0]).parent)
    for root in protected:
        if _overlap(path, root):
            raise ValueError('backup/restore location overlaps a state or live-source tree')
    return path


def _walk(root):
    directory(root)
    for child in sorted(root.iterdir()):
        info = child.lstat()
        if child.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('linked tree entries are forbidden')
        if stat.S_ISDIR(info.st_mode):
            yield from _walk(child)
        else:
            _file(child)
            yield child


def _sidecars(path, *, forbidden=False):
    for suffix in ('-wal', '-shm', '-journal'):
        child = path.with_name(path.name + suffix)
        if os.path.lexists(child):
            _file(child)
            if forbidden:
                raise ValueError('closed state database has a sidecar')


def _integrity(db):
    if [r[0] for r in db.execute('PRAGMA integrity_check')] != ['ok']:
        raise ValueError('SQLite integrity check failed')
    if list(db.execute('PRAGMA foreign_key_check')):
        raise ValueError('SQLite foreign-key check failed')


def _readonly(path, *, immutable=True):
    _file(path)
    db = sqlite3.connect(path.as_uri() + '?mode=ro' + ('&immutable=1' if immutable else ''), uri=True)
    db.execute('PRAGMA query_only=ON')
    db.execute('PRAGMA trusted_schema=OFF')
    return db


def _manifest_path(value):
    if (not isinstance(value, str) or '\\' in value
            or any(ord(c) < 32 or c in '<>:"|?*' for c in value)):
        raise ValueError('invalid manifest path')
    path = PurePosixPath(value)
    if (path.is_absolute() or not path.parts or path.as_posix() != value
            or any(p in ('', '.', '..') or p.endswith((' ', '.')) for p in value.split('/'))):
        raise ValueError('manifest path traversal or alias')
    # Narrow restoration scope; never permit database sidecars or writer locks.
    allowed = value in _REQUIRED or value == SECRETS
    allowed |= bool(re.fullmatch(r'cache/[0-9a-f]{64}\.(db|pages\.sqlite)', value))
    allowed |= len(path.parts) >= 2 and path.parts[0] == 'reports' and path.suffix == '.json'
    if not allowed or any(PureWindowsPath(p).is_reserved() for p in path.parts):
        raise ValueError('manifest file outside the next backup format')
    return value


def _repository(path, owner=None, *, create=False):
    path = _parents(path)
    if not os.path.lexists(path):
        if not create or owner is None:
            raise FileNotFoundError('backup repository does not exist')
        path.mkdir(parents=True, exist_ok=False)
        write_json_new(path/'OWNER.private.json', owner)
    else:
        directory(path)
    marker = path/'OWNER.private.json'
    _file(marker)
    actual = json.loads(marker.read_text(encoding='utf-8'))
    if (not isinstance(actual, dict) or set(actual) != {'schema', 'catalog_instance'}
            or actual.get('schema') != SCHEMA or not isinstance(actual.get('catalog_instance'), str)
            or not actual['catalog_instance'] or (owner is not None and actual != owner)):
        raise ValueError('foreign repository owner; adoption is forbidden')
    allowed = {'OWNER.private.json', DATABASE, DATABASE+'-journal', 'repository.lock'}
    for child in path.iterdir():
        _file(child)
        if child.name not in allowed:
            raise ValueError('unexpected repository entry or unsupported SQLite sidecar')
    target = path/DATABASE
    if create and not target.exists():
        # A pre-existing owner-only directory is resumable only with exact owner.
        with target.open('xb'):
            pass
    _file(target)
    return path, actual


@contextmanager
def _repository_lock(path):
    """A separate OS lock survives neither process death nor interrupted SQL.

    Unlike SQLite's own journal locks this covers recovery plus the transition
    to a read-only connection, so no cooperating writer can race that cut.
    """
    target = path/'repository.lock'
    if os.path.lexists(target):
        _file(target)
    stream = target.open('a+b')
    try:
        _file(target)
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        stream.close()


def _single_database_journal(path):
    """Our writer never ATTACHes; reject superjournal references before SQLite.

    Standard SQLite recovery may inspect a superjournal pathname embedded in
    the journal footer. No repository input may make it follow an external path.
    This is validation only: journal removal/replay belongs solely to SQLite.
    """
    if not os.path.lexists(path):
        return
    size = _file(path).st_size
    if size < 16:
        return
    with path.open('rb') as stream:
        stream.seek(-16, os.SEEK_END)
        tail = stream.read(16)
    if tail[-8:] == b'\xd9\xd5\x05\xf9\x20\xa1\x63\xd7':
        # Footer magic is used for multi-database transactions only. Refuse
        # even malformed footer lengths instead of asking SQLite to interpret.
        raise ValueError('repository rollback journal has a forbidden superjournal footer')


def _writer(path, owner, *, fault=None):
    """Recover with standard SQLite rollback and atomically initialize empties.

    Caller holds the repository OS lock and has checked every filesystem entry.
    A zero-schema owned database is retryable; any nonempty unknown/partial
    schema is fail-closed. fault is a test-only process-crash injection hook.
    """
    _single_database_journal(path/(DATABASE+'-journal'))
    db = sqlite3.connect((path/DATABASE).as_uri()+'?mode=rw', uri=True, timeout=0)
    try:
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA synchronous=FULL')
        # This ordinary read triggers any hot rollback journal recovery BEFORE
        # schema validation, unlike immutable=1 which would ignore the journal.
        empty = db.execute('SELECT 1 FROM sqlite_master LIMIT 1').fetchone() is None
        if db.execute('PRAGMA journal_mode').fetchone()[0].casefold() != 'delete':
            raise ValueError('unsupported repository journal mode; only rollback-journal repositories are owned')
        if empty:
            if fault:
                fault('schema_begin', db)
            db.execute('BEGIN IMMEDIATE')
            statements = (
                'CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)',
                'CREATE TABLE chunk(hash TEXT PRIMARY KEY,bytes INTEGER NOT NULL,data BLOB NOT NULL)',
                'CREATE TABLE snapshot(id TEXT PRIMARY KEY,created TEXT NOT NULL,manifest_json TEXT NOT NULL)',
                '''CREATE TABLE snapshot_chunk(snapshot_id TEXT NOT NULL REFERENCES snapshot(id),
                    chunk_hash TEXT NOT NULL REFERENCES chunk(hash),PRIMARY KEY(snapshot_id,chunk_hash))''')
            for statement in statements:
                db.execute(statement)
                if fault:
                    fault('schema_statement', db)
            db.executemany('INSERT INTO meta VALUES(?,?)', [('schema', SCHEMA), ('catalog_instance', owner['catalog_instance'])])
            if fault:
                fault('schema_before_commit', db)
            db.commit()
        _check_repository(db, owner)
        return db
    except BaseException:
        db.rollback()
        db.close()
        raise


def _check_repository(db, owner, *, verify_integrity=True):
    expected = {'meta': ('key', 'value'), 'chunk': ('hash', 'bytes', 'data'),
        'snapshot': ('id', 'created', 'manifest_json'), 'snapshot_chunk': ('snapshot_id', 'chunk_hash')}
    actual = dict(db.execute("SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
    if actual != {name: 'table' for name in expected}:
        raise ValueError('unknown or incomplete repository schema; refusing adoption or repair')
    if any(tuple(row[1] for row in db.execute(f'PRAGMA table_info({name})')) != columns
            for name, columns in expected.items()):
        raise ValueError('unknown or incomplete repository table shape')
    if dict(db.execute('SELECT key,value FROM meta')) != {'schema': SCHEMA, 'catalog_instance': owner['catalog_instance']}:
        raise ValueError('repository database identity mismatch')
    if verify_integrity:
        _integrity(db)


@contextmanager
def _repository_session(path, owner=None, *, create=False, readonly=False):
    """Safely recover the owned repository, then hold a stable writer/RO cut."""
    path, owner = _repository(path, owner, create=create)
    with _repository_lock(path):
        # Revalidate after taking the lock, including journal/lock link counts.
        _repository(path, owner)
        had_journal = os.path.lexists(path/(DATABASE+'-journal'))
        with closing(_writer(path, owner)) as writer:
            if not readonly:
                yield path, owner, writer, had_journal
                return
        _repository(path, owner)
        with closing(_readonly(path/DATABASE, immutable=False)) as reader:
            reader.execute('BEGIN')
            _check_repository(reader, owner)
            yield path, owner, reader, had_journal


def recover_repository(repository):
    """Recover this owned repository with SQLite, never delete journals by hand.

    Recovery may change repository bytes. All normal snapshot APIs perform the
    same operation automatically before reading, under the independent OS lock.
    No configured live source or state path is opened by this entry point.
    """
    with _repository_session(repository) as (path, owner, db, had_journal):
        return dict(repository=str(path), journal_present=had_journal,
            recovery='sqlite_standard_rollback', snapshots=db.execute('SELECT count(*) FROM snapshot').fetchone()[0])


@contextmanager
def _frozen(service):
    state = _parents(service.state)
    for obj, name in ((service.catalog, 'catalog.sqlite'), (service.objects, 'objects.sqlite')):
        target = state/name
        _file(target)
        _sidecars(target)
        actual = obj.db.execute('PRAGMA database_list').fetchone()[2]
        if _absolute(actual) != target or obj.db.in_transaction:
            raise ValueError('backup requires owned databases at a transaction boundary')
    # This performs no source acquisition, and refuses unaccepted current views.
    service.verify_state()
    with ExitStack() as stack:
        for obj in (service.catalog, service.objects):
            _integrity(obj.db)
            result = obj.db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
            if result[0] or result[1] != 0 or result[2] != 0:
                raise ValueError('owned SQLite checkpoint is busy or incomplete')
        try:
            for obj in (service.catalog, service.objects):
                obj.db.execute('BEGIN IMMEDIATE')
                stack.callback(obj.db.rollback)
            yield
        finally:
            pass


def _files(service, include_secrets):
    state = service.state
    names = set(_REQUIRED)
    cache = state/'cache'
    directory(cache)
    for path in _walk(cache):
        if path.suffix in ('.dirty', '.pending'):
            raise ValueError('unaccepted dirty/pending view cannot be backed up')
    for relative, in service.catalog.db.execute('SELECT relative_path FROM checkpoint WHERE source_id=?',
            (service.config['source_id'],)):
        view = service.view_path(relative)
        names.add(view.relative_to(state).as_posix())
        names.add(view.with_suffix('.pages.sqlite').relative_to(state).as_posix())
    reports = state/'reports'
    directory(reports)
    names.update(path.relative_to(state).as_posix() for path in _walk(reports))
    if include_secrets:
        if not os.path.lexists(state/SECRETS):
            raise FileNotFoundError('include_secrets=True requires the state keyring file')
        names.add(SECRETS)
    result = []
    for name in sorted(names):
        _manifest_path(name)
        path = state/name
        _parents(path.parent)
        _file(path)
        if name.startswith('cache/'):
            _sidecars(path, forbidden=True)
            if name.endswith('.pages.sqlite'):
                with closing(_readonly(path)) as db:
                    _integrity(db)
        result.append((name, path))
    return result


def _consistent_config(service):
    """Refuse asset-root binding transitions and stale in-memory configuration."""
    state = service.state
    for name in ('asset-root-change.private.json', 'asset-root-config.private.json'):
        if os.path.lexists(state/name):
            raise ValueError('asset-root configuration transition must be completed before backup')
    target = state/'config.private.json'
    _file(target)
    actual = json.loads(target.read_text(encoding='utf-8'))
    if actual != service.config:
        raise ValueError('disk and service configuration differ; reopen a consistent state')
    binding = canonical({key: actual.get(key) for key in
        ('source_id', 'account_alias', 'self_username', 'database_root', 'asset_root')})
    row = service.catalog.db.execute("SELECT value FROM meta WHERE key='source_binding'").fetchone()
    if row is None or row[0] != binding:
        raise ValueError('disk configuration and catalog source/account binding differ')
    return actual


def _add_file(db, path):
    before = stamp(path)
    digest = hashlib.sha256()
    chunks = []
    total = added = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(CHUNK_BYTES), b''):
            key = hashlib.sha256(block).hexdigest()
            digest.update(block)
            total += len(block)
            chunks.append(key)
            existing = db.execute('SELECT bytes FROM chunk WHERE hash=?', (key,)).fetchone()
            if existing is None:
                db.execute('INSERT INTO chunk VALUES(?,?,?)', (key, len(block), zlib.compress(block, 1)))
                added += 1
            elif existing[0] != len(block):
                raise ValueError('CAS chunk length collision')
            elif _block(db, key) != block:
                raise ValueError('existing CAS chunk differs from source')
    if stamp(path) != before:
        raise RuntimeError('state file changed during backup')
    return dict(sha256=digest.hexdigest(), bytes=total, chunks=chunks), before, added


def backup(service, repository, include_secrets=False):
    """Capture an incremental snapshot; caller owns writer_lock(service.state).

    include_secrets is opt-in. Plaintext views/reports are sensitive even when
    encryption keys are excluded. No-op calls do not modify repository bytes.
    """
    if type(include_secrets) is not bool:
        raise TypeError('include_secrets must be boolean')
    if getattr(service, '_pending_asset', None) is not None:
        raise ValueError('finish pending asset chunk publication before backup')
    state = _parents(service.state)
    _consistent_config(service)
    roots = _source_roots(service.config)
    repository = _guard_location(repository, state, roots)
    # Identity creation is an owned-catalog write, before freezing SQLite.
    for name in _REQUIRED:
        _file(state/name)
    for obj, name in ((service.catalog, 'catalog.sqlite'), (service.objects, 'objects.sqlite')):
        _sidecars(state/name)
        if obj.db.in_transaction:
            raise ValueError('backup requires an existing transaction boundary')
    # Reject linked cache/secret/report paths before verify_state can read them.
    files = _files(service, include_secrets)
    identity = catalog_identity(service)
    owner = dict(schema=SCHEMA, catalog_instance=identity)
    with _frozen(service):
        _consistent_config(service)
        if files != _files(service, include_secrets):
            raise RuntimeError('backup inventory changed while freezing state')
        with _repository_session(repository, owner, create=True) as (repository, owner, db, recovered):
            try:
                db.execute('BEGIN IMMEDIATE')
                manifest = dict(schema=SCHEMA, catalog_instance=identity, chunk_bytes=CHUNK_BYTES,
                    origin_state=str(state), source_roots=roots,
                    include_secrets=any(name == SECRETS for name, path in files), files={})
                stamps = []
                added = logical = 0
                for name, path in files:
                    entry, before, count = _add_file(db, path)
                    manifest['files'][name] = entry
                    stamps.append((path, before))
                    added += count
                    logical += entry['bytes']
                if any(stamp(path) != before for path, before in stamps):
                    raise RuntimeError('state cut changed before snapshot publication')
                text = canonical(manifest)
                ident = hashlib.sha256(text.encode()).hexdigest()
                last = db.execute('SELECT id FROM snapshot ORDER BY rowid DESC LIMIT 1').fetchone()
                # Returning to an older identical cut can reuse that immutable
                # snapshot too, without manufacturing another repository write.
                reused = db.execute('SELECT 1 FROM snapshot WHERE id=?', (ident,)).fetchone() is not None
                noop = last is not None and (last[0] == ident or reused)
                if noop:
                    # No writes were needed for existing chunks; rollback keeps
                    # the complete repository file bit-for-bit identical.
                    db.rollback()
                else:
                    db.execute('INSERT INTO snapshot VALUES(?,?,?)', (ident, utcnow(), text))
                    refs = {key for item in manifest['files'].values() for key in item['chunks']}
                    db.executemany('INSERT INTO snapshot_chunk VALUES(?,?)', ((ident, key) for key in sorted(refs)))
                    db.commit()
                return dict(snapshot_id=ident, noop=noop, files=len(files), logical_bytes=logical,
                    new_chunks=0 if noop else added, includes_secrets=SECRETS in manifest['files'], repository=str(repository))
            except BaseException:
                db.rollback()
                raise


def _manifest(db, ident, owner):
    if not isinstance(ident, str) or not _HASH.fullmatch(ident):
        raise ValueError('invalid snapshot identifier')
    row = db.execute('SELECT manifest_json FROM snapshot WHERE id=?', (ident,)).fetchone()
    if row is None:
        raise KeyError('snapshot not found')
    text = row[0]
    if not isinstance(text, str) or hashlib.sha256(text.encode()).hexdigest() != ident:
        raise ValueError('snapshot manifest authentication failed')
    value = json.loads(text)
    if (canonical(value) != text or set(value) != {'schema', 'catalog_instance', 'chunk_bytes',
            'origin_state', 'source_roots', 'include_secrets', 'files'} or value['schema'] != SCHEMA
            or value['catalog_instance'] != owner['catalog_instance'] or value['chunk_bytes'] != CHUNK_BYTES
            or type(value['include_secrets']) is not bool or not isinstance(value['source_roots'], list)
            or not isinstance(value['files'], dict) or not _REQUIRED.issubset(value['files'])):
        raise ValueError('unsupported or incomplete snapshot manifest')
    _external_root(value['origin_state'])
    for root in value['source_roots']:
        _external_root(root)
    if SECRETS in value['files'] and not value['include_secrets']:
        raise ValueError('manifest unexpectedly contains secrets')
    folded = set()
    refs = set()
    for name, entry in value['files'].items():
        _manifest_path(name)
        if name.casefold() in folded:
            raise ValueError('case-aliased manifest paths')
        folded.add(name.casefold())
        if (not isinstance(entry, dict) or set(entry) != {'sha256', 'bytes', 'chunks'}
                or not isinstance(entry['sha256'], str) or not _HASH.fullmatch(entry['sha256'])
                or type(entry['bytes']) is not int or entry['bytes'] < 0 or not isinstance(entry['chunks'], list)
                or len(entry['chunks']) != (entry['bytes'] + CHUNK_BYTES - 1)//CHUNK_BYTES
                or any(not isinstance(key, str) or not _HASH.fullmatch(key) for key in entry['chunks'])):
            raise ValueError('invalid snapshot file map')
        refs.update(entry['chunks'])
    actual = {r[0] for r in db.execute('SELECT chunk_hash FROM snapshot_chunk WHERE snapshot_id=?', (ident,))}
    if actual != refs:
        raise ValueError('snapshot chunk reference set mismatch')
    if db.execute('''SELECT 1 FROM snapshot_chunk r LEFT JOIN chunk c ON c.hash=r.chunk_hash
            WHERE r.snapshot_id=? AND c.hash IS NULL LIMIT 1''', (ident,)).fetchone():
        raise ValueError('snapshot refers to a missing chunk')
    return value


def list_snapshots(repository):
    """Metadata-only after safe owned-repository recovery, never source reads."""
    with _repository_session(repository, readonly=True) as (repository, owner, db, recovered):
        result = []
        for ident, created in db.execute('SELECT id,created FROM snapshot ORDER BY rowid'):
            manifest = _manifest(db, ident, owner)
            result.append(dict(snapshot_id=ident, created=created, files=len(manifest['files']),
                logical_bytes=sum(item['bytes'] for item in manifest['files'].values()),
                includes_secrets=SECRETS in manifest['files']))
        return result


def list_published_snapshots(repository):
    """Read an already-published cut without creating locks or recovering it.

    HTTP readers must not call the recovery-capable snapshot API. A journal
    requires an explicit writer operation; even an empty journal is refused.
    SQLite's read transaction protects this cut against cooperating writers.
    Only schema/identity, manifest hashes and reference metadata are validated:
    no full integrity scan or chunk payload reads. This is NOT content proof.
    """
    repository, owner = _repository(repository)
    if os.path.lexists(repository/(DATABASE+'-journal')):
        raise BlockingIOError('backup repository requires a writer recovery boundary')
    with closing(_readonly(repository/DATABASE, immutable=False)) as db:
        db.execute('BEGIN')
        _check_repository(db, owner, verify_integrity=False)
        result = []
        for ident, created in db.execute('SELECT id,created FROM snapshot ORDER BY rowid'):
            manifest = _manifest(db, ident, owner)
            result.append(dict(snapshot_id=ident, created=created, files=len(manifest['files']),
                logical_bytes=sum(item['bytes'] for item in manifest['files'].values()),
                includes_secrets=SECRETS in manifest['files']))
        return result


def inspect_snapshot(repository, snapshot_id):
    with _repository_session(repository, readonly=True) as (repository, owner, db, recovered):
        return _manifest(db, snapshot_id, owner)


def _block(db, key):
    row = db.execute('SELECT bytes,data FROM chunk WHERE hash=?', (key,)).fetchone()
    if row is None:
        raise ValueError('snapshot chunk missing')
    size, payload = row
    if type(size) is not int or not 0 < size <= CHUNK_BYTES:
        raise ValueError('chunk size outside backup format')
    decoder = zlib.decompressobj()
    try:
        block = decoder.decompress(payload, CHUNK_BYTES + 1)
    except zlib.error as exc:
        raise ValueError('snapshot chunk compression corrupt') from exc
    if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or len(block) != size or hashlib.sha256(block).hexdigest() != key):
        raise ValueError('snapshot chunk authentication failed')
    return block


def _config_from_cas(db, manifest):
    """Validate actual configuration before creating any restore output.

    Only small configuration metadata is accumulated, never SQLite payloads.
    The manifest's claimed source boundaries are not accepted on their own.
    """
    entry = manifest['files']['config.private.json']
    digest = hashlib.sha256()
    parts = []
    size = 0
    for i, key in enumerate(entry['chunks']):
        block = _block(db, key)
        if len(block) != min(CHUNK_BYTES, entry['bytes'] - i*CHUNK_BYTES):
            raise ValueError('configuration chunk boundary mismatch')
        parts.append(block)
        digest.update(block)
        size += len(block)
    if size != entry['bytes'] or digest.hexdigest() != entry['sha256']:
        raise ValueError('configuration file authentication failed')
    config = json.loads(b''.join(parts).decode('utf-8'))
    if (not isinstance(config, dict) or config.get('schema') != 'wechat-capture-v2-config-1'
            or not isinstance(config.get('source_id'), str) or not config['source_id']
            or not config.get('database_root') or _source_roots(config) != manifest['source_roots']):
        raise ValueError('configuration source roots differ from manifest')
    return config


def _restore_file(db, path, entry):
    _parents(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    total = 0
    with path.open('xb') as output:
        for i, key in enumerate(entry['chunks']):
            block = _block(db, key)
            expected = min(CHUNK_BYTES, entry['bytes'] - i*CHUNK_BYTES)
            if len(block) != expected:
                raise ValueError('snapshot fixed chunk boundary mismatch')
            output.write(block)
            digest.update(block)
            total += len(block)
        output.flush()
        os.fsync(output.fileno())
    if total != entry['bytes'] or digest.hexdigest() != entry['sha256'] or digest_file(path) != entry['sha256']:
        raise ValueError('restored file readback hash mismatch')


def _verify_restored(output, manifest):
    config = json.loads((output/'config.private.json').read_text(encoding='utf-8'))
    if _source_roots(config) != manifest['source_roots']:
        raise ValueError('restored source configuration differs from manifest')
    marker = json.loads((output/'next.private.json').read_text(encoding='utf-8'))
    if marker.get('schema') != MODE or marker.get('evidence_storage') not in (None, FORMAT):
        raise ValueError('restored state is not capture-next')
    # No load_config(), key-loading, source.exists(), watcher or login. This
    # verification object is intentionally offline and only opens NEW files.
    service = CaptureService.__new__(CaptureService)
    service.state, service.config = output, config
    with ExitStack() as stack:
        for name in ('catalog.sqlite', 'objects.sqlite'):
            with closing(_readonly(output/name)) as db:
                _integrity(db)
        service.catalog = Catalog(output/'catalog.sqlite')
        stack.callback(service.catalog.close)
        service.objects = Objects(output/'objects.sqlite')
        stack.callback(service.objects.close)
        identity = service.catalog.db.execute("SELECT value FROM meta WHERE key='next_catalog_instance'").fetchone()
        if identity is None or identity[0] != manifest['catalog_instance']:
            raise ValueError('restored catalog identity mismatch')
        binding = canonical({key: config.get(key) for key in
            ('source_id', 'account_alias', 'self_username', 'database_root', 'asset_root')})
        original = service.catalog.db.execute("SELECT value FROM meta WHERE key='source_binding'").fetchone()
        if original is None or original[0] != binding:
            raise ValueError('restored source/account binding mismatch')
        expected = {name for name in manifest['files'] if name.startswith('cache/')}
        actual = set()
        for relative, in service.catalog.db.execute('SELECT relative_path FROM checkpoint WHERE source_id=?', (config['source_id'],)):
            view = service.view_path(relative)
            actual.update((view.relative_to(output).as_posix(), view.with_suffix('.pages.sqlite').relative_to(output).as_posix()))
        if actual != expected:
            raise ValueError('restored current views/fingerprints incomplete')
        for name in actual:
            if name.endswith('.pages.sqlite'):
                with closing(_readonly(output/name)) as db:
                    _integrity(db)
        result = service.verify_state()
    # Constructors open WAL mode but must not change backed-up file bytes.
    for name in ('catalog.sqlite', 'objects.sqlite'):
        if digest_file(output/name) != manifest['files'][name]['sha256']:
            raise ValueError('offline verification unexpectedly changed a database')
    return result


def restore(repository, snapshot_id, output):
    """Restore only into a fresh directory, offline, without starting capture.

    A failure leaves a clearly marked partial directory for investigation; it
    never overwrites or deletes existing state or a previous deliverable.
    """
    repository = _absolute(repository)
    output = _parents(output)
    if _overlap(output, repository):
        raise ValueError('restore output overlaps repository')
    if os.path.lexists(output):
        raise FileExistsError('restore requires a fresh independent directory')
    with _repository_session(repository, readonly=True) as (repository, owner, db, recovered):
        manifest = _manifest(db, snapshot_id, owner)
        _config_from_cas(db, manifest)
        _guard_location(output, _external_root(manifest['origin_state']), manifest['source_roots'])
        required = sum(entry['bytes'] for entry in manifest['files'].values()) + RESTORE_MARGIN_BYTES
        for parent in output.parents:
            if parent.exists():
                directory(parent)
                if shutil.disk_usage(parent).free < required:
                    raise InsufficientRestoreSpace('not enough free space for a new restore')
                break
        else:
            raise FileNotFoundError('restore output volume is unavailable')
        output.mkdir(parents=True, exist_ok=False)
        write_json_new(output/'RESTORE.partial.private.json', dict(schema=SCHEMA, snapshot_id=snapshot_id,
            state='partial', note='offline restore incomplete; do not use as accepted state'))
        try:
            for name, entry in manifest['files'].items():
                _restore_file(db, output/name, entry)
            for name in ('cache', 'reports', 'tmp'):
                (output/name).mkdir(exist_ok=True)
            if (output/SECRETS).exists():
                os.chmod((output/SECRETS).parent, 0o700)
            verification = _verify_restored(output, manifest)
            result = dict(schema=SCHEMA, snapshot_id=snapshot_id, state='complete', output=str(output),
                offline=True, watch_started=False, login_started=False,
                includes_secrets=SECRETS in manifest['files'], verification=verification)
            write_json_new(output/'RESTORE.complete.private.json', result)
            (output/'RESTORE.partial.private.json').unlink()
            return result
        except BaseException as exc:
            # Do not put potentially sensitive exception text in the marker.
            write_json_new(output/'RESTORE.failure.private.json', dict(schema=SCHEMA,
                snapshot_id=snapshot_id, state='partial', error_type=type(exc).__name__))
            raise
