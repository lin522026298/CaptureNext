"""Stream a guarded ZIP's msg members into the existing next CAS.

The output is a SMALL metadata-only retained SQLite, suitable for the existing
union_assets importer. No media path is extracted to disk; no second media CAS
is created. Published CAS files intentionally survive failures and retries.
The original ZIP remains necessary for container-level byte reconstruction.
"""
from contextlib import closing, nullcontext
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import sqlite3
import stat
import uuid
import zipfile
import zlib

from wechat_capture_v2.common import directory, regular, digest_file
from wechat_capture_v2.objects import CHUNK_BYTES
from .paths import local_absolute
from .state_guard import state_preflight, writer_lock
from .union_archive import cold_input
from .union_assets import verify_published_object
from wua.store import _json

SCHEMA = 'next-zip-assets-1'
SPACE_MARGIN_BYTES = 64 * 1024 * 1024
_HASH = re.compile(r'[0-9a-f]{64}')


def _hit(fault, stage):
    if fault:
        fault(stage)


def _typed(value):
    if value is None:
        return {'type': 'null', 'value': None}
    if isinstance(value, bytes):
        return {'type': 'bytes', 'value': base64.b64encode(value).decode('ascii')}
    if isinstance(value, tuple):
        return {'type': 'tuple', 'value': [_typed(item) for item in value]}
    if isinstance(value, list):
        return {'type': 'list', 'value': [_typed(item) for item in value]}
    if isinstance(value, dict):
        return {'type': 'dict', 'value': [[_typed(key), _typed(item)] for key, item in value.items()]}
    if isinstance(value, bool):
        return {'type': 'bool', 'value': value}
    if isinstance(value, int):
        return {'type': 'int', 'value': value}
    if isinstance(value, float):
        return {'type': 'float', 'value': value.hex()}
    if isinstance(value, str):
        return {'type': 'str', 'value': value}
    raise TypeError('unsupported ZipInfo attribute type')


def _untyped(record):
    kind, value = record['type'], record['value']
    if kind == 'bytes':
        return base64.b64decode(value, validate=True)
    if kind == 'tuple':
        return tuple(_untyped(item) for item in value)
    if kind == 'list':
        return [_untyped(item) for item in value]
    if kind == 'dict':
        return {_untyped(key): _untyped(item) for key, item in value}
    if kind == 'float':
        return float.fromhex(value)
    if kind in ('null', 'bool', 'int', 'str'):
        return value
    raise ValueError('unknown ZipInfo attribute encoding')


def zip_info_json(info):
    """Capture every instance slot/extra attribute with its Python value type."""
    names = set(getattr(info, '__dict__', {}))
    for cls in type(info).__mro__:
        slots = getattr(cls, '__slots__', ())
        names.update((slots,) if isinstance(slots, str) else slots)
    values = {}
    for name in sorted(names):
        if name not in ('__dict__', '__weakref__') and hasattr(info, name):
            value = getattr(info, name)
            if not callable(value):
                values[name] = _typed(value)
    return _json(values)


def decode_zip_info(text):
    return {name: _untyped(value) for name, value in json.loads(text).items()}


def _member_name(info):
    original = info.orig_filename
    if (not isinstance(original, str) or not original or any(ord(ch) < 32 for ch in original)
            or '\\' in original or original.startswith('/') or PureWindowsPath(original).drive):
        raise ValueError('unsafe ZIP member name')
    name = original[:-1] if original.endswith('/') else original
    parts = name.split('/')
    if any(part in ('', '.', '..') or ':' in part for part in parts):
        raise ValueError('unsafe ZIP member path')
    # We never extract paths, but still reject Windows aliases before accepting
    # a PC-origin member as a distinct source pathname.
    if any(part.endswith((' ', '.')) or PureWindowsPath(part).is_reserved() for part in parts):
        raise ValueError('ambiguous ZIP member path')
    mode = (info.external_attr >> 16) & 0xffff
    file_type = stat.S_IFMT(mode)
    if file_type not in (0, stat.S_IFREG, stat.S_IFDIR) or (file_type == stat.S_IFDIR and not info.is_dir()):
        raise ValueError('linked or special ZIP member is outside raw media scope')
    if info.flag_bits & 1:
        raise ValueError('encrypted ZIP member requires a separate explicit workflow')
    if info.file_size < 0 or info.compress_size < 0:
        raise ValueError('invalid ZIP member length')
    if info.compress_type == zipfile.ZIP_STORED and info.file_size != info.compress_size:
        raise ValueError('stored ZIP member length mismatch')
    encoding = 'utf-8' if info.flag_bits & 0x800 else 'cp437'
    raw_name = original.encode(encoding)
    if raw_name.decode(encoding) != original:
        raise ValueError('ZIP filename encoding was not exact')
    return name, raw_name


def _members(archive, prefix):
    if not isinstance(prefix, str) or not prefix.endswith('/'):
        raise ValueError('an explicit slash-terminated ZIP member prefix is required')
    probe = zipfile.ZipInfo(prefix)
    _member_name(probe)
    seen, selected, total, directories, outside = set(), [], 0, 0, 0
    for ordinal, info in enumerate(archive.infolist()):
        name, raw_name = _member_name(info)
        identity = name.casefold()
        if identity in seen:
            raise ValueError('duplicate or aliased ZIP member name')
        seen.add(identity)
        if info.is_dir():
            directories += 1
            continue
        if not info.orig_filename.startswith(prefix):
            outside += 1
            continue
        selected.append((ordinal, info, raw_name, zip_info_json(info)))
        total += info.file_size
    if not selected:
        raise ValueError('explicit ZIP media prefix contains no file members')
    return selected, total, dict(container_entries=len(archive.infolist()), directory_entries=directories,
                                 outside_prefix_file_entries=outside)


def _owned_cas(service):
    state = local_absolute(service.state)
    state_preflight(state)
    path = state/'objects.sqlite'
    if regular(path).st_nlink != 1 or local_absolute(service.objects.path) != path:
        raise ValueError('ZIP target must be this next state\'s exact CAS')
    actual = next(row[2] for row in service.objects.db.execute('PRAGMA database_list') if row[1] == 'main')
    if local_absolute(actual) != path:
        raise ValueError('ZIP CAS connection differs from owned state')
    if service.objects.db.in_transaction or getattr(service, '_pending_asset', None) is not None:
        raise ValueError('finish current pending asset publication before ZIP import')
    return state, path


def _output(path, state, source):
    path = local_absolute(path)
    if path == source or path.is_relative_to(state) or state.is_relative_to(path):
        raise ValueError('ZIP metadata output overlaps protected input or state')
    directory(path.parent)
    if os.path.lexists(path):
        raise FileExistsError('ZIP metadata output must be a fresh file')
    for suffix in ('-wal', '-shm', '-journal'):
        if os.path.lexists(Path(str(path)+suffix)):
            raise ValueError('ZIP metadata output has a pre-existing sidecar')
    return path


def _space(folder, required):
    if shutil.disk_usage(folder).free < required:
        raise OSError('insufficient free space for conservative ZIP media import')


def _existing_chunk(db, key, block):
    previous = db.execute('SELECT bytes,data FROM chunk WHERE hash=?', (key,)).fetchone()
    if previous is None:
        return False
    decoder = zlib.decompressobj()
    restored = decoder.decompress(previous[1], CHUNK_BYTES+1)
    if (previous[0] != len(block) or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or hashlib.sha256(restored).hexdigest() != key or restored != block):
        raise ValueError('existing ZIP CAS chunk collision or corruption')
    return True


class _CountInflated:
    """Count decoder output BEFORE ZipExtFile clamps it to header file_size.

    ZipExtFile intentionally trusts the declared size when slicing output. Its
    CRC can therefore authenticate only a prefix if both ZIP headers lie. Keep
    its local-header/CRC implementation, but fail closed unless the underlying
    supported decoder produced exactly the declared bytes and reached EOF.
    """
    def __init__(self, decoder, expected):
        self.decoder, self.expected, self.produced = decoder, expected, 0

    def __getattr__(self, name):
        return getattr(self.decoder, name)

    def _count(self, output):
        self.produced += len(output)
        if self.produced > self.expected:
            raise ValueError('ZIP decoder exceeds declared uncompressed length')
        return output

    def decompress(self, *args, **kwargs):
        return self._count(self.decoder.decompress(*args, **kwargs))

    def flush(self, *args, **kwargs):
        return self._count(self.decoder.flush(*args, **kwargs))


def _store_member(service, archive, info, verified, fault):
    db = service.objects.db
    digest, crc, size, chunks = hashlib.sha256(), 0, 0, []
    db.execute('BEGIN IMMEDIATE')
    try:
        with archive.open(info, 'r') as stream:
            decoder = getattr(stream, '_decompressor', None)
            counted = None
            if info.compress_type != zipfile.ZIP_STORED:
                # Private CPython interface is deliberately feature-checked:
                # an unsupported runtime must refuse, never silently skip this
                # independent inflated-length proof.
                if decoder is None or not callable(getattr(decoder, 'decompress', None)):
                    raise ValueError('ZIP runtime cannot verify actual decoder output')
                counted = _CountInflated(decoder, info.file_size)
                stream._decompressor = counted
            while True:
                block = stream.read(CHUNK_BYTES)
                if not block:
                    break
                size += len(block)
                if size > info.file_size:
                    raise ValueError('ZIP member exceeds declared uncompressed length')
                digest.update(block)
                crc = zlib.crc32(block, crc)
                key = hashlib.sha256(block).hexdigest()
                if not _existing_chunk(db, key, block):
                    _space(service.objects.path.parent, SPACE_MARGIN_BYTES + 2*CHUNK_BYTES)
                    db.execute('INSERT INTO chunk VALUES(?,?,?)', (key, len(block), zlib.compress(block, 1)))
                chunks.append(key)
            decompressor = getattr(stream, '_decompressor', None)
            if decompressor is not None and hasattr(decompressor, 'eof') and not decompressor.eof:
                raise ValueError('ZIP compressed member ended before stream terminator')
            if decompressor is not None and getattr(decompressor, 'unused_data', b''):
                raise ValueError('ZIP compressed member has unauthenticated trailing data')
            if getattr(stream, '_compress_left', 0) != 0:
                raise ValueError('ZIP member has unconsumed compressed bytes')
            if counted is not None and counted.produced != info.file_size:
                raise ValueError('ZIP decoder output differs from declared uncompressed length')
        key = digest.hexdigest()
        if size != info.file_size or (crc & 0xffffffff) != info.CRC:
            raise ValueError('ZIP member size or CRC mismatch')
        previous = db.execute('SELECT bytes,chunk_count FROM file WHERE hash=?', (key,)).fetchone()
        published = previous is not None
        if previous and tuple(previous) != (size, len(chunks)):
            raise ValueError('existing ZIP CAS file shape collision')
        if not previous:
            for ordinal, chunk in enumerate(chunks):
                mapping = db.execute('SELECT chunk_hash FROM file_chunk WHERE file_hash=? AND ordinal=?', (key, ordinal)).fetchone()
                if mapping and mapping[0] != chunk:
                    raise ValueError('existing ZIP CAS unpublished mapping collision')
                if not mapping:
                    db.execute('INSERT INTO file_chunk VALUES(?,?,?)', (key, ordinal, chunk))
            if db.execute('SELECT count(*) FROM file_chunk WHERE file_hash=?', (key,)).fetchone()[0] != len(chunks):
                raise ValueError('ZIP CAS mapping has excess chunks')
            db.execute('INSERT INTO file VALUES(?,?,?)', (key, size, len(chunks)))
        _hit(fault, 'before_cas_file_commit')
        db.commit()
    except BaseException:
        db.rollback()
        raise
    _hit(fault, 'after_cas_file_commit')
    if key not in verified:
        verify_published_object(db, key, size)
        verified.add(key)
    return key, size, published


def _metadata():
    db = sqlite3.connect(':memory:')
    for statement in (
        'CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)',
        'CREATE TABLE file(hash TEXT PRIMARY KEY,bytes INTEGER NOT NULL,chunk_count INTEGER NOT NULL)',
        'CREATE TABLE chunk(hash TEXT PRIMARY KEY,bytes INTEGER NOT NULL,data BLOB NOT NULL)',
        'CREATE TABLE file_chunk(file_hash TEXT,ordinal INTEGER,chunk_hash TEXT,PRIMARY KEY(file_hash,ordinal))',
        '''CREATE TABLE asset(source_id TEXT NOT NULL,relative_path TEXT NOT NULL,file_sha TEXT NOT NULL,
            bytes INTEGER NOT NULL,stamp_json TEXT NOT NULL,cycle_id TEXT NOT NULL,
            zip_artifact_sha TEXT NOT NULL,zip_member_ordinal INTEGER NOT NULL,zip_filename_raw BLOB NOT NULL,
            zip_info_json TEXT NOT NULL,PRIMARY KEY(source_id,relative_path))''',
        '''CREATE TABLE asset_history(source_id TEXT NOT NULL,relative_path TEXT NOT NULL,file_sha TEXT NOT NULL,
            bytes INTEGER NOT NULL,cycle_id TEXT NOT NULL,zip_artifact_sha TEXT NOT NULL,
            zip_member_ordinal INTEGER NOT NULL,zip_filename_raw BLOB NOT NULL,zip_info_json TEXT NOT NULL,
            PRIMARY KEY(source_id,relative_path,file_sha))'''):
        db.execute(statement)
    return db


def _publish_metadata(memory, output, state, source, fault):
    temporary = output.with_name(output.name+'.partial-'+uuid.uuid4().hex)
    # Only metadata is staged. Its random, freshly-created sibling is never an
    # accepted retained input until publication succeeds; media bytes stay CAS.
    with temporary.open('xb'):
        pass
    try:
        with closing(sqlite3.connect(temporary.as_uri()+'?mode=rw', uri=True)) as db:
            memory.backup(db)
            if [row[0] for row in db.execute('PRAGMA quick_check')] != ['ok']:
                raise ValueError('ZIP metadata SQLite readback failed')
            db.commit()
        with temporary.open('r+b') as stream:
            stream.flush()
            os.fsync(stream.fileno())
        _hit(fault, 'before_metadata_publish')
        _output(output, state, source)
        if os.name == 'nt':
            os.rename(temporary, output)  # Windows refuses an existing destination.
        else:
            os.link(temporary, output)  # No-overwrite publication, then remove our staging name.
            temporary.unlink()
        _hit(fault, 'after_metadata_publish')
    except BaseException:
        if os.path.lexists(temporary):
            if regular(temporary).st_nlink == 1:
                temporary.unlink()
        raise


def import_zip_assets(service, zip_path, metadata_output, *, expected_sha256, source_id,
                      member_prefix='source_C_xwechat_files/msg/', locks_held=False,
                      fault=None, source_receipt=None):
    """Stream selected raw members, then publish a fresh metadata-only SQLite.

    Caller may pass locks_held=True only while holding the current state's OS
    writer lock. On failure, existing/published CAS files are never removed;
    retry with the same immutable ZIP and a fresh metadata path. No stored
    filename/ZipInfo attribute is used as an output filesystem pathname.
    """
    if not isinstance(expected_sha256, str) or not _HASH.fullmatch(expected_sha256):
        raise ValueError('an exact expected ZIP SHA-256 is required')
    if not isinstance(source_id, str) or not source_id or '\x00' in source_id:
        raise ValueError('a stable opaque ZIP source_id is required')
    state, cas = _owned_cas(service)
    source = local_absolute(zip_path)
    if source == cas or source == state/'catalog.sqlite':
        raise ValueError('ZIP input overlaps the owned current state')
    output = _output(metadata_output, state, source)
    lock = nullcontext() if locks_held else writer_lock(state)
    with lock:
        _owned_cas(service)
        with cold_input(source):
            actual_sha = digest_file(source)  # Exactly one complete container hash per operation.
            if actual_sha != expected_sha256:
                raise ValueError('ZIP artifact SHA-256 does not match expected evidence')
            with closing(zipfile.ZipFile(source, 'r')) as archive:
                selected, declared_bytes, excluded = _members(archive, member_prefix)
                # This is a conservative worst-case capacity check, not a file/
                # ratio/count cap. Actual chunk publication still checks free space.
                _space(cas.parent, declared_bytes + SPACE_MARGIN_BYTES)
                _space(output.parent, SPACE_MARGIN_BYTES)
                with closing(_metadata()) as metadata:
                    metadata.executemany('INSERT INTO meta VALUES(?,?)', [
                        ('schema', SCHEMA), ('zip_sha256', actual_sha), ('source_id', source_id),
                        ('member_prefix', member_prefix), ('source_receipt', _json(source_receipt)),
                        ('zip_comment', _json(_typed(archive.comment))),
                        ('entry_scope', _json(excluded)),
                        ('coverage', 'selected_msg_members_only; original ZIP retained; no message association')])
                    verified, added, replayed = set(), 0, 0
                    for ordinal, info, raw_name, info_json in selected:
                        sha, size, existed = _store_member(service, archive, info, verified, fault)
                        added += not existed
                        replayed += existed
                        cycle = 'zip:' + actual_sha
                        stamp = _json({'zip_sha256': actual_sha, 'member_ordinal': ordinal,
                                       'crc32': info.CRC, 'zip_info_basis': 'central_directory'})
                        metadata.execute('INSERT INTO asset VALUES(?,?,?,?,?,?,?,?,?,?)',
                            (source_id, info.orig_filename, sha, size, stamp, cycle, actual_sha, ordinal, raw_name, info_json))
                        metadata.execute('INSERT INTO asset_history VALUES(?,?,?,?,?,?,?,?,?)',
                            (source_id, info.orig_filename, sha, size, cycle, actual_sha, ordinal, raw_name, info_json))
                    metadata.commit()
                    _publish_metadata(metadata, output, state, source, fault)
            return dict(schema=SCHEMA, zip_sha256=actual_sha, source_id=source_id,
                member_prefix=member_prefix, members_verified=len(selected), logical_bytes=declared_bytes,
                **excluded,
                unique_objects_verified=len(verified), added_cas_files=added, reused_member_objects=replayed,
                metadata_output=str(output), metadata_sha256=digest_file(output),
                metadata_only=True, media_temporary_plaintext=False, runtime_cas_copies=1,
                zip_container_reconstruction=False, message_media_association='not_implemented',
                source_zip_retained=True)
