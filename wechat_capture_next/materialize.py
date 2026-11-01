"""Conservative full-read / changed-write SQLCipher materialization.

This deliberately does NOT implement a live SQLite VFS, WAL tail cursor,
page-to-row locator, or per-commit history. It retains the v2 stable-main /
double WAL-prefix proof, but never copies the main file. Only different final
pages are decrypted and written to one current decoded database. Every accepted
database is still structurally checked and fully row-scanned by the collector.

The caller must own the state's writer lock. The decoded view is private while
updating. A durable dirty marker precedes every in-place mutation; interruption
forces rebuilding that view, never advancing the archive checkpoint.
"""
from contextlib import closing, ExitStack, nullcontext
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile

from wechat_capture_v2.cipher import PAGE, RESERVE, STRIDE, PageCipher
from wechat_capture_v2.common import canonical, digest_file, readonly_database, regular, stamp
from wechat_capture_v2.source import prefix_hash
from .wal_memory import freeze_wal, stream_prefix_hash, stream_wal_prefix


def _durable_marker(path, value):
    with path.open('w', encoding='utf-8') as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


def _verify_wal(live, frozen, audit, frozen_sha=None):
    if frozen is None:
        if live.exists():
            raise RuntimeError('WAL appeared during capture')
        return
    count = audit['committed_bytes'] or min(32, audit['physical_bytes'])
    expected = frozen_sha if frozen_sha is not None else stream_prefix_hash(frozen, count)
    if not live.exists() or prefix_hash(live, count) != expected:
        raise RuntimeError('WAL prefix/reset changed during capture')


def update_view(source, view, key, *, scratch, binding='weixin4-reserve80-v1', fault=None, wal_memory_bytes=64*1024**2):
    source, view, scratch = Path(source), Path(view), Path(scratch)
    before = stamp(source)
    size = before[2]
    if not size or size % PAGE:
        raise ValueError('unsupported main database size')
    view.parent.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)
    dirty = view.with_suffix('.dirty')
    index_path = view.with_suffix('.pages.sqlite')
    regular(view) if view.exists() else None
    regular(index_path) if index_path.exists() else None
    regular(dirty) if dirty.exists() else None
    with source.open('rb') as main:
        salt = main.read(16)
    identity = hashlib.sha256((binding + ':' + hashlib.sha256(key+salt).hexdigest()).encode()).hexdigest()
    with closing(sqlite3.connect(index_path)) as index:
        index.execute('PRAGMA synchronous=FULL')
        index.execute('PRAGMA cache_size=-2048')
        index.execute('PRAGMA temp_store=MEMORY')
        index.executescript('''
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS page(number INTEGER PRIMARY KEY,cipher_hash BLOB NOT NULL,plain_hash BLOB NOT NULL);
            CREATE TEMP TABLE overlay(number INTEGER PRIMARY KEY,offset INTEGER NOT NULL);
        ''')
        old = dict(index.execute('SELECT key,value FROM meta'))
        reusable = (not dirty.exists() and view.exists() and old.get('binding') == identity
                    and view.stat().st_size == int(old.get('bytes', -1)))
        _durable_marker(dirty, {'state': 'updating', 'format': 1})
        try:
            index.execute('BEGIN IMMEDIATE')
            if not reusable:
                index.execute('DELETE FROM page')
            with tempfile.TemporaryDirectory(prefix='wal-', dir=scratch) as work, ExitStack() as resources:
                live_wal = Path(str(source)+'-wal')
                frozen = None
                wal_hashes = {}
                audit = {'last_commit_frame': 0, 'committed_database_pages': None,
                         'committed_bytes': 0, 'tail_reason': 'absent'}
                cipher = PageCipher(key, salt)
                wal_bytes, wal_disk = 0, False
                if live_wal.exists():
                    frozen, wal_bytes, wal_disk = resources.enter_context(freeze_wal(live_wal, work, wal_memory_bytes))
                    audit = stream_wal_prefix(frozen, wal_bytes, cipher,
                        prefix_hashes=wal_hashes, authentication_only=True)
                    if audit['tail_reason'] in ('checksum_tail', 'invalid_frame_tail'):
                        raise RuntimeError('invalid/torn WAL tail; checkpoint not advanced')
                floor = size//PAGE
                final_pages = audit['committed_database_pages'] or floor
                if frozen is not None:
                    with nullcontext(frozen) as wal:
                        wal.seek(32)
                        for _ in range(audit['last_commit_frame']):
                            offset = wal.tell()+24
                            frame = wal.read(STRIDE)
                            number, pages = struct.unpack_from('>II', frame)
                            index.execute('INSERT OR REPLACE INTO overlay VALUES(?,?)', (number, offset))
                            if pages:
                                floor = min(floor, pages)
                                index.execute('DELETE FROM overlay WHERE number>?', (pages,))
                _verify_wal(live_wal, frozen, audit, wal_hashes.get('verification'))
                changed = decrypted = reused = zero_pages = 0
                source_hash = hashlib.sha256()
                zero = bytes(PAGE)
                with source.open('rb') as main, view.open('r+b' if reusable else 'w+b') as target:
                    wal = frozen
                    try:
                        def apply(number, encrypted):
                            nonlocal changed, decrypted, reused, zero_pages
                            zero_pages += int(encrypted is None)
                            fingerprint = hashlib.sha256(b'E'+encrypted if encrypted is not None else b'Z').digest()
                            known = index.execute('SELECT cipher_hash,plain_hash FROM page WHERE number=?', (number,)).fetchone()
                            target.seek((number-1)*PAGE)
                            previous = target.read(PAGE)
                            if (known and known[0] == fingerprint and len(previous) == PAGE
                                    and hashlib.sha256(previous).digest() == known[1]):
                                reused += 1
                                return
                            plain = cipher.decrypt(encrypted, number) if encrypted is not None else zero
                            decrypted += int(encrypted is not None)
                            if previous != plain:
                                target.seek((number-1)*PAGE)
                                target.write(plain)
                                changed += 1
                            index.execute('INSERT OR REPLACE INTO page VALUES(?,?,?)',
                                (number, fingerprint, hashlib.sha256(plain).digest()))

                        for number in range(1, size//PAGE+1):
                            page = main.read(PAGE)
                            if len(page) != PAGE:
                                raise RuntimeError('main truncated during capture')
                            source_hash.update(page)
                            # Preserve v2's ALL-main-page authentication even
                            # when WAL overrides a page or the final DB shrinks.
                            # HMAC verification is not full AES decryption.
                            start = 16 if number == 1 else 0
                            mac = hmac.new(cipher.mac_key, page[start:PAGE-64], hashlib.sha512)
                            mac.update(struct.pack('<I', number))
                            if not hmac.compare_digest(mac.digest(), page[PAGE-64:]):
                                raise ValueError('main page HMAC failed')
                            if number <= final_pages:
                                overlay = index.execute('SELECT offset FROM overlay WHERE number=?', (number,)).fetchone()
                                if overlay:
                                    wal.seek(overlay[0])
                                    apply(number, wal.read(PAGE))
                                else:
                                    apply(number, page if number <= floor else None)
                        for number in range(size//PAGE+1, final_pages+1):
                            overlay = index.execute('SELECT offset FROM overlay WHERE number=?', (number,)).fetchone()
                            if overlay:
                                wal.seek(overlay[0])
                                apply(number, wal.read(PAGE))
                            else:
                                apply(number, None)
                        if target.seek(0, os.SEEK_END) != final_pages*PAGE:
                            target.truncate(final_pages*PAGE)
                        target.flush()
                        os.fsync(target.fileno())
                    finally:
                        if wal:
                            wal.seek(0)  # Borrowed stream; ExitStack owns closure.
                if fault:
                    fault('after_view_fsync')
                main_sha = source_hash.hexdigest()
                if stamp(source) != before or digest_file(source) != main_sha:
                    raise RuntimeError('main checkpoint/change during capture')
                _verify_wal(live_wal, frozen, audit, wal_hashes.get('verification'))
                if stamp(source) != before:
                    raise RuntimeError('main changed after WAL verification')
                with view.open('rb') as stream:
                    header = stream.read(100)
                if len(header) != 100 or struct.unpack_from('>H', header, 16)[0] != PAGE or header[20] != RESERVE:
                    raise ValueError('decoded profile mismatch')
                with closing(readonly_database(view)) as db:
                    try:
                        checks = [row[0] for row in db.execute('PRAGMA quick_check')]
                    except sqlite3.OperationalError as exc:
                        if 'MMFtsTokenizer' not in str(exc):
                            raise
                        checks = ['unsupported_custom_tokenizer']
                if checks not in (['ok'], ['unsupported_custom_tokenizer']):
                    raise ValueError('decoded database structural check failed')
                plain_sha = digest_file(view)
                prefix_sha = wal_hashes['committed'] if frozen is not None else None
                signature = hashlib.sha256((main_sha+':'+(prefix_sha or 'absent')).encode()).hexdigest()
                index.execute('DELETE FROM page WHERE number>?', (final_pages,))
                index.executemany('INSERT OR REPLACE INTO meta VALUES(?,?)',
                    [('binding', identity), ('bytes', str(final_pages*PAGE)), ('sha256', plain_sha)])
                index.commit()
                if fault:
                    fault('after_index_commit')
                dirty.unlink()
                return dict(profile='weixin4-4096-reserve80-raw32', signature=signature,
                    main_sha256=main_sha, plaintext_sha256=plain_sha, wal_sha256=prefix_sha, wal=audit,
                    quick_check=checks, structured_readable=checks == ['ok'],
                    effective_page_count=final_pages, authenticated_final_cipher_pages=final_pages-zero_pages,
                    zero_filled_pages=zero_pages, all_main_pages_hmac=True,
                    main_pages_authenticated=size//PAGE,
                    changed_plain_pages=changed, decrypted_pages=decrypted, reused_pages=reused,
                    main_copy_bytes=0, plaintext_write_bytes=changed*PAGE,
                    temporary_wal_bytes=wal_bytes if wal_disk else 0,
                    frozen_wal_bytes=wal_bytes, memory_wal_bytes=0 if wal_disk else wal_bytes,
                    wal_storage='disk_spill' if wal_disk else 'memory', recovered_invalid_view=not reusable,
                    raw_ciphertext_retained=False, intermediate_commit_history=False,
                    source_read_only=True, source_stamp=before)
        except BaseException:
            index.rollback()
            # The marker intentionally survives. A mixed/incomplete view must
            # never become the next accepted baseline after a crash or race.
            raise
