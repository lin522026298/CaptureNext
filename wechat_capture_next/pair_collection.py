"""Resumable collection after a paired restore point has been accepted.

The caller keeps one ``pair_repository.session`` writer lock for this entire
call and must enter with no open SQL transaction. Acceptance is deliberately
not performed here: a collector error cannot undo, or report failure of, an
already committed backup. A crash may leave extra snapshots, orphan blocks or
free pages, but never requires a persisted, unauthenticated reachability list.

``seconds`` is a work budget checked between batches, not a timeout for graph
authentication or an individual SQLite statement. Payload and row budgets
bound each deletion transaction; they are not an exact SQLite journal-size
formula. Journal high-water telemetry and a conservative free-space reserve
make that distinction explicit. No complete file is reconstructed on disk.
"""
import json
import math
from pathlib import Path
import shutil
import sqlite3
import time

from . import pair_repository as repository


DEFAULT_BATCH_PAYLOAD = 16 * 1024 * 1024
DEFAULT_BATCH_ROWS = 128
MINIMUM_RESERVE = 64 * 1024 * 1024
# A zlib stream produced from any valid repository node is smaller than this.
# Refuse a malformed giant orphan rather than defeating the transaction budget.
MAX_STORED_NODE = repository.MAX_BLOCK + 65536


def progress_phase(name):
    """Coarse user progress, not a durable report for every deletion batch."""
    if name in ('before_retention','before_retention_commit'):return 'backup_collection_auth'
    if name in ('after_retention_commit','after_batch_edges','after_edge_commit','after_batch_delete',
                'before_batch_commit','after_batch_commit'):return 'backup_collection_blocks'
    return name


def pending(db, *, keep=2):
    """Read-only maintenance hint, not a content-verification certificate.

    A valid finite map DAG with unreferenced blocks has an unreferenced root.
    ``edge_child`` indexes that probe, but a clean repository can still require
    scanning every block. Callers may cache a negative result only for the
    exact independently authenticated same-process repository-file hash.
    """
    repository.require(type(keep) is int and keep >= 2, 'keep at least two successful generations')
    free = db.execute('PRAGMA freelist_count').fetchone()[0]
    extra_generations = max(0, db.execute('SELECT count(*) FROM generation').fetchone()[0] - keep)
    expired = db.execute('''SELECT 1 FROM snapshot WHERE id NOT IN
        (SELECT snapshot_id FROM generation UNION SELECT snapshot_id FROM pin) LIMIT 1''').fetchone() is not None
    quick = bool(free or extra_generations or expired)
    orphan = False
    if not quick:
        orphan = db.execute('''SELECT 1 FROM block b
            WHERE NOT EXISTS(SELECT 1 FROM edge e WHERE e.child=b.hash)
            AND NOT EXISTS(SELECT 1 FROM snapshot_file f WHERE f.root=b.hash) LIMIT 1''').fetchone() is not None
    return dict(cleanup_pending=bool(quick or orphan), freelist_pages=free,
                extra_generations=extra_generations, expired_snapshot_present=expired,
                orphan_root_found=orphan, orphan_root_probe_executed=not quick,
                probe_cost='metadata_only_may_scan_all_blocks',
                repository_block_payloads_read=False)


def _journal_bytes(path):
    try:
        return (path / (repository.DATABASE + '-journal')).stat().st_size
    except FileNotFoundError:
        return 0


def _repository_size(path):
    try:
        return (path / repository.DATABASE).stat().st_size
    except OSError:
        return None


def _mark_survivors(db, owner, keep):
    """Authenticate survivors before any generation/snapshot is retired."""
    repository.require(type(keep) is int and keep >= 2, 'keep at least two successful generations')
    repository.require(not list(db.execute('PRAGMA foreign_key_check')), 'cannot collect a broken repository')
    latest = db.execute('SELECT snapshot_id FROM generation ORDER BY seq DESC LIMIT 1').fetchone()
    repository.require(latest is not None, 'no successfully accepted pair')
    db.execute('CREATE TEMP TABLE IF NOT EXISTS collection_live(hash TEXT PRIMARY KEY,height INTEGER,bytes INTEGER) WITHOUT ROWID')
    db.execute('CREATE TEMP TABLE IF NOT EXISTS collection_dead(hash TEXT PRIMARY KEY,stored_bytes INTEGER) WITHOUT ROWID')
    db.execute('CREATE TEMP TABLE IF NOT EXISTS collection_survivor(id TEXT PRIMARY KEY) WITHOUT ROWID')
    for name in ('collection_live', 'collection_dead', 'collection_survivor'):
        db.execute('DELETE FROM ' + name)
    db.execute('''INSERT INTO collection_survivor
        SELECT snapshot_id FROM (SELECT snapshot_id FROM generation ORDER BY seq DESC LIMIT ?)
        UNION SELECT snapshot_id FROM pin''', (keep,))
    rows = db.execute('SELECT id FROM snapshot').fetchall()
    manifests = {row[0]: repository.manifest(db, row[0], owner) for row in rows}
    survivors = {row[0] for row in db.execute('SELECT id FROM collection_survivor')}
    repository.require(survivors.issubset(manifests), 'retained paired snapshot missing')
    repository.require(db.execute('''SELECT 1 FROM edge e JOIN block b ON b.hash=e.parent
        WHERE b.kind!='N' LIMIT 1''').fetchone() is None, 'data leaf has unexpected graph edges')
    blocks = repository.Blocks(db)

    def mark(key, height, size):
        previous = db.execute('SELECT height,bytes FROM collection_live WHERE hash=?', (key,)).fetchone()
        if previous is not None:
            repository.require(tuple(previous) == (height, size), 'inconsistent shared tree shape')
            return
        db.execute('INSERT INTO collection_live VALUES(?,?,?)', (key, height, size))
        if height:
            kind, raw = blocks.get(key)
            repository.require(kind == 'N', 'expected authenticated map for collection')
            node = json.loads(raw)
            repository.require(node['height'] == height and sum(item[1] for item in node['children']) == size,
                               'collection map length/height differs')
            for child, length in node['children']:
                mark(child, height - 1, length)

    for snapshot in survivors:
        for entry in manifests[snapshot]['files'].values():
            mark(entry['root'], entry['height'], entry['bytes'])
    repository.require(db.execute('''SELECT 1 FROM collection_live l LEFT JOIN block b ON b.hash=l.hash
        WHERE b.hash IS NULL OR (l.height=0 AND (b.kind!='D' OR b.bytes!=l.bytes)) LIMIT 1''').fetchone() is None,
        'missing or invalid retained leaf')
    return [row[0] for row in rows if row[0] not in survivors]


def _next_batch(db, payload_limit, row_limit):
    result = []
    total = 0
    for row in db.execute('SELECT hash,stored_bytes FROM collection_dead ORDER BY hash LIMIT ?', (row_limit,)):
        key, size = row
        repository.require(type(size) is int and 0 <= size <= MAX_STORED_NODE, 'oversized or invalid orphan payload')
        # One valid node is allowed when its compressed payload exceeds a tiny
        # requested budget. This single-node allowance is exposed in the result.
        if result and total + size > payload_limit:
            break
        result.append(key)
        total += size
    return result, total


def cleanup(db, owner, path, *, keep=2, seconds=5.0,
            batch_payload_limit=DEFAULT_BATCH_PAYLOAD, batch_row_limit=DEFAULT_BATCH_ROWS,
            fault=None):
    """Retain latest successful generations + pins, then collect in chunks.

    ``db`` belongs to the still-held repository writer session. The current
    accepted point must have completed the publisher's full file readback.
    Every later invocation rebuilds its private live/dead sets from manifests.
    Ordinary cleanup errors are returned as ``cleanup_pending``; acceptance
    remains the caller's already committed outcome. Process termination still
    exercises SQLite recovery of just the current metadata/deletion batch.
    """
    repository.require(not db.in_transaction, 'collection requires committed acceptance')
    repository.require(type(batch_payload_limit) is int and 0 < batch_payload_limit <= DEFAULT_BATCH_PAYLOAD,
                       'collection payload budget outside bounded range')
    repository.require(type(batch_row_limit) is int and 1 <= batch_row_limit <= DEFAULT_BATCH_ROWS,
                       'collection row budget outside bounded range')
    repository.require(isinstance(seconds, (int, float)) and not isinstance(seconds, bool) and
                       math.isfinite(seconds) and seconds >= 0,
                       'nonnegative collection time budget required')
    repository.require(db.execute('PRAGMA foreign_keys').fetchone()[0] == 1, 'collection requires enabled foreign keys')
    path = Path(path)
    result = dict(expired_snapshots=[], deleted_payload_bytes=0, deleted_blocks=0,
                  collection_batches=0, collection_edge_batches=0, cleanup_pending=True, retention_committed=False,
                  batch_payload_limit=batch_payload_limit, batch_row_limit=batch_row_limit,
                  single_node_payload_allowance=MAX_STORED_NODE, journal_bytes_peak=0,
                  journal_bytes_peak_scope='retention_and_collection_only_excludes_reclaim',
                  batch_payload_bytes_peak=0, batch_rows_peak=0, edge_batch_rows_peak=0,
                  reclaim_rounds=0, file_bytes_reclaimed=0, reclaim_progress_stalled=False,
                  required_free_reserve_bytes=max(MINIMUM_RESERVE, 4 * (batch_payload_limit + MAX_STORED_NODE)),
                  legacy_repositories_touched=False)

    def phase(name):
        result['journal_bytes_peak'] = max(result['journal_bytes_peak'], _journal_bytes(path))
        if fault:
            fault(name, db)

    try:
        db.execute('BEGIN IMMEDIATE')
        victims = _mark_survivors(db, owner, keep)
        phase('before_retention')
        db.execute('DELETE FROM generation WHERE seq NOT IN (SELECT seq FROM generation ORDER BY seq DESC LIMIT ?)', (keep,))
        db.executemany('DELETE FROM snapshot WHERE id=?', ((key,) for key in victims))
        phase('before_retention_commit')
        db.commit()
        result.update(expired_snapshots=victims, retention_committed=True)
        phase('after_retention_commit')
        # This is TEMP-only state, never a trusted durable GC certificate.
        repository.require(db.execute('''SELECT 1 FROM block WHERE hash NOT IN (SELECT hash FROM collection_live)
            AND (length(hash)!=64 OR hash GLOB '*[^0-9a-f]*' OR kind NOT IN ('D','N')
            OR typeof(bytes)!='integer' OR bytes<0 OR bytes>? OR length(data)>?) LIMIT 1''',
            (repository.MAX_BLOCK, MAX_STORED_NODE)).fetchone() is None, 'invalid orphan block shape')
        db.execute('''INSERT INTO collection_dead SELECT hash,length(data) FROM block
            WHERE hash NOT IN (SELECT hash FROM collection_live)''')
        db.commit()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            keys, payload = _next_batch(db, batch_payload_limit, batch_row_limit)
            if not keys:
                break
            reserve = result['required_free_reserve_bytes']
            repository.require(shutil.disk_usage(path).free >= reserve, 'insufficient bounded collection journal reserve')
            placeholders = ','.join('?' for _ in keys)
            # A live map must never refer to this dead set. Its authenticated
            # payload and complete edge set were checked before retirement.
            repository.require(db.execute('''SELECT 1 FROM edge e JOIN collection_live l ON l.hash=e.parent
                WHERE e.child IN (''' + placeholders + ') LIMIT 1', keys).fetchone() is None,
                'retained map points into collection batch')
            # Child-only deletion can violate FKs when a dead parent belongs
            # to a later batch. Delete BOTH incoming and outgoing dead edges.
            # Incoming degree is not bounded by FANOUT: shared dead children
            # can have many parents. Thus edges have their own row-bounded
            # commits rather than one unbounded incident-edge DELETE.
            while True:
                edges = [row[0] for row in db.execute('SELECT rowid FROM edge WHERE parent IN (' + placeholders +
                    ') OR child IN (' + placeholders + ') LIMIT ?', keys + keys + [batch_row_limit])]
                if not edges:
                    break
                db.execute('BEGIN IMMEDIATE')
                db.executemany('DELETE FROM edge WHERE rowid=?', ((rowid,) for rowid in edges))
                phase('after_batch_edges')
                # Removing referencing rows cannot introduce an FK violation.
                # foreign_keys remains ON and the initial complete check was
                # performed before retention. Do not rescan all million live
                # edges for each tiny dead-edge transaction.
                db.commit()
                result['collection_edge_batches'] += 1
                result['edge_batch_rows_peak'] = max(result['edge_batch_rows_peak'], len(edges))
                phase('after_edge_commit')
                if time.monotonic() >= deadline:
                    break
            if time.monotonic() >= deadline:
                break
            db.execute('BEGIN IMMEDIATE')
            db.executemany('DELETE FROM block WHERE hash=?', ((key,) for key in keys))
            phase('after_batch_delete')
            # All FKs targeting block are these three columns. Check exactly
            # this batch in addition to SQLite's enabled immediate FK checks.
            repository.require(db.execute('SELECT 1 FROM edge WHERE parent IN (' + placeholders +
                ') OR child IN (' + placeholders + ') LIMIT 1', keys + keys).fetchone() is None and
                db.execute('SELECT 1 FROM snapshot_file WHERE root IN (' + placeholders + ') LIMIT 1', keys).fetchone() is None,
                'collection broke a paired dependency')
            db.executemany('DELETE FROM collection_dead WHERE hash=?', ((key,) for key in keys))
            phase('before_batch_commit')
            db.commit()
            result['deleted_payload_bytes'] += payload
            result['deleted_blocks'] += len(keys)
            result['collection_batches'] += 1
            result['batch_payload_bytes_peak'] = max(result['batch_payload_bytes_peak'], payload)
            result['batch_rows_peak'] = max(result['batch_rows_peak'], len(keys))
            phase('after_batch_commit')
        dead = db.execute('SELECT count(*) FROM collection_dead').fetchone()[0]
        free = db.execute('PRAGMA freelist_count').fetchone()[0]
        result.update(dead_blocks_remaining=dead, freelist_pages_before=free, freelist_pages_after=free)
        # Reclamation only follows committed deletion batches. A no-work cut
        # does not open a write transaction or invalidate a readback memo.
        while free and time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            reclaimed = repository._reclaim(db, path, seconds=remaining)
            result['reclaim_rounds'] += 1
            reclaimed_bytes = reclaimed.get('file_bytes_reclaimed', 0)
            result['file_bytes_reclaimed'] += reclaimed_bytes
            after = reclaimed.get('freelist_pages_after')
            if after is None:
                after = db.execute('PRAGMA freelist_count').fetchone()[0]
            result['freelist_pages_after'] = after
            if 'cleanup_error' in reclaimed:
                result['cleanup_error'] = reclaimed['cleanup_error']
                free = after
                break
            if after >= free and not reclaimed_bytes:
                result['reclaim_progress_stalled'] = True
                free = after
                break
            free = after
        result['cleanup_pending'] = bool(dead or free or result.get('cleanup_error'))
        result['repository_bytes'] = _repository_size(path)
        return result
    except Exception as error:
        if db.in_transaction:
            db.rollback()
        result.update(cleanup_pending=True, cleanup_error=type(error).__name__,
                      repository_bytes=_repository_size(path))
        return result
