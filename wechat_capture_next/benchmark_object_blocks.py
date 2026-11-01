"""Same-input object-SQLite leaf-only storage estimate; never publish a backup.

A is authenticated and streamed from Blocks.walk. B is streamed once from an
explicit cold restored file and authenticated against snapshot B. Exact hashes
live only in SQLite :memory:; no reconstructed files or disk temp databases.
Compression uses the repository's D-prefixed hash and zlib level 1 convention.
Map nodes, SQLite pages/indexes, collection and restore costs are NOT estimated.
"""
import argparse
from contextlib import ExitStack, closing
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import time
import traceback
import zlib

import psutil

from wechat_capture_v2.common import digest_file, write_json_new
from . import pair_repository as repository
from .paths import local_absolute
from .union_archive import cold_input

SIZES = (1048576, 65536, 16384, 4096)
READ_BYTES = 1048576


class Leaves:
    def __init__(self, db, phase):
        self.db = db; self.phase = phase; self.pending = {size:bytearray() for size in SIZES}
        self.total = 0; self.digest = hashlib.sha256(); self.batch = []
        self.stats = {size:dict(leaf_occurrences=0, raw_leaf_bytes=0, unique_inserted=0,
            new_unique_raw_bytes=0, new_unique_compressed_payload_bytes=0,
            occurrences_already_in_a=0, new_in_b_repeat_occurrences=0) for size in SIZES}

    def _leaf(self, size, raw):
        stats = self.stats[size]; stats['leaf_occurrences'] += 1; stats['raw_leaf_bytes'] += len(raw)
        digest = hashlib.sha256(b'D'); digest.update(raw); key = digest.digest()
        if self.phase == 'A':
            self.batch.append((size, key, 0))
            if len(self.batch) >= 2048:
                self.flush()
            return
        old = self.db.execute('SELECT first_phase FROM leaf WHERE leaf_bytes=? AND hash=?', (size, key)).fetchone()
        if old is not None:
            stats['occurrences_already_in_a' if old[0] == 0 else 'new_in_b_repeat_occurrences'] += 1
            return
        self.db.execute('INSERT INTO leaf VALUES(?,?,1)', (size, key))
        stats['unique_inserted'] += 1
        stats['new_unique_raw_bytes'] += len(raw)
        stats['new_unique_compressed_payload_bytes'] += len(zlib.compress(raw, 1))

    def flush(self):
        if self.batch:
            self.db.executemany('INSERT OR IGNORE INTO leaf VALUES(?,?,?)', self.batch)
            self.batch.clear()

    def feed(self, raw):
        self.digest.update(raw); self.total += len(raw)
        view = memoryview(raw)
        for size in SIZES:
            pending = self.pending[size]; offset = 0
            if pending:
                count = min(size-len(pending), len(view)); pending.extend(view[:count]); offset = count
                if len(pending) == size:
                    self._leaf(size, pending); pending.clear()
            while offset+size <= len(view):
                self._leaf(size, view[offset:offset+size]); offset += size
            if offset < len(view):
                pending.extend(view[offset:])

    def finish(self, expected):
        for size in SIZES:
            if self.pending[size] or self.total == 0:
                self._leaf(size, self.pending[size]); self.pending[size].clear()
        self.flush()
        if self.total != expected['bytes'] or self.digest.hexdigest() != expected['sha256']:
            raise ValueError('full original file SHA-256 or length differs from authenticated snapshot')
        for size in SIZES:
            if self.stats[size]['raw_leaf_bytes'] != self.total:
                raise ValueError('leaf stream omitted or duplicated original bytes')
            expected_count = max(1, (self.total+size-1)//size)
            if self.stats[size]['leaf_occurrences'] != expected_count:
                raise ValueError('leaf stream coverage differs')
            if self.phase == 'A':
                self.stats[size]['unique_inserted'] = self.db.execute('SELECT count(*) FROM leaf WHERE leaf_bytes=? AND first_phase=0', (size,)).fetchone()[0]
        return dict(bytes=self.total, sha256=self.digest.hexdigest(), original_verified=True,
            per_leaf_bytes={str(size):stats for size, stats in self.stats.items()})


def _memory_db():
    db = sqlite3.connect(':memory:')
    db.execute('PRAGMA temp_store=MEMORY'); db.execute('PRAGMA journal_mode=MEMORY')
    db.execute('CREATE TABLE leaf(leaf_bytes INTEGER NOT NULL,hash BLOB NOT NULL,first_phase INTEGER NOT NULL,PRIMARY KEY(leaf_bytes,hash)) WITHOUT ROWID')
    return db


def compare(repo, snapshot_a, snapshot_b, restored_b, *, progress=None, memory_guard=None):
    repo = local_absolute(repo); restored_b = local_absolute(restored_b)
    with ExitStack() as stack:
        for path in (repo/repository.DATABASE, repo/'OWNER.private.json', restored_b):
            stack.enter_context(cold_input(path))
        db, owner = stack.enter_context(repository.session(repo, readonly=True))
        db.execute('BEGIN')
        manifests = [repository.manifest(db, identity, owner) for identity in (snapshot_a, snapshot_b)]
        expected_a, expected_b = [manifest['files']['state/objects.sqlite'] for manifest in manifests]
        if restored_b.stat().st_size != expected_b['bytes']:
            raise ValueError('explicit restored B object file length differs from snapshot B')
        index = stack.enter_context(closing(_memory_db())); started = time.monotonic()
        a = Leaves(index, 'A'); blocks = repository.Blocks(db)
        if progress:progress('A_stream_started')
        for raw in blocks.walk(expected_a['root'], expected_a['height'], expected_a['bytes']):
            if memory_guard:memory_guard()
            a.feed(raw)
        proof_a = a.finish(expected_a); a_seconds = time.monotonic()-started
        blocks.cache.clear(); blocks.cached = 0
        if progress:progress('A_stream_verified')
        started = time.monotonic(); b = Leaves(index, 'B')
        with restored_b.open('rb') as stream:
            while raw := stream.read(READ_BYTES):
                if memory_guard:memory_guard()
                b.feed(raw)
        proof_b = b.finish(expected_b); b_seconds = time.monotonic()-started
        if progress:progress('B_stream_verified')
        estimate = []
        baseline = proof_b['per_leaf_bytes'][str(SIZES[0])]['new_unique_compressed_payload_bytes']
        for size in SIZES:
            stats_a = proof_a['per_leaf_bytes'][str(size)]; stats_b = proof_b['per_leaf_bytes'][str(size)]
            payload = stats_b['new_unique_compressed_payload_bytes']
            estimate.append(dict(leaf_bytes=size, a_unique_leaves=stats_a['unique_inserted'],
                b_leaf_occurrences=stats_b['leaf_occurrences'], b_new_unique_leaves=stats_b['unique_inserted'],
                b_new_unique_compressed_leaf_payload_bytes=payload,
                reduction_vs_1m_leaf_payload_bytes=baseline-payload,
                reduction_vs_1m_leaf_payload_fraction=(baseline-payload)/baseline if baseline else None))
        index_bytes = index.execute('PRAGMA page_count').fetchone()[0]*index.execute('PRAGMA page_size').fetchone()[0]
        value = dict(schema='next-object-block-leaf-estimate-1', snapshot_a=snapshot_a, snapshot_b=snapshot_b,
            inputs=dict(a=proof_a, b=proof_b), estimates=estimate,
            phase_seconds=dict(a_authenticated_stream_and_index=a_seconds, b_stream_hash_and_new_leaf_compress=b_seconds),
            index=dict(storage='SQLite :memory: WITHOUT ROWID', allocated_page_bytes=index_bytes,
                distinct_keys=index.execute('SELECT count(*) FROM leaf').fetchone()[0], disk_temp_files_created=False),
            raw_input_passes=dict(a=1, b=1), raw_input_bytes=proof_a['bytes']+proof_b['bytes'],
            python_stream_and_compress_buffers_estimated_bound_bytes=sum(SIZES)+4*READ_BYTES+2048*128,
            source_tree_cache_limit_bytes=8*repository.MAX_BLOCK,
            compressed_algorithm='zlib level 1, hash=SHA256(D || raw leaf)',
            scope='same_original_A_B_bytes_leaf_payload_estimate_only',
            actual_new_repository_created=False, actual_repository_growth_measured=False,
            estimated_repository_restore_verified=False,
            exclusions=['map nodes', 'SQLite row/index/page/freelist overhead', 'repository collection/reclaim',
                'cross_file_or_other_snapshot_block_reuse', 'new_repository_restore_validation'],
            no_source_mutations=True)
    # This flag is emitted only after all cold handles and SQLite connections close.
    value['cold_guards_and_connections_released'] = True
    return value


def measured(operation, *, max_private_mib=1024):
    own = psutil.Process(); started = time.monotonic(); cpu0 = own.cpu_times(); io0 = own.io_counters()
    done = threading.Event(); exceeded = threading.Event(); peak = dict(private_bytes=0, rss_bytes=0)
    def sample():
        while not done.is_set():
            memory = own.memory_info(); private = getattr(memory, 'private', memory.vms)
            peak['private_bytes'] = max(peak['private_bytes'], private); peak['rss_bytes'] = max(peak['rss_bytes'], memory.rss)
            if private > max_private_mib*1024**2:exceeded.set()
            done.wait(.25)
    def guard():
        if exceeded.is_set():raise MemoryError('explicit process-private memory budget exceeded')
    thread = threading.Thread(target=sample, daemon=True); thread.start(); result = None; error = None
    try:
        result = operation(guard)
    except Exception:
        error = traceback.format_exc()
    finally:
        done.set(); thread.join()
    io1 = own.io_counters(); cpu1 = own.cpu_times()
    return dict(partial=error is not None, error_trace_private=error, result=result,
        elapsed_seconds=time.monotonic()-started, cpu_seconds=cpu1.user+cpu1.system-cpu0.user-cpu0.system,
        process_logical_read_bytes=io1.read_bytes-io0.read_bytes, process_logical_write_bytes=io1.write_bytes-io0.write_bytes,
        physical_disk_io_measured=False, memory_sample_seconds=.25, peak=peak,
        max_private_mib=max_private_mib, memory_budget_enforced_at_input_chunk_boundaries=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'restored_b', 'out'):
        parser.add_argument('--'+name.replace('_', '-'), type=Path, required=True)
    for name in ('snapshot_a', 'snapshot_b'):
        parser.add_argument('--'+name.replace('_', '-'), required=True)
    parser.add_argument('--max-private-mib', type=int, default=1024)
    args = parser.parse_args(argv)
    if args.out.exists():raise FileExistsError('fresh report required')
    if args.max_private_mib < 128:raise ValueError('memory budget must be at least 128 MiB')
    before = digest_file(Path(__file__))
    value = measured(lambda guard:compare(args.repo, args.snapshot_a, args.snapshot_b, args.restored_b,
        progress=lambda phase:print(json.dumps(dict(phase=phase)), flush=True), memory_guard=guard), max_private_mib=args.max_private_mib)
    value.update(source_sha256_before=before, source_sha256_after=digest_file(Path(__file__)))
    value['code_changed_during_run'] = value['source_sha256_before'] != value['source_sha256_after']
    write_json_new(args.out, value)
    print(json.dumps({k:value[k] for k in ('partial', 'elapsed_seconds', 'cpu_seconds', 'peak')}), flush=True)
    return int(value['partial'])


if __name__ == '__main__':
    raise SystemExit(main())
