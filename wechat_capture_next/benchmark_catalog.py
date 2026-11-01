"""Isolated final-metadata replay, NOT an eight-hour collector rerun.

Only cycle/db_capture snapshots are replayed. Source reads, decryption, decoded
views and message/head reconstruction are excluded. A historical end-state
head table cannot reconstruct the cohort's initial heads reliably. All source
access is immutable/read-only; nonempty source WALs are rejected, not settled.
"""
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import time

import psutil

from wechat_capture_v2.common import canonical, directory, regular, write_json_new
from .catalog import Catalog, pack
from .reports import decode_report, encode_report

CYCLE = ('id', 'started', 'finished', 'mode', 'status', 'report_json')
CAPTURE = ('id', 'cycle_id', 'source_id', 'relative_path', 'signature',
           'evidence_json', 'message_count', 'accepted')
SCOPE = ('Final cycle/db_capture metadata snapshots only, not a complete 8h rerun '
         'or system-level storage/IO measurement. Source reads, decoded-view writes, '
         'message payload writes, head reconstruction, checkpoints and assets are '
         'excluded. Metadata replay uses identical artificial transaction order in '
         'both arms, not the unavailable historical SQL trace. Process logical IO '
         'is not physical disk IO. Temporary peak is unmeasured.')


def _digest(rows):
    """Length framing preserves exact text bytes, NULL and row boundaries."""
    result, count, size = hashlib.sha256(), 0, 0
    for row in rows:
        count += 1
        result.update(b'R')
        for value in row:
            if value is None:
                result.update(b'N')
            else:
                raw = value if isinstance(value, bytes) else str(value).encode('utf-8')
                size += len(raw)
                result.update(b'V'+len(raw).to_bytes(8, 'big')+raw)
        result.update(b'E')
    return dict(sha256=result.hexdigest(), rows=count, value_bytes=size)


def _expanded_cycles(db, order):
    for row in db.execute('SELECT '+','.join(CYCLE)+' FROM cycle ORDER BY '+order):
        yield (*row[:-1], decode_report(db, row[-1]) if row[-1] is not None else None)


def _identity(db):
    cycles = list(_expanded_cycles(db, 'id'))
    return dict(evidence=_digest(db.execute('SELECT id,evidence_json FROM db_capture ORDER BY id')),
                reports=_digest((row[0], row[5]) for row in cycles),
                cycle_rows=_digest(cycles),
                capture_rows=_digest(db.execute('SELECT '+','.join(CAPTURE)+' FROM db_capture ORDER BY id')))


def _safe_paths(source, output):
    source, output = Path(source), Path(output)
    for path in (source.parent, output):
        for parent in (path, *path.parents):
            if parent.exists() or parent.is_symlink():
                directory(parent)
    regular(source)
    source, output = source.resolve(strict=True), output.resolve()
    root = source.parent
    if output.is_relative_to(root) or root.is_relative_to(output):
        raise ValueError('output must not overlap source catalog or its parent state')
    if output.exists():
        raise FileExistsError('replay output must be a fresh directory')
    wal = Path(str(source)+'-wal')
    if wal.exists() and wal.stat().st_size:
        raise ValueError('source has a nonempty WAL; do not checkpoint or ignore it')
    return source, output


def _payload(db, ids):
    """Source payload accounting only; no message content is copied or emitted."""
    membership = ' IN (SELECT value FROM json_each(?))'
    bound = (json.dumps(ids),)
    result = {}
    for table, columns in (('version', ('raw_z', 'normalized_json', 'locator_json')),
                           ('interpretation', ('normalized_json',))):
        expr = ','.join(f'coalesce(sum(length(CAST(v.{col} AS BLOB))),0)' for col in columns)
        row = db.execute(f'SELECT count(*),{expr} FROM {table} v '
                         'JOIN db_capture d ON d.id=v.first_capture WHERE d.cycle_id'+membership,
                         bound).fetchone()
        result[table] = dict(rows=row[0], column_bytes=dict(zip(columns, row[1:])))
    result['transitions'] = dict(db.execute('SELECT t.kind,count(*) FROM transition t '
        'JOIN db_capture d ON d.id=t.capture_id WHERE d.cycle_id'+membership+' GROUP BY t.kind', bound))
    result['head_end_snapshot_rows_referencing_cohort_versions'] = db.execute(
        'SELECT count(*) FROM head h JOIN version v ON v.id=h.version_id '
        'JOIN db_capture d ON d.id=v.first_capture WHERE d.cycle_id'+membership, bound).fetchone()[0]
    result['replayed'] = False
    result['head_caveat'] = 'end snapshot only; not an initial-head reconstruction or a cohort head-write count'
    return result


def _settle(db):
    db.commit()
    result = tuple(db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone())
    if result[0]:
        raise RuntimeError('owned replay catalog did not settle')
    return result


def _snapshot(catalog, folder):
    checkpoint = _settle(catalog.db)
    db = catalog.db
    try:
        objects = {row[0]: dict(pages=row[1], bytes=row[2], payload_bytes=row[3], unused_bytes=row[4])
            for row in db.execute('SELECT name,count(*),sum(pgsize),sum(payload),sum(unused) '
                                  'FROM dbstat GROUP BY name ORDER BY name')}
    except sqlite3.OperationalError:
        objects = None
    quick = [row[0] for row in db.execute('PRAGMA quick_check')]
    foreign = [tuple(row) for row in db.execute('PRAGMA foreign_key_check')]
    if quick != ['ok'] or foreign:
        raise ValueError('replay integrity check failed')
    files = {path.relative_to(folder).as_posix(): path.stat().st_size
             for path in folder.rglob('*') if path.is_file()}
    page_count = db.execute('PRAGMA page_count').fetchone()[0]
    page_size = db.execute('PRAGMA page_size').fetchone()[0]
    return dict(checkpoint_truncate=checkpoint, quick_check=quick, foreign_key_check=foreign,
        main_file_bytes=catalog.path.stat().st_size, sqlite_allocated_page_bytes=page_count*page_size,
        page_count=page_count, page_size=page_size,
        freelist_count=db.execute('PRAGMA freelist_count').fetchone()[0],
        report_files=sum(name.startswith('reports/') for name in files),
        report_file_bytes=sum(size for name,size in files.items() if name.startswith('reports/')),
        state_file_bytes=sum(files.values()), files=files, table_and_index_dbstat=objects,
        temporary_peak_bytes=None)


def _replay(catalog, cycles, captures, reports):
    # Source final snapshots cannot recover the original intermediate evidence
    # update. Each cycle begin, each final capture, and each cycle finish is one
    # transaction. Preserve source rowid order within each of these three passes.
    for row in cycles:
        with catalog.db:
            catalog.db.execute("INSERT INTO cycle VALUES(?,?,NULL,?,'running',NULL)",
                               (row[0], row[1], row[3]))
    for row in captures:
        with catalog.db:
            catalog.db.execute('INSERT INTO db_capture VALUES(?,?,?,?,?,?,?,?)', row)
    for row in cycles:
        stored = encode_report(catalog.db, row[5]) if catalog.compact and row[5] is not None else row[5]
        with catalog.db:
            catalog.db.execute('UPDATE cycle SET finished=?,status=?,report_json=? WHERE id=?',
                               (row[2], row[4], stored, row[0]))
        if reports is not None and row[5] is not None:
            # Hashed names avoid trusting source cycle IDs as filesystem paths.
            path = reports/(hashlib.sha256(row[0].encode()).hexdigest()+'.json')
            with path.open('x', encoding='utf-8', newline='\n') as stream:
                stream.write(row[5]+'\n')


def benchmark(source, cycle_ids, output):
    """Compare identical metadata inputs in two fresh, isolated Catalogs.

    The baseline consists of every non-cohort source cycle, even cycles later
    than the recorded cohort. Therefore this measures a controlled partitioned
    replay, not historical start/end archive allocation.
    """
    source, output = _safe_paths(source, output)
    ids = list(cycle_ids)
    if not ids or any(not isinstance(item, str) or not item for item in ids) or len(ids) != len(set(ids)):
        raise ValueError('cycle_ids must be nonempty unique strings')
    source_stat = source.stat()
    with closing(sqlite3.connect(source.as_uri()+'?mode=ro&immutable=1', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        cycles = list(_expanded_cycles(db, 'rowid'))
        # A compact source's compatibility view has no meaningful rowid.
        entity = 'capture_record' if db.execute("SELECT 1 FROM sqlite_master WHERE name='capture_record' AND type='table'").fetchone() else 'db_capture'
        captures = list(db.execute('SELECT '+','.join('d.'+col for col in CAPTURE)+
            ' FROM db_capture d JOIN '+entity+' e ON e.id=d.id ORDER BY e.rowid'))
        if not set(ids).issubset({row[0] for row in cycles}):
            raise ValueError('cohort cycle not found in source catalog')
        expected, payload = _identity(db), _payload(db, ids)
    cohort_ids = set(ids)
    phases = {}
    for label, selected in (('baseline', False), ('cohort', True)):
        phases[label] = ([row for row in cycles if (row[0] in cohort_ids) == selected],
                         [row for row in captures if (row[1] in cohort_ids) == selected])
    output.mkdir(parents=True, exist_ok=False)
    arms = {}
    for label, compact in (('legacy', False), ('compact', True)):
        folder = output/label
        folder.mkdir()
        reports = None if compact else folder/'reports'
        if reports is not None:
            reports.mkdir()
        pack.cache_clear()
        with closing(Catalog(folder/'catalog.sqlite', compact_new=compact)) as catalog:
            _replay(catalog, *phases['baseline'], reports)
            before = _snapshot(catalog, folder)
            own = psutil.Process()
            io0, cpu0, start = own.io_counters(), own.cpu_times(), time.monotonic()
            _replay(catalog, *phases['cohort'], reports)
            # Include the same owned WAL TRUNCATE in both measured intervals;
            # exclude diagnostic dbstat/integrity/hash reads from process IO.
            _settle(catalog.db)
            io1, cpu1, elapsed = own.io_counters(), own.cpu_times(), time.monotonic()-start
            after = _snapshot(catalog, folder)
            identity = _identity(catalog.db)
            if identity != expected:
                raise ValueError('expanded evidence/report bytes differ from source')
            arms[label] = dict(before=before, after=after, exact_expanded_identity=identity,
                main_file_net_growth_bytes=after['main_file_bytes']-before['main_file_bytes'],
                sqlite_allocated_page_net_growth_bytes=after['sqlite_allocated_page_bytes']-before['sqlite_allocated_page_bytes'],
                report_files_added=after['report_files']-before['report_files'],
                report_file_net_growth_bytes=after['report_file_bytes']-before['report_file_bytes'],
                logical_read_bytes=io1.read_bytes-io0.read_bytes,
                logical_write_bytes=io1.write_bytes-io0.write_bytes,
                cpu_seconds=cpu1.user+cpu1.system-cpu0.user-cpu0.system, elapsed_seconds=elapsed,
                physical_write_bytes=None, temporary_peak_bytes=None)
    end_stat = source.stat()
    wal = Path(str(source)+'-wal')
    if ((source_stat.st_size, source_stat.st_mtime_ns) != (end_stat.st_size, end_stat.st_mtime_ns)
            or (wal.exists() and wal.stat().st_size)):
        raise RuntimeError('source file changed during replay')
    result = dict(kind='isolated-final-metadata-replay-3', scope=SCOPE,
        compact_report_storage='RS-framed capture-reference codec, with exact expanded text identity; literal JSON preserved',
        source=dict(path=str(source), bytes=source_stat.st_size, mtime_ns=source_stat.st_mtime_ns,
                    immutable_read_only=True, stat_unchanged=True),
        cohort_cycle_ids=ids, source_exact_expanded_identity=expected,
        inputs={name: dict(cycles=len(rows[0]), captures=len(rows[1]),
                          evidence_json_bytes=sum(len(row[5].encode('utf-8')) for row in rows[1]),
                          report_json_bytes=sum(len(row[5].encode('utf-8')) for row in rows[0] if row[5] is not None),
                          cycle_sequence=_digest(rows[0]), capture_sequence=_digest(rows[1]))
                for name, rows in phases.items()},
        baseline_caveat='all noncohort cycles first, including any postcohort cycles; not historical pre-8h state',
        ordering='baseline then cohort; each phase: cycle begins by rowid, final captures by rowid, cycle finishes by rowid',
        transaction_scope='one transaction per cycle begin, final capture insert, and cycle finish',
        io_scope='cohort metadata writes, legacy report file writes, and owned WAL TRUNCATE only; excludes source reads, diagnostics and output summary',
        message_payload_source_cohort=payload, arms=arms, exact_identity_equal=True,
        physical_write_bytes=None, temporary_peak_bytes=None)
    write_json_new(output/'RESULT.json', result)
    return result


def cohort_from_trial(trial):
    """Bind to recorded successful trial IDs, never a wall-clock approximation."""
    trial = Path(trial)
    result = json.loads((trial/'RESULT.json').read_text(encoding='utf-8'))
    if result['returncode'] or 'end' not in result['endpoints']:
        raise ValueError('successful completed trial required')
    ids, counts = [], dict(cycles=0, idle=0, partial=0)
    with (trial/'cycles.private.jsonl').open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            if row['event'] != 'cycle':
                continue
            report = row['report']
            counts['cycles'] += 1
            counts['idle'] += report['status'] == 'idle'
            counts['partial'] += report['status'] == 'partial'
            if report['cycle_id']:
                ids.append(report['cycle_id'])
    if len(ids) != len(set(ids)) or any(counts[key] != result['events'][key] for key in counts):
        raise ValueError('recorded cohort does not match trial result')
    return ids


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--trial', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = benchmark(args.source, cohort_from_trial(args.trial), args.out)
    # Private payloads remain in the isolated catalog, not stdout.
    print(canonical(dict(kind=result['kind'], exact_identity_equal=result['exact_identity_equal'],
                         output=str(args.out.resolve()), scope=result['scope'])))
