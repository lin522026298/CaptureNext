"""Read-only aggregation of one finished load trial; never emit chat bodies.

The measured interval is bound by its recorded cycle IDs, not a guessed wall
clock cutoff. Catalog cohort payloads are NOT B-tree allocation deltas. Output
is a fresh evidence file outside the state and source, not a replacement log.
"""
import argparse
from contextlib import closing
import hashlib
import json
import math
from pathlib import Path
import sqlite3

from wechat_capture_v2.common import write_json_new


def quantiles(values):
    values.sort()
    return {name: values[min(len(values)-1, max(0, math.ceil(p*len(values))-1))]
        for name, p in (('p50', .5), ('p95', .95), ('p99', .99), ('max', 1))} if values else {}


def json_lines(path):
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            yield json.loads(line)


def analyze(folder, state):
    result_path = folder/'RESULT.json'
    result = json.loads(result_path.read_text(encoding='utf-8'))
    if result['returncode'] or 'end' not in result['endpoints']:
        raise ValueError('a successful settled trial is required')
    cycle_ids, top, last_summary = [], [], None
    observed_cycles = dict(cycles=0, idle=0, partial=0)
    frozen = {}
    for row in json_lines(folder/'cycles.private.jsonl'):
        if row['event'] != 'cycle':
            continue
        report = row['report']
        observed_cycles['cycles'] += 1
        observed_cycles['idle'] += report['status'] == 'idle'
        observed_cycles['partial'] += report['status'] == 'partial'
        last_summary = report['summary']
        if not report['cycle_id']:
            continue
        cycle_ids.append(report['cycle_id'])
        top.append(dict(unix=row['unix'], mode=report['mode'], write_bytes=row['logical_write_bytes'],
            elapsed_seconds=report['elapsed_seconds'], databases=[
                {key: db.get(key, 0) for key in ('relative_path','changed_plain_pages','temporary_wal_bytes','new_versions')}
                for db in report['databases'] if db.get('changed_plain_pages')]))
        top = sorted(top, key=lambda item: item['write_bytes'], reverse=True)[:5]
        for db in report['databases']:
            if db.get('status') == 'accepted':
                path = db['relative_path']
                item = frozen.setdefault(path, dict(acceptances=0, changed_plain_pages=0, new_versions=0))
                item['acceptances'] += 1
                item['changed_plain_pages'] += db.get('changed_plain_pages', 0)
                item['new_versions'] += db.get('new_versions', 0)
    if len(cycle_ids) != len(set(cycle_ids)):
        raise ValueError('duplicate non-idle cycle in evidence log')
    if any(observed_cycles[key] != result['events'][key] for key in observed_cycles):
        raise ValueError('cycle evidence does not match completed result')
    metrics = {key: [] for key in ('private_bytes','rss_bytes','logical_write_bytes_per_second')}
    for row in json_lines(folder/'samples.jsonl'):
        for key in metrics:
            if key != 'logical_write_bytes_per_second' or not row.get('first_counter_baseline'):
                metrics[key].append(row[key])
    end = result['endpoints']['end']
    if not metrics['private_bytes']:
        raise ValueError('no memory samples in completed evidence')
    duration = end['whole_worker_seconds']
    payload = json.dumps(cycle_ids)
    membership = ' IN (SELECT value FROM json_each(?))'
    with closing(sqlite3.connect((state/'catalog.sqlite').resolve().as_uri()+'?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        cohort = {}
        for table, columns in (('version', ('raw_z','normalized_json','locator_json')),
                               ('interpretation', ('normalized_json',))):
            expression = ','.join(f'coalesce(sum(length(CAST(v.{c} AS BLOB))),0)' for c in columns)
            row = db.execute(f'''SELECT count(*),{expression} FROM {table} v
                JOIN db_capture d ON d.id=v.first_capture WHERE d.cycle_id'''+membership, (payload,)).fetchone()
            cohort[table] = dict(rows=row[0], column_bytes=dict(zip(columns,row[1:])))
        count, evidence = db.execute('''SELECT count(*),coalesce(sum(length(CAST(evidence_json AS BLOB))),0)
            FROM db_capture WHERE cycle_id'''+membership, (payload,)).fetchone()
        cohort['db_capture'] = dict(rows=count, evidence_json_bytes=evidence)
        cohort['cycle'] = dict(rows=len(cycle_ids), report_json_bytes=db.execute('''SELECT
            coalesce(sum(length(CAST(report_json AS BLOB))),0) FROM cycle WHERE id'''+membership,(payload,)).fetchone()[0])
        cohort['transitions'] = dict(db.execute('''SELECT t.kind,count(*) FROM transition t
            JOIN db_capture d ON d.id=t.capture_id WHERE d.cycle_id'''+membership+' GROUP BY t.kind',(payload,)))
        distinct_cuts = db.execute('''SELECT count(*) FROM (SELECT source_id,relative_path,signature
            FROM db_capture WHERE cycle_id'''+membership+' GROUP BY source_id,relative_path,signature)',(payload,)).fetchone()[0]
        cohort['distinct_source_cuts'] = distinct_cuts
        cohort['repeated_source_cut_acceptances'] = count-distinct_cuts
        actual_cycles = db.execute('SELECT count(*) FROM cycle WHERE id'+membership,(payload,)).fetchone()[0]
        if actual_cycles != len(cycle_ids) or cohort['version']['rows'] != result['events']['new_versions']:
            raise ValueError('source catalog cohort does not match completed trial')
    before, after = end['settled_before'], end['settled_after']
    growth = {key: after['buckets'].get(key,0)-before['buckets'].get(key,0)
        for key in before['buckets'].keys() | after['buckets'].keys()}
    return dict(result_sha256=hashlib.sha256(result_path.read_bytes()).hexdigest(),
        started_unix=result['endpoints']['start']['unix'], ended_unix=end['unix'], duration_seconds=duration,
        cpu_one_core_percent=100*end['cpu_seconds']/duration,
        mean_logical_write_bytes_per_second=end['logical_write_bytes']/duration,
        mean_logical_read_bytes_per_second=end['logical_read_bytes']/duration,
        sampled_quantiles={key:quantiles(values) for key,values in metrics.items()},
        state_bucket_growth_bytes=growth, measured_cohort=cohort, last_cycle_summary=last_summary,
        per_database=frozen, highest_write_cycles=top, physical_disk_write_bytes=None,
        consistency_checks=dict(cycles=observed_cycles, unique_non_idle_cycles=len(cycle_ids),
            catalog_cohort_matches_result=True, memory_samples=len(metrics['private_bytes'])),
        caveat='cohort payloads exclude SQLite record/index overhead; net allocation change is only measured at filesystem bucket level; CPU percent is one-core equivalent')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trial', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    from argparse import Namespace
    from .load_probe import validate_measurement_output
    validate_measurement_output(Namespace(state=args.state.resolve(strict=True), out=args.out.parent, managed=None))
    summary = analyze(args.trial, args.state)
    write_json_new(args.out, summary)
    print(json.dumps(summary, ensure_ascii=False, separators=(',',':')))
