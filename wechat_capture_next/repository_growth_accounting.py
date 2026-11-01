"""Read-only attribution of an accepted A -> B repository's new blocks.

Scratch membership/indexes are in RAM. This is accounting of already verified
graphs, not a replacement for independent restore or collision authentication.
"""
import argparse
from collections import defaultdict
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import zlib

from wechat_capture_v2.common import write_json_new
from . import pair_repository as repo
from .union_archive import cold_input
from .storage_ledger import inventory


def account(repository,before,after,latest_only):
    repository=repo.legacy._parents(repository);latest_only=repo.legacy._parents(latest_only)
    with cold_input(repository/repo.DATABASE),repo.session(repository,readonly=True) as (source,owner):
        a=repo.manifest(source,before,owner);b=repo.manifest(source,after,owner)
        with closing(sqlite3.connect(':memory:',uri=True)) as db:
            db.execute('PRAGMA temp_store=MEMORY');db.execute('PRAGMA cache_size=-131072')
            db.execute('ATTACH DATABASE ? AS retained',((repository/repo.DATABASE).as_uri()+'?mode=ro&immutable=1',))
            db.execute('CREATE TABLE old(hash TEXT PRIMARY KEY) WITHOUT ROWID')
            db.execute('''INSERT INTO old WITH RECURSIVE reached(hash) AS (
                SELECT root FROM retained.snapshot_file WHERE snapshot_id=?
                UNION SELECT e.child FROM retained.edge e JOIN reached r ON e.parent=r.hash)
                SELECT hash FROM reached''',(before,))
            db.execute('CREATE TABLE seen(hash TEXT PRIMARY KEY) WITHOUT ROWID')
            files={};totals=defaultdict(int)
            for name,entry in sorted(b['files'].items()):
                previous=a['files'].get(name);row=dict(original_bytes=entry['bytes'],
                    original_size_delta=entry['bytes']-(previous['bytes'] if previous else 0),
                    original_changed=previous is None or previous['sha256']!=entry['sha256'],
                    new_data_blocks=0,new_map_blocks=0,new_compressed_data_bytes=0,new_compressed_map_bytes=0)
                pending=[entry['root']]
                while pending:
                    sha=pending.pop()
                    if db.execute('SELECT 1 FROM old WHERE hash=?',(sha,)).fetchone():continue
                    if not db.execute('INSERT OR IGNORE INTO seen VALUES(?)',(sha,)).rowcount:continue
                    value=db.execute('SELECT kind,bytes,data FROM retained.block WHERE hash=?',(sha,)).fetchone()
                    repo.require(value is not None,'accounting graph missing block')
                    kind,size,payload=value;raw=zlib.decompress(payload)
                    repo.require(kind in ('D','N') and len(raw)==size and hashlib.sha256(kind.encode()+raw).hexdigest()==sha,
                        'new accounting block authentication failed')
                    label='data' if kind=='D' else 'map'
                    row['new_'+label+'_blocks']+=1;row['new_compressed_'+label+'_bytes']+=len(payload)
                    if kind=='N':
                        node=json.loads(raw);edges=[r[0] for r in db.execute('SELECT child FROM retained.edge WHERE parent=? ORDER BY ordinal',(sha,))]
                        repo.require(edges==[item[0] for item in node['children']],'accounting node edges differ')
                        pending.extend(reversed(edges))
                if row['original_changed'] or row['new_data_blocks'] or row['new_map_blocks']:files[name]=row
                for key,value in row.items():
                    if key.startswith('new_'):totals[key]+=value
            actual=db.execute('SELECT count(*) FROM retained.block b LEFT JOIN old o ON o.hash=b.hash WHERE o.hash IS NULL').fetchone()[0]
            repo.require(actual==totals['new_data_blocks']+totals['new_map_blocks'],
                'repository has extra points or unreferenced blocks; A/B-only attribution invalid')
            try:pages={name:bytes for name,bytes in db.execute("SELECT name,sum(pgsize) FROM dbstat('retained') GROUP BY name")}
            except sqlite3.OperationalError:pages=None
            page_count=db.execute('PRAGMA retained.page_count').fetchone()[0]
            page_size=db.execute('PRAGMA retained.page_size').fetchone()[0]
            freelist=db.execute('PRAGMA retained.freelist_count').fetchone()[0]
    rolling=inventory(repository);sole=inventory(latest_only)
    with cold_input(latest_only/repo.DATABASE),repo.session(latest_only,readonly=True) as (db,owner):
        points=[r[0] for r in db.execute('SELECT id FROM snapshot')]
        repo.require(len(points)==1,'latest-only reference must have exactly one accepted point')
        c=repo.manifest(db,points[0],owner)
        repo.require(c['files']==b['files'],'latest-only reference is not byte-identical B input')
        baseline_free=db.execute('PRAGMA freelist_count').fetchone()[0]
        repo.require(baseline_free==0,'latest-only baseline contains reclaimable pages')
    return dict(schema='next-repository-growth-accounting-1',before=before,after=after,files=files,new_blocks=dict(totals),
        attribution='first_sorted_file_reference_new_unique_blocks_no_double_count',
        rolling_logical_bytes=rolling['logical_bytes'],rolling_allocated_bytes=rolling['allocated_bytes'],
        latest_only_B_logical_bytes=sole['logical_bytes'],latest_only_B_allocated_bytes=sole['allocated_bytes'],
        rolling_to_B_allocated_ratio=rolling['allocated_bytes']/sole['allocated_bytes'],
        repository_page_bytes=page_count*page_size,freelist_pages=freelist,sqlite_page_bytes_by_table_index=pages,
        physical_disk_write_bytes=None,not_a_write_amplification_ratio=True,
        preserves_all_old_points_in_this_two_point_comparison=True)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('repository','latest-only','out'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('before','after'):p.add_argument('--'+name,required=True)
    a=p.parse_args(argv)
    from .benchmark_pair import measure
    result=measure(lambda:account(a.repository,a.before,a.after,a.latest_only),a.repository,
        samples_path=a.out.with_suffix('.samples.private.jsonl'))
    write_json_new(a.out,result);print(json.dumps(dict(partial=result['partial'],error_type=result['error_type'],elapsed_seconds=result['elapsed_seconds'])))


if __name__=='__main__':main()
