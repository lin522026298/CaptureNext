"""Fresh independent one-point repository; no old-repository adoption or GC.

Useful for measuring latest-only B and for a portable, fixed recovery point.
Only authenticated map reachability is copied. Source graph edges are ignored.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

from wechat_capture_v2.common import canonical,utcnow,write_json_new
from . import pair_repository as repo
from .union_archive import cold_input


def copy_snapshot(source,snapshot,target,*,fault=None):
    source=repo.legacy._parents(source);target=repo.legacy._parents(target)
    repo.require(not target.exists() and not repo.legacy._overlap(source,target),'fresh disjoint repository copy required')
    with repo.session(source,readonly=True) as (origin,owner):
        origin.execute('BEGIN');value=repo.manifest(origin,snapshot,owner)
        for protected in value['context'].get('protected_roots',[]):
            repo.require(not repo.legacy._overlap(target,repo.legacy._external_root(protected)),'copy overlaps protected original')
        parent=target.parent
        while not parent.exists():parent=parent.parent
        # Conservative bound for an already governed source, not input logical
        # bytes (which include compression). Refuse before target creation.
        required=(source/repo.DATABASE).stat().st_size+1024**3
        repo.require(shutil.disk_usage(parent).free>=required,'insufficient independent copy space')
        with cold_input(source/repo.DATABASE),repo.session(target,owner,create=True) as (db,_):
            db.execute('BEGIN IMMEDIATE')
            db.execute('PRAGMA temp_store=MEMORY')
            db.execute('CREATE TEMP TABLE copy_live(hash TEXT PRIMARY KEY,height INTEGER NOT NULL,bytes INTEGER NOT NULL) WITHOUT ROWID')
            blocks=repo.Blocks(origin);leaves=nodes=0
            def mark(key,height,size):
                nonlocal leaves,nodes
                old=db.execute('SELECT height,bytes FROM copy_live WHERE hash=?',(key,)).fetchone()
                if old is not None:
                    repo.require(tuple(old)==(height,size),'copy node shape conflict');return
                db.execute('INSERT INTO copy_live VALUES(?,?,?)',(key,height,size))
                if height==0:
                    shape=origin.execute('SELECT kind,bytes FROM block WHERE hash=?',(key,)).fetchone()
                    repo.require(shape is not None and tuple(shape)==('D',size),'missing selected leaf')
                    leaves+=1;return
                kind,raw=blocks.get(key);repo.require(kind=='N','selected map kind differs')
                node=json.loads(raw)
                repo.require(node['height']==height and sum(c[1] for c in node['children'])==size,'selected map shape differs')
                nodes+=1
                for child,length in node['children']:mark(child,height-1,length)
            for entry in value['files'].values():mark(entry['root'],entry['height'],entry['bytes'])
            if fault:fault('selected',db)
            # Attach read-only under an existing source guard. Bulk SQL copy
            # avoids materializing a million BLOBs or row objects in Python.
            db.execute('ATTACH DATABASE ? AS selected_source',((source/repo.DATABASE).as_uri()+'?mode=ro&immutable=1',))
            db.execute('''INSERT INTO block SELECT b.hash,b.kind,b.bytes,b.data FROM selected_source.block b
                JOIN temp.copy_live l ON l.hash=b.hash''')
            repo.require(db.execute('SELECT count(*) FROM block').fetchone()[0]==leaves+nodes,'selected block copy incomplete')
            for key, in db.execute('SELECT hash FROM copy_live WHERE height>0'):
                kind,raw=blocks.get(key);repo.require(kind=='N','selected map differs')
                children=json.loads(raw)['children']
                db.executemany('INSERT INTO edge VALUES(?,?,?)',((key,i,c[0]) for i,c in enumerate(children)))
            proof=repo.verify_files(db,value)  # Independent full target readback.
            literal=canonical(value)
            db.execute('INSERT INTO snapshot VALUES(?,?,?)',(snapshot,literal,utcnow()))
            db.executemany('INSERT INTO snapshot_file VALUES(?,?,?)',((snapshot,name,e['root']) for name,e in value['files'].items()))
            db.execute('INSERT INTO generation(snapshot_id,accepted_at) VALUES(?,?)',(snapshot,utcnow()))
            repo.require(not list(db.execute('PRAGMA foreign_key_check')),'copied references differ')
            if fault:fault('before_commit',db)
            db.commit()
    return dict(snapshot_id=snapshot,latest_only=True,independent=True,pins_copied=False,
        selected_data_blocks=leaves,selected_map_blocks=nodes,verification=proof,source_mutated=False)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','target','out'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--snapshot',required=True);a=p.parse_args(argv)
    from .benchmark_pair import measure
    paths=(Path(__file__),Path(repo.__file__));hashes=lambda:{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    before=hashes()
    result=measure(lambda:copy_snapshot(a.source,a.snapshot,a.target),a.target,samples_path=a.out.with_suffix('.samples.private.jsonl'))
    result.update(source_hashes_before=before,source_hashes_after=hashes(),code_changed_during_run=before!=hashes())
    write_json_new(a.out,result)
    print(json.dumps({k:result[k] for k in ('partial','elapsed_seconds','settled_after_bytes','settled_net_bytes')}))
    return int(result['partial'])


if __name__=='__main__':raise SystemExit(main())
