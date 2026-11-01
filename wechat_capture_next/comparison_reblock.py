"""One-time, explicit reblocking of an owned working/comparison A snapshot.

Never runs automatically. Only two unpinned accepted comparison generations,
with selected A older than B, are eligible. A successful authenticated full
readback commits new A16k and retains B; any failure rolls back all publication
and collection. This is a migration cost, NOT daily incremental backup cost.
"""
import argparse
import hashlib
import json
from pathlib import Path

from wechat_capture_v2.common import canonical, utcnow, write_json_new, digest_file
from . import pair_repository as repository
from .paths import local_absolute

WORKING_ROOT=Path(__file__).resolve().parents[1]/'working'


def reblock(repo,snapshot,*,fault=None):
    repo=local_absolute(repo);working=local_absolute(WORKING_ROOT)
    repository.require(repo!=working and repo.is_relative_to(working),'comparison reblock is restricted to project working')
    with repository.session(repo) as (db,owner):
        db.execute('BEGIN IMMEDIATE')
        old=repository.manifest(db,snapshot,owner)
        repository.require(old['context'].get('comparison_only') is True,'explicit comparison_only A snapshot required')
        repository.require(str(repo) in old['context'].get('protected_roots',[]),'comparison repository is not explicitly owned by A context')
        repository.require(db.execute('SELECT count(*) FROM pin').fetchone()[0]==0,'pinned snapshots forbid comparison reblock')
        generations=db.execute('SELECT snapshot_id FROM generation ORDER BY seq DESC').fetchall()
        snapshots={row[0] for row in db.execute('SELECT id FROM snapshot')}
        repository.require(len(generations)==2 and len(snapshots)==2 and {row[0] for row in generations}==snapshots,
            'exactly two accepted comparison generations required')
        retained_b=generations[0][0]
        repository.require(generations[1][0]==snapshot and retained_b!=snapshot,'selected comparison A must be older than retained B')
        entry=old['files'].get('state/objects.sqlite')
        repository.require(entry is not None and entry['leaf_bytes']==repository.MAX_BLOCK,'one-time old 1MiB A profile required')
        context=dict(old['context'])
        repository.require(context.get('object_leaf_bytes',repository.MAX_BLOCK)==repository.MAX_BLOCK,'source A profile differs')
        context.pop('object_leaf_bytes',None)
        context=repository._profile(context,repository.DEFAULT_OBJECT_BLOCK)
        context['comparison_reblock']=dict(source_snapshot=snapshot,retained_b_snapshot=retained_b,
            original_objects_sha256=entry['sha256'],cost_scope='one_time_profile_migration_not_daily_backup')
        blocks=repository.Blocks(db)
        replacement,added=repository.add_stream(db,blocks.walk(entry['root'],entry['height'],entry['bytes']),
            repository.DEFAULT_OBJECT_BLOCK,expected=entry)
        files=dict(old['files']);files['state/objects.sqlite']=replacement
        value=dict(schema=repository.SCHEMA,owner=owner,files=files,context=context)
        literal=canonical(value);identity=hashlib.sha256(literal.encode()).hexdigest()
        if fault:fault('before_verify',db)
        proof=repository.verify_files(db,value)
        db.execute('INSERT INTO snapshot VALUES(?,?,?)',(identity,literal,utcnow()))
        db.executemany('INSERT INTO snapshot_file VALUES(?,?,?)',((identity,name,item['root']) for name,item in files.items()))
        repository.manifest(db,identity,owner)
        db.execute('INSERT INTO generation(snapshot_id,accepted_at) VALUES(?,?)',(identity,utcnow()))
        governance=repository._govern_transaction(db,owner,2,fault)
        repository.require({row[0] for row in db.execute('SELECT id FROM snapshot')}=={retained_b,identity},'comparison retain set differs')
        if fault:fault('before_commit',db)
        db.commit()
        governance.update(repository._reclaim(db,repo))
        return dict(snapshot_id=identity,source_snapshot=snapshot,retained_b_snapshot=retained_b,
            original_objects_sha256=entry['sha256'],original_objects_bytes=entry['bytes'],
            object_leaf_bytes=replacement['leaf_bytes'],new_blocks=added,verification=proof,governance=governance,
            other_file_roots_preserved=True,comparison_only=True,
            cost_scope='one_time_profile_migration_not_daily_backup',full_plaintext_temporary_created=False)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,required=True);parser.add_argument('--snapshot',required=True)
    parser.add_argument('--out',type=Path,required=True);args=parser.parse_args(argv)
    if args.out.exists():raise FileExistsError('fresh migration report required')
    from .benchmark_pair import measure
    sources=[Path(__file__),Path(repository.__file__)]
    hashes=lambda:{path.name:digest_file(path) for path in sources}
    before=hashes()
    result=measure(lambda:reblock(args.repo,args.snapshot),args.repo)
    result.update(source_hashes_before=before,source_hashes_after=hashes())
    result['code_changed_during_run']=result['source_hashes_before']!=result['source_hashes_after']
    write_json_new(args.out,result)
    print(json.dumps({key:result[key] for key in ('partial','elapsed_seconds','settled_net_bytes')}))
    return int(result['partial'])


if __name__=='__main__':raise SystemExit(main())
