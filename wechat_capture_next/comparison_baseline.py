"""Explicit one-time settlement of a working comparison repository to A16 only.

This is NOT the product retention policy. It retires the older coarse B
generation only after full keeper readback and an independently guarded, fully
hashed OfflineView of B prove recoverability. No synthetic generation is added.
Collection may remain pending after accepted metadata retirement; A16 and the
independent preserved B stay protected. No real operations run on import.
"""
import argparse
from contextlib import ExitStack,closing
import json
import math
from pathlib import Path

from wechat_capture_v2.common import digest_file,write_json_new
from . import pair_repository as repository,pair_collection
from .offline_view import OfflineView
from .paths import local_absolute

WORKING_ROOT=Path(__file__).resolve().parents[1]/'working'


def _entry_hashes(files):
    result={}
    repository.require(isinstance(files,dict) and files,'complete preserved B file tree required')
    for name,entry in files.items():
        repository.file_name(name)
        repository.require(isinstance(entry,dict) and type(entry.get('bytes')) is int and entry['bytes']>=0,
            'invalid preserved file length')
        repository.identifier(entry.get('sha256'))
        result[name]=dict(bytes=entry['bytes'],sha256=entry['sha256'])
    return result


def _shape(db,owner,keeper):
    repository.identifier(keeper)
    repository.require(db.execute('SELECT count(*) FROM pin').fetchone()[0]==0,
        'pinned snapshots forbid comparison baseline retirement')
    generations=db.execute('SELECT seq,snapshot_id FROM generation ORDER BY seq DESC').fetchall()
    snapshots={row[0] for row in db.execute('SELECT id FROM snapshot')}
    repository.require(len(generations)==2 and len(snapshots)==2 and
        {row[1] for row in generations}==snapshots,'exactly two accepted unpinned comparison points required')
    repository.require(generations[0][1]==keeper,'explicit keeper must be the latest accepted A16 point')
    coarse_b=generations[1][1]
    a=repository.manifest(db,keeper,owner);b=repository.manifest(db,coarse_b,owner)
    repository.require(a['context'].get('comparison_only') is True,'comparison_only keeper required')
    link=a['context'].get('comparison_reblock')
    repository.require(isinstance(link,dict) and link.get('retained_b_snapshot')==coarse_b,
        'keeper comparison reblock does not identify the other coarse B')
    repository.require(a['context'].get('object_leaf_bytes')==16384 and
        a['files'].get('state/objects.sqlite',{}).get('leaf_bytes')==16384,'keeper must use explicit 16KiB object profile')
    repository.require(b['context'].get('object_leaf_bytes',repository.MAX_BLOCK)==repository.MAX_BLOCK and
        b['files'].get('state/objects.sqlite',{}).get('leaf_bytes')==repository.MAX_BLOCK,
        'other point must be the coarse 1MiB B profile')
    return a,b,coarse_b,generations[0][0]


def settle(repo,keeper_snapshot,preserved_restored_b,*,seconds=1800,fault=None):
    """Accept explicit comparison-only retirement, then settle bounded cleanup.

    Before retirement commit, failures raise and preserve both accepted points.
    After commit, failures return partial=True and leave only safe extra garbage.
    The normal collection keep=2 API remains unchanged; with one real accepted
    generation it correctly protects that one keeper plus any pins (none here).
    """
    repo=local_absolute(repo);preserved=local_absolute(preserved_restored_b);working=local_absolute(WORKING_ROOT)
    repository.require(isinstance(seconds,(int,float)) and not isinstance(seconds,bool) and
        math.isfinite(seconds) and seconds>=0,'nonnegative finite collection budget required before retirement')
    repository.require(repo!=working and repo.is_relative_to(working),'baseline retirement is restricted to project working')
    repository.require(preserved!=working and preserved.is_relative_to(working),'preserved B must be an explicit project working restore')
    repository.require(not (repo==preserved or repo.is_relative_to(preserved) or preserved.is_relative_to(repo)),
        'preserved B must be independent of comparison repository')
    result=None
    with ExitStack() as stack:
        db,owner=stack.enter_context(repository.session(repo))
        db.execute('BEGIN IMMEDIATE')
        a,b,coarse_b,keeper_seq=_shape(db,owner,keeper_snapshot)
        repository.require(str(repo) in a['context'].get('protected_roots',[]),
            'keeper does not explicitly own this comparison repository')
        literal_before=db.execute('SELECT manifest FROM snapshot WHERE id=?',(keeper_snapshot,)).fetchone()[0]
        if fault:fault('before_keeper_verify',db)
        keeper_proof=repository.verify_files(db,a)
        repository.require(keeper_proof.get('verified') is True,'full A16 keeper file proof required')
        if fault:fault('after_keeper_verify',db)
        # Actual OfflineView attributes intentionally inspected: it owns lifetime
        # guards but does not expose a receipt property. Read its guarded receipt.
        view=stack.enter_context(closing(OfflineView(preserved)))
        repository.require(view.root==preserved and view.catalog_instance==owner['catalog_instance'] and
            view.union_id==owner['union_id'],'preserved B owner identities differ')
        receipt=json.loads((view.root/'DELIVERY.complete.private.json').read_text(encoding='utf-8'))
        expected_b=_entry_hashes(b['files']);actual_b=_entry_hashes(receipt['restored_files'])
        repository.require(actual_b==expected_b,'preserved B receipt file tree SHA/length differs from coarse B')
        if fault:fault('after_preserved_B_verify',db)
        count=db.execute('DELETE FROM generation WHERE snapshot_id=?',(coarse_b,)).rowcount
        repository.require(count==1,'coarse B accepted generation changed unexpectedly')
        if fault:fault('before_retirement_commit',db)
        db.commit()
        result=dict(schema='next-owned-comparison-baseline-1',keeper_snapshot=keeper_snapshot,retired_coarse_b_snapshot=coarse_b,
            preserved_B_restored_snapshot_id=view.snapshot,preserved_B_file_count=len(actual_b),
            preserved_B_verified_bytes=sum(entry['bytes'] for entry in actual_b.values()),
            preserved_B_full_file_hashes_verified=True,preserved_B_lifetime_denywrite_guards=True,
            keeper_full_readback_before_retirement=keeper_proof,metadata_retirement_accepted=True,
            artificial_generation_added=False,normal_product_retention_policy_changed=False,
            comparison_only=True,partial=True,settled=False,cleanup_pending=True,
            cost_scope='one_time_comparison_baseline_governance_not_daily_backup')
        try:
            if fault:fault('after_retirement_commit',db)
            cleanup_fault=(None if fault is None else lambda name,connection:fault('collection:'+name,connection))
            cleanup=pair_collection.cleanup(db,owner,repo,keep=2,seconds=seconds,fault=cleanup_fault)
            result['cleanup']=cleanup
            # Authenticate the original keeper manifest again; do not invent a
            # duplicate acceptance merely to make keep=2 retain a single point.
            after=repository.manifest(db,keeper_snapshot,owner)
            literal_after=db.execute('SELECT manifest FROM snapshot WHERE id=?',(keeper_snapshot,)).fetchone()[0]
            repository.require(literal_after==literal_before and after==a,'keeper manifest changed during baseline retirement')
            generations=[tuple(row) for row in db.execute('SELECT seq,snapshot_id FROM generation ORDER BY seq')]
            snapshots=[row[0] for row in db.execute('SELECT id FROM snapshot ORDER BY id')]
            free=db.execute('PRAGMA freelist_count').fetchone()[0]
            # collection_live was freshly authenticated from keeper maps in this
            # same held writer session. The independent count is not a persisted
            # reusable GC certificate and never authorizes an extra deletion.
            live=db.execute("SELECT 1 FROM sqlite_temp_master WHERE name='collection_live' AND type='table'").fetchone()
            dead=(db.execute('SELECT count(*) FROM block WHERE hash NOT IN (SELECT hash FROM collection_live)').fetchone()[0]
                if live else None)
            foreign=list(db.execute('PRAGMA foreign_key_check'))
            result.update(keeper_manifest_unchanged=True,final_generation_count=len(generations),final_snapshot_count=len(snapshots),
                freelist_pages_after=free,dead_blocks_after=dead,foreign_key_check_empty=not foreign,
                keeper_generation_sequence_preserved=generations==[(keeper_seq,keeper_snapshot)])
            settled=(not cleanup.get('cleanup_pending',True) and generations==[(keeper_seq,keeper_snapshot)] and
                snapshots==[keeper_snapshot] and free==0 and dead==0 and not foreign)
            result.update(settled=settled,partial=not settled,cleanup_pending=not settled)
        except Exception as error:
            if db.in_transaction:db.rollback()
            result.update(post_accept_error_type=type(error).__name__,partial=True,settled=False,cleanup_pending=True)
    result['preserved_B_guards_and_repository_writer_session_released']=True
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--keeper-snapshot',required=True)
    parser.add_argument('--preserved-restored-B',dest='preserved_b',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--seconds',type=float,default=1800)
    args=parser.parse_args(argv)
    out=local_absolute(args.out);repo=local_absolute(args.repo);preserved=local_absolute(args.preserved_b)
    working=local_absolute(WORKING_ROOT)
    repository.require(out.is_relative_to(working) and out.parent.exists(),'private report must use an existing project working directory')
    repository.require(not out.is_relative_to(repo) and not out.is_relative_to(preserved),'report overlaps protected comparison inputs')
    samples=out.with_name(out.stem+'.samples.private.jsonl')
    if out.exists() or samples.exists():raise FileExistsError('fresh baseline report and sample paths required')
    from . import benchmark_pair,offline_view,union_archive,backup
    sources=[Path(__file__),Path(repository.__file__),Path(pair_collection.__file__),Path(offline_view.__file__),
        Path(benchmark_pair.__file__),Path(union_archive.__file__),Path(backup.__file__)]
    hashes=lambda:{path.name:digest_file(path) for path in sources}
    before=hashes();last=[None]
    def phase(name,db):
        coarse=pair_collection.progress_phase(name[len('collection:'):]) if name.startswith('collection:') else name
        if coarse!=last[0]:print(json.dumps(dict(phase=coarse)),flush=True);last[0]=coarse
    value=benchmark_pair.measure(lambda:settle(repo,args.keeper_snapshot,preserved,seconds=args.seconds,fault=phase),
        repo,samples_path=samples)
    value.update(source_hashes_before=before,source_hashes_after=hashes())
    value['code_changed_during_run']=value['source_hashes_before']!=value['source_hashes_after']
    if value.get('result') is not None and value['result'].get('partial',True):value['partial']=True
    value['all_operation_resources_released']=True
    write_json_new(out,value)
    print(json.dumps({key:value[key] for key in ('partial','elapsed_seconds','settled_net_bytes','code_changed_during_run')}),flush=True)
    return int(value['partial'])


if __name__=='__main__':raise SystemExit(main())
