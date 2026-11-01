"""Read-only retirement plan for the explicitly verified legacy A expansion.

Never deletes. Require point/file hashes, owned restore markers, no links and
no process dependency before a separate literal-path native cleanup operation.
"""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path

import psutil
from wechat_capture_v2.common import digest_file,write_json_new
from . import pair_repository as repo
from .storage_ledger import inventory
from .union_archive import cold_input


def plan(root,repository,snapshot):
    root=repo.legacy._parents(root);workspace=Path(__file__).resolve().parent.parent
    repo.require(root.is_relative_to(workspace/'working') and root.name=='legacy-baseline-restored','only the explicit task-owned A expansion may be planned')
    evidence=inventory(root);repo.require(evidence['deletion_candidate_clean'],'linked or nonregular expansion cannot be retired')
    ignored={os.getpid(),*(p.pid for p in psutil.Process().parents())};dependencies=[]
    for process in psutil.process_iter(['pid','cmdline','cwd','exe']):
        if process.pid in ignored:continue
        try:
            values=[process.info['cwd'] or '',process.info['exe'] or '',*(process.info['cmdline'] or [])]
            if any(str(root).casefold() in str(value).casefold() for value in values):dependencies.append(process.pid)
        except (psutil.NoSuchProcess,psutil.AccessDenied):continue
    repo.require(not dependencies,'a running process still references the expansion')
    with repo.session(repository,readonly=True) as (db,owner):value=repo.manifest(db,snapshot,owner)
    repo.require(value['context'].get('comparison_only') is True,'authenticated comparison point required')
    for protected in value['context']['source_roots']:
        repo.require(not repo.legacy._overlap(root,repo.legacy._external_root(protected)),'expansion overlaps an original source')
    receipt=json.loads((root/'DELIVERY.complete.private.json').read_text(encoding='utf-8'))
    repo.require(receipt['schema']=='next-union-delivery-1' and receipt['attachments_closed'] is True and
        receipt['state_restore']['snapshot_id']==value['context']['legacy_state_snapshot_id'] and
        receipt['union_restore']['snapshot_id']==value['context']['legacy_union_snapshot_id'],'legacy restore proof differs')
    expected={name:entry for name,entry in value['files'].items() if name.startswith('state/') or name=='union/archive.wua.sqlite'}
    generated={'DELIVERY.complete.private.json','DELIVERY.partial.private.json','state/RESTORE.complete.private.json',
        'union/RESTORE.complete.private.json','union/RESTORE.partial.private.json','state/writer.lock','union/writer.lock'}
    names={f['relative'] for f in evidence['files']}
    repo.require(set(expected).issubset(names),'authenticated expansion files missing; preserve for review')
    repo.require(names.issubset(set(expected)|generated),'unexpected expansion files; preserve for review: '+json.dumps(sorted(names-set(expected)-generated)))
    hashes={}
    with ExitStack() as guards:
        for row in evidence['files']:
            path=root/row['relative'];guards.enter_context(cold_input(path));sha=digest_file(path);hashes[row['relative']]=sha
            if row['relative'] in expected:
                entry=expected[row['relative']]
                repo.require((row['bytes'],sha)==(entry['bytes'],entry['sha256']),'expansion changed from authenticated point; do not retire')
            elif row['relative'].endswith('writer.lock'):
                repo.require(path.read_bytes() in (b'',b'0'),'unexpected lock content')
            elif row['relative']=='union/RESTORE.partial.private.json':
                marker=json.loads(path.read_text(encoding='utf-8'))
                repo.require(marker==dict(schema='next-union-cas-backup-1',
                    snapshot_id=value['context']['legacy_union_snapshot_id'],status='partial'),
                    'unexpected partial marker content; preserve for review')
    return dict(schema='next-retired-restore-plan-1',target=str(root),inventory=evidence,sha256=hashes,
        comparison_snapshot=snapshot,comparison_repository=str(repository),
        original_legacy_backups_retained=True,original_sources_retained=True,
        reconstructed_from_real_legacy_backups=True,fully_read_back_new_repository=True,
        process_dependencies=dependencies,reason='verified_rebuildable_restore_expansion_not_a_unique_source',deletion_executed=False)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('root','repository','out'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--snapshot',required=True);a=p.parse_args(argv)
    result=plan(a.root,a.repository,a.snapshot);write_json_new(a.out,result)
    print(json.dumps(dict(files=result['inventory']['file_count'],bytes=result['inventory']['logical_bytes'],allocated_bytes=result['inventory']['allocated_bytes'],clean=result['inventory']['deletion_candidate_clean'])))


if __name__=='__main__':main()
