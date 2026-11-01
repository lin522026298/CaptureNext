"""Seed a fresh comparison repository from an authenticated old restored cut.

Read-only legacy sources; not adoption, takeover, or a live capture state. The
result is for the A/B storage experiment and restores into a new target only.
"""
import argparse
from contextlib import ExitStack,closing
import hashlib
import json
from pathlib import Path

from wechat_capture_v2.common import digest_file,write_json_new
from . import backup,union_backup,pair_repository as repository
from .union_archive import cold_input,cold_reader


def seed(restored,state_repo,union_repo,owner_file,repo,*,provenance=None):
    paths=[backup._parents(p) for p in (restored,state_repo,union_repo,repo)]
    restored,state_repo,union_repo,repo=paths
    if repo.exists():raise FileExistsError('fresh comparison repository required')
    if any(backup._overlap(repo,p) for p in paths[:-1]):raise ValueError('comparison target overlaps retained data')
    with ExitStack() as stack:
        receipt=restored/'DELIVERY.complete.private.json';backup._file(receipt);stack.enter_context(cold_input(receipt))
        completed=json.loads(receipt.read_text(encoding='utf-8'))
        if completed.get('schema')!='next-union-delivery-1' or completed.get('attachments_closed') is not True:
            raise ValueError('verified existing legacy pair required')
        state_id=completed['state_restore']['snapshot_id'];union_id=completed['union_restore']['snapshot_id']
        def manifest(root,identity,module):
            path=root/'repository.sqlite';stack.enter_context(cold_input(path))
            owner=json.loads((root/'OWNER.private.json').read_text(encoding='utf-8'))
            db=stack.enter_context(closing(cold_reader(path)))
            return module._manifest(db,identity,owner)
        state=manifest(state_repo,state_id,backup);union=manifest(union_repo,union_id,union_backup)
        if union['state_companion']['snapshot_id']!=state_id or union['catalog_instance']!=state['catalog_instance']:
            raise ValueError('legacy pair identities differ')
        for name,key in (('catalog.sqlite','catalog_sha256'),('objects.sqlite','objects_sha256')):
            if state['files'][name]['sha256']!=union['state_companion'][key]:raise ValueError('legacy companion hashes differ')
        owner_file=backup._parents(Path(owner_file).parent)/Path(owner_file).name;backup._file(owner_file)
        stack.enter_context(cold_input(owner_file))
        if json.loads(owner_file.read_text(encoding='utf-8'))!=dict(schema='next-formal-union-1',catalog_instance=state['catalog_instance']):
            raise ValueError('explicit formal-owner witness differs')
        files={}
        for name,entry in state['files'].items():
            path=restored/'state'/backup._manifest_path(name);backup._file(path);stack.enter_context(cold_input(path))
            if path.stat().st_size!=entry['bytes'] or digest_file(path)!=entry['sha256']:raise ValueError('legacy restored state differs from authenticated manifest')
            files['state/'+name]=path
        archive=restored/'union/archive.wua.sqlite';stack.enter_context(cold_input(archive))
        if archive.stat().st_size!=union['archive']['bytes'] or digest_file(archive)!=union['archive']['sha256']:
            raise ValueError('legacy restored WUA differs from authenticated manifest')
        with closing(cold_reader(archive)) as db:
            if db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()[0]!=union['union_id']:
                raise ValueError('legacy union identity differs')
        files.update({'union/archive.wua.sqlite':archive,'union/OWNER.private.json':owner_file})
        if provenance is not None:
            provenance=backup._parents(provenance)
            if backup._overlap(repo,provenance):raise ValueError('comparison output overlaps original provenance')
            for name in ('pre-evidence-catalog.sqlite.zst','legacy-bag-derived.tar.zst'):
                path=provenance/name;backup._file(path);stack.enter_context(cold_input(path));files['provenance/'+name]=path
        protected={str(p) for p in (restored,state_repo,union_repo,repo,owner_file.parent)}|set(state['source_roots'])
        if provenance:protected.add(str(provenance))
        context=dict(verification_profile='authenticated_legacy_manifests_and_completed_restore',
            origin_state=str(restored/'state'),origin_union=str(restored/'union'),source_roots=state['source_roots'],
            protected_roots=sorted(protected),includes_secrets=state['include_secrets'],provenance_included=provenance is not None,
            asset_binding=completed['union_restore']['attachment_verification'],
            media_binding=dict(status='not_indexed',rows_verified=0),integrity=completed['union_restore']['integrity'],
            comparison_only=True,legacy_state_snapshot_id=state_id,legacy_union_snapshot_id=union_id)
        owner=dict(schema=repository.SCHEMA,catalog_instance=state['catalog_instance'],union_id=union['union_id'])
        return repository.publish(repo,owner,files,context,block_bytes=4096)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('restored','state_repo','union_repo','owner_file','repo','out'):p.add_argument('--'+name.replace('_','-'),type=Path,required=True)
    p.add_argument('--provenance',type=Path);a=p.parse_args(argv)
    from .benchmark_pair import measure
    before={p.name:digest_file(p) for p in (Path(__file__),Path(repository.__file__),Path(backup.__file__),Path(union_backup.__file__))}
    result=measure(lambda:seed(a.restored,a.state_repo,a.union_repo,a.owner_file,a.repo,provenance=a.provenance),a.repo,
        samples_path=a.out.with_suffix('.samples.private.jsonl'))
    result.update(source_hashes_before=before,source_hashes_after={p.name:digest_file(p) for p in (Path(__file__),Path(repository.__file__),Path(backup.__file__),Path(union_backup.__file__))})
    result['code_changed_during_run']=result['source_hashes_before']!=result['source_hashes_after']
    write_json_new(a.out,result);print(json.dumps({k:result[k] for k in ('partial','elapsed_seconds','settled_net_bytes')}));return int(result['partial'])


if __name__=='__main__':raise SystemExit(main())
