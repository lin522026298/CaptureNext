"""Same-input cold unchanged vs guarded in-process readback reuse."""
import argparse
import json
from pathlib import Path
from wechat_capture_v2.common import digest_file,write_json_new
from .benchmark_pair import measure
from .pair_readback_memo import PairReadbackMemo
from . import pair_repository as repo,rolling_delivery
from .product_settings import atomic_json


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('state','union','repo','provenance','out'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--object-block-bytes',type=int,required=True,choices=repo.ALLOWED_BLOCKS);a=p.parse_args(argv)
    from .paths import local_absolute
    for name in ('state','union','repo','provenance','out'):setattr(a,name,local_absolute(getattr(a,name),allow_relative=True))
    if a.out.exists():raise FileExistsError('fresh measurement receipt required')
    paths=[Path(__file__).with_name(name+'.py') for name in ('benchmark_repeat_pair','benchmark_pair',
        'pair_repository','pair_readback_memo','rolling_delivery','backup','service','compact_archive','viewer_identity','viewer_media','assets','union_assets','operation_objects')]
    hashes=lambda:{path.name:digest_file(path) for path in paths}
    source_before=hashes();repo_before=digest_file(a.repo/repo.DATABASE);memo=PairReadbackMemo();steps=[]
    for label in ('cold_unchanged_authentication','warm_guarded_file_hash_reuse'):
        atomic_json(a.out.with_suffix('.phase.private.json'),dict(step=label,phase='starting'))
        def phase(name,db):atomic_json(a.out.with_suffix('.phase.private.json'),dict(step=label,phase=name))
        value=measure(lambda:rolling_delivery.backup(a.state,a.union,a.repo,provenance=a.provenance,
            object_block_bytes=a.object_block_bytes,_memo=memo,fault=phase),a.repo,
            samples_path=a.out.with_name(a.out.stem+'.'+label+'.samples.private.jsonl'))
        steps.append(dict(label=label,measurement=value))
        write_json_new(a.out.with_name(a.out.stem+'.'+label+'.private.json'),value)
        if value['partial'] or not value['result'].get('noop'):break
    repo_after=digest_file(a.repo/repo.DATABASE)
    passed=(len(steps)==2 and all(not row['measurement']['partial'] and row['measurement']['settled_net_bytes']==0 and
        row['measurement']['result'].get('noop') for row in steps) and repo_before==repo_after and
        steps[1]['measurement']['result'].get('reused_same_process_authenticated_repository_cut') is True)
    result=dict(pass_all=passed,steps=steps,repository_sha256_before=repo_before,repository_sha256_after=repo_after,
        repository_bytes_unchanged=repo_before==repo_after,source_hashes_before=source_before,source_hashes_after=hashes(),
        code_changed_during_run=source_before!=hashes(),object_leaf_bytes=a.object_block_bytes,
        initial_final_independent_repo_hash_cost_outside_step_measurements=True,
        physical_disk_write_bytes=None,not_phone_or_capture_coverage=True)
    write_json_new(a.out,result);print(json.dumps(dict(pass_all=passed,code_changed_during_run=result['code_changed_during_run'])))
    return int(not passed)


if __name__=='__main__':raise SystemExit(main())
