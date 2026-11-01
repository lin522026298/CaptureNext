"""Analyze measured samples; do not turn a short run into a 24-hour claim."""
from __future__ import annotations
import argparse
import importlib.metadata
import json
from pathlib import Path
import statistics
import sys

from .common import canonical,utcnow,write_json_new


def evaluate(folder):
    folder=Path(folder)
    samples=[json.loads(line) for line in (folder/'samples.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    cycles=[json.loads(line) for line in (folder/'cycles.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    rows=[c for c in cycles if 'elapsed_seconds' in c['result']]
    first=rows[0]['elapsed'] if rows else float('inf')
    warm=[s for s in samples if s['elapsed']>=first+10]
    verified=[r for r in rows[1:] if r['result'].get('databases_verified_unchanged',0)>=19 and r['result']['mode']=='full_reconciliation']
    if not warm:
        return {'qualified_for_frontend':False,'reason':'warmup_not_complete'}
    cpu=statistics.mean(s['cpu_machine_percent'] for s in warm)
    private=max(s['private_bytes'] for s in warm)
    handles=max(0,warm[-1]['handles']-warm[0]['handles'])
    periodic_median=statistics.median(r['result']['elapsed_seconds'] for r in verified) if verified else None
    checks={'observation_at_least_700_seconds':samples[-1]['elapsed']>=700,
        'two_periodic_content_reconciliations':len(verified)>=2,
        'warm_machine_cpu_mean_at_most_1_percent':cpu<=1,
        'private_peak_at_most_512_mib':private<=512*1024**2,
        'handle_growth_at_most_8':handles<=8,
        'identical_content_reconciliation_at_most_10_seconds':periodic_median is not None and periodic_median<=10,
        'no_failed_capture_rounds':all(r['result'].get('error_count',0)==0 for r in rows)}
    first_window=warm[:min(30,len(warm))];last_window=warm[-min(30,len(warm)):]
    return {'schema':'wechat-performance-development-gate-1','time':utcnow(),
        'qualified_for_frontend':all(checks.values()),'checks':checks,'sampled_seconds':samples[-1]['elapsed'],
        'warm_cpu_machine_mean_percent':cpu,'warm_private_peak_bytes':private,
        'warm_rss_peak_bytes':max(s['rss_bytes'] for s in warm),
        'warm_private_start_median_bytes':statistics.median(s['private_bytes'] for s in first_window),
        'warm_private_end_median_bytes':statistics.median(s['private_bytes'] for s in last_window),
        'warm_logical_read_bytes':max(0,warm[-1]['logical_read_bytes']-warm[0]['logical_read_bytes']),
        'warm_logical_write_bytes':max(0,warm[-1]['logical_write_bytes']-warm[0]['logical_write_bytes']),
        'handles_start':warm[0]['handles'],'handles_end':warm[-1]['handles'],
        'verified_periodic_rounds':len(verified),'verified_periodic_median_seconds':periodic_median,
        'idle_polls_without_ledger_rows':sum(r['result'].get('cycle_id') is None for r in rows),
        'not_a_24_hour_stability_certification':True}


def size_report():
    root=Path(__file__).parent
    source=[p for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    runtime=Path(sys.base_prefix)
    runtime_files=[p for p in runtime.rglob('*') if p.is_file() and not p.is_relative_to(runtime/'Lib'/'site-packages')]
    dependencies=[]
    for name in ('cryptography','cffi','pycparser','zstandard','psutil','fastapi','starlette','pydantic','pydantic_core',
                 'uvicorn','anyio','h11','click','typing_extensions','annotated_types','typing_inspection','idna'):
        try:
            dist=importlib.metadata.distribution(name)
            paths=[dist.locate_file(f) for f in (dist.files or [])]
            total=sum(p.stat().st_size for p in paths if p.is_file())
            dependencies.append({'name':name,'version':dist.version,'installed_bytes':total})
        except importlib.metadata.PackageNotFoundError:
            continue
    project=root.parent
    legacy=[project/p for p in ('wua/__init__.py','wua/store.py','wua/weixin4.py','tools/sqlite_wal.py','tools/decrypt_weixin4_database.py')]
    return {'schema':'wechat-source-and-shared-runtime-size-1','time':utcnow(),'source_files':len(source),
        'source_and_docs_bytes':sum(p.stat().st_size for p in source),
        'frontend_asset_bytes':sum(p.stat().st_size for p in source if 'web' in p.parts),
        'shared_python_runtime_excluding_site_packages_bytes':sum(p.stat().st_size for p in runtime_files),
        'installed_dependency_inventory':dependencies,
        'readonly_reused_legacy_code_bytes':sum(p.stat().st_size for p in legacy if p.is_file()),
        'readonly_reused_legacy_code_files':[p.relative_to(project).as_posix() for p in legacy if p.is_file()],
        'not_a_built_standalone_installer_size':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--benchmark',type=Path)
    parser.add_argument('--size',action='store_true')
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    result=size_report() if args.size else evaluate(args.benchmark)
    write_json_new(args.out,result)
    print(canonical(result))


if __name__=='__main__':main()
