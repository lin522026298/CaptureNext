"""Package this milestone's finite evidence; inventory, never delete.

Only two explicit retired trees may be proposed. The formal state, app,
repositories and original sources are never candidates. Use literal-path
PowerShell separately after checking this manifest and running --verify.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

import psutil

from wechat_capture_next.storage_ledger import inventory, verify_inventory


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def save(path,value):
    with path.open('x',encoding='utf-8') as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2)


def require(value,message):
    if not value:raise ValueError(message)


def process_gate(targets):
    for process in psutil.process_iter(['pid','exe','cwd','cmdline']):
        try:
            for value in (process.info['exe'],process.info['cwd']):
                if value:
                    path=Path(value).resolve()
                    require(not any(path==t or path.is_relative_to(t) for t in targets),
                            'a process still uses a proposed retired tree')
            # Include Python script, output and other path arguments, not just
            # image/cwd. A shell's whole command string is not treated as a path.
            for value in process.info['cmdline'] or []:
                if not value or value.startswith('-'):continue
                try:
                    path=Path(value.strip('"'))
                    if not path.is_absolute():
                        if not process.info['cwd']:continue
                        path=Path(process.info['cwd'])/path
                    path=path.resolve()
                except (OSError,ValueError):continue
                require(not any(path==t or path.is_relative_to(t) for t in targets),
                        'a process argument still depends on a proposed retired tree')
        except (psutil.NoSuchProcess,psutil.AccessDenied):
            continue


def restore_gate(stage,restored):
    restoration=json.loads((stage/'formal-restore-1/RESULT.private.json').read_text(encoding='utf-8'))
    require(restoration['status']=='completed' and restoration['result']['attachments_closed'] is True,
            'latest full restore incomplete; preserve all outputs')
    require(restoration['restore_name']==restored.name and
            Path(restoration['result']['receipt_root']).resolve()==restored,'another restore target')
    receipt=json.loads((restored/'DELIVERY.complete.private.json').read_text(encoding='utf-8'))
    require(receipt['attachments_closed'] is True and receipt['referenced_cas_bytes_verified'] is True and
            Path(receipt['receipt_root']).resolve()==restored and
            receipt['state_restore']['state']=='complete' and
            receipt['union_restore']['metadata_only'] is False and
            receipt['union_restore']['snapshot_id']==restoration['snapshot_id'],
            'candidate is not the successfully verified restored snapshot')
    return restoration


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--out',type=Path)
    parser.add_argument('--verify',type=Path)
    args=parser.parse_args();root=args.root.resolve()
    stage=root/'working/wechat_product_20261021'
    restored=root/'archives/wechat-next/product/restore-product-20261021-01'
    targets=[stage,restored]
    # inventory validates all ancestors, reparse points and hardlink members.
    if args.verify:
        report=json.loads(args.verify.read_text(encoding='utf-8'))
        require(report['project']==str(root),'wrong project')
        require([Path(x['root']) for x in report['entries']]==targets,'unexpected cleanup target')
        bundle=args.verify.parent/report['evidence']['name']
        require(sha(bundle)==report['evidence']['sha256'],'evidence archive changed')
        process_gate(targets)
        restore_gate(stage,restored)
        for item in report['entries']:verify_inventory(item)
        members=json.loads((args.verify.parent/'MEMBERS.private.json').read_text(encoding='utf-8'))
        with zipfile.ZipFile(bundle) as archive:
            require(set(archive.namelist())==set(members),'evidence member set differs')
            for name,wanted in members.items():
                part=Path(name)
                require(part.parts[0] in ('stage','restored') and '..' not in part.parts,'unsafe evidence name')
                source=(stage if part.parts[0]=='stage' else restored).joinpath(*part.parts[1:])
                require(source.stat().st_size==wanted['bytes'] and sha(source)==wanted['sha256'],
                        'unarchived evidence content change; do not delete')
                with archive.open(name) as stream:
                    require(hashlib.file_digest(stream,'sha256').hexdigest()==wanted['sha256'],
                            'archived evidence differs from member proof')
        app=json.loads((args.verify.parent/'APP-FILES.private.json').read_text(encoding='utf-8'))
        require(app['inventory']['deletion_candidate_clean'],'linked/special application dependency')
        verify_inventory(app['inventory'])
        print(json.dumps(dict(verified=True,targets=[str(t) for t in targets])))
        return
    require(args.out is not None,'--out required')
    out=args.out.resolve()
    require(out.parent==root/'archives/wechat-next/acceptance','wrong evidence destination')
    process_gate(targets)
    restoration=restore_gate(stage,restored)
    regression=(stage/'regression-delivery.private.txt').read_text(encoding='utf-8-sig')
    require('Ran 317 tests' in regression and 'OK (skipped=5)' in regression,'final regression gate failed')
    final=json.loads((stage/'final-packaged-2/RESULT.private.json').read_text(encoding='utf-8'))
    require(final['returncode']==0 and not final['backend_survivors'],'final packaged exercise incomplete')
    out.mkdir(parents=True,exist_ok=False)
    stage_inv=inventory(stage)
    require(stage_inv['deletion_candidate_clean'],'linked/special stage member')
    excluded={'app','build-env','freeze-build','webview2-sdk'}
    members={}
    for entry in stage_inv['files']:
        relative=Path(entry['relative'])
        if relative.parts[0] in excluded or relative.name=='webview2.zip':continue
        members['stage/'+relative.as_posix()]=stage/relative
    restore_inv=inventory(restored)
    require(restore_inv['deletion_candidate_clean'],'linked/special restore member')
    for entry in restore_inv['files']:
        relative=Path(entry['relative'])
        if relative.name.startswith(('DELIVERY.','RESTORE.')):
            members['restored/'+relative.as_posix()]=restored/relative
    expected={name:dict(bytes=p.stat().st_size,sha256=sha(p)) for name,p in members.items()}
    bundle=out/'evidence.zip'
    with zipfile.ZipFile(bundle,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=8) as archive:
        for name,path in members.items():archive.write(path,name)
    with zipfile.ZipFile(bundle) as archive:
        require(len(archive.infolist())==len(expected),'duplicate evidence member')
        for name,wanted in expected.items():
            with archive.open(name) as stream:
                require(hashlib.file_digest(stream,'sha256').hexdigest()==wanted['sha256'],'evidence readback differs')
    require(all(sha(path)==expected[name]['sha256'] for name,path in members.items()),'source evidence changed')
    save(out/'MEMBERS.private.json',expected)
    for name in ('formal-maintenance-1','formal-restore-1','formal-shell-3','final-packaged-2'):
        shutil.copyfile(stage/name/'RESULT.private.json',out/(name+'.private.json'))
    app=root/'archives/wechat-next/app';app_inv=inventory(app)
    require(app_inv['deletion_candidate_clean'],'linked/special application dependency')
    save(out/'APP-FILES.private.json',dict(inventory=app_inv,
        hashes={x['relative']:sha(app/x['relative']) for x in app_inv['files']}))
    report=dict(schema='next-product-cleanup-plan-1',project=str(root),
        evidence=dict(name=bundle.name,sha256=sha(bundle),bytes=bundle.stat().st_size,readback_verified=True),
        entries=[stage_inv,restore_inv],
        logical_bytes=stage_inv['logical_bytes']+restore_inv['logical_bytes'],
        allocated_bytes=stage_inv['allocated_bytes']+restore_inv['allocated_bytes'],
        restoration_verified=True,originals_excluded=True,
        cleanup_inventory_scope='metadata/identity; restored bytes independently verified by full restore')
    for item in report['entries']:verify_inventory(item)
    save(out/'CLEANUP-PLAN.private.json',report)
    print(json.dumps({k:v for k,v in report.items() if k!='entries'},ensure_ascii=False))


if __name__=='__main__':main()
