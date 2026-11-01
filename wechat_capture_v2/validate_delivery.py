"""Reproducible real-account validation, entirely inside new local outputs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from .common import canonical,digest_file,utcnow,writer_lock,write_json_new
from .compare import compare_native,verify_legacy
from .export import backup,export_jsonl,export_wua,extract_assets,restore_backup
from .service import CaptureService


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',required=True,type=Path)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    started=time.monotonic()
    report={'schema':'real-delivery-validation-1','started':utcnow(),'pass':False,
            'scope':'current_pc_only_not_phone_full_history','steps':{}}
    output=None
    def phase(name,value=None):
        print(canonical({'phase':name,'time':utcnow(),'result':value}),flush=True)
    try:
        with writer_lock(args.state):
            service=CaptureService(args.state)
            try:
                output=service.validate_output(args.out)
                output.mkdir(parents=True,exist_ok=False)
                phase('relogin_full_reconciliation')
                captured=service.capture(force=True)
                report['steps']['capture']={'cycle_id':captured['cycle_id'],'status':captured['status'],'summary':captured['summary']}
                markers={}
                for name in ('归档测试-在线-A','归档测试-停采-B','归档测试-微信退出-C'):
                    rows=service.catalog.db.execute("""SELECT json_extract(normalized_json,'$.conversation_id'),
                        json_extract(normalized_json,'$.direction') FROM version
                        WHERE json_extract(normalized_json,'$.body_text')=?""",(name,)).fetchall()
                    markers[name]={'count':len(rows),'file_transfer_helper':bool(rows) and all(r[0]=='filehelper' for r in rows),
                                   'outgoing':bool(rows) and all(r[1]=='outgoing' for r in rows)}
                report['steps']['markers']=markers
                phase('markers_after_relogin',markers)
                phase('private_backup_including_keys')
                report['steps']['backup']=backup(service,output/'backup',include_secrets=True)
            finally:
                service.close()
        phase('restore_new_independent_state')
        restored=output/'restored_state'
        report['steps']['restore']=restore_backup(output/'backup',restored)
        with writer_lock(restored):
            service=CaptureService(restored)
            try:
                phase('deep_verify_all_retained_objects')
                report['steps']['deep_verify']=service.verify_state()
                phase('legacy_full_comparison_from_restored_backup')
                compared=verify_legacy(service,output/'legacy_comparison')
                report['steps']['legacy']={key:compared[key] for key in
                    ('pass','expected_message_rows','matched_message_rows','comparison_scope','phone_completeness')}
                phase('complete_raw_jsonl_export')
                report['steps']['jsonl']=export_jsonl(service,output/'raw_versions.jsonl')
                phase('single_rebuild_wua_export')
                report['steps']['wua']=export_wua(service,output/'currentpc.wua.sqlite')
                phase('restore_all_last_observed_assets')
                report['steps']['assets_restored']=extract_assets(service,output/'restored_assets')
                extracted=[]
                for checkpoint in service.catalog.db.execute("""SELECT d.* FROM checkpoint c JOIN db_capture d ON d.id=c.capture_id
                        WHERE c.source_id=? AND c.relative_path LIKE 'message/%' ORDER BY c.relative_path""",(service.config['source_id'],)):
                    evidence=json.loads(checkpoint['evidence_json'])
                    if not evidence.get('authentication',{}).get('structured_readable'):
                        continue
                    name=checkpoint['relative_path'].split('/')[-1]
                    path=output/'extracted_message_databases'/name
                    service.objects.restore(evidence['plaintext']['sha256'],path)
                    result=compare_native(service.catalog,service.config['source_id'],checkpoint['relative_path'],path)
                    extracted.append({'relative_path':checkpoint['relative_path'],'pass':result['pass'],
                                      'expected_rows':result['expected_rows'],'sha256':digest_file(path)})
                report['steps']['extracted_message_databases']=extracted
                report['restored_state_summary']=service.catalog.summary()
                report['pass']=(captured['status']=='local_complete' and compared['pass'] and
                    all(value['count']==1 and value['file_transfer_helper'] and value['outgoing'] for value in markers.values()) and
                    all(value['pass'] for value in extracted))
            finally:
                service.close()
    except BaseException as exc:
        report['error']={'type':type(exc).__name__,'detail_private':str(exc)}
        raise
    finally:
        report['finished']=utcnow()
        report['elapsed_seconds']=round(time.monotonic()-started,3)
        if output is not None:
            write_json_new(output/'VALIDATION.private.json',report)
        phase('validation_finished',{'pass':report['pass'],'elapsed_seconds':report['elapsed_seconds']})
    return 0 if report['pass'] else 1


if __name__=='__main__':
    raise SystemExit(main())
