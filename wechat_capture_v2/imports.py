"""Explicit local imports: preserve old inputs and immutable raw evidence."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import uuid

from .cipher import PageCipher
from .common import canonical,digest_file,regular,safe_relative,stamp,utcnow,write_json_new


def import_keyring(service,path):
    payload=json.loads(Path(path).read_text(encoding='utf-8-sig'))
    current=service.state/'90_SECRETS_PLAINTEXT_RESTRICTED'/'keyring.json'
    original=json.loads(current.read_text(encoding='utf-8-sig')) if current.exists() else {'schema':'wechat-keyring-1','databases':[]}
    entries={safe_relative(item['relative_path']):item for item in original.get('databases',[])}
    verified=[]
    seen=set()
    for item in payload.get('databases',[]):
        if not item.get('verified') or not item.get('raw_encryption_key_hex'):
            continue
        relative=safe_relative(item['relative_path'])
        if relative in seen:
            raise ValueError('duplicate normalized incoming key path')
        seen.add(relative)
        source=service.databases().get(relative)
        if source is None:
            raise ValueError('incoming key does not match a configured source database')
        before=stamp(source)
        with source.open('rb') as stream:
            first=stream.read(4096)
        PageCipher(bytes.fromhex(item['raw_encryption_key_hex']),first[:16]).decrypt(first,1)
        with source.open('rb') as stream:
            if stream.read(4096)!=first or stamp(source)!=before:
                raise RuntimeError('source changed during incoming-key verification; retry')
        entries[relative]=item
        verified.append(relative)
    if not verified:
        raise ValueError('no incoming keys verified against this account')
    history=current.parent/'history'/uuid.uuid4().hex
    history.mkdir(parents=True)
    if current.exists():
        shutil.copyfile(current,history/'keyring.previous.json')
    write_json_new(history/'IMPORT.private.json',{'time':utcnow(),'incoming_sha256':digest_file(path),
                   'verified_relative_paths':verified,'verification':'current_source_page1_hmac'})
    updated={**original,'databases':[entries[key] for key in sorted(entries)]}
    pending=current.with_name('keyring.'+uuid.uuid4().hex+'.pending')
    write_json_new(pending,updated)
    os.replace(pending,current)
    service.load_keys()
    return {'pass':True,'keys_verified':len(verified),'previous_keys_preserved':bool(original.get('databases'))}


def import_plain(service,manifest_path):
    manifest_path=Path(manifest_path).resolve(strict=True)
    manifest=json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    if manifest.get('account_alias')!=service.config['account_alias'] or manifest.get('self_username')!=service.config.get('self_username'):
        raise ValueError('historical manifest account must explicitly match the configured account')
    source_id='plain-import-'+hashlib.sha256(canonical(manifest['source_meta']).encode()).hexdigest()
    manifest_object=service.objects.add(manifest_path)
    cycle=service.catalog.begin_cycle('explicit_historical_plain_import')
    report={'cycle_id':cycle,'status':'running','databases':[],'source_id':source_id,
            'source_manifest_sha256':digest_file(manifest_path),'started':utcnow(),'errors':[]}
    try:
        seen=set()
        for entry in manifest['databases']:
            relative=safe_relative(entry['relative_path'])
            if relative in seen:
                raise ValueError('duplicate database path in historical manifest')
            seen.add(relative)
            source=Path(entry['path'])
            if not source.is_absolute():
                source=manifest_path.parent/source
            regular(source)
            if any(Path(str(source)+suffix).exists() and Path(str(source)+suffix).stat().st_size
                   for suffix in ('-wal','-journal')):
                raise ValueError('historical plaintext must have no nonempty SQLite sidecar')
            before=stamp(source)
            obj=service.objects.add(source)
            cached=service.state/'tmp'/('import-'+uuid.uuid4().hex+'.db')
            service.objects.restore(obj['sha256'],cached)
            try:
                if stamp(source)!=before or digest_file(source)!=obj['sha256']:
                    raise RuntimeError('historical source changed while capturing')
                evidence={'plaintext':obj,'origin':'explicit_historical_plain_import',
                          'source_manifest':manifest_object,
                          'source_manifest_sha256':report['source_manifest_sha256'],'source_read_only':True}
                result=service.catalog.ingest(cycle=cycle,source_id=source_id,
                    account=manifest['account_alias'],relative=relative,path=cached,evidence=evidence,
                    signature=obj['sha256'],stamp_value=before,self_username=manifest.get('self_username'))
                report['databases'].append({'relative_path':relative,**result})
            finally:
                cached.unlink(missing_ok=True)  # Exact new temporary file, never the input.
        report['status']='local_complete'
    except BaseException:
        report['status']='interrupted'
        raise
    finally:
        report['finished']=utcnow()
        service.catalog.finish_cycle(cycle,report)
        write_json_new(service.state/'reports'/(cycle+'.json'),report)
    return {'pass':True,'source_id':source_id,'databases':len(report['databases']),
            'new_versions':sum(row['new_versions'] for row in report['databases']),
            'legacy_modified':False}
