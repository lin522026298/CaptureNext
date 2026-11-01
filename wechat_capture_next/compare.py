"""Read-only WUA set comparison, independent of snapshot IDs and multiplicity.

No fuzzy matches, merged candidates or source identity claims are inferred.
Set differences report counts only; private message text stays in input files.
Caller excludes writers of the managed archive. External archives must be cold.
"""
from contextlib import closing
import hashlib
from pathlib import Path
import os
import sqlite3

from .paths import local_absolute
from wechat_capture_v2.common import directory, regular, stamp, digest_file, write_json_new
from wua.store import SCHEMA_VERSION, RULE_VERSION


def _input(value):
    path = local_absolute(value)
    for parent in (path.parent,*path.parents):
        directory(parent)
    if regular(path).st_nlink != 1:
        raise ValueError('linked archive input is outside comparison scope')
    for suffix in ('-wal','-journal'):
        sidecar = Path(str(path)+suffix)
        if os.path.lexists(sidecar):
            regular(sidecar)
            if sidecar.stat().st_size:
                raise ValueError('archive must be cold; do not ignore or checkpoint its journal')
    return path


def compare_wua(current, reference, output):
    current, reference = _input(current), _input(reference)
    output = local_absolute(output)
    if output.exists() or output in (current,reference):
        raise FileExistsError('comparison requires a new report file')
    for source in (current,reference):
        if output.is_relative_to(source.parent):
            raise ValueError('comparison report must not be written into an input archive directory')
    for parent in (output.parent,*output.parents):
        if parent.exists():
            directory(parent)
    before = [stamp(path) for path in (current,reference)]
    result = dict(schema='next-wua-readonly-comparison-1', phone_completeness=False,
        source_identity_inferred=False, snapshot_multiplicity_ignored_for_sets=True,
        scope='native raw identity and normalized message fields; counts only, no fuzzy inference', inputs={})
    with closing(sqlite3.connect(':memory:', uri=True)) as db:
        db.execute('PRAGMA temp_store=MEMORY')
        for alias,path in (('current',current),('reference',reference)):
            db.execute(f'ATTACH DATABASE ? AS {alias}', (path.as_uri()+'?mode=ro&immutable=1',))
        db.execute('BEGIN')
        for alias in ('current','reference'):
            required = {'db_relative_path','table_name','native_locator_json','row_hash','raw_record_json','account_alias',
                        'conversation_id','sender_id','direction','event_time','message_type','server_id','body_text'}
            if not required.issubset({r[1] for r in db.execute(f'PRAGMA {alias}.table_info(message_observation)')}):
                raise ValueError('supported WUA observation schema required')
            if [r[0] for r in db.execute(f'PRAGMA {alias}.quick_check')] != ['ok']:
                raise ValueError('archive integrity failed')
            if list(db.execute(f'PRAGMA {alias}.foreign_key_check')):
                raise ValueError('archive foreign keys failed')
            metadata = dict(db.execute(f'SELECT key,value FROM {alias}.archive_meta'))
            if metadata.get('schema_version') != SCHEMA_VERSION or metadata.get('rule_version') != RULE_VERSION:
                raise ValueError('unsupported WUA schema or rule version')
            # quick_check verifies SQLite structure, not the observation's
            # content-address binding. Do not trust a stored row_hash blindly.
            verified = 0
            for raw, expected in db.execute(f'SELECT raw_record_json,row_hash FROM {alias}.message_observation'):
                if not isinstance(raw,str) or hashlib.sha256(raw.encode('utf-8')).hexdigest() != expected:
                    raise ValueError('archive raw observation hash mismatch')
                verified += 1
            result['inputs'][alias] = dict(observations=db.execute(f'SELECT count(*) FROM {alias}.message_observation').fetchone()[0],
                raw_payload_hashes_verified=verified,
                logical_messages=db.execute(f'SELECT count(*) FROM {alias}.logical_message').fetchone()[0])
        for label,fields in (
            ('raw_native_without_account_label', 'db_relative_path,table_name,native_locator_json,row_hash'),
            ('raw_native_with_account_label', 'account_alias,db_relative_path,table_name,native_locator_json,row_hash'),
            ('message_fields_without_account_label', 'conversation_id,sender_id,direction,event_time,message_type,server_id,body_text')):
            counts = {}
            for a,b in (('current','reference'),('reference','current')):
                counts[a+'_only'] = db.execute(f'SELECT count(*) FROM (SELECT {fields} FROM {a}.message_observation EXCEPT SELECT {fields} FROM {b}.message_observation)').fetchone()[0]
            counts['equal'] = counts['current_only'] == counts['reference_only'] == 0
            result[label] = counts
    for path, previous in zip((current,reference),before):
        _input(path)
        if stamp(path) != previous:
            raise RuntimeError('archive changed during read-only comparison')
    result['input_sha256'] = dict(current=digest_file(current),reference=digest_file(reference))
    if [stamp(path) for path in (current,reference)] != before:
        raise RuntimeError('archive changed during final hash')
    output.parent.mkdir(parents=True,exist_ok=True)
    write_json_new(output,result)
    return result
