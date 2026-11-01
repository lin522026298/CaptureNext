"""Explicit next-only evidence migration, with an independently verified backup.

Caller owns the state writer lock. Historical reports, raw observations and
decoded views are not removed or compacted. This is NOT a full state backup.
"""
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3

from wechat_capture_v2.common import digest_file, write_json_new


def table_digest(db, table, order):
    result = hashlib.sha256()
    rows = 0
    # Callers supply fixed internal table/order names, never user SQL.
    for row in db.execute(f'SELECT * FROM {table} ORDER BY {order}'):
        for item in row:
            raw = item if isinstance(item, bytes) else str(item).encode()
            tag = type(item).__name__.encode()
            result.update(len(tag).to_bytes(2, 'big')+tag+len(raw).to_bytes(8, 'big')+raw)
        result.update(b'\xffROW')
        rows += 1
    return dict(rows=rows, sha256=result.hexdigest())


def migrate(service, output):
    if service.catalog.compact:
        return dict(changed=False, storage=service.catalog.verify_templates())
    output = service.validate_output(output)
    # Do not place a large recovery copy into a runtime/source subtree.
    if output.is_relative_to(service.state):
        raise ValueError('migration backup must be outside the runtime state')
    output.mkdir(parents=True, exist_ok=False)
    target = output/'catalog.before.sqlite'
    with closing(sqlite3.connect(target)) as backup:
        service.catalog.db.backup(backup)
        if backup.execute('PRAGMA quick_check').fetchone()[0] != 'ok' or list(backup.execute('PRAGMA foreign_key_check')):
            raise ValueError('pre-migration backup integrity failed')
    unchanged = {'version': 'id', 'head': 'source_id,relative_path,table_name,locator_json',
                 'interpretation': 'version_id,normalization_hash', 'interpretation_head': 'version_id',
                 'transition': 'id', 'checkpoint': 'source_id,relative_path', 'cycle': 'id',
                 'asset': 'source_id,relative_path', 'asset_history': 'source_id,relative_path,file_sha',
                 'db_capture': 'id'}
    before = {table: table_digest(service.catalog.db, table, order) for table, order in unchanged.items()}
    with closing(sqlite3.connect(target.as_uri()+'?mode=ro', uri=True)) as backup:
        copied = {table: table_digest(backup, table, order) for table, order in unchanged.items()}
    if copied != before:
        raise ValueError('pre-migration backup content mismatch')
    write_json_new(output/'BEFORE.private.json', dict(tables=before, backup_sha256=digest_file(target)))
    service.catalog.enable_compact()
    after = {table: table_digest(service.catalog.db, table, order) for table, order in unchanged.items()}
    if before != after:
        raise ValueError('migration readback changed authoritative records; retain backup and stop')
    result = dict(changed=True, exact_expanded_tables_match=True, tables=after,
                  storage=service.catalog.verify_templates(), full_state_backup=False,
                  historical_report_files_removed=0, vacuum=False)
    write_json_new(output/'RESULT.json', result)
    return result
