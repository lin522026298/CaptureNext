"""Read-only final-space inventory. Prefer a runtime compiled with SQLite dbstat.

No VACUUM, checkpoint, deletion or migration. SQL payload bytes and allocated
SQLite pages are reported separately; column payloads can overlap semantically.
Only aggregate sizes/names are emitted, never message text or key contents.
"""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3


def database_inventory(path, kind):
    path = Path(path).resolve(strict=True)
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA temp_store=MEMORY')
        db.execute('BEGIN')
        result = dict(main_file_bytes=path.stat().st_size,
            page_size=db.execute('PRAGMA page_size').fetchone()[0],
            page_count=db.execute('PRAGMA page_count').fetchone()[0],
            freelist_pages=db.execute('PRAGMA freelist_count').fetchone()[0], tables={})
        try:
            result['allocated_btree_pages'] = {name: dict(bytes=pages, payload_bytes=payload, pages=count)
                for name, pages, payload, count in db.execute(
                    'SELECT name,sum(pgsize),sum(payload),count(*) FROM dbstat GROUP BY name')}
        except sqlite3.OperationalError:
            result['allocated_btree_pages'] = None
        if kind == 'catalog':
            for table, columns in {
                'version': ['raw_z', 'normalized_json', 'locator_json'],
                'interpretation': ['normalized_json'], 'db_capture': ['evidence_json'],
                'cycle': ['report_json'], 'head': ['locator_json'],
                'transition': [], 'asset': [], 'asset_history': []}.items():
                fields = ','.join('coalesce(sum(length(CAST('+c+' AS BLOB))),0)' for c in columns)
                row = db.execute(f'SELECT count(*)'+(','+fields if fields else '')+f' FROM {table}').fetchone()
                result['tables'][table] = dict(rows=row[0], column_bytes=dict(zip(columns, row[1:])))
            result['normalized_body_utf8_bytes'] = db.execute("""SELECT coalesce(sum(length(CAST(
                json_extract(normalized_json,'$.body_text') AS BLOB))),0) FROM version""").fetchone()[0]
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='capture_record'").fetchone():
                for table, columns in {'capture_record': ['slots_json'], 'evidence_template': ['text', 'sha256']}.items():
                    row = db.execute('SELECT count(*),'+','.join('coalesce(sum(length(CAST('+c+' AS BLOB))),0)' for c in columns)+f' FROM {table}').fetchone()
                    result['tables'][table] = dict(rows=row[0], column_bytes=dict(zip(columns, row[1:])))
                result['expanded_evidence_is_virtual_not_additional_storage'] = True
        elif kind == 'wua':
            for table, columns in {
                'message_observation': ['raw_record_json', 'normalized_json', 'body_text', 'native_locator_json'],
                'logical_message': ['body_text'], 'message_link': ['evidence_json'],
                'conflict': ['values_json'], 'dedupe_candidate': ['evidence_json'],
                'source_device': ['metadata_json'], 'source_snapshot': ['metadata_json']}.items():
                fields = ','.join('coalesce(sum(length(CAST('+c+' AS BLOB))),0)' for c in columns)
                row = db.execute(f'SELECT count(*),{fields} FROM {table}').fetchone()
                result['tables'][table] = dict(rows=row[0], column_bytes=dict(zip(columns, row[1:])))
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='message_fts'").fetchone():
                count, body = db.execute('SELECT count(*),coalesce(sum(length(CAST(body_text AS BLOB))),0) FROM message_fts').fetchone()
                result['tables']['message_fts'] = dict(rows=count, column_bytes={'body_text': body})
        elif kind == 'objects':
            result['unique_chunks'], result['compressed_chunk_bytes'], result['uncompressed_chunk_bytes'] = db.execute(
                'SELECT count(*),coalesce(sum(length(data)),0),coalesce(sum(bytes),0) FROM chunk').fetchone()
            result['logical_files'], result['logical_file_bytes'] = db.execute(
                'SELECT count(*),coalesce(sum(bytes),0) FROM file').fetchone()
        return result


def state_inventory(state):
    state = Path(state).resolve(strict=True)
    categories = {}
    files = 0
    for path in state.rglob('*'):
        if path.is_symlink():
            raise ValueError('linked state object outside inventory scope')
        if not path.is_file():
            continue
        relative = path.relative_to(state)
        if relative.parts[0] == 'cache':
            category = 'page_fingerprints' if '.pages.sqlite' in path.name else 'current_decoded_views'
        elif relative.parts[0] == 'reports':
            category = 'reports'
        elif relative.parts[0] == 'tmp':
            category = 'temporary'
        elif path.name.startswith('catalog.sqlite'):
            category = 'catalog_main' if path.name == 'catalog.sqlite' else 'catalog_sidecars'
        elif path.name.startswith('objects.sqlite'):
            category = 'objects_main' if path.name == 'objects.sqlite' else 'objects_sidecars'
        else:
            category = 'configuration_and_control'
        categories[category] = categories.get(category, 0)+path.stat().st_size
        files += 1
    return dict(files=files, filesystem_bytes=sum(categories.values()), categories=categories,
        catalog=database_inventory(state/'catalog.sqlite', 'catalog'),
        objects=database_inventory(state/'objects.sqlite', 'objects'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--wua', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = dict(sqlite_version=sqlite3.sqlite_version, state=state_inventory(args.state),
                  snapshot_closure='read-only snapshot; physical sidecars reported separately; no forced checkpoint')
    if args.wua:
        result['wua'] = database_inventory(args.wua, 'wua')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x', encoding='utf-8') as output:
        json.dump(result, output, ensure_ascii=False, indent=2)
    print(json.dumps({'state_filesystem_bytes': result['state']['filesystem_bytes'],
        'state_categories': result['state']['categories'],
        'dbstat_available': result['state']['catalog']['allocated_btree_pages'] is not None,
        'wua_main_bytes': result.get('wua', {}).get('main_file_bytes')}))
