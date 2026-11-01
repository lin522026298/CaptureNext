"""Same WUA observation/schema format, using the small-scope lean reducer."""
import hashlib
import json
import zlib

from wechat_capture_v2.common import decoded
from wua.store import _json
from .merge import LeanArchiveStore


def export_wua(service, output):
    output = service.validate_output(output)
    totals = dict(captures=0, observations=0)
    with LeanArchiveStore(output) as archive:
        captures = service.catalog.db.execute('''SELECT * FROM db_capture WHERE id IN
            (SELECT first_capture FROM version UNION SELECT first_capture FROM interpretation) ORDER BY accepted,id''')
        archive._db.execute('BEGIN IMMEDIATE')
        try:
            for capture in captures:
                evidence = json.loads(capture['evidence_json'])
                source = dict(source_id=capture['source_id'], platform='windows', kind='capture-v2-raw-observations')
                snapshot = dict(snapshot_id=capture['id'], source_id=capture['source_id'],
                    basis='authenticated-source-cut' if evidence.get('authentication') else 'explicit-frozen-plaintext-import',
                    evidence_sha256=hashlib.sha256(capture['evidence_json'].encode()).hexdigest())
                archive._db.execute('INSERT OR IGNORE INTO source_device VALUES(?,?)', (capture['source_id'], _json(source)))
                archive._db.execute('INSERT INTO source_snapshot VALUES(?,?,?)', (capture['id'], capture['source_id'], _json(snapshot)))
                for row in service.catalog.db.execute('''SELECT raw_z,normalized_json FROM version WHERE first_capture=?
                    UNION ALL SELECT v.raw_z,i.normalized_json FROM interpretation i JOIN version v ON v.id=i.version_id
                    WHERE i.first_capture=?''', (capture['id'], capture['id'])):
                    item = json.loads(row['normalized_json'])
                    item['raw_record'] = decoded(json.loads(zlib.decompress(row['raw_z'])))
                    item['input_database_sha256'] = evidence['plaintext']['sha256']
                    if evidence.get('reader', {}).get('schema_sha256'):
                        item['input_schema_sha256'] = evidence['reader']['schema_sha256']
                    prepared = archive._prepare_row(capture['id'], item)
                    columns = ','.join(prepared)
                    archive._db.execute('INSERT INTO message_observation ('+columns+') VALUES ('+
                        ','.join('?' for _ in prepared)+')', tuple(prepared.values()))
                    totals['observations'] += 1
                totals['captures'] += 1
            archive._rebuild()
            archive._db.execute('COMMIT')
        except BaseException:
            archive._db.execute('ROLLBACK')
            raise
        totals['stats'] = archive.stats()
        totals['integrity'] = archive.integrity_check()
        totals['pass'] = totals['integrity']['quick_check'] == ['ok'] and not totals['integrity']['foreign_key_check']
        if not totals['pass']:
            raise ValueError('new WUA export integrity failed')
        totals['semantic_digest'] = archive.semantic_digest()
    return totals
