"""Exact report reconstruction from already retained capture evidence.

cycle.report_json is an INTERNAL framed storage envelope for new compact reports, not
the public expanded report. Use Catalog.report(id) for the original text. Old
literal reports remain readable and are never rewritten on open. No message,
error, elapsed time or unusual field is discarded to reduce space.
"""
import hashlib
import json

from wechat_capture_v2.common import canonical

FORMAT = 'next-cycle-capture-refs-1'
MAGIC = '\x1e'+FORMAT+'\n'  # Raw RS cannot begin any valid literal JSON document.
FIELDS = ('relative_path', 'status', 'changed_plain_pages', 'decrypted_pages',
          'frozen_wal_bytes', 'memory_wal_bytes', 'main_copy_bytes',
          'temporary_wal_bytes', 'reader', 'rows', 'new_versions',
          'verified_identical_decoded_rows_reused')


def derived(db, ident):
    row = db.execute('SELECT relative_path,evidence_json FROM db_capture WHERE id=?', (ident,)).fetchone()
    if row is None:
        raise ValueError('report refers to a missing accepted capture')
    evidence = json.loads(row[1])
    result = dict(relative_path=row[0], status='accepted', rows=0, new_versions=0,
                  verified_identical_decoded_rows_reused=True)
    auth = evidence.get('authentication', {})
    for name in FIELDS[2:8]:
        if name in auth:
            result[name] = auth[name]
    if 'reader' in evidence:
        result['reader'] = evidence['reader']
    return result


def encode_report(db, text):
    report = json.loads(text)
    if (not isinstance(report, dict) or report.get('schema') != 'capture-next-cycle-1'
            or canonical(report) != text or not isinstance(report.get('databases'), list)):
        return text
    root = {key: value for key, value in report.items() if key != 'databases'}
    entries = []
    for original in report['databases']:
        if not isinstance(original, dict) or original.get('status') != 'accepted' or not original.get('capture_id'):
            entries.append({'literal': original})
            continue
        expected = derived(db, original['capture_id'])
        rest = {key: val for key, val in original.items() if key != 'capture_id'}
        mask = 0
        for index, key in enumerate(FIELDS):
            if key in rest and key in expected and canonical(rest[key]) == canonical(expected[key]):
                mask |= 1 << index
                del rest[key]
        entries.append({'c': original['capture_id'], 'm': mask, 'v': rest})
    envelope = MAGIC+canonical(dict(root=root, entries=entries,
                                    original_sha256=hashlib.sha256(text.encode()).hexdigest()))
    # Never store a larger envelope merely for uniformity.
    if len(envelope.encode()) >= len(text.encode()):
        return text
    if decode_report(db, envelope) != text:
        raise ValueError('report reference encoding was not byte exact')
    return envelope


def decode_report(db, text):
    if not text.startswith('\x1e'):
        json.loads(text)  # Literal valid JSON, including arbitrary unknown keys.
        return text
    if not text.startswith(MAGIC):
        raise ValueError('unsupported report storage format')
    value = json.loads(text[len(MAGIC):])
    root = dict(value['root'])
    entries = []
    for stored in value['entries']:
        if 'literal' in stored:
            entries.append(stored['literal'])
            continue
        mask = stored['m']
        if type(mask) is not int or mask < 0 or mask >= 1 << len(FIELDS):
            raise ValueError('invalid report reference field mask')
        expected = derived(db, stored['c'])
        entry = dict(stored['v'], capture_id=stored['c'])
        for index, key in enumerate(FIELDS):
            if mask & 1 << index:
                if key in entry or key not in expected:
                    raise ValueError('invalid report reference fields')
                entry[key] = expected[key]
        entries.append(entry)
    root['databases'] = entries
    original = canonical(root)
    if hashlib.sha256(original.encode()).hexdigest() != value['original_sha256']:
        raise ValueError('expanded report content hash mismatch')
    return original
