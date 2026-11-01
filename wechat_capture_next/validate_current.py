"""Independent native-row and same-frozen-cut legacy-decoder validation.

Per-shard scratch is deleted at completion. No old state/archive is changed.
Native row comparison uses the accepted current view, not a later live cut.
Decoder equality separately uses precisely the same frozen ciphertext input.
"""
import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
import tempfile

from tools.decrypt_weixin4_database import decrypt_copy
from wechat_capture_v2.common import digest_file, write_json_new
from .state_guard import writer_lock
from wechat_capture_v2.compare import compare_native
from wechat_capture_v2.source import capture_pair
from .materialize import update_view
from .service import CaptureService


def validate(service, output, only=None):
    output = service.validate_output(output)
    output.mkdir(parents=True, exist_ok=False)
    service.verify_state()
    result = dict(pass_all=True, phone_completeness=False, databases=[],
        scratch_peak_observed_bytes=0, raw_intermediates_retained=False,
        scope='accepted-current-view native rows; separately same-frozen-cut legacy vs new decoder')
    rows = service.catalog.db.execute('''SELECT c.relative_path,c.capture_id,d.evidence_json
        FROM checkpoint c JOIN db_capture d ON d.id=c.capture_id WHERE c.source_id=? ORDER BY c.relative_path''',
        (service.config['source_id'],))
    for relative, capture_id, evidence_json in rows:
        if only and relative not in only:
            continue
        evidence = json.loads(evidence_json)
        row = dict(relative_path=relative, capture_id=capture_id)
        view = service.view_path(relative)
        if evidence['authentication']['structured_readable']:
            row['accepted_view_native'] = compare_native(service.catalog, service.config['source_id'], relative, view)
        else:
            row['accepted_view_native'] = None
            row['structured_scope'] = 'custom_tokenizer_unsupported_authenticated_bytes_only'
        try:
            with tempfile.TemporaryDirectory(prefix='same-cut-', dir=service.state/'tmp') as work:
                work = Path(work)
                pair = capture_pair(service.root/relative, work/'source')
                legacy = work/'legacy.db'
                try:
                    old = decrypt_copy(pair['main'], legacy, service.keys[relative], pair['wal'])
                    row['legacy_structured_check'] = old['plaintext']['pass']
                except (ValueError, sqlite3.OperationalError) as exc:
                    # This exact reference decoder retains its authenticated
                    # output as .pending when only the custom tokenizer fails.
                    pending = legacy.with_name(legacy.name+'.pending')
                    if (evidence['authentication']['structured_readable'] or not pending.is_file()
                            or not any(reason in str(exc) for reason in ('SQLite quick_check failed', 'MMFtsTokenizer'))):
                        raise
                    legacy = pending
                    row['legacy_structured_check'] = False
                # Give the new decoder exactly the same committed WAL prefix.
                # No live SHM or binary overwrite of an active source DB.
                new_source = pair['main']
                if pair['wal'] is not None:
                    # update_view expects the conventional adjacent WAL name.
                    from wechat_capture_v2.source import copy_prefix
                    copy_prefix(pair['wal'], Path(str(new_source)+'-wal'))
                new_view = work/'next.db'
                auth = update_view(new_source, new_view, service.keys[relative], scratch=work/'scratch')
                row['same_cut_plaintext_sha256_equal'] = digest_file(legacy) == auth['plaintext_sha256']
                row['same_cut_matches_accepted_view'] = auth['plaintext_sha256'] == evidence['plaintext']['sha256']
                row['source_cut_signature'] = pair['signature']
                result['scratch_peak_observed_bytes'] = max(result['scratch_peak_observed_bytes'],
                    sum(p.stat().st_size for p in work.rglob('*') if p.is_file()))
                row['pass'] = row['same_cut_plaintext_sha256_equal'] and (
                    row['accepted_view_native'] is None or row['accepted_view_native']['pass'])
        except Exception as exc:
            row.update({'pass': False, 'error_type': type(exc).__name__, 'detail_private': str(exc)})
        result['databases'].append(row)
        result['pass_all'] = result['pass_all'] and row['pass']
    if not result['databases'] or (only and set(only) != {r['relative_path'] for r in result['databases']}):
        raise ValueError('requested validation database set is missing or empty')
    result['expected_native_rows'] = sum(r.get('accepted_view_native', {}).get('expected_rows', 0)
        for r in result['databases'] if r.get('accepted_view_native') is not None)
    result['matched_native_rows'] = sum(r.get('accepted_view_native', {}).get('matched_rows', 0)
        for r in result['databases'] if r.get('accepted_view_native') is not None)
    result['same_cut_matches_accepted_views'] = sum(r.get('same_cut_matches_accepted_view', False) for r in result['databases'])
    result['source_hashes'] = {name: digest_file(Path(__file__).with_name(name)) for name in
        ('materialize.py', 'wal_memory.py', 'service.py', 'merge.py')}
    write_json_new(output/'RESULT.json', result)
    return {k: v for k, v in result.items() if k != 'databases'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--only', action='append', help='retry named validation shard only; never limits collection')
    args = parser.parse_args()
    with writer_lock(args.state):
        service = CaptureService(args.state)
        try:
            result = validate(service, args.out, args.only)
            print(json.dumps(result))
            if not result['pass_all']:
                raise SystemExit(2)
        finally:
            service.close()
