"""Read-only takeover gate; an offline view is not a capture credential.

Only receipt-covered keys are accepted. Never import keys into a verified
restore, borrow credentials from another state, or construct a capture service.
The optional live-source probe authenticates one page per current shard, not a
whole database/WAL or future capture; acquisition still needs an explicit start.
"""
from contextlib import ExitStack
import json
import re

from wechat_capture_v2.cipher import PAGE, PageCipher
from wechat_capture_v2.common import digest_file, safe_relative, source_files, stamp
from .backup import SECRETS, _file, _parents, _overlap
from .union_archive import cold_input
from .union_delivery import _offline


KEYLESS_NEXT_STEP = ('此副本仍可离线查看。请在保有原状态和已验证密钥的设备上显式选择包含密钥备份'
    '（backup_pair: include_secrets=true），再恢复到全新目录并重试接管；不要手改副本或回执。'
    '若只剩无密钥备份，可继续查看；重新采集需另建独立状态并重新取得授权密钥。')

PROVENANCE_MEMBERS = ('pre-evidence-catalog.sqlite.zst', 'legacy-bag-derived.tar.zst')


def verified_provenance_root(root, snapshot):
    """Bind only complete, receipt-covered historical materials after takeover.

    Mutable recovered catalogs cannot be reopened as an OfflineView on every
    boot. These two immutable provenance files still require full byte checks;
    never fall back to another host's originals or accept timestamps alone.
    Older receipts with neither member retain their existing legacy behavior.
    """
    from .pair_repository import SCHEMA
    root = _parents(root)
    marker = root/'DELIVERY.complete.private.json'; _file(marker)
    with ExitStack() as guards:
        guards.enter_context(cold_input(marker))
        receipt = json.loads(marker.read_text(encoding='utf-8'))
        if (receipt.get('schema') != SCHEMA or receipt.get('snapshot_id') != snapshot or
                receipt.get('attachments_closed') is not True or receipt.get('source_reconnected') is not False):
            raise ValueError('recovered provenance receipt identity differs')
        files = receipt.get('restored_files')
        if not isinstance(files, dict):raise ValueError('missing recovered file manifest')
        names = ['provenance/'+name for name in PROVENANCE_MEMBERS]
        present = [name in files for name in names]
        if not any(present):return None
        if not all(present):raise ValueError('incomplete receipt-covered provenance pair')
        directory = _parents(root/'provenance')
        for name, relative in zip(PROVENANCE_MEMBERS, names):
            expected = files[relative]
            if (not isinstance(expected, dict) or type(expected.get('bytes')) is not int or expected['bytes'] < 0 or
                    not isinstance(expected.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', expected['sha256'])):
                raise ValueError('invalid recovered provenance manifest')
            path = directory/name; _file(path); guards.enter_context(cold_input(path))
            if path.stat().st_size != expected['bytes'] or digest_file(path) != expected['sha256']:
                raise ValueError('recovered provenance bytes differ')
        return directory


def requirements():
    return dict(mode='offline_view_separate_from_capture_takeover', action='promote_restore',
        requires_receipt_included_keys=True, requires_current_source_authentication=True,
        external_key_import_supported=False, starts_capture=False, starts_login=False,
        next_step=KEYLESS_NEXT_STEP)


def inspect(reader, *, authenticate_source=False):
    """Return only redacted scalar diagnostics; never serialize keys or paths."""
    result = dict(status='partial', binding_prepared=False, capture_paused=True,
        old_state_preserved=True, capture_started=False, login_started=False,
        takeover_materials_ready=False, live_source_authenticated=False,
        verification_scope='receipt_keys_and_captured_inventory', next_step=KEYLESS_NEXT_STEP)
    receipt = json.loads((reader.root/'DELIVERY.complete.private.json').read_text(encoding='utf-8'))
    if 'state/'+SECRETS not in receipt['restored_files']:
        return dict(result, reason='receipt_key_material_missing')
    try:
        # OfflineView already guards these receipt-covered bytes, including the
        # keyring. Recheck configuration/account binding without any writer.
        with _offline(reader.state, configuration=True) as service:
            config = service.config
            required = {safe_relative(row[0]) for row in service.catalog.db.execute(
                'SELECT relative_path FROM checkpoint WHERE source_id=? UNION '
                'SELECT relative_path FROM db_capture WHERE source_id=?',
                (config['source_id'],config['source_id']))}
        keyring = reader.state/SECRETS
        _file(keyring)
        with cold_input(keyring):
            expected=receipt['restored_files']['state/'+SECRETS]
            if keyring.stat().st_size!=expected['bytes'] or digest_file(keyring)!=expected['sha256']:
                raise ValueError('receipt key material changed')
            payload = json.loads(keyring.read_text(encoding='utf-8-sig'))
        if not isinstance(payload,dict) or not isinstance(payload.get('databases'),list):
            raise ValueError('invalid material shape')
        keys = {}
        for item in payload['databases']:
            if not isinstance(item,dict):raise ValueError('invalid material entry')
            if item.get('verified') is not True:continue
            relative = item.get('relative_path');key = item.get('raw_encryption_key_hex')
            if not isinstance(relative,str) or not isinstance(key,str) or not re.fullmatch('[0-9a-fA-F]{64}',key):
                raise ValueError('invalid verified raw32 material')
            relative = safe_relative(relative)
            if relative in keys:raise ValueError('duplicate normalized material')
            keys[relative] = bytes.fromhex(key)
        if not required or not keys:
            return dict(result, reason='verified_key_material_empty')
        if not required.issubset(keys):
            return dict(result, reason='captured_shard_keys_incomplete', missing_keys=len(required-set(keys)))
    except (OSError, ValueError, TypeError, KeyError):
        return dict(result, reason='key_material_or_binding_invalid')
    if not authenticate_source:
        return dict(result, status='ready', takeover_materials_ready=True,
            reason='receipt_key_material_complete', captured_shards=len(required))
    try:
        root = _parents(config['database_root'])
        if any(_overlap(root,p) for p in (reader.state,reader.union)):
            raise ValueError('source overlaps recovered data')
        inventory = {relative:path for relative,path in source_files(root) if path.suffix.casefold()=='.db'}
        if not required.issubset(inventory) or not inventory:
            return dict(result, reason='captured_source_shards_unavailable',
                next_step='此副本仍可离线查看。请先提供配置绑定的原账号数据库目录；不要手改恢复副本配置。跨设备或新账号应另建独立采集状态。')
        if not set(inventory).issubset(keys):
            return dict(result, reason='current_source_keys_incomplete', missing_keys=len(set(inventory)-set(keys)))
        for relative,path in inventory.items():
            _file(path);before = stamp(path)
            if not before[2] or before[2]%PAGE:raise ValueError('unsupported source database shape')
            with path.open('rb') as stream:page = stream.read(PAGE)
            PageCipher(keys[relative],page[:16]).decrypt(page,1)
            with path.open('rb') as stream:after = stream.read(PAGE)
            if stamp(path)!=before or after!=page:raise ValueError('source changed during probe')
        # Detect newly created/removed shards across the bounded page probe.
        if inventory != {r:p for r,p in source_files(root) if p.suffix.casefold()=='.db'}:
            raise ValueError('source inventory changed during probe')
    except (OSError, ValueError, TypeError, KeyError):
        return dict(result, reason='current_source_authentication_unavailable',
            next_step='此副本仍可离线查看。请确认原账号数据库目录可用且密钥匹配，再重试；源库忙碌时稍后重试。跨设备或密钥变化应另建独立采集状态，不要覆盖旧状态。')
    return dict(result, status='ready', takeover_materials_ready=True,
        live_source_authenticated=True, captured_shards=len(required), authenticated_source_shards=len(inventory),
        verification_scope='current_source_first_page_hmac_only', reason='takeover_materials_authenticated',
        next_step='接管仅准备暂停状态；重启后仍须显式开始采集。后续采集会重新验证完整数据库和已提交日志，不会自动登录微信。')
