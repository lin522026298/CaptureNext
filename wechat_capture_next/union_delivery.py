"""Explicit, offline-first union delivery CLI; never starts acquisition.

Only ``sync`` constructs a live CaptureService (binding/key checks, no capture).
Backup retains state -> union OS locks across closing every SQLite writer and
the cold companion snapshot. A receipt directory is always fresh; failures
retain partial outputs and never adopt/delete an existing delivery.
"""
import argparse
from contextlib import ExitStack, closing, contextmanager
import json
import os
from pathlib import Path
import sqlite3
import sys
from types import MethodType, SimpleNamespace

from wechat_capture_v2.common import directory, write_json_new, utcnow
from wechat_capture_v2.objects import Objects
from . import backup as state_backup
from . import union_backup
from .catalog import Catalog, FORMAT
from .compact_archive import CompactArchive
from .content_pool import register_codec
from .paths import local_absolute
from .service import CaptureService, MODE
from .state_guard import state_preflight, writer_lock
from .union_archive import cold_input, cold_reader, sync_union, union_path
from .union_assets import verify_union_assets

SCHEMA = 'next-union-delivery-1'
PARTIAL = 'DELIVERY.partial.private.json'
COMPLETE = 'DELIVERY.complete.private.json'
FAILURE = 'DELIVERY.failure.private.json'


def _disjoint(paths):
    items = list(paths)
    for index, first in enumerate(items):
        for second in items[index+1:]:
            if state_backup._overlap(first, second):
                raise ValueError('delivery inputs, repositories and output must be independent trees')


def _fresh(value, protected):
    path = local_absolute(value)
    directory(path.parent)  # Never create a chain through absent/old source roots.
    if os.path.lexists(path):
        raise FileExistsError('delivery output must be a fresh directory')
    _disjoint([path, *protected])
    return path


def _protect(path, roots):
    for value in roots:
        if state_backup._overlap(path, state_backup._external_root(value)):
            raise ValueError('delivery location overlaps a protected source or historical tree')


def _config(state):
    for name in ('next.private.json', 'config.private.json'):
        state_backup._file(state/name)
    marker = json.loads((state/'next.private.json').read_text(encoding='utf-8'))
    if marker.get('schema') != MODE or marker.get('evidence_storage') not in (None, FORMAT):
        raise ValueError('explicit supported capture-next state required')
    if any(os.path.lexists(state/name) for name in
           ('RESTORE.partial.private.json', 'RESTORE.failure.private.json')):
        raise ValueError('incomplete state restoration cannot be delivered')
    value = json.loads((state/'config.private.json').read_text(encoding='utf-8'))
    if not isinstance(value, dict) or not isinstance(value.get('source_id'), str):
        raise ValueError('invalid offline state configuration')
    return value


def _instance(service):
    row = service.catalog.db.execute("SELECT value FROM meta WHERE key='next_catalog_instance'").fetchone()
    if row is None or not isinstance(row[0], str) or not row[0]:
        raise ValueError('existing stable catalog identity required; run explicit sync first')
    return row[0]


def _formal(value, instance=None):
    root = local_absolute(value)
    state_preflight(root)
    owner = union_backup._union_owner(root/'archive.wua.sqlite')
    if instance is not None and owner['catalog_instance'] != instance:
        raise ValueError('state/formal union identity mismatch')
    return union_path(root, catalog_instance=owner['catalog_instance']), owner


def _backup_owner(path, formal_owner, repository):
    """Cold, read-only identity gate BEFORE receipts or state snapshots."""
    with cold_input(path), closing(cold_reader(path)) as db:
        row = db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()
        identity = union_backup._uuid(row[0] if row else None)
    expected = dict(schema=union_backup.SCHEMA,
                    catalog_instance=formal_owner['catalog_instance'], union_id=identity)
    if os.path.lexists(repository):
        union_backup._repository(repository, expected)
    return expected


def _state_owner(state, formal_owner):
    """Existing current-catalog identity, with no constructor or writer."""
    path = state/'catalog.sqlite'
    with cold_input(path), closing(cold_reader(path)) as db:
        instance = _instance(SimpleNamespace(catalog=SimpleNamespace(db=db)))
    if instance != formal_owner['catalog_instance']:
        raise ValueError('state/formal union identity mismatch')
    return instance


@contextmanager
def _offline(state, *, readonly=True, configuration=False):
    """Open exact owned DBs without constructors, schema writes, keys or source.

    Readonly mode is deliberately cold-only: immutable reads under cold guards
    cannot create WAL/SHM. Refuse an active/dirty state instead of inventing a
    coherent cut. The writable backup adapter opens existing files mode=rw and
    reuses verification methods only; it never calls Catalog/Objects startup.
    """
    state = state_preflight(local_absolute(state))
    config = _config(state) if configuration else None
    with ExitStack() as stack:
        service = SimpleNamespace(state=state)
        for name, cls in (('catalog', Catalog), ('objects', Objects)):
            path = state/(name+'.sqlite')
            state_backup._file(path)
            state_backup._sidecars(path)
            if readonly:
                stack.enter_context(cold_input(path))
                db = stack.enter_context(closing(cold_reader(path)))
            else:
                db = stack.enter_context(closing(sqlite3.connect(path.as_uri()+'?mode=rw', uri=True)))
                db.row_factory = sqlite3.Row
                db.execute('PRAGMA foreign_keys=ON')
                db.execute('PRAGMA synchronous=FULL')
                register_codec(db)
            obj = cls.__new__(cls)
            obj.path, obj.db = path, db
            setattr(service, name, obj)
        if configuration:
            service.config = config
            service.view_path = MethodType(CaptureService.view_path, service)
            service.verify_state = MethodType(CaptureService.verify_state, service)
            state_backup._consistent_config(service)
        _instance(service)
        yield service


@contextmanager
def _receipt(path, command):
    path.mkdir(exist_ok=False)
    write_json_new(path/PARTIAL, dict(schema=SCHEMA, command=command, status='partial', created=utcnow()))
    try:
        yield
    except BaseException as error:
        # Do not serialize exception values, configuration or credentials.
        write_json_new(path/FAILURE, dict(schema=SCHEMA, command=command, status='failed',
                                        error_type=type(error).__name__, partial_outputs_retained=True))
        raise


def stats(state, union):
    """Strictly readonly cold-state stats; no configuration/key/source loading."""
    state, root = local_absolute(state), local_absolute(union)
    _disjoint([state, root])
    with _offline(state) as service:
        path, _ = _formal(root, _instance(service))
        with cold_input(path), CompactArchive(path, readonly=True) as archive:
            exists = archive._db.execute("SELECT 1 FROM sqlite_master WHERE name='next_union_asset_meta'").fetchone()
            assets = verify_union_assets(archive, service, deep=False) if exists else dict(
                status='not_initialized', closure_complete=False, verification_scope='whole_union', origin_id=None)
            return dict(schema=SCHEMA, command='stats', state=str(state), union=str(root),
                        stats=archive.stats(), storage=archive.storage_stats(), assets=assets,
                        readonly=True, fts_verified=False, capture_started=False, login_started=False)


def sync(state, union, *, verify=False):
    """Import already captured current history. Never calls capture()."""
    state, root = local_absolute(state), local_absolute(union)
    _disjoint([state, root])
    # Fail on foreign existing roots before the service constructor can recover
    # or update any owned current-state bookkeeping.
    if os.path.lexists(root):
        _formal(root)
    with writer_lock(state), closing(CaptureService(state)) as service:
        result = sync_union(service, root, verify=verify)
    return dict(schema=SCHEMA, command='sync', result=result, capture_started=False,
                login_started=False, implicit_capture=False)


def _same_volume(paths):
    devices = set()
    for path in paths:
        while not path.exists():
            path = path.parent
        devices.add(path.stat().st_dev)
    return len(devices) == 1


def backup(state, union, state_repo, union_repo, out, *, include_secrets=False):
    """Deep bind existing union, then snapshot exact post-pin state and union."""
    # Preserve refusal-before-any-write for foreign current states/repositories.
    _prepare_backup(state, union, state_repo, union_repo, out)
    with writer_lock(local_absolute(state)):
        return backup_owned(state, union, state_repo, union_repo, out, include_secrets=include_secrets)


def backup_owned(state, union, state_repo, union_repo, out, *, include_secrets=False):
    """Internal adapter: caller owns state OS lock and has closed ALL readers.

    Retains every public preflight/identity gate; never re-enters the state lock.
    The product worker may reopen only after this function releases cold guards.
    """
    state,root,state_repo,union_repo,output,path,owner,expected_owner = _prepare_backup(
        state,union,state_repo,union_repo,out)
    with writer_lock(root):
        locked_path, locked_owner = _formal(root)
        _state_owner(state, locked_owner)
        if (locked_path != path or locked_owner != owner
                or _backup_owner(path, locked_owner, union_repo) != expected_owner):
            raise ValueError('formal union identity changed during delivery preflight')
        return _backup_locked(state, root, state_repo, union_repo, output, path, owner,
                              include_secrets=include_secrets)


def _prepare_backup(state, union, state_repo, union_repo, out):
    state, root, state_repo, union_repo = map(local_absolute, (state, union, state_repo, union_repo))
    _disjoint([state, root, state_repo, union_repo])
    output = _fresh(out, [state, root, state_repo, union_repo])
    config = _config(state_preflight(state))
    roots = state_backup._source_roots(config)
    protected = roots + ([str(state_backup._external_root(roots[0]).parent)] if roots else [])
    for location in (root, state_repo, union_repo, output):
        _protect(location, protected)
    # All path/ownership checks precede receipt creation and any writer opens.
    path, owner = _formal(root)
    _state_owner(state, owner)
    if state_repo.exists():
        state_backup._repository(state_repo, dict(schema=state_backup.SCHEMA,
                                                  catalog_instance=owner['catalog_instance']))
    expected_owner = _backup_owner(path, owner, union_repo)
    return state,root,state_repo,union_repo,output,path,owner,expected_owner


def _backup_locked(state, root, state_repo, union_repo, output, path, owner, *, include_secrets):
    """Caller holds both OS locks; preflight has not created any output yet."""
    with _receipt(output, 'backup'):
        with _offline(state, readonly=False, configuration=True) as service:
            if _instance(service) != owner['catalog_instance']:
                raise ValueError('state/formal union identity mismatch')
            with CompactArchive(path) as archive:
                assets = verify_union_assets(archive, service, deep=True)
                if assets['closure_complete'] is not True:
                    raise ValueError('whole-union deep attachment closure required')
                integrity = archive.integrity_check()
                if integrity['quick_check'] != ['ok'] or integrity['foreign_key_check']:
                    raise ValueError('formal union SQLite integrity failed')
            snapshot = state_backup.backup(service, state_repo, include_secrets=include_secrets)
        # Both service DB writers and the union RW connection are now CLOSED.
        # No checkpoint/migration after the exact state cut: a retained foreign
        # writer or dirty sidecar is a hard failure, not permission to recut.
        with ExitStack() as guards:
            for target in (state/'catalog.sqlite', state/'objects.sqlite', path):
                guards.enter_context(cold_input(target))
            companion = union_backup.backup_archive(path, state_repo, snapshot['snapshot_id'], union_repo,
                state_catalog=state/'catalog.sqlite', state_objects=state/'objects.sqlite', asset_binding=assets)
        result = dict(schema=SCHEMA, command='backup', state_snapshot=snapshot, union_snapshot=companion,
            state=str(state), union=str(root), state_repository=str(state_repo), union_repository=str(union_repo),
            receipt_root=str(output), asset_verification=assets, integrity=integrity,
            exact_post_pin_companion=True, implicit_sync=False, capture_started=False, login_started=False,
            same_volume=_same_volume([state, root, state_repo, union_repo]),
            disaster_backup=False, portable_restore_verified=False, attachments_closed=False,
            limitation='repositories may share one failure domain; no portable disaster-recovery claim')
        write_json_new(output/COMPLETE, result)
        return result


def _companions(union_manifest, state_manifest):
    companion = union_manifest['state_companion']
    if (state_manifest['catalog_instance'] != companion['catalog_instance']
            or state_manifest['files']['catalog.sqlite']['sha256'] != companion['catalog_sha256']
            or state_manifest['files']['objects.sqlite']['sha256'] != companion['objects_sha256']):
        raise ValueError('state repository is not the exact union companion')
    return companion['snapshot_id']


def restore(state_repo, union_repo, snapshot, out):
    """Fresh state + union restoration; success requires real deep CAS closure."""
    state_repo, union_repo = map(local_absolute, (state_repo, union_repo))
    output = _fresh(out, [state_repo, union_repo])
    manifest = union_backup.inspect_snapshot(union_repo, snapshot)
    state_id = manifest['state_companion']['snapshot_id']
    state_manifest = state_backup.inspect_snapshot(state_repo, state_id)
    _companions(manifest, state_manifest)  # MUST pass before creating out/state.
    protected = [*manifest['protected_roots'], str(Path(manifest['origin_archive']).parent),
                 state_manifest['origin_state'], *state_manifest['source_roots']]
    if state_manifest['source_roots']:
        protected.append(str(state_backup._external_root(state_manifest['source_roots'][0]).parent))
    _protect(output, protected)
    # Check combined capacity before making partial directories (individual
    # restore APIs additionally verify their own exact manifest budgets).
    import shutil
    needed = sum(entry['bytes'] for entry in state_manifest['files'].values()) + manifest['archive']['bytes']
    if shutil.disk_usage(output.parent).free < needed+2*state_backup.RESTORE_MARGIN_BYTES:
        raise state_backup.InsufficientRestoreSpace('insufficient space for complete union delivery restore')
    with _receipt(output, 'restore'):
        state_result = state_backup.restore(state_repo, state_id, output/'state')
        with _offline(output/'state') as offline:
            union_result = union_backup.restore_archive(union_repo, snapshot, output/'union',
                offline_state=offline, asset_verifier=verify_union_assets)
        if union_result.get('attachments_closed') is not True or union_result.get('metadata_only') is not False:
            raise ValueError('restoration did not establish full referenced-attachment closure')
        result = dict(schema=SCHEMA, command='restore', state_restore=state_result, union_restore=union_result,
            receipt_root=str(output), attachments_closed=True, referenced_cas_bytes_verified=True,
            capture_started=False, login_started=False, source_reconnected=False,
            phone_completeness=False, message_media_association='not_implemented',
            disaster_backup=False, portable_restore_verified=False,
            limitation='verified referenced CAS closure only; original sources remain required')
        write_json_new(output/COMPLETE, result)
        return result


def parser():
    result = argparse.ArgumentParser(description='联合归档交付：不启动采集、不登录；所有路径必须是显式本地绝对路径。')
    commands = result.add_subparsers(dest='command', required=True)
    for name, help_text in (('stats', '只读统计（须关闭状态/联合数据库写连接）'),
                            ('sync', '将已采集的 current 历史同步到正式联合归档，不采集'),
                            ('backup', '深验附件后备份精确配套状态与联合库，不隐式同步'),
                            ('restore', '在全新目录恢复配套状态与联合库并深验附件闭包')):
        command = commands.add_parser(name, help=help_text, description=help_text)
        if name in ('stats', 'sync', 'backup'):
            command.add_argument('--state', required=True, help='已有 current 状态绝对目录')
            command.add_argument('--union', required=True, help='正式联合归档绝对目录；仅 sync 可新建')
        if name in ('backup', 'restore'):
            command.add_argument('--state-repo', required=True, help='独立 current 状态备份仓库绝对目录')
            command.add_argument('--union-repo', required=True, help='独立联合备份仓库绝对目录')
            command.add_argument('--out', required=True, help='全新交付回执目录；restore 下含 state 与 union')
        if name == 'sync':
            command.add_argument('--verify', action='store_true', help='同步后完整校验联合消息库')
        if name == 'backup':
            command.add_argument('--include-secrets', action='store_true', help='显式包含明文密钥；不选时视图/附件仍为敏感数据')
        if name == 'restore':
            command.add_argument('--snapshot', required=True, help='联合备份 snapshot ID（配套状态 ID 自动严格读取）')
    return result


def main(argv=None):
    arguments = vars(parser().parse_args(argv))
    command = arguments.pop('command')
    try:
        result = globals()[command](**arguments)
    except Exception as error:
        print(json.dumps(dict(schema=SCHEMA, command=command, status='failed',
                              error_type=type(error).__name__, error=str(error)), ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
