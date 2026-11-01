"""Next-only raw attachment APIs. Call mutations under the state's writer lock.

No message/media matching is inferred from a filename. Raw CAS bytes remain
authoritative; optional DAT previews are separate, fully validated derivatives.
Configuration recovery MUST run before the inherited service constructor checks
source_binding. A durable journal authorizes only one asset_root-only change;
recovery rolls that change forward, never relaxing source/account validation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid
import zlib

from wechat_capture_v2.common import (canonical, digest_file, directory, regular,
                                      source_files, stamp)
from wechat_capture_v2.objects import CHUNK_BYTES, PendingImport
from .paths import local_absolute

MODE = 'capture-next-final-views-1'
JOURNAL = 'asset-root-change.private.json'
STAGED = 'asset-root-config.private.json'
BINDING_KEYS = ('source_id', 'account_alias', 'self_username', 'database_root', 'asset_root')
_HASH = re.compile(r'[0-9a-f]{64}\Z')


def _absolute(path):
    return local_absolute(path)


def _parents(path, *, is_file=False):
    path = _absolute(path)
    target = path.parent if is_file else path
    for parent in reversed((target, *target.parents)):
        if os.path.lexists(parent):
            directory(parent)
    return path


def _file(path, *, source_read=False):
    # Source paths come exclusively from the checked non-linked traversal.
    # Re-walking every ancestor for every block/file is quadratic metadata I/O
    # in deep media trees. Reads still re-lstat the file and verify its stamp
    # and two full content digests; writable paths keep full ancestor checks.
    if not source_read:
        _parents(path, is_file=True)
    info = regular(path)
    if not source_read and info.st_nlink != 1:
        raise ValueError('hardlinked files are outside attachment scope')
    return info


def _overlap(a, b):
    return a.is_relative_to(b) or b.is_relative_to(a)


def _next_state(state):
    state = _parents(state)
    directory(state)
    marker = state/'next.private.json'
    _file(marker)
    if json.loads(marker.read_text(encoding='utf-8')).get('schema') != MODE:
        raise ValueError('an explicit next state is required')
    return state


def _binding(config):
    return canonical({key: config.get(key) for key in BINDING_KEYS})


def _walk(root):
    root = _parents(root)
    directory(root)
    for relative, path in source_files(root):
        # WeChat legitimately uses ordinary hardlinks in its media tree.
        # These handles are READ ONLY; bytes are copied into independent CAS.
        # State/config/output paths still require a single link everywhere.
        # source_files already checks each parent and every regular file.
        yield relative, path


def _asset_path(state, config, path, output_roots=(), *, require_tree=True):
    root = _parents(path)
    database = _parents(config['database_root'])
    account = database.parent
    # An account-root attachment pass is permitted; capture excludes database
    # files, whose authenticated acquisition uses a stronger separate protocol.
    if not root.is_relative_to(account):
        raise ValueError('asset root must stay inside the currently bound account tree')
    roots = [state, *(Path(p) for p in output_roots)]
    roots.extend(Path(config[k]) for k in ('output_root', 'outputs_root') if config.get(k))
    if any(_overlap(root, _absolute(other)) for other in roots):
        raise ValueError('asset root overlaps state or a declared output')
    if require_tree:
        for _ in _walk(root):
            pass
    return root


def _catalog_path(state):
    path = state/'catalog.sqlite'
    _file(path)
    for suffix in ('-wal', '-shm', '-journal'):
        child = Path(str(path)+suffix)
        if os.path.lexists(child):
            _file(child)
    return path


def _read_config(state):
    path = state/'config.private.json'
    _file(path)
    return path.read_text(encoding='utf-8')


def _publish_text_new(state, name, text, *, kind, fault=None):
    """Publish only a complete fsynced file, under the state's writer lock.

    Process death during write/fsync leaves only a random .pending sibling,
    never a truncated authoritative journal or staging filename. Unpublished
    siblings are deliberately not adopted or removed during later startup.
    os.rename is a same-directory atomic publication. On Windows it also
    refuses an existing destination; the required writer lock serializes the
    existence check/publication on other platforms.
    """
    target = state/name
    if os.path.lexists(target):
        raise FileExistsError('configuration publication already exists')
    temporary = state/('.'+name+'.'+uuid.uuid4().hex+'.pending')
    payload = text.encode('utf-8')
    with temporary.open('xb') as stream:
        boundary = max(1, len(payload)//2)
        stream.write(payload[:boundary])
        stream.flush()
        _fault(fault, kind+'_temp_partial')
        stream.write(payload[boundary:])
        stream.flush()
        os.fsync(stream.fileno())
    _fault(fault, kind+'_temp_fsynced')
    _file(temporary)
    if temporary.read_bytes() != payload:
        raise ValueError('configuration publication readback failed')
    if os.path.lexists(target):
        raise FileExistsError('configuration publication appeared concurrently')
    os.rename(temporary, target)


def _stage_replace(state, text, *, fault=None):
    staged = state/STAGED
    if os.path.lexists(staged):
        _file(staged)
        if staged.read_text(encoding='utf-8') != text:
            raise ValueError('unexpected configuration staging contents')
    else:
        _publish_text_new(state, STAGED, text, kind='staged', fault=fault)
    _fault(fault, 'after_staged')
    _file(state/'config.private.json')
    os.replace(staged, state/'config.private.json')


def _fault(fault, stage):
    if fault:
        fault(stage)


def recover_asset_configuration(state, *, fault=None, catalog_db=None):
    """Roll forward a journaled asset_root-only change, before service startup.

    Exact accepted crash states are old-config/old-meta, new-config/old-meta,
    and new-config/new-meta. Anything else fails closed with evidence retained.
    No source files are read during recovery; unavailable sources stay valid
    offline archives. Existing path ancestors still must not be links. Random
    unpublished .pending files never authorize recovery and are left isolated;
    a malformed *published* journal fails closed rather than being ignored.
    """
    state = _next_state(state)
    journal_path = state/JOURNAL
    if not os.path.lexists(journal_path):
        if os.path.lexists(state/STAGED):
            raise ValueError('unexplained asset configuration staging file')
        return {'recovered': False}
    _file(journal_path)
    journal = json.loads(journal_path.read_text(encoding='utf-8'))
    if journal.get('schema') != 'next-asset-config-journal-1':
        raise ValueError('unsupported asset configuration journal')
    old_text, new_text = journal['old_text'], journal['new_text']
    old, new = json.loads(old_text), json.loads(new_text)
    if (not isinstance(old, dict) or not isinstance(new, dict)
            or {k:v for k,v in old.items() if k != 'asset_root'} !=
               {k:v for k,v in new.items() if k != 'asset_root'}
            or not new.get('asset_root')):
        raise ValueError('journal changes more than asset_root')
    _asset_path(state, new, new['asset_root'], journal.get('output_roots', ()), require_tree=False)
    current_text = _read_config(state)
    own_db = catalog_db is None
    path = _catalog_path(state)
    db = catalog_db or sqlite3.connect(path.as_uri()+'?mode=rw', uri=True)
    try:
        if db.in_transaction:
            raise ValueError('configuration recovery requires a transaction boundary')
        row = db.execute("SELECT value FROM meta WHERE key='source_binding'").fetchone()
        if row is None or (current_text, row[0]) not in {
                (old_text, _binding(old)), (new_text, _binding(old)), (new_text, _binding(new))}:
            raise ValueError('configuration/binding is outside the journaled transition')
        if current_text != new_text:
            _stage_replace(state, new_text, fault=fault)
        elif os.path.lexists(state/STAGED):
            # Only our exact redundant staging file may be removed.
            _file(state/STAGED)
            if (state/STAGED).read_text(encoding='utf-8') != new_text:
                raise ValueError('unexpected redundant staging contents')
            (state/STAGED).unlink()
        _fault(fault, 'after_config')
        with db:
            count = db.execute("UPDATE meta SET value=? WHERE key='source_binding' AND value IN (?,?)",
                               (_binding(new), _binding(old), _binding(new))).rowcount
            if count != 1:
                raise ValueError('source binding changed concurrently')
            audit = canonical(journal)
            db.execute('INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)',
                ('next_asset_root_change:'+hashlib.sha256(audit.encode()).hexdigest(), audit))
        _fault(fault, 'after_binding')
        if _read_config(state) != new_text:
            raise ValueError('configuration readback failed')
        _fault(fault, 'before_journal_remove')
        journal_path.unlink()
        return {'recovered': True, 'asset_root': new['asset_root'], 'config': new}
    finally:
        if own_db:
            db.close()


def configure_asset_root(service, path, *, output_roots=(), fault=None):
    """Explicit safe setting; caller declares any external output roots it owns.

    An exception after journal creation requires recovery/restart before further
    work. Never edit source_id/account/database_root to bypass startup binding.
    """
    state = _next_state(service.state)
    if getattr(service, '_pending_asset', None) or getattr(service, '_asset_iterator', None):
        raise ValueError('finish the active attachment pass before reconfiguration')
    if os.path.lexists(state/JOURNAL) or os.path.lexists(state/STAGED):
        raise ValueError('recover the previous asset configuration first')
    old_text = _read_config(state)
    old = json.loads(old_text)
    if old != service.config:
        raise ValueError('service configuration differs from persisted configuration')
    row = service.catalog.db.execute("SELECT value FROM meta WHERE key='source_binding'").fetchone()
    if row is None or row[0] != _binding(old) or service.catalog.db.in_transaction:
        raise ValueError('source binding mismatch or active catalog transaction')
    roots = tuple(str(_absolute(p)) for p in output_roots)
    root = _asset_path(state, old, path, roots)
    new = dict(old, asset_root=str(root))
    if new == old:
        return {'changed': False, 'asset_root': str(root)}
    # Publication is atomic only AFTER the complete journal has been fsynced.
    # Neither a partial temp nor an unrelated old temp is recovery authority.
    journal = {'schema':'next-asset-config-journal-1',
        'old_text':old_text, 'new_text':canonical(new)+'\n', 'output_roots':roots}
    _publish_text_new(state, JOURNAL, canonical(journal)+'\n', kind='journal', fault=fault)
    _fault(fault, 'after_journal')
    result = recover_asset_configuration(state, fault=fault, catalog_db=service.catalog.db)
    service.config = new
    service._asset_iterator = None
    service._pending_asset = None
    service._asset_retry = {}
    # Asset-root participates in the frozen reader binding. Reopening derives
    # the exact binding for this state and all next extensions; invalidate the
    # live instance conservatively until its normal reopen.
    if hasattr(service, 'interpretation_binding'):
        service.interpretation_binding = hashlib.sha256(
            (service.interpretation_binding+_binding(new)).encode()).hexdigest()
    return {'changed': True, 'asset_root': result['asset_root'], 'reopen_recommended': True}


def _notifications(service):
    """Lazily arm before scanning; never trust continuity across a restart."""
    from .asset_notifications import AssetNotifications
    root = Path(service.config['asset_root'])
    observer = getattr(service, '_asset_notifications', None)
    if observer is not None and (observer.root != root or not observer.poll()['available']):
        observer.close()
        service._asset_notifications = observer = None
        # A lost watcher/root invalidates an in-progress byte proof too.
        service._asset_iterator = service._pending_asset = None
    if observer is None:
        observer = service._asset_notifications = AssetNotifications(root)
    return observer


def _dirty_prefixes(relative, names):
    # O(path depth), not files × dirty names after a large notification batch.
    parts = relative.casefold().split('/')
    return {names[prefix] for prefix in ('/'.join(parts[:i]) for i in range(1,len(parts)+1))
            if prefix in names}


def _dirty_inodes(service, root, names):
    """A write through one hardlink invalidates all aliases of its identity."""
    identities, resolved = set(), set()
    for relative, text in service.catalog.db.execute('SELECT relative_path,stamp_json FROM asset WHERE source_id=?',
                                                   (service.config['source_id'],)):
        matches = _dirty_prefixes(relative, names)
        if matches:
            identities.add(tuple(json.loads(text)[:2]))
            resolved.update(matches)
    for name in names.values():
        path = root/name
        try:
            path = _parents(path, is_file=True)
            if path.is_dir():
                for _, child in _walk(path):
                    info = regular(child)
                    identities.add((info.st_dev,info.st_ino))
            else:
                info = regular(path)
                identities.add((info.st_dev,info.st_ino))
            resolved.add(name)
        except FileNotFoundError:
            pass
    return identities, set(names.values())-resolved


class _KnownSourceCheck(PendingImport):
    """Hash known source bytes once, reusing an accepted immutable CAS object.

    Matching a previously accepted SHA is a byte proof, not an mtime shortcut.
    A mismatch enters the original double-read import with no quantity cap.
    """
    def __init__(self, objects, path, expected):
        super().__init__(objects,path)
        self.expected = expected
        self.phase = 'verify_known_source'

    def advance(self, deadline):
        if self.phase != 'verify_known_source':
            return super().advance(deadline)
        if stamp(self.path) != self.before:
            raise RuntimeError('known attachment generation changed')
        with self.path.open('rb') as stream:
            stream.seek(self.offset)
            worked = False
            while not worked or time.monotonic() < deadline:
                block = stream.read(min(CHUNK_BYTES,self.size-self.offset))
                if len(block) != min(CHUNK_BYTES,self.size-self.offset):
                    raise RuntimeError('known attachment short read')
                self.digest.update(block)
                self.offset += len(block)
                worked = True
                if self.offset == self.size:
                    break
        if stamp(self.path) != self.before:
            raise RuntimeError('known attachment changed during verification')
        if self.offset == self.size:
            if self.digest.hexdigest() == self.expected:
                row = self.objects.db.execute('SELECT bytes,chunk_count FROM file WHERE hash=?',(self.expected,)).fetchone()
                if row is None or row[0] != self.size:
                    raise ValueError('accepted attachment object missing or mismatched')
                self.result = dict(sha256=self.expected,bytes=self.size,chunk_count=row[1],reused_known=True)
                self.phase = 'complete'
                return self.result
            self.phase, self.offset, self.digest = 'store', 0, hashlib.sha256()
        return None


class _AssetPreflightFailure(Exception):
    def __init__(self, error):
        self.error_type = type(error).__name__
        super().__init__('asset source preflight failed')


def capture_assets(service, cycle, force=False, budget_seconds=None, verify_shared=False):
    """Keep source preflight failures visible in both acquisition report paths.

    Budget/configuration checks and post-preflight exceptions retain their
    original behavior. Abandoned unpublished work is not deleted: accepted
    per-file history and CAS remain intact. A retry flag additionally forces
    bytes when the notification observer cannot record its own invalidation.
    """
    try:
        result = _capture_assets_pass(service, cycle,
            force or getattr(service, '_asset_preflight_retry', False), budget_seconds, verify_shared)
    except _AssetPreflightFailure as error:
        iterator = getattr(service, '_asset_iterator', None)
        service._asset_iterator = service._pending_asset = None
        service._asset_pass_failed = True
        service._asset_preflight_retry = True
        if iterator is not None:
            try:
                iterator.close()
            except Exception:
                pass  # Cleanup must not replace the original source failure.
        observer = getattr(service, '_asset_notifications', None)
        if observer is not None:
            try:
                observer.require_full_bytes('asset_source_preflight_failed')
            except Exception:
                pass  # The independent retry flag still requires full bytes.
        return dict(enabled=True, complete=False, files_seen=0, new_versions=0, bytes_seen=0,
            verified_unchanged_files=0, verified_unchanged_bytes=0,
            errors=[dict(error_type=error.error_type, phase='asset_preflight')],
            coverage='configured_local_asset_tree_only', message_media_association='not_implemented',
            message_count_limit=None, history_time_limit=None)
    if result.get('enabled') is True and result.get('complete') is True and not result.get('errors'):
        service._asset_preflight_retry = False
    return result


def _capture_assets_pass(service, cycle, force=False, budget_seconds=None, verify_shared=False):
    """Complete raw-file acquisition; time slices are scheduling, never caps."""
    if not service.config.get('asset_root'):
        return dict(enabled=False, errors=[], files_seen=0, new_versions=0, complete=True,
                    message_media_association='not_implemented')
    if budget_seconds is not None and budget_seconds <= 0:
        raise ValueError('asset time slice must be positive')
    if os.path.lexists(service.state/JOURNAL):
        raise ValueError('asset configuration recovery required')
    try:
        root = _parents(service.config['asset_root'])
        observer = _notifications(service)
        upgrade = (force and not service._asset_force) if service._asset_iterator is not None else False
        upgrade = upgrade or (verify_shared and service._asset_iterator is not None
                              and not service._asset_force and not getattr(service,'_asset_verify_shared',False))
        if upgrade:
            # A full pass must also cover the prefix an incremental pass skipped.
            # Unpublished chunks may be reused by CAS; no accepted file is removed.
            service._asset_iterator = None
            service._pending_asset = None
        if service._asset_iterator is None:
            ticket = observer.begin()
            # Native APIs may supply an unresolved DOS short name. A complete
            # byte sweep is safe even when that name cannot be mapped after delete.
            if any(re.search(r'~[0-9]+(?:\.|/|$)', name) for name in ticket.dirty_paths):
                observer.require_full_bytes('short_notification_name_requires_full_byte_sweep')
                ticket = observer.begin()
            names = {name.casefold():name for name in ticket.dirty_paths}
            identities, unresolved = (set(),set()) if force or ticket.full_required or not names else _dirty_inodes(service,root,names)
            if unresolved:
                observer.require_full_bytes('unresolved_notification_identity_requires_full_byte_sweep')
                ticket = observer.begin()
            service._asset_iterator = iter(_walk(root))
            service._asset_force = force or ticket.full_required
            service._asset_pass_ticket = ticket
            service._asset_dirty_names = {name.casefold():name for name in ticket.dirty_paths}
            service._asset_dirty_inodes = identities
            service._asset_verify_shared = verify_shared
            service._asset_pass_seen = set()
            service._asset_pass_failed = False
        ticket = service._asset_pass_ticket
    except Exception as error:
        raise _AssetPreflightFailure(error) from error
    result = dict(enabled=True, errors=[], files_seen=0, new_versions=0, bytes_seen=0,
        verified_unchanged_files=0, verified_unchanged_bytes=0,
        complete=True, message_count_limit=None, history_time_limit=None,
        message_media_association='not_implemented', coverage='configured_local_asset_tree_only',
        notification_available=ticket.available, notification_generation=ticket.generation,
        byte_verification='full_sweep' if service._asset_force else 'named_changes_and_metadata_differences',
        unchanged_reuse_basis='accepted_source_sha256_match' if service._asset_force else
            'event_hints_and_stamps_between_periodic_full_byte_audits',
        shared_inode_periodic_bytes=service._asset_verify_shared)
    if service._asset_pass_failed:
        result['errors'].append(dict(error_type='previous_asset_slice_failed',
            recovery='finish remaining files, then retry the entire unacknowledged pass'))
    began = time.monotonic()
    deadline = began+budget_seconds if budget_seconds is not None else float('inf')
    attempted = 0
    while True:
        if attempted and time.monotonic() >= deadline:
            result['complete'] = False
            break
        try:
            if service._pending_asset is not None:
                relative, path, pending = service._pending_asset
            else:
                relative, path = next(service._asset_iterator)
                pending = None
        except StopIteration:
            service._asset_iterator = None
            if not service._asset_pass_failed:
                observer.complete(ticket, verified_paths=service._asset_pass_seen,
                    absent_paths=ticket.dirty_paths-service._asset_pass_seen,
                    inventory_complete=True, full_bytes=bool(service._asset_force))
            else:
                result['complete'] = False
                if not result['errors']:
                    result['errors'].append(dict(error_type='previous_asset_slice_failed'))
            break
        except Exception as exc:
            result['errors'].append(dict(error_type=type(exc).__name__, detail_private=str(exc), phase='asset_walk'))
            result['complete'] = False
            service._asset_pass_failed = True
            service._asset_iterator = None
            break
        attempted += 1
        if path.is_relative_to(service.root):
            continue
        result['files_seen'] += 1
        try:
            info = _file(path, source_read=True)
            before = stamp(path)
            result['bytes_seen'] += before[2]
            old = service.catalog.db.execute('SELECT stamp_json,file_sha FROM asset WHERE source_id=? AND relative_path=?',
                (service.config['source_id'], relative)).fetchone()
            dirty = _dirty_prefixes(relative, service._asset_dirty_names)
            service._asset_pass_seen.update(dirty)
            force_bytes = (service._asset_force or dirty or tuple(before[:2]) in service._asset_dirty_inodes
                           or (service._asset_verify_shared and info.st_nlink > 1))
            known_stamp = old is not None and old[0] == canonical(before)
            if pending is None and not force_bytes and known_stamp:
                continue
            pending = pending or (_KnownSourceCheck(service.objects,path,old[1]) if known_stamp else PendingImport(service.objects,path))
            service._pending_asset = (relative, path, pending)
            obj = pending.advance(deadline)
            while obj is None and time.monotonic() < deadline:
                _file(path, source_read=True)
                obj = pending.advance(deadline)
            if obj is None:
                result.update(complete=False, pending_phase=pending.phase,
                    pending_bytes=pending.size, pending_processed_bytes=pending.offset)
                break
            _file(path, source_read=True)
            if stamp(path) != pending.before:
                raise RuntimeError('asset changed after publication')
            if obj.get('reused_known'):
                service._pending_asset = None
                result['verified_unchanged_files'] += 1
                result['verified_unchanged_bytes'] += obj['bytes']
                continue
            with service.catalog.db:
                inserted = service.catalog.db.execute('INSERT OR IGNORE INTO asset_history VALUES(?,?,?,?,?)',
                    (service.config['source_id'], relative, obj['sha256'], obj['bytes'], cycle)).rowcount
                service.catalog.db.execute('''INSERT INTO asset VALUES(?,?,?,?,?,?) ON CONFLICT(source_id,relative_path)
                    DO UPDATE SET file_sha=excluded.file_sha,bytes=excluded.bytes,
                    stamp_json=excluded.stamp_json,cycle_id=excluded.cycle_id''',
                    (service.config['source_id'], relative, obj['sha256'], obj['bytes'], canonical(pending.before), cycle))
            service._pending_asset = None
            result['new_versions'] += inserted
        except Exception as exc:
            service._pending_asset = None
            service._asset_pass_failed = True
            result['errors'].append(dict(path=relative, error_type=type(exc).__name__, detail_private=str(exc)))
    return result


def assets_need_scan(service):
    """Cheap loss-aware event check, not a metadata/mtime-only byte proof.

    The watch's periodic DB full still audits every source byte, including
    silent same-stamp writes. Hints never replace this integrity fallback.
    """
    if not service.config.get('asset_root'):
        return False
    if getattr(service, '_asset_preflight_retry', False):
        return True  # Failed observer invalidation must not cache the retry idle.
    observer = _notifications(service)
    if getattr(service, '_pending_asset', None) is not None or getattr(service, '_asset_iterator', None) is not None:
        return True
    snapshot = observer.poll()
    return bool(not snapshot['available'] or snapshot['full_required'] or
                snapshot['inventory_required'] or snapshot['dirty_paths'])


def _verify_references(service):
    references = set()
    counts = {}
    for table in ('asset', 'asset_history'):
        counts[table] = 0
        for source, relative, sha, size in service.catalog.db.execute(
                f'SELECT source_id,relative_path,file_sha,bytes FROM {table}'):
            if not isinstance(sha, str) or not _HASH.fullmatch(sha):
                raise ValueError('catalog asset has an invalid object hash')
            row = service.objects.db.execute('SELECT bytes FROM file WHERE hash=?', (sha,)).fetchone()
            if row is None or row[0] != size:
                raise ValueError('catalog asset references a missing or size-mismatched published object')
            if table == 'asset' and not service.catalog.db.execute('''SELECT 1 FROM asset_history
                WHERE source_id=? AND relative_path=? AND file_sha=? AND bytes=?''',
                (source, relative, sha, size)).fetchone():
                raise ValueError('current asset is missing its retained history reference')
            references.add(sha)
            counts[table] += 1
    # External unions share the same published CAS, but are not current-source
    # acquisition cycles. Never disguise their provenance as asset/history.
    external_owners=external_refs=0
    db=service.catalog.db
    tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('external_asset_owner','external_asset_ref')")}
    if tables:
        if tables!={'external_asset_owner','external_asset_ref'}:
            raise ValueError('incomplete external asset reference extension')
        expected={'external_asset_owner':('owner_id','cas_id','schema'),
                  'external_asset_ref':('owner_id','file_sha','bytes','cas_id')}
        if any(tuple(r[1] for r in db.execute('PRAGMA table_info('+table+')'))!=columns for table,columns in expected.items()):
            raise ValueError('unsupported external asset reference schema')
        identity=db.execute("SELECT value FROM meta WHERE key='next_catalog_instance'").fetchone()
        if identity is None:raise ValueError('external asset catalog identity missing')
        cas_id='capture-next-objects:'+identity[0]
        owners={}
        import uuid
        for owner,cas,schema in db.execute('SELECT owner_id,cas_id,schema FROM external_asset_owner'):
            try:valid=isinstance(owner,str) and owner in (uuid.UUID(owner).hex,str(uuid.UUID(owner)))
            except (ValueError,AttributeError):valid=False
            if not valid or cas!=cas_id or schema not in ('next-union-assets-1','next-viewer-media-1'):
                raise ValueError('external asset owner binding mismatch')
            owners[owner]=cas
        external_owners=len(owners)
        for owner,sha,size,cas in db.execute('SELECT owner_id,file_sha,bytes,cas_id FROM external_asset_ref'):
            if owner not in owners or cas!=cas_id or not isinstance(sha,str) or not _HASH.fullmatch(sha) or type(size) is not int or size<0:
                raise ValueError('external asset reference binding invalid')
            published=service.objects.db.execute('SELECT bytes FROM file WHERE hash=?',(sha,)).fetchone()
            if published is None or published[0]!=size:
                raise ValueError('external asset references a missing or size-mismatched published object')
            references.add(sha);external_refs+=1
    return dict(asset_references_verified=counts['asset'], asset_history_references_verified=counts['asset_history'],
                referenced_asset_objects_verified=len(references),external_asset_owners_verified=external_owners,
                external_asset_references_verified=external_refs)


def verify_assets(service, *, verify_objects=True):
    result = service.objects.verify_all() if verify_objects else {}
    return dict(result, **_verify_references(service), message_media_association='not_implemented')


def _output(service, out):
    target = _parents(out, is_file=True)
    # Protect the entire bound account, including currently unconfigured media.
    for root in (service.state, _absolute(service.config['database_root']).parent):
        if _overlap(target, root):
            raise ValueError('attachment output must not overlap state or the bound account tree')
    if os.path.lexists(target):
        raise FileExistsError('a new attachment output is required')
    return service.validate_output(target)


def _blocks(service, sha):
    count = total = 0
    digest = hashlib.sha256()
    expected = service.objects.db.execute('SELECT bytes,chunk_count FROM file WHERE hash=?', (sha,)).fetchone()
    if expected is None:
        raise KeyError('published attachment object missing')
    for ordinal, key, size, payload in service.objects.db.execute('''SELECT f.ordinal,c.hash,c.bytes,c.data
            FROM file_chunk f JOIN chunk c ON c.hash=f.chunk_hash WHERE f.file_hash=? ORDER BY f.ordinal''', (sha,)):
        if ordinal != count or not 0 <= size <= CHUNK_BYTES:
            raise ValueError('invalid attachment chunk sequence/size')
        decoder = zlib.decompressobj()
        block = decoder.decompress(payload, CHUNK_BYTES+1)
        if (not decoder.eof or decoder.unused_data or len(block) != size
                or hashlib.sha256(block).hexdigest() != key):
            raise ValueError('attachment chunk verification failed')
        digest.update(block)
        count += 1
        total += len(block)
        yield block
    if (total, count) != tuple(expected) or digest.hexdigest() != sha:
        raise ValueError('attachment object hash/length mismatch')


def _authorized(service, sha):
    if not isinstance(sha, str) or not _HASH.fullmatch(sha):
        raise ValueError('a lowercase SHA-256 object hash is required')
    rows = list(service.catalog.db.execute('SELECT bytes FROM asset_history WHERE file_sha=? AND source_id=?',
            (sha, service.config['source_id'])))
    if not rows and service.catalog.db.execute("SELECT 1 FROM sqlite_master WHERE name IN ('external_asset_owner','external_asset_ref') LIMIT 1").fetchone():
        # An explicitly registered union pin authorizes raw export without
        # forging a current acquisition cycle or a media-message association.
        _verify_references(service)
        rows=list(service.catalog.db.execute('SELECT bytes FROM external_asset_ref WHERE file_sha=?',(sha,)))
    if not rows:
        raise ValueError('object has no attachment history authorization')
    published = service.objects.db.execute('SELECT bytes FROM file WHERE hash=?', (sha,)).fetchone()
    if not published:
        raise KeyError('attachment object is not published')
    if any(row[0] != published[0] for row in rows):
        raise ValueError('attachment history/object size mismatch')


def export_asset(service, file_sha, out):
    """Stream verified original bytes to an exclusive new output, no live reads."""
    _authorized(service, file_sha)
    target = _output(service, out)
    target.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with target.open('xb') as stream:
            created = True
            for block in _blocks(service, file_sha):
                stream.write(block)
            stream.flush()
            os.fsync(stream.fileno())
        if digest_file(target) != file_sha:
            raise ValueError('attachment export readback mismatch')
        return dict(sha256=file_sha, bytes=target.stat().st_size, raw_preserved=True)
    except BaseException:
        if created:
            target.unlink()
        raise


def preview_asset(service, file_sha, out, *, candidates=()):
    """Optional bounded DAT decode; unsupported leaves no preview, raw untouched."""
    from tools.decode_weixin_dat import DecodeError, MAX_BYTES, decode
    _authorized(service, file_sha)
    target = _output(service, out)
    size = service.objects.db.execute('SELECT bytes FROM file WHERE hash=?', (file_sha,)).fetchone()[0]
    if size > MAX_BYTES:
        return dict(status='unsupported', reason='preview decoder size limit', raw_preserved=True)
    raw = b''.join(_blocks(service, file_sha))
    try:
        result = decode(raw, tuple(candidates))
    except DecodeError as exc:
        return dict(status='unsupported', reason=str(exc), raw_preserved=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with target.open('xb') as stream:
            created = True
            stream.write(result.data)
            stream.flush()
            os.fsync(stream.fileno())
        if digest_file(target) != result.summary()['sha256']:
            raise ValueError('preview readback failed')
    except BaseException:
        if created:
            target.unlink()
        raise
    return dict(status='decoded', source_sha256=file_sha, raw_preserved=True, **result.summary())


def inventory_assets(service):
    """One explicit scoped inventory, no file-content reads or account search."""
    if not service.config.get('asset_root'):
        return dict(enabled=False, files=0, bytes=0, message_media_association='not_implemented')
    files = size = 0
    extensions = {}
    for relative, path in _walk(service.config['asset_root']):
        if path.is_relative_to(service.root):
            continue
        files += 1
        size += _file(path, source_read=True).st_size
        suffix = path.suffix.casefold() or '[none]'
        extensions[suffix] = extensions.get(suffix, 0)+1
    return dict(enabled=True, files=files, bytes=size, extensions=extensions,
        snapshot_atomic=False, coverage='configured_local_asset_tree_only',
        message_media_association='not_implemented', content_read=False)


def prune_unpublished(service, *, fault=None):
    """Explicit next-only transactional GC, never delete any published file.

    Reports logical/compressed payload removed; SQLite pages are reusable, not
    necessarily returned to the OS. No automatic VACUUM or real-state invocation.
    Caller holds the OS writer lock, excluding other acquisition processes.
    """
    state = _next_state(service.state)
    expected = state/'objects.sqlite'
    _file(expected)
    if _absolute(service.objects.path) != expected:
        raise ValueError('cleanup requires this next state\'s exact object database')
    if getattr(service, '_pending_asset', None) is not None:
        raise ValueError('cannot prune an active pending import')
    db = service.objects.db
    actual = next(row[2] for row in db.execute('PRAGMA database_list') if row[1] == 'main')
    if _absolute(actual) != expected:
        raise ValueError('cleanup connection is not the expected next object database')
    if db.in_transaction or service.catalog.db.in_transaction:
        raise ValueError('cleanup requires a transaction boundary')
    refs = _verify_references(service)
    try:
        db.execute('BEGIN IMMEDIATE')
        maps = db.execute('DELETE FROM file_chunk WHERE file_hash NOT IN (SELECT hash FROM file)').rowcount
        _fault(fault, 'after_maps')
        count, logical, compressed = db.execute('''SELECT count(*),coalesce(sum(bytes),0),coalesce(sum(length(data)),0)
            FROM chunk WHERE hash NOT IN (SELECT chunk_hash FROM file_chunk)''').fetchone()
        db.execute('DELETE FROM chunk WHERE hash NOT IN (SELECT chunk_hash FROM file_chunk)')
        _fault(fault, 'after_chunks')
        _verify_references(service)
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return dict(unpublished_maps_removed=maps, chunks_removed=count,
        logical_chunk_bytes_removed=logical, compressed_payload_bytes_removed=compressed,
        published_files_removed=0, physical_file_shrink_guaranteed=False, **refs)
