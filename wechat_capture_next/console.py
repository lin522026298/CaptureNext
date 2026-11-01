"""Loopback-only local console; one worker owns all capture mutations.

The browser never selects an executable or an arbitrary output path. Read APIs
use independent read-only SQLite connections, never a service constructor.
This console reports only locally landed observations, not phone completeness.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict, deque
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from urllib.parse import parse_qs, unquote, urlsplit
import uuid
import hashlib

from wechat_capture_v2.common import canonical, directory, regular, utcnow, write_json_new
from wechat_capture_v2.service import load_config
from .service import CaptureService
from .reports import decode_report
from .paths import local_absolute, safe_name
from .state_guard import writer_lock
from .backup import InsufficientRestoreSpace

SCOPE = '仅本机已落盘'
MAX_BODY = 64 * 1024
MAX_JOBS = 100
QUEUE_SIZE = 16
SUMMARY_KEYS = ('versions', 'active_messages', 'captures', 'assets')
WEB = Path(__file__).with_name('web')
OUTPUT_SCHEMA = 'capture-next-console-output-1'
_HASH = re.compile(r'[0-9a-f]{64}\Z')
_ACTIONS = {
    'refresh_status': set(),
    'start_watch': {'assets'}, 'stop_watch': set(), 'capture': {'full', 'assets'},
    'verify': set(), 'validate': {'name'}, 'sync_wua': {'verify'},
    'backup': {'name', 'include_secrets'}, 'restore': {'name', 'snapshot_id'},
    'compare': {'name', 'reference', 'path'}, 'configure_assets': {'root'},
    'export_asset': {'name', 'sha', 'hash'},
}


class QueueFull(RuntimeError):
    pass


class SummaryUnavailable(OSError):
    pass


def _parents(value):
    path = local_absolute(value, allow_relative=True)
    for parent in reversed((path, *path.parents)):
        if os.path.lexists(parent):
            directory(parent)
    return path


def _file(path):
    _parents(Path(path).parent)
    info = regular(path)
    if info.st_nlink != 1:
        raise ValueError('hardlinked files are forbidden')
    return info


def _overlap(a, b):
    return a.is_relative_to(b) or b.is_relative_to(a)


def _name(value):
    safe_name(value)
    if (not isinstance(value, str) or not 1 <= len(value) <= 80
            or not value[0].isalnum() or value.endswith((' ', '.')) or '..' in value
            or not all(c.isalnum() or c in '_-. ' for c in value)
            or value.casefold() in {'backups', 'managed-wua'}
            or value.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(10)),
                                *(f'LPT{i}' for i in range(10))}):
        raise ValueError('a single safe output name is required')
    return value


def checked_output(state, output):
    state = _parents(state)
    directory(state)
    for name in ('config.private.json', 'next.private.json'):
        _file(state/name)
    config = load_config(state)
    output = _parents(output)
    roots = [state, _parents(config['database_root']), _parents(config['database_root']).parent]
    if config.get('asset_root'):
        roots.append(_parents(config['asset_root']))
    if any(_overlap(output, root) for root in roots):
        raise ValueError('console output overlaps state or a live source')
    owner = {'schema': OUTPUT_SCHEMA, 'state': str(state)}
    if output.exists():
        marker = output/'OWNER.private.json'
        _file(marker)
        if json.loads(marker.read_text(encoding='utf-8')) != owner:
            raise ValueError('foreign console output cannot be adopted')
    lock = state/'writer.lock'
    if os.path.lexists(lock):
        _file(lock)
    return state, output, config, owner


def _compact_result(value):
    """Retain job summaries, not full collector reports or message payloads."""
    if not isinstance(value, dict):
        return {'result_type': type(value).__name__}
    result = {key: item for key,item in value.items()
              if item is None or isinstance(item, (str, int, float, bool))}
    for key in ('summary', 'stats', 'verification'):
        if isinstance(value.get(key), dict):
            result[key] = {k:v for k,v in value[key].items()
                           if v is None or isinstance(v, (str, int, float, bool))}
    if 'errors' in value:
        result['errors_count'] = len(value['errors']) if isinstance(value['errors'], list) else 1
    if len(canonical(result).encode()) > 32768:
        return {'summary': 'result exceeds in-memory metadata budget'}
    return result


class Coordinator:
    def __init__(self, state, output_root, *, repository_root=None, managed_root=None,
                 queue_size=QUEUE_SIZE, interval=3, reconcile_seconds=300):
        self.state, self.output_root, self.config, self._owner = checked_output(state, output_root)
        self.repository_root = _parents(repository_root if repository_root is not None else self.output_root/'backups')
        self.managed_root = _parents(managed_root if managed_root is not None else self.output_root/'managed-wua')
        self._catalog_instance = None  # Established only by the locked worker.
        if not 0 < queue_size <= MAX_JOBS-1 or interval <= 0 or reconcile_seconds <= 0:
            raise ValueError('invalid coordinator bounds')
        self.queue_size, self.interval, self.reconcile_seconds = queue_size, interval, reconcile_seconds
        self.condition = threading.Condition()
        self.pending = deque()
        self.jobs = OrderedDict()
        self.receipts = OrderedDict()
        self.watching = False
        self.watch_assets = None
        self.busy = False
        self.current_job = None
        self.closing = False
        self.ready = threading.Event()
        self.startup_error = None
        self.watch_error = None
        self.asset_progress = None
        self._service_epoch = 0
        self._summary_generation = 0
        self._summary_snapshot = None
        self._summary_valid = False
        self._summary_error = None
        self.service = None  # Worker-thread-only; never used by HTTP handlers.
        self.thread = threading.Thread(target=self._worker, name='capture-next-writer', daemon=True)
        self.thread.start()
        self.ready.wait()
        if self.startup_error is not None:
            self.thread.join()
            raise RuntimeError('console writer startup failed: '+self.startup_error)

    def _open(self):
        from .assets import recover_asset_configuration
        recover_asset_configuration(self.state)
        service = CaptureService(self.state)
        with service.catalog.db:
            service.catalog.db.execute('CREATE INDEX IF NOT EXISTS next_head_version ON head(version_id)')
        self._service_epoch += 1
        return service

    def _summary_values(self, value):
        if (not isinstance(value, dict) or any(type(value.get(key)) is not int or value[key] < 0
                                               for key in SUMMARY_KEYS)):
            raise ValueError('invalid committed count summary')
        return {key:value[key] for key in SUMMARY_KEYS}

    def _read_summary(self):
        """Read one committed catalog cut on the owning worker only."""
        if threading.current_thread() is not self.thread or self.service is None:
            raise SummaryUnavailable('summary requires the owned worker')
        db = self.service.catalog.db
        if db.in_transaction:
            raise SummaryUnavailable('summary requires a transaction boundary')
        db.execute('BEGIN')
        try:
            return self._summary_values(self.service.catalog.summary())
        finally:
            db.rollback()  # Only the read transaction opened immediately above.

    def _refresh_summary(self, report=None, *, constructor_cache=False):
        """Publish immutable counts, never manufacture a fresh idle sample."""
        if threading.current_thread() is not self.thread:
            raise RuntimeError('summary publication is worker-thread-only')
        try:
            if self.service is None or self.service.catalog.db.in_transaction:
                raise SummaryUnavailable('summary requires an owned committed boundary')
            if isinstance(report, dict) and report.get('mode') == 'metadata_poll' and report.get('status') == 'idle':
                if self._summary_snapshot and self._summary_snapshot['service_epoch'] != self._service_epoch:
                    raise SummaryUnavailable('a reopened service needs its own count snapshot')
                return self._summary_valid  # An invalid cache stays invalid, too.
            candidate = (getattr(self.service, '_summary_cache', None) if constructor_cache
                         else report.get('summary') if isinstance(report, dict) else None)
            try:
                values = self._summary_values(candidate)
            except ValueError:
                values = self._read_summary()
            snapshot = dict(summary=values, summary_as_of=utcnow(), service_epoch=self._service_epoch,
                summary_scope='last_committed_worker_boundary',
                asset_enabled=bool(self.service.config.get('asset_root')))
            with self.condition:
                self._summary_generation += 1
                snapshot['summary_generation'] = self._summary_generation
                self._summary_snapshot = snapshot
                self._summary_valid = True
                self._summary_error = None
            return True
        except Exception as exc:
            with self.condition:
                self._summary_valid = False
                self._summary_error = type(exc).__name__
            return False

    def _owned_output(self):
        # Revalidate on the worker immediately before creating the owned root.
        checked_output(self.state, self.output_root)
        if not self.output_root.exists():
            self.output_root.mkdir(parents=True, exist_ok=False)
            write_json_new(self.output_root/'OWNER.private.json', self._owner)

    def _check_bound_directory(self, root, schema, files):
        root = _parents(root)
        if not root.exists():
            return
        directory(root)
        marker = root/'OWNER.private.json'
        _file(marker)
        owner = json.loads(marker.read_text(encoding='utf-8'), object_pairs_hook=_unique_object)
        if owner != {'schema': schema, 'catalog_instance': self._catalog_instance}:
            raise ValueError('delivery root belongs to a foreign or historical catalog')
        for child in root.iterdir():
            _file(child)
            if child.name not in files:
                raise ValueError('unexpected entry in an owned delivery root')

    def _check_delivery_bindings(self):
        from .backup import SCHEMA, DATABASE
        roots = (self.repository_root, self.managed_root)
        protected = [self.state, _parents(self.config['database_root']).parent]
        if self.config.get('asset_root'):
            protected.append(_parents(self.config['asset_root']))
        if _overlap(*roots):
            raise ValueError('repository and managed roots must be separate')
        for root in roots:
            if any(_overlap(root, other) for other in protected):
                raise ValueError('delivery root overlaps state or a live account')
            if self.output_root.is_relative_to(root):
                raise ValueError('delivery root must not contain the console output')
        self._check_bound_directory(self.repository_root, SCHEMA,
            {'OWNER.private.json', DATABASE, DATABASE+'-journal', 'repository.lock'})
        archive = 'archive.wua.sqlite'
        self._check_bound_directory(self.managed_root, 'next-managed-wua-1',
            {'OWNER.private.json', archive, *(archive+s for s in ('-journal', '-wal', '-shm'))})

    def target(self, name):
        target = _parents(self.output_root)/_name(name)
        if any(_overlap(target, root) for root in (self.repository_root, self.managed_root)):
            raise ValueError('named output overlaps a bound delivery root')
        if os.path.lexists(target):
            raise FileExistsError('a fresh named output is required')
        return target

    def _validate(self, payload):
        if not isinstance(payload, dict) or not isinstance(payload.get('action'), str):
            raise ValueError('action object required')
        action = payload['action']
        params = {k:v for k,v in payload.items() if k != 'action'}
        for alias, key in (('output_name', 'name'), ('reference_path', 'reference'), ('file_sha', 'sha')):
            if alias in params:
                if key in params:
                    raise ValueError('duplicate parameter alias')
                params[key] = params.pop(alias)
        if action not in _ACTIONS or set(params)-_ACTIONS[action]:
            raise ValueError('unknown action or parameter')
        for key in ('full', 'assets', 'verify', 'include_secrets'):
            if key in params and type(params[key]) is not bool:
                raise ValueError('boolean parameter required')
        if 'name' in params:
            if action == 'backup':
                _name(params['name'])  # A task note, not a new repository path.
            else:
                self.target(params['name'])
        if action == 'restore' and not (isinstance(params.get('snapshot_id'), str) and _HASH.fullmatch(params['snapshot_id'])):
            raise ValueError('snapshot_id must be SHA-256')
        if action == 'export_asset':
            if 'sha' in params and 'hash' in params:
                raise ValueError('duplicate asset hash')
            sha = params.get('sha', params.get('hash'))
            if not isinstance(sha, str) or not _HASH.fullmatch(sha):
                raise ValueError('asset SHA-256 required')
        if action == 'configure_assets':
            root = params.get('root')
            if not isinstance(root, str) or not Path(root).is_absolute():
                raise ValueError('absolute asset root required')
            _parents(root)
        for key in ('path', 'reference'):
            if key in params and (not isinstance(params[key], str) or not params[key]):
                raise ValueError('reference path must be text')
        return action, params

    def submit(self, payload):
        if not isinstance(payload,dict):
            raise ValueError('action object required')
        payload = dict(payload)
        request_id = payload.pop('request_id',None)
        if request_id is not None and (not isinstance(request_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{8,128}',request_id)):
            raise ValueError('invalid request id')
        fingerprint = hashlib.sha256(canonical(payload).encode()).hexdigest()
        with self.condition:
            if request_id in self.receipts:
                old_fp, old_id = self.receipts[request_id]
                if fingerprint != old_fp:
                    raise ValueError('request id was used for different parameters')
                if old_id in self.jobs:
                    return dict(self.jobs[old_id])
                raise ValueError('request receipt expired; inspect existing outputs before retrying')
            if self.closing:
                raise ValueError('console is closing')
            # Only the same request identity is a retry. Distinct requests
            # must retain order, including stop -> start -> stop controls.
            action, params = self._validate(payload)
            if self.closing:
                raise ValueError('console is closing')
            if len(self.pending) >= self.queue_size:
                raise QueueFull('job queue is full; request was not accepted')
            while len(self.jobs) >= MAX_JOBS:
                old = next((key for key,value in self.jobs.items()
                            if value['status'] not in ('queued', 'running')), None)
                if old is None:
                    raise QueueFull('job metadata limit reached')
                del self.jobs[old]
            ident = uuid.uuid4().hex
            job = dict(id=ident, action=action, status='queued', created=utcnow(),
                       started=None, finished=None, result=None)
            self.jobs[ident] = job
            if request_id:
                self.receipts[request_id]=(fingerprint,ident)
                while len(self.receipts)>MAX_JOBS*4:
                    self.receipts.popitem(last=False)
            self.pending.append((ident, action, params))
            self.condition.notify_all()
            return dict(job)

    def jobs_snapshot(self):
        with self.condition:
            return {'jobs': [dict(item) for item in reversed(self.jobs.values())],
                    'queue_capacity': self.queue_size, 'queued': len(self.pending)}

    def control_snapshot(self, *, require_summary=False):
        with self.condition:
            if require_summary and not self._summary_valid:
                raise SummaryUnavailable('committed statistics are unavailable')
            result = dict(watching=self.watching, busy=self.busy,
                        current_job=dict(self.current_job) if self.current_job else None,
                        closing=self.closing, watch_error=self.watch_error,
                        asset_progress=dict(self.asset_progress) if self.asset_progress else None,
                        scope=SCOPE, output_root=str(self.output_root),
                        repository_root=str(self.repository_root), managed_root=str(self.managed_root))
            result.update(summary_valid=self._summary_valid, summary_error=self._summary_error,
                          summary_stale=self.busy)
            if self._summary_valid:
                result.update(self._summary_snapshot)
                result['summary'] = dict(self._summary_snapshot['summary'])
            return result

    def _execute(self, action, params, ident):
        service = self.service
        if action == 'refresh_status':
            # Explicit, authenticated recovery only: no source reads or capture.
            # Publish once; failure must not get an implicit second retry below.
            if not self._refresh_summary():
                raise SummaryUnavailable('committed statistics remain unavailable')
            return {'summary_refreshed': True, 'read_only': True}
        if action in ('sync_wua', 'backup', 'restore', 'compare'):
            self._check_delivery_bindings()
        if action == 'start_watch':
            with self.condition:
                self.watching = True
                self.watch_assets = params.get('assets')
            self._last_full = None
            self._next_watch = time.monotonic()
            return {'watching': True}
        if action == 'stop_watch':
            service.finish_asset_progress('interrupted',reason='watch_stopped_at_safe_boundary')
            with self.condition:
                self.watching = False
            return {'watching': False, 'safe_boundary': True}
        if action == 'capture':
            self._before_capture()
            report = service.capture(force=params.get('full', True),
                assets=params.get('assets', bool(service.config.get('asset_root'))))
            self._after_capture(report)
            return report
        if action == 'verify':
            return service.verify_state()
        if action == 'validate':
            from .validate_current import validate
            target = self.target(params.get('name', 'validate-'+ident[:12]))
            return dict(validate(service, target), output=str(target))
        if action == 'sync_wua':
            from .sync_wua import sync_wua
            return dict(sync_wua(service, self.managed_root, verify=params.get('verify', True)),
                        output=str(self.managed_root))
        if action == 'backup':
            from .backup import backup
            return dict(backup(service, self.repository_root, include_secrets=params.get('include_secrets', False)),
                        requested_name=params.get('name'))
        if action == 'restore':
            from .backup import restore
            return restore(self.repository_root, params['snapshot_id'],
                           self.target(params.get('name', 'restore-'+ident[:12])))
        if action == 'compare':
            from .compare import compare_wua
            reference = params.get('reference', params.get('path'))
            if not reference:
                raise ValueError('a cold reference WUA file is required')
            target = self.target(params.get('name','compare-'+ident[:12]))
            target.mkdir(exist_ok=False)
            # Compare the current catalog, not a silently stale managed cut.
            # This also validates the catalog-instance ownership marker before
            # any managed file is opened. Only our own materialization writes.
            from .sync_wua import sync_wua
            synchronized = sync_wua(self.service, self.managed_root)
            result = compare_wua(self.managed_root/'archive.wua.sqlite', reference, target/'RESULT.json')
            return dict(output=str(target/'RESULT.json'),
                comparison_basis='current_catalog_synchronized',
                synchronized_observations=synchronized['added_observations'],
                raw_native_equal=result['raw_native_without_account_label']['equal'],
                account_label_equal=result['raw_native_with_account_label']['equal'],
                message_fields_equal=result['message_fields_without_account_label']['equal'],
                current_only=result['raw_native_without_account_label']['current_only'],
                reference_only=result['raw_native_without_account_label']['reference_only'],
                phone_completeness=False)
        if action == 'configure_assets':
            from .assets import configure_asset_root
            try:
                return configure_asset_root(service, params['root'],
                    output_roots=(self.output_root, self.repository_root, self.managed_root))
            finally:
                # Recover a journaled partial change before accepting any more
                # jobs, and derive the new reader/source binding on reopen.
                service.close()
                self.service = None
                self.service = self._open()
                self.config = self.service.config
        if action == 'export_asset':
            from .assets import export_asset
            target = self.target(params.get('name', 'asset-'+ident[:12]))
            return dict(export_asset(service, params.get('sha', params.get('hash')), target),output=str(target))
        raise ValueError('unknown action')

    def _worker(self):
        try:
            with writer_lock(self.state):
                self.service = self._open()
                try:
                    self.config = self.service.config
                    from .sync_wua import catalog_identity
                    self._catalog_instance = catalog_identity(self.service)
                    self._check_delivery_bindings()
                    self._owned_output()
                    self._next_watch, self._last_full = 0.0, None
                    if not self._refresh_summary(constructor_cache=True):
                        raise SummaryUnavailable('initial committed statistics are unavailable')
                    self.ready.set()
                    self._loop()
                finally:
                    if self.service is not None:
                        self.service.close()
                        self.service = None
        except BaseException as exc:
            with self.condition:
                if not self.ready.is_set():
                    self.startup_error = type(exc).__name__
                self.watching = False
                self.busy = False
                self.closing = True
                self._summary_valid = False
                self._summary_error = type(exc).__name__
                for ident, _, _ in self.pending:
                    self.jobs[ident].update(status='interrupted', finished=utcnow())
                self.pending.clear()
                self.condition.notify_all()
        finally:
            self.ready.set()

    def _loop(self):
        while True:
            with self.condition:
                while not self.closing and not self.pending and not (
                        self.watching and time.monotonic() >= self._next_watch):
                    wait = max(.01, self._next_watch-time.monotonic()) if self.watching else None
                    self.condition.wait(wait)
                if self.closing:
                    return
                job = self.pending.popleft() if self.pending else None
                self.busy = True
                self.current_job = dict(id=job[0], action=job[1]) if job else dict(id=None, action='watch')
                if job:
                    self.jobs[job[0]].update(status='running', started=utcnow())
            summary_report = None
            epoch_before = self._service_epoch
            succeeded = False
            try:
                if job:
                    ident, action, params = job
                    raw_result = self._execute(action, params, ident)
                    if action == 'capture':
                        summary_report = raw_result
                    if isinstance(raw_result,dict) and isinstance(raw_result.get('assets'),dict):
                        with self.condition:
                            self.asset_progress = _compact_result(raw_result['assets'])
                    result = _compact_result(raw_result)
                    # Share durable/product outcome semantics. In particular,
                    # saved-but-unsupported media must not turn green here after
                    # the journal has correctly marked it as a warning.
                    from .product_journal import warning as result_warning
                    warning = result_warning(raw_result)
                    with self.condition:
                        self.jobs[ident].update(status='warning' if warning else 'completed', result=result, finished=utcnow())
                else:
                    self._before_capture()
                    now = time.monotonic()
                    full = self._last_full is None or now-self._last_full >= self.reconcile_seconds
                    assets = self.watch_assets if self.watch_assets is not None else bool(self.service.config.get('asset_root'))
                    report = self.service.capture(force=full, assets=assets,
                        asset_budget_seconds=2 if assets else None, reuse_identical=True)
                    self._after_capture(report)
                    summary_report = report
                    with self.condition:
                        if isinstance(report.get('assets'),dict):
                            self.asset_progress = _compact_result(report['assets'])
                        self.watch_error = 'partial' if report.get('status') == 'partial' else None
                    if full:
                        self._last_full = now
                succeeded = True
            except Exception as exc:
                summary_report = None  # A failed job may already have committed shards.
                if job:
                    with self.condition:
                        self.jobs[job[0]].update(status='failed', finished=utcnow(),
                            error_type=type(exc).__name__, error=(
                                '独立参照比对尚未就绪；未执行也未判定通过' if isinstance(exc, NotImplementedError)
                                else '可用空间不足，未开始恢复，请选择空间充足的新目标' if isinstance(exc, InsufficientRestoreSpace)
                                else '任务未完成；未将失败标记为通过'))
                else:
                    with self.condition:
                        self.watch_error = type(exc).__name__
                if self.service is None:
                    raise
            finally:
                if not job or job[1] != 'refresh_status':
                    self._refresh_summary(summary_report,
                        constructor_cache=succeeded and epoch_before != self._service_epoch)
                with self.condition:
                    self.busy = False
                    self.current_job = None
                    # Manual work pauses automatic capture in this same worker.
                    if not job or job[1] != 'start_watch':
                        self._next_watch = time.monotonic()+self.interval
                    self.condition.notify_all()

    def _before_capture(self):
        """Optional owned-worker consistency barrier, no-op for the console."""

    def _after_capture(self, report):
        """Optional owned-worker pipeline hook; legacy console stays unchanged."""

    def close(self):
        with self.condition:
            self.closing = True
            self.watching = False
            for ident, _, _ in self.pending:
                self.jobs[ident].update(status='interrupted', finished=utcnow())
            self.pending.clear()
            self.condition.notify_all()
        if threading.current_thread() is not self.thread:
            self.thread.join()


def _readonly(state):
    path = state/'catalog.sqlite'
    _file(path)
    for suffix in ('-wal', '-shm', '-journal'):
        sidecar = Path(str(path)+suffix)
        if os.path.lexists(sidecar):
            _file(sidecar)
    db = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=1)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA query_only=ON')
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA temp_store=MEMORY')
    return db


def _page(query):
    limit, offset = int(query.get('limit', ['50'])[0]), int(query.get('offset', ['0'])[0])
    if not 1 <= limit <= 200 or not 0 <= offset <= 2**63-1:
        raise ValueError('invalid browser pagination')
    return limit, offset


def _errors(report):
    if not isinstance(report, dict):
        return []
    values = report.get('errors', [])
    if not isinstance(values, list):
        return [{'error_type': 'reported_error'}]
    return [{'error_type': value.get('error_type', 'reported_error') if isinstance(value, dict) else 'reported_error'}
            for value in values[:20]]


def read_api(coordinator, path, query):
    if path == '/api/jobs':
        return coordinator.jobs_snapshot()
    if path == '/api/backups':
        from .backup import list_published_snapshots
        repository = coordinator.repository_root
        scope = dict(integrity_scope='manifest_metadata_only', contents_verified=False)
        if not os.path.lexists(repository):
            return dict(snapshots=[], **scope)
        current = coordinator.control_snapshot()['current_job']
        if current and current['action'] == 'backup':
            raise BlockingIOError('snapshot publication is in progress')
        from .backup import SCHEMA, DATABASE
        coordinator._check_bound_directory(repository, SCHEMA,
            {'OWNER.private.json', DATABASE, DATABASE+'-journal', 'repository.lock'})
        return dict(snapshots=[dict(item, id=item['snapshot_id'], include_secrets=item['includes_secrets'])
                              for item in list_published_snapshots(repository)], **scope)
    with closing(_readonly(coordinator.state)) as db:
        db.execute('BEGIN')
        if path == '/api/status':
            row = db.execute('SELECT id,status,finished,report_json FROM cycle ORDER BY rowid DESC LIMIT 1').fetchone()
            last = None
            if row:
                report = json.loads(decode_report(db, row['report_json'])) if row['report_json'] is not None else {}
                errors = report.get('errors',[]) if isinstance(report,dict) else []
                count = len(errors) if isinstance(errors,list) else int(bool(errors))
                last = dict(id=row['id'], status=row['status'], finished=row['finished'], errors=_errors(report),
                            errors_count=count, errors_sample_truncated=count>20, assets=report.get('assets') if isinstance(report,dict) else None)
            control = coordinator.control_snapshot(require_summary=True)
            if row and row['status'] == 'running' and last['assets'] is None:
                last['assets'] = control.get('asset_progress')
            return dict(control, last_cycle=last,
                        cycle_scope='independent_readonly_transaction_not_same_cut_as_summary')
        limit, offset = _page(query)
        if path == '/api/messages':
            q = query.get('q', [''])[0]
            if len(q) > 1000:
                raise ValueError('search text too long')
            if not q:
                total = db.execute('SELECT count(*) FROM head WHERE active=1').fetchone()[0]
                rows=[]
                for ident,text in db.execute('''SELECT v.id,coalesce(i.normalized_json,v.normalized_json)
                    FROM version v JOIN head h INDEXED BY next_head_version ON h.version_id=v.id AND h.active=1
                    LEFT JOIN interpretation_head ih ON ih.version_id=v.id
                    LEFT JOIN interpretation i ON i.version_id=ih.version_id AND i.normalization_hash=ih.normalization_hash
                    ORDER BY v.rowid DESC LIMIT ? OFFSET ?''',(limit,offset)):
                    value=json.loads(text)
                    rows.append(dict(id=ident,**{key:value.get(key) for key in
                        ('conversation_id','sender_id','event_time','body_text','message_type')}))
                return dict(rows=rows,total=total,next_offset=offset+len(rows) if offset+len(rows)<total else None,
                            ordering='latest_archived_observation_first_not_event_time')
            cte = '''WITH latest AS (SELECT v.id,coalesce(i.normalized_json,v.normalized_json) AS n
                FROM head h JOIN version v ON v.id=h.version_id
                LEFT JOIN interpretation_head ih ON ih.version_id=v.id
                LEFT JOIN interpretation i ON i.version_id=ih.version_id AND i.normalization_hash=ih.normalization_hash
                WHERE h.active=1), matches AS (SELECT id,n FROM latest
                WHERE ?='' OR instr(lower(coalesce(json_extract(n,'$.body_text'),'')),lower(?))>0) '''
            total = db.execute(cte+'SELECT count(*) FROM matches', (q,q)).fetchone()[0]
            rows = [dict(row) for row in db.execute(cte+'''SELECT id,
                json_extract(n,'$.conversation_id') AS conversation_id,
                json_extract(n,'$.sender_id') AS sender_id,json_extract(n,'$.event_time') AS event_time,
                json_extract(n,'$.body_text') AS body_text,json_extract(n,'$.message_type') AS message_type
                FROM matches ORDER BY event_time DESC,id LIMIT ? OFFSET ?''', (q,q,limit,offset))]
            return dict(rows=rows, total=total, next_offset=offset+len(rows) if offset+len(rows)<total else None)
        if path == '/api/assets':
            total = db.execute('SELECT count(*) FROM asset').fetchone()[0]
            rows = [dict(row) for row in db.execute('SELECT relative_path,file_sha,bytes FROM asset ORDER BY relative_path LIMIT ? OFFSET ?', (limit,offset))]
            return dict(rows=rows, total=total, next_offset=offset+len(rows) if offset+len(rows)<total else None)
        if path == '/api/reports':
            total = db.execute('SELECT count(*) FROM cycle').fetchone()[0]
            rows = []
            for row in db.execute('SELECT id,mode,status,started,finished,report_json FROM cycle ORDER BY rowid DESC LIMIT ? OFFSET ?', (limit,offset)):
                value = dict(row)
                text = value.pop('report_json')
                report = json.loads(decode_report(db, text)) if text is not None else {}
                errors = report.get('errors', []) if isinstance(report, dict) else []
                value['errors_count'] = len(errors) if isinstance(errors, list) else int(bool(errors))
                rows.append(value)
            return dict(rows=rows, total=total, next_offset=offset+len(rows) if offset+len(rows)<total else None)
    raise KeyError('unknown API')


class ConsoleServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, coordinator, port, *, owns_coordinator=True, handler=None, web_root=None):
        self.coordinator = coordinator
        self.owns_coordinator = owns_coordinator
        self.web_root = WEB if web_root is None else Path(web_root)
        self.token = secrets.token_urlsafe(32)
        super().__init__(('127.0.0.1', port), handler or ConsoleHandler)
        self.base_url = f'http://127.0.0.1:{self.server_port}'

    def server_close(self):
        try:
            super().server_close()
        finally:
            if self.owns_coordinator:
                self.coordinator.close()

    def handle_error(self, request, client_address):
        pass  # Never print request context or exception payloads to HTTP logs.


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


class ConsoleHandler(BaseHTTPRequestHandler):
    server_version = 'CaptureNext'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass  # No URL, chat query, path, token, or request-body HTTP logs.

    def send_error(self, code, message=None, explain=None):
        self._send(code, {'error': 'invalid or unsupported HTTP request'})

    def _send(self, code, body, content_type='application/json; charset=utf-8', nonce=None):
        if not isinstance(body, bytes):
            body = canonical(body).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        scripts = "'self'"+(f" 'nonce-{nonce}'" if nonce else '')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src "+scripts+
            "; style-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _boundary(self):
        hosts = self.headers.get_all('Host', [])
        allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        if len(hosts) != 1 or hosts[0] not in allowed:
            self._send(400, {'error': 'invalid Host'})
            return None
        origins = self.headers.get_all('Origin', [])
        if len(origins)>1 or (origins and origins[0] != 'http://'+hosts[0]):
            self._send(403, {'error': 'untrusted Origin'})
            return None
        try:
            parts = urlsplit(self.path)
            path = unquote(parts.path, errors='strict')
            if parts.scheme or parts.netloc or '\\' in path or '\x00' in path or '..' in path.split('/'):
                raise ValueError('invalid path')
            query = parse_qs(parts.query, keep_blank_values=True, max_num_fields=16)
            if any(len(items) != 1 for items in query.values()):
                raise ValueError('duplicate query parameter')
        except (ValueError, UnicodeError):
            self._send(400, {'error': 'invalid request path'})
            return None
        if path.startswith('/api/'):
            tokens = self.headers.get_all('X-Capture-Token', [])
            if (len(tokens) != 1 or not secrets.compare_digest(tokens[0].encode('utf-8'), self.server.token.encode('ascii'))):
                self._send(403, {'error': 'token required'})
                return None
        if self.command == 'POST' and (not origins or origins[0] != 'http://'+hosts[0]):
            self._send(403, {'error': 'trusted Origin required'})
            return None
        return path, query, hosts[0]

    def do_GET(self):
        checked = self._boundary()
        if checked is None:
            return
        path, query, host = checked
        try:
            if path.startswith('/api/'):
                if set(query)-getattr(self.server,'query_parameters',{'q', 'limit', 'offset'}):
                    raise ValueError('unknown query parameter')
                reader = getattr(self.server, 'read_api', read_api)
                value = reader(self.server.coordinator, path, query)
                from .media_preview import BinaryMedia
                if isinstance(value,BinaryMedia):
                    self._send(200,value.data,value.content_type)
                    return
                self._send(200, value)
                return
            if path in ('/', '/index.html'):
                _file(self.server.web_root/'index.html')
                html = (self.server.web_root/'index.html').read_text(encoding='utf-8')
                bootstrap = canonical(dict(token=self.server.token, base_url='http://'+host,
                    scope=SCOPE, output_root=str(self.server.coordinator.output_root)))
                for old,new in (('&','\\u0026'),('<','\\u003c'),('>','\\u003e'),('\u2028','\\u2028'),('\u2029','\\u2029')):
                    bootstrap = bootstrap.replace(old,new)
                nonce = secrets.token_urlsafe(24)
                script = '<script nonce="'+nonce+'">window.__BOOTSTRAP__='+bootstrap+';</script>'
                if '</head>' not in html:
                    raise ValueError('index needs a head boundary')
                html = html.replace('</head>', script+'</head>', 1)
                self._send(200, html.encode('utf-8'), 'text/html; charset=utf-8', nonce)
                return
            static = {'/app.js': 'text/javascript; charset=utf-8', '/styles.css': 'text/css; charset=utf-8',
                      '/style.css': 'text/css; charset=utf-8'}
            if path not in static:
                raise KeyError('unknown path')
            file = self.server.web_root/path[1:]
            _file(file)
            self._send(200, file.read_bytes(), static[path])
        except (ValueError, TypeError, json.JSONDecodeError):
            self._send(400, {'error': 'invalid request or local metadata'})
        except (KeyError, FileNotFoundError):
            self._send(404, {'error': 'not found'})
        except (OSError, sqlite3.Error):
            self._send(503, {'error': 'local state temporarily unavailable'})
        except Exception:
            self._send(500, {'error': 'local request failed'})

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        checked = self._boundary()
        if checked is None:
            return
        path, query, _ = checked
        if path != '/api/jobs' or query:
            self._send(404, {'error': 'unknown action endpoint'})
            return
        lengths = self.headers.get_all('Content-Length', [])
        if (self.headers.get('Transfer-Encoding') or len(lengths) != 1
                or not re.fullmatch(r'[0-9]{1,10}', lengths[0])):
            self._send(400, {'error': 'one Content-Length is required'})
            return
        length = int(lengths[0])
        if length > MAX_BODY:
            self._send(413, {'error': 'request body too large'})
            return
        if self.headers.get_content_type() != 'application/json':
            self._send(415, {'error': 'JSON content type required'})
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('incomplete body')
            def invalid_constant(_):
                raise ValueError('nonfinite JSON is forbidden')
            payload = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object,
                                 parse_constant=invalid_constant)
            job = self.server.coordinator.submit(payload)
            self._send(202, job)
        except QueueFull:
            self._send(429, {'error': 'queue full; request not accepted; retry later'})
        except (ValueError, TypeError, UnicodeError, FileExistsError):
            self._send(400, {'error': 'invalid job request or output name'})
        except (OSError, sqlite3.Error):
            self._send(503, {'error': 'local state temporarily unavailable'})
        except Exception:
            self._send(500, {'error': 'local request failed'})


def create_server(state, output_root, port=0, *, repository_root=None, managed_root=None, **engine_options):
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError('invalid loopback port')
    coordinator = Coordinator(state, output_root, repository_root=repository_root,
                              managed_root=managed_root, **engine_options)
    try:
        return ConsoleServer(coordinator, port)
    except BaseException:
        coordinator.close()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--repository-root', type=Path)
    parser.add_argument('--managed-root', type=Path)
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args(argv)
    server = create_server(args.state, args.output_root, args.port,
                           repository_root=args.repository_root, managed_root=args.managed_root)
    print(server.base_url, flush=True)  # Session token appears only in the local bootstrap response.
    try:
        server.serve_forever(poll_interval=.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
