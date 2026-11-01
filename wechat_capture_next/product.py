"""Single-writer product core. Desktop and browser are borrowed listeners.

No GUI toolkit here; the owned writer serializes capture, merge and maintenance.
Schedules only enqueue jobs. Deep maintenance pauses acquisition, never truncates
history, and the next capture reconciles the local client afterwards.
"""
from contextlib import contextmanager
from datetime import datetime
import json
import os
from pathlib import Path
import threading
import time

from wechat_capture_v2.common import canonical, utcnow
from . import product_settings as preferences
from .console import Coordinator, _ACTIONS, _parents, _overlap, _file
from .cut_reuse import ExactCut
from .state_guard import writer_lock
from .reader_gate import ReaderGate
from .product_journal import DurableJobs,Journal

PRODUCT_ACTIONS = dict(settings={'value'}, sync_union=set(), deep_verify=set(),
    backup_pair={'include_secrets'}, restore_pair={'snapshot_id','name'},
    import_source={'path','origin'}, export_union={'name'}, webui={'enabled'},
    snapshot_pin={'snapshot_id','enabled'},open_restored={'path'},close_restored=set())
PRODUCT_ACTIONS.update(index_media=set(),prepare_media={'logical_id','snapshot_id','locator','view'})
PRODUCT_ACTIONS.update(prepare_image={'logical_id','sha','expected_md5','view'},load_image_keys={'path'})
PRODUCT_ACTIONS['restore_pair'].add('repository')
PRODUCT_ACTIONS.update(verify_attachment={'logical_id','sha','view','kind'},
    export_attachment={'logical_id','sha','view','kind','name'},
    prepare_attachment={'logical_id','sha','view','kind'})
PRODUCT_ACTIONS['backup_cleanup']=set()
PRODUCT_ACTIONS['export_raw_asset']={'sha','name','view'}


def _asset_outcome(assets):
    """Project one acquisition slice, never infer success from visited files."""
    details={key:assets[key] for key in ('enabled','complete') if type(assets.get(key)) is bool}
    for key in ('files_seen','files_changed','new_versions','bytes_seen','verified_unchanged_files',
                'verified_unchanged_bytes','pending_bytes','pending_processed_bytes'):
        if type(assets.get(key)) is int and assets[key]>=0:details[key]=assets[key]
    if assets.get('pending_phase') in ('store','verify','map','verify_known_source','complete'):
        details['pending_phase']=assets['pending_phase']
    errors=assets.get('errors',[])
    details['errors_count']=len(errors)
    pending=any(key in assets for key in ('pending_phase','pending_bytes','pending_processed_bytes'))
    error_type=None
    if errors:
        status,reason='failed','asset_source_errors'
        first=errors[0].get('error_type') if isinstance(errors[0],dict) else None
        if isinstance(first,str) and first.isascii() and first.isidentifier() and len(first)<=80:
            error_type=first
        next_step='已归档的附件保留；请检查来源可用性，后续采集将重试未完成的扫描。'
    elif assets.get('enabled') is False:
        status,reason='warning','asset_source_not_configured'
        next_step='未配置原始附件来源；已有附件保留，但本轮不代表附件已完成归档。'
    elif assets.get('complete') is True and not pending:
        status,reason,next_step='completed','configured_local_asset_tree_only',None
    else:
        status='warning'
        reason='asset_import_pending' if pending else ('asset_scan_pending' if assets.get('complete') is False
                                                      else 'asset_completion_unconfirmed')
        next_step='本轮附件处理尚未完成；后台将继续处理，若持续待处理请检查来源后重试。'
    return dict(status=status,reason=reason,details=details,error_type=error_type,next_step=next_step)


def _cleanup_outcome(cleanup):
    """Separate accepted backup health from unfinished space maintenance."""
    error=cleanup.get('cleanup_error')
    safe_error=error if isinstance(error,str) and error.isascii() and error.isidentifier() and len(error)<=80 else None
    remaining=any(type(cleanup.get(k)) is int and cleanup[k]>0 for k in
        ('dead_blocks_remaining','freelist_pages_after','freelist_pages','extra_generations'))
    pending=(cleanup.get('cleanup_pending') is not False or bool(error) or remaining or
             any(cleanup.get(k) is True for k in ('reclaim_progress_stalled','expired_snapshot_present','orphan_root_found')))
    reason=('backup_cleanup_error' if error else
            'backup_cleanup_reclaim_stalled' if cleanup.get('reclaim_progress_stalled') else
            'authenticated_noop_cleanup_deferred' if pending and cleanup.get('maintenance_deferred') else
            'backup_cleanup_pending' if pending else 'backup_cleanup_complete')
    return dict(status='warning' if pending else 'completed',reason=reason,details=cleanup,error_type=safe_error,
        retry=dict(action='backup_cleanup') if pending else None,
        next_step='恢复点已保留；可手动整理。本周期不反复自动重试；启用计划备份时，下个成功周期可在闲时续接。' if pending else
                  '备份空间整理完成；成功恢复点保留，原始来源和旧版仓库未改动。')


class ProductCore(DurableJobs,Coordinator):
    managed_pipeline_actions=frozenset(('sync_union','import_source','backup_cleanup'))

    def __init__(self, state, output_root, *, union_root, union_repository,
                 paired_repository=None,provenance_root=None,start_paused=False,active_binding_path=None,**options):
        self.union_root, self.union_repository = map(_parents, (union_root, union_repository))
        self.paired_repository=_parents(paired_repository) if paired_repository is not None else None
        self.provenance_root=_parents(provenance_root) if provenance_root is not None else None
        self.offline_view=None
        from .image_media import ImageCache
        self.image_cache=ImageCache()
        from .attachment_preview import AttachmentCache
        self.attachment_cache=AttachmentCache()
        self.journal=None
        self.identity_status=dict(status='pending',reason='startup_index_not_checked')
        self._identity_retry_after=0
        self.media_status=dict(status='pending',reason='startup_index_not_checked')
        self._media_retry_after=0;self._media_preserved=False
        self.active_binding_path=Path(active_binding_path) if active_binding_path is not None else None
        self.reader_gate = ReaderGate()
        self.maintenance = False
        self.settings_path = Path(output_root)/'settings.private.json'
        self.settings = preferences.load(self.settings_path)
        if start_paused:self.settings=dict(self.settings,auto_capture=False)
        self.union_status = dict(status='pending', reason='startup_recovery', phone_completeness=False)
        self._sync_pending = True
        self.message_recovery_completed = False
        self._backup_reuse, self._verify_reuse = ExactCut(), ExactCut()
        from .pair_readback_memo import PairReadbackMemo
        self._paired_backup_reuse=PairReadbackMemo()
        self._scheduler_stop = threading.Event()
        self._schedule_last = dict(backup_pair=time.time(), deep_verify=time.time())
        self._schedule_jobs = {}
        self.schedule_error = None
        self._schedule_dirty = False
        # Only this process's normally completed scheduled backup may offer
        # one cleanup. Never reconstruct/replay an interrupted cleanup at boot.
        self._cleanup_schedule_candidate = None
        self.endpoint_control = None
        options.setdefault('managed_root',Path(output_root).with_name('compatibility-wua'))
        super().__init__(state, output_root, **options)
        # Core startup has validated state bindings. Validate product locations
        # before allowing either UI to queue any operation.
        try:
            protected = [self.state, self.output_root, self.repository_root,
                         self.managed_root, self.union_root, self.union_repository,
                         _parents(self.config['database_root']).parent]
            if self.config.get('asset_root'):
                protected.append(_parents(self.config['asset_root']))
            owned = protected[:6]
            for extra in (self.paired_repository,self.provenance_root):
                if extra is not None:
                    if any(_overlap(extra,p) for p in protected):raise ValueError('paired/provenance root overlaps protected tree')
                    protected.append(extra)
            for i, first in enumerate(owned):
                if any(_overlap(first, other) for other in owned[i+1:]+protected[6:]):
                    raise ValueError('product roots must be disjoint')
            ledger = self.output_root/'schedule.private.json'
            if ledger.exists():
                _file(ledger)
                value = json.loads(ledger.read_text(encoding='utf-8'))
                if set(value) != set(self._schedule_last) or any(type(v) not in (int,float) or not 0<=v<=time.time()+60 for v in value.values()):
                    raise ValueError('invalid persisted schedule ledger')
                self._schedule_last = value
            else:
                preferences.atomic_json(ledger,self._schedule_last)
            if self.active_binding_path is not None:
                from .recovery_core import mark_binding_initialized
                mark_binding_initialized(self.active_binding_path,state=self.state,
                    union_root=self.union_root,output_root=self.output_root)
            self.submit(dict(action='sync_union'))
            if self.settings['auto_capture']:
                self.submit(dict(action='start_watch'))
            self.scheduler = threading.Thread(target=self._schedule, name='next-scheduler', daemon=True)
            self.scheduler.start()
        except BaseException:
            super().close()
            raise

    def _owned_output(self):
        super()._owned_output()
        self.journal=Journal(self.output_root/'operations.private.json',self)
        if (self.output_root/'media-preview').exists():
            try:
                from .media_preview import _cache,_recover,_prune
                cache=_cache(self.output_root,create=False)
                recovered=_recover(cache,self.service.objects.db);result=_prune(cache,'',self.service.objects.db)
                if recovered or result['removed_derivatives'] or result['cleanup_pending']:
                    self.journal.health(self,'media_cache','warning' if result['cleanup_pending'] else 'completed',
                        reason='preview_only_originals_preserved',details=dict(result,recovered_stages=recovered))
            except Exception as error:
                self.journal.health(self,'media_cache','warning',reason=type(error).__name__)

    def _validate(self, payload):
        action = payload.get('action')
        if action not in PRODUCT_ACTIONS:
            return super()._validate(payload)
        params = {k:v for k,v in payload.items() if k != 'action'}
        if set(params)-PRODUCT_ACTIONS[action]:
            raise ValueError('unknown product parameter')
        if action == 'settings':
            params['value'] = preferences.validate(params.get('value'))
        if action in ('webui', 'backup_pair'):
            key = 'enabled' if action == 'webui' else 'include_secrets'
            if key in params and type(params[key]) is not bool:
                raise ValueError('boolean required')
            if action == 'webui' and key not in params:
                raise ValueError('enabled required')
        if action == 'restore_pair':
            import re
            if not isinstance(params.get('snapshot_id'), str) or not re.fullmatch('[0-9a-f]{64}',params['snapshot_id']):
                raise ValueError('snapshot required')
            if params.get('repository','rolling' if self.paired_repository else 'legacy') not in ('rolling','legacy'):
                raise ValueError('unknown paired repository format')
        if action=='snapshot_pin':
            from .pair_repository import identifier
            identifier(params.get('snapshot_id'))
            if type(params.get('enabled')) is not bool:raise ValueError('pin boolean required')
        if action=='open_restored':
            from .paths import local_absolute
            params['path']=str(local_absolute(params.get('path')))
        if action=='prepare_media':
            from .viewer_media import validate_request
            validate_request(params)
        if action=='prepare_image':
            from .image_media import validate_request
            validate_request(params)
        if action=='load_image_keys':
            from .paths import local_absolute
            params['path']=str(local_absolute(params.get('path')))
        if action in ('verify_attachment','export_attachment','prepare_attachment'):
            from .attachment_actions import validate
            validate(params,export=action=='export_attachment')
        if action=='export_raw_asset':
            from .raw_assets import validate
            validate(params)
        if action in ('restore_pair','export_union') and 'name' in params:
            self.target(params['name'])
        if action == 'import_source':
            from .paths import safe_name, local_absolute
            safe_name(params.get('origin'))
            params['path'] = str(local_absolute(params.get('path')))
        return action, params

    def control_snapshot(self, **options):
        result = super().control_snapshot(**options)
        with self.condition:
            result['product'] = dict(mode='normal',settings=dict(self.settings), union=dict(self.union_status),
                maintenance=self.maintenance, union_root=str(self.union_root),
                schedules=dict(self._schedule_last),
                schedule_error=self.schedule_error,
                message_recovery_completed=self.message_recovery_completed,
                paired_repository=str(self.paired_repository) if self.paired_repository else None,
                offline_view=self.offline_view.summary() if self.offline_view else None,
                identities=dict(self.identity_status),media=dict(self.media_status),pipelines=dict(self.journal.pipelines) if self.journal else {},
                settings_scope='startup registration applied by desktop shell',
                attachment_scope='current and historical CAS retained; native voice association indexed separately; other media association may be unknown')
        return result

    def _sync(self, inputs=()):
        from .union_archive import sync_union
        self._sync_pending = True
        if self.journal:
            with self.condition:self.journal.health(self,'union','running',retry=dict(action='sync_union'),
                next_step='正在整理已采集的消息；未完成时将保留原始采集并重试。')
        try:
            result = sync_union(self.service, self.union_root, inputs=inputs)
            if getattr(self,'config',{}).get('standalone_install') is True:
                from .union_assets import initialize_standalone_assets
                from .compact_archive import CompactArchive
                with writer_lock(self.union_root), CompactArchive(self.union_root/'archive.wua.sqlite') as archive:
                    initialize_standalone_assets(archive,self.service)
            with self.condition:
                self.union_status = dict(status='caught_up', as_of=utcnow(),
                    added_observations=result['current']['added_observations'],
                    stats=result['stats'], phone_completeness=False,
                    attachments_included=False)
            self._sync_pending = False
            if self.journal:
                with self.condition:self.journal.health(self,'union','completed',details=result['stats'])
        except Exception as error:
            self._sync_pending = True
            with self.condition:
                self.union_status = dict(status='pending',reason='capture_retained_sync_retry_required',
                    error_type=type(error).__name__)
                if self.journal:self.journal.health(self,'union','failed',reason='capture_retained_sync_retry_required',
                    error_type=type(error).__name__,retry=dict(action='sync_union'),
                    next_step='已采集原始数据保留；后续采集会重试，也可手动整理联合档案。')
            raise
        # Auxiliary indexes have independent outcomes. They cannot turn a
        # committed message union into a false union failure or success.
        self._sync_names(force=True)
        self._sync_media()
        return result

    def _after_capture(self, report):
        # A previous failed sync MUST retry even when acquisition now is idle.
        # Asset continuations must not rescan all message ID sets. The owned
        # ingestion result reports both new raw versions and interpretations;
        # full reconciliation still provides an independent membership check.
        rows=report.get('databases',[])
        changed=any(r.get('new_versions',0) or r.get('new_interpretations',0) or
                    (r.get('status')=='accepted' and 'new_versions' not in r)
                    for r in rows)
        # Acquisition committed before entering this hook. Record its outcome
        # independently, even if the downstream union/index operation fails.
        if self.journal and report.get('mode')!='metadata_poll':
            with self.condition:
                status='warning' if report.get('errors') else 'completed'
                self.journal.health(self,'capture',status,reason='source_errors' if report.get('errors') else None,
                    details=dict(mode=report.get('mode'),errors_count=len(report.get('errors',[]))))
                if report.get('assets'):
                    self.journal.health(self,'assets',**_asset_outcome(report['assets']))
        joined=self._sync_pending or changed or report.get('mode')=='full_reconciliation'
        if joined:
            self._sync()
        else:
            contacts_changed=any(r.get('relative_path')=='contact/contact.db' and r.get('status')=='accepted' for r in rows)
            if contacts_changed or self.identity_status.get('status')=='pending':
                self._sync_names(force=contacts_changed)
        if not joined and any(r.get('relative_path','').startswith('message/media_') and r.get('status')=='accepted' for r in rows):
            self._sync_media()
        if report.get('mode')=='full_reconciliation' and not report.get('errors'):
            self.message_recovery_completed = True

    def _sync_names(self,*,force=False):
        if not force and self.identity_status.get('status')=='pending' and time.monotonic()<self._identity_retry_after:
            return dict(self.identity_status)
        if self.journal:
            with self.condition:self.journal.health(self,'identities','running',retry=dict(action='sync_union'),
                next_step='正在更新联系人显示名称；原始消息采集不受影响。')
        try:
            from .viewer_identity import sync_names
            result=sync_names(self.service,self.union_root)
            unavailable=result.get('status')=='source_unavailable'
            with self.condition:
                self.identity_status=dict(result,status='source_unavailable' if unavailable else 'ready')
                self._identity_retry_after=0
                if self.journal:self.journal.health(self,'identities','warning' if unavailable else 'completed',
                    reason=result.get('reason') if unavailable else None,details=result,
                    retry=dict(action='sync_union') if unavailable else None,
                    next_step='尚无已接受的联系人数据库；采集到联系人后将自动更新，当前保留消息标识。' if unavailable else None)
            return result
        except Exception as error:
            with self.condition:
                self.identity_status=dict(status='pending',reason=type(error).__name__)
                self._identity_retry_after=time.monotonic()+30
                if self.journal:self.journal.health(self,'identities','failed',reason='contact_index_retry_required',
                    error_type=type(error).__name__,retry=dict(action='sync_union'),
                    next_step='联系人显示名称未更新；消息采集继续，稍后自动重试或手动整理联合档案。')
            return dict(status='failed',reason=type(error).__name__)

    def _sync_media(self,*,strict=False):
        if not strict and self.media_status.get('status')=='pending' and time.monotonic()<self._media_retry_after:
            return dict(self.media_status)
        try:
            from .viewer_media import sync
            result=sync(self.service,self.union_root)
            self.media_status=dict(result,status='ready' if result.get('status')=='completed' else result.get('status'))
            self._media_preserved=True;self._media_retry_after=0
            if self.journal:
                with self.condition:
                    self.journal.health(self,'media_voice','completed' if result.get('status')=='completed' else 'warning',details=result)
                    self.journal.health(self,'media','warning',reason='native_voice_only_other_media_pending',details=result)
            return result
        except Exception as error:
            self.media_status=dict(status='pending',reason=type(error).__name__)
            self._media_retry_after=time.monotonic()+30;self._media_preserved=False
            if self.journal:
                with self.condition:
                    self.journal.health(self,'media_voice','failed',reason=type(error).__name__)
                    self.journal.health(self,'media','warning',reason='native_import_retry_required')
            self._preserve_media_pending()
            if strict:raise
            return dict(status='failed',reason=type(error).__name__)

    def _preserve_media_pending(self):
        from .media_pending import preserve
        from .compact_archive import CompactArchive
        with writer_lock(self.union_root),CompactArchive(self.union_root/'archive.wua.sqlite',readonly=True) as archive:
            result=preserve(archive,self.service)
        self._media_preserved=True
        return result

    def _before_capture(self):
        # On ordinary success this is only an in-memory branch. A failed
        # partially committed native import must retain its exact old cut
        # before acquisition can replace that accepted view. Retry has its own
        # failure backoff; normal message acquisition frequency is unchanged.
        if self.media_status.get('status')=='pending':
            if not self._media_preserved:self._preserve_media_pending()
            if time.monotonic()>=self._media_retry_after:self._sync_media()

    @contextmanager
    def _cold(self):
        with self.condition:
            self.maintenance = True
        try:
            # Drain in-flight DB reads, prevent new ones, keep memory status live.
            with self.reader_gate:
                service = self.service
                self.service = None
                # If close itself fails, keep None: the base worker fails
                # closed rather than accepting jobs on half-closed handles.
                service.close()
                try:
                    yield
                finally:
                    self.service = self._open()  # Failure propagates: fatal, not stale green.
        finally:
            with self.condition:
                self.maintenance = False

    def _cut_files(self, *, repositories=False, include_secrets=False):
        from .union_delivery import _offline
        from .backup import _files
        with _offline(self.state, configuration=True) as offline:
            files = [path for _,path in _files(offline,include_secrets)]
        files += [self.union_root/'archive.wua.sqlite', self.union_root/'OWNER.private.json']
        if repositories:
            for root in (self.repository_root,self.union_repository):
                files += [root/'repository.sqlite',root/'OWNER.private.json']
        return files

    def _execute(self,action,params,ident):
        try:
            return self._run_durable(action,params,ident,self._perform)
        except BaseException as error:
            if action=='backup_pair':
                with self.condition:
                    cleanup=self.journal.pipelines.get('backup_cleanup',{})
                    if (cleanup.get('outcome')=='running' and
                            (cleanup.get('details') or {}).get('backup_job_id')==ident):
                        self.journal.health(self,'backup_cleanup','failed',
                            reason='piggyback_cleanup_completion_unconfirmed',error_type=type(error).__name__,
                            retry=dict(action='backup_cleanup'),
                            next_step='新恢复点已提交；空间整理未确认完成，请检查结果后手动整理。')
            raise

    def _backup_phase(self,ident,phase):
        from .pair_collection import progress_phase
        if phase=='collection_start':
            with self.condition:self.journal.health(self,'backup_cleanup','running',
                reason='accepted_backup_collection_started',details=dict(backup_job_id=ident),
                retry=dict(action='backup_cleanup'),
                next_step='新恢复点已提交，正在认证并整理旧空间；中断后请检查再整理。')
            phase='backup_collection_auth'
        self.job_phase(ident,progress_phase(phase))

    def _perform(self, action, params, ident):
        if action=='export_raw_asset':
            from .raw_assets import perform
            return perform(self,params)
        if action=='backup_cleanup':
            # Managed here so durable-job finalization cannot erase reason,
            # next_step or retry with its generic stage projection.
            with self.condition:self.journal.health(self,'backup_cleanup','running',
                reason='backup_cleanup_requested',next_step='正在核验恢复点并整理备份空间；不会启动采集。')
            try:
                if self.paired_repository is None:raise ValueError('new paired repository not configured')
                from .pair_repository import govern
                self._paired_backup_reuse.reset()
                self.job_phase(ident,'backup_collection')
                with self._cold():
                    result=govern(self.paired_repository,seconds=300,
                        fault=lambda phase,db:self._backup_phase(ident,phase))
            except BaseException as error:
                with self.condition:self.journal.health(self,'backup_cleanup','failed',
                    reason='backup_cleanup_unconfirmed',error_type=type(error).__name__,retry=dict(action='backup_cleanup'),
                    next_step='空间整理未确认完成；已有恢复点保留，请检查结果和可用空间后手动重试。')
                raise
            outcome=_cleanup_outcome(result)
            with self.condition:self.journal.health(self,'backup_cleanup',**outcome)
            return dict(result,status='partial' if outcome['status']=='warning' else 'completed',
                accepted_restore_points_preserved=True,reason=outcome['reason'],
                next_step=outcome['next_step'],retry=outcome['retry'])
        if action in ('verify_attachment','export_attachment','prepare_attachment'):
            from .attachment_actions import perform
            return perform(self,action,params)
        if action=='load_image_keys':
            from .image_media import load_keys
            return load_keys(self.image_cache,params['path'])
        if action=='prepare_image':
            from .compact_archive import CompactArchive
            from .union_archive import cold_reader
            from contextlib import closing
            with self.reader_gate:
                restored=params.get('view','current')=='restored'
                if restored and self.offline_view is None:raise ValueError('open completed offline copy first')
                root=self.offline_view.union if restored else self.union_root
                with CompactArchive(root/'archive.wua.sqlite',readonly=True,immutable=restored) as archive:
                    archive._db.execute('BEGIN');args={k:params[k] for k in ('logical_id','sha','expected_md5')}
                    if restored:
                        with closing(cold_reader(self.offline_view.state/'catalog.sqlite')) as catalog,closing(cold_reader(self.offline_view.state/'objects.sqlite')) as objects:
                            return self.image_cache.prepare(archive,catalog,objects,**args)
                    return self.image_cache.prepare(archive,self.service.catalog.db,self.service.objects.db,**args)
        if action=='index_media':return self._sync_media(strict=True)
        if action=='prepare_media':
            from .media_preview import prepare
            from .compact_archive import CompactArchive
            from .union_archive import cold_reader
            from contextlib import closing
            with self.reader_gate:
                restored=params.get('view','current')=='restored'
                if restored and self.offline_view is None:raise ValueError('open completed offline copy first')
                root=self.offline_view.union if restored else self.union_root
                with CompactArchive(root/'archive.wua.sqlite',readonly=True,immutable=restored) as archive:
                    archive._db.execute('BEGIN')
                    args={k:params[k] for k in ('logical_id','snapshot_id','locator')}
                    if restored:
                        with closing(cold_reader(self.offline_view.state/'objects.sqlite')) as db:
                            return prepare(archive,db,self.output_root,**args)
                    return prepare(archive,self.service.objects.db,self.output_root,**args)
        if action=='start_watch' and self.active_binding_path is not None:
            value=json.loads(self.active_binding_path.read_text(encoding='utf-8'))
            if _parents(value['receipt_root'])/'state'!=self.state:raise ValueError('active binding no longer matches writer')
            value['capture_paused']=False;preferences.atomic_json(self.active_binding_path,value)
        if action=='snapshot_pin':
            from .pair_repository import pin
            if self.paired_repository is None:raise ValueError('new paired repository not configured')
            return pin(self.paired_repository,params['snapshot_id'],params['enabled'])
        if action=='open_restored':
            from .offline_view import OfflineView
            with self.reader_gate:
                reader=OfflineView(params['path'])
                previous,self.offline_view=self.offline_view,reader
                if previous:previous.close()
                return reader.summary()
        if action=='close_restored':
            with self.reader_gate:
                if self.offline_view:self.offline_view.close();self.offline_view=None
            return dict(closed=True,capture_unchanged=True)
        if action == 'settings':
            changed = preferences.save(self.settings_path, params['value'])
            with self.condition:
                self.settings = dict(params['value'])
            return dict(saved=True, changed=changed, applies_to_current_capture=False)
        if action == 'webui':
            if self.endpoint_control is None:
                raise RuntimeError('endpoint controller not ready')
            return self.endpoint_control(params['enabled'])
        if action == 'sync_union':
            return self._sync()
        if action == 'import_source':
            return self._sync([(params['origin'],params['path'])])
        if action in ('deep_verify','backup_pair'):
            # Always drain captured versions first, before closing DB handles.
            self.job_phase(ident,'sync_captured_versions')
            self._sync()
            with self._cold():
                if action == 'deep_verify':
                    from .union_delivery import _offline, _formal
                    from .compact_archive import CompactArchive
                    from .union_assets import verify_union_assets
                    with writer_lock(self.union_root):
                        path,_ = _formal(self.union_root)
                        with _offline(self.state,readonly=False,configuration=True) as service:
                            self.job_phase(ident,'state_deep_verification')
                            state_result = service.verify_state()
                            with CompactArchive(path) as archive:
                                self.job_phase(ident,'union_deep_verification')
                                union_result = archive.integrity_check()
                                self.job_phase(ident,'union_attachment_verification')
                                assets = verify_union_assets(archive,service,deep=True)
                                from .viewer_media import verify as verify_media
                                media=verify_media(archive,service,deep=True)
                        if (union_result.get('quick_check') != ['ok'] or
                                union_result.get('foreign_key_check') or
                                union_result.get('fts_verified') is not True or
                                assets.get('closure_complete') is not True):
                            raise ValueError('deep union/attachment integrity failed')
                        result = dict(pass_all=True,state=state_result,union=union_result,assets=assets,media=media,
                                      deep_verification_executed_now=True)
                        return result
                if self.paired_repository is not None:
                    from .rolling_delivery import backup_owned
                    result=backup_owned(self.state,self.union_root,self.paired_repository,
                        provenance=self.provenance_root,include_secrets=params.get('include_secrets',False),
                        fault=lambda phase,db:self._backup_phase(ident,phase),_memo=self._paired_backup_reuse)
                    cleanup=dict(result.get('governance') or {},backup_job_id=ident)
                    outcome=_cleanup_outcome(cleanup)
                    with self.condition:self.journal.health(self,'backup_cleanup',**outcome)
                    # DurableJobs/Coordinator compact twice; nested governance
                    # is intentionally dropped, but this strict top-level bool
                    # survives and is tied to the final cleanup health job ID.
                    return dict(result,cleanup_pending=outcome['status']!='completed')
                from .union_delivery import backup_owned
                secret = params.get('include_secrets',False)
                files = self._cut_files(repositories=True,include_secrets=secret) if self.repository_root.exists() and self.union_repository.exists() else []
                reused = self._backup_reuse.lookup(files) if files else None
                if reused is not None:
                    return reused
                output = self.target('pair-'+ident[:12])
                result = backup_owned(self.state,self.union_root,self.repository_root,
                    self.union_repository,output,include_secrets=secret)
                from .cut_reuse import seal_backup
                seal_backup(self._backup_reuse,self._cut_files(repositories=True,include_secrets=secret),
                    result,self.state,self.union_root,self.repository_root,self.union_repository)
                return result
        if action == 'restore_pair':
            if params.get('repository','rolling' if self.paired_repository else 'legacy')=='rolling':
                from .rolling_delivery import restore
                if self.paired_repository is None:raise ValueError('new paired repository not configured')
                return restore(self.paired_repository,params['snapshot_id'],
                    self.target(params.get('name','restore-'+ident[:12])))
            from .union_delivery import restore
            return restore(self.repository_root,self.union_repository,params['snapshot_id'],
                self.target(params.get('name','restore-'+ident[:12])))
        if action == 'export_union':
            from .compact_archive import CompactArchive
            target = self.target(params.get('name','export-'+ident[:12]))
            # Full fidelity observations, unknown fields and versions included.
            with self.reader_gate, CompactArchive(self.union_root/'archive.wua.sqlite',readonly=True) as archive:
                archive._db.execute('BEGIN')
                with target.open('x',encoding='utf-8') as stream:
                    stream.write(canonical(dict(kind='manifest',format='next-union-records-jsonl-1',
                        attachments_included=False,standalone_restore_supported=False))+'\n')
                    for table in ('archive_meta','source_device','source_snapshot','message_observation',
                                  'message_link','conflict','dedupe_candidate'):
                        for row in archive._db.execute('SELECT * FROM '+table+' ORDER BY 1'):
                            stream.write(canonical(dict(kind=table,record=dict(row)))+'\n')
                    stream.flush()
                    os.fsync(stream.fileno())
            return dict(output=str(target),format='next-union-records-jsonl-1',attachments_included=False,
                        standalone_restore_supported=False)
        return super()._execute(action, params, ident)

    def _schedule(self):
        while not self._scheduler_stop.wait(30):
            try:
                self._schedule_tick()
                self.schedule_error = None
            except Exception as error:
                # Keep scheduler alive and retry persistence next tick. Never
                # persist exception payloads, paths or configuration values.
                self.schedule_error = type(error).__name__

    def _schedule_tick(self):
        with self.condition:
            if self.closing:
                return
            settings = dict(self.settings)
            jobs = [dict(j) for j in self.jobs.values()]
        changed=False
        # Persist actual completed attempts, not every polling tick. A failed
        # attempt gets a bounded retry interval, not a hot retry loop.
        for action,ident in list(self._schedule_jobs.items()):
            job=next((j for j in jobs if j['id']==ident),None)
            if job and job['status'] not in ('queued','running'):
                self._schedule_last[action]=time.time()
                if (action=='backup_pair' and job['status']=='completed' and
                        (job.get('result') or {}).get('cleanup_pending') is True):
                    self._cleanup_schedule_candidate=ident
                del self._schedule_jobs[action]
                changed=True
        self._schedule_dirty |= changed
        if self._schedule_dirty:
            preferences.atomic_json(self.output_root/'schedule.private.json',self._schedule_last)
            self._schedule_dirty = False
        if not preferences.in_window(datetime.now().hour,settings['heavy_start'],settings['heavy_end']):
            return
        for action,key in (('backup_pair','backup'),('deep_verify','verify')):
            if not settings[key+'_enabled'] or time.time()-self._schedule_last[action] < settings[key+'_hours']*3600:
                continue
            active = any(j['action']==action and j['status'] in ('queued','running') for j in jobs)
            if not active:
                try:
                    request=dict(action=action)
                    if action=='backup_pair':
                        request['include_secrets']=settings['backup_include_secrets']
                    job=self.submit(request)
                except (ValueError,RuntimeError):
                    continue
                self._schedule_jobs[action] = job['id']
        self._maybe_schedule_cleanup()

    def _maybe_schedule_cleanup(self):
        # No repository I/O on ticks: eligibility is the completed planned
        # backup's actual receipt and current health, NOT health timestamps.
        with self.condition:
            ident=self._cleanup_schedule_candidate
            settings=dict(self.settings)
            if self.closing or not ident or not settings['backup_enabled']:
                return
            if not preferences.in_window(datetime.now().hour,settings['heavy_start'],settings['heavy_end']):
                return
            if any(j['status'] in ('queued','running') for j in self.jobs.values()):
                return
            job=(self.journal.records.get(ident) or {}).get('job',{})
            if (job.get('status')!='completed' or
                    (job.get('result') or {}).get('cleanup_pending') is not True or
                    self.journal.pipelines.get('backup_cleanup',{}).get('pending') is not True or
                    (self.journal.pipelines.get('backup_cleanup',{}).get('details') or {}).get('backup_job_id')!=ident):
                self._cleanup_schedule_candidate=None
                return
            # Consume before submission. Even queue/persistence failure gets
            # no per-tick retry. Journal.accept persists this unique receipt
            # before execution; restart never recreates this memory candidate.
            self._cleanup_schedule_candidate=None
            try:
                self.submit(dict(action='backup_cleanup',request_id='scheduled-cleanup-'+ident))
            except Exception as error:
                self.journal.health(self,'backup_cleanup','warning',
                    reason='scheduled_cleanup_submission_unconfirmed',error_type=type(error).__name__,
                    retry=dict(action='backup_cleanup'),
                    next_step='自动整理未提交确认；本周期不自动重试，可手动整理或等待下个正常备份周期。')

    def close(self):
        self._scheduler_stop.set()
        super().close()
        if hasattr(self,'scheduler'):
            self.scheduler.join()
        with self.reader_gate:
            if self.offline_view:self.offline_view.close();self.offline_view=None
            self.image_cache.clear()
            self.attachment_cache.clear()
