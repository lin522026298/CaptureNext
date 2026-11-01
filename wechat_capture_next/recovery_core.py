"""Independent no-key recovery/offline UI core, never a partial live core.

The sole queue here can restore/open copies and prepare an explicit binding
switch after receipt-covered material checks. It never captures, imports keys,
migrates a catalog or logs in; ordinary offline viewing never reads keys.
"""
from collections import OrderedDict,deque
from contextlib import nullcontext,closing,contextmanager
import json
import os
from pathlib import Path
import threading
import uuid
from types import SimpleNamespace

from wechat_capture_v2.common import utcnow,write_json_new
from .backup import _parents,_file,_overlap
from .console import Coordinator,_compact_result,_name
from .offline_view import OfflineView
from .product_settings import DEFAULTS,atomic_json
from .reader_gate import ReaderGate
from .state_guard import writer_lock
from .product_journal import DurableJobs,Journal,warning

SCHEMA='next-active-recovered-binding-1'


@contextmanager
def binding_lock(base):
    root=_parents(base)/'binding-control'
    root.mkdir(parents=True,exist_ok=True)
    with writer_lock(root):yield


def _binding_value(base):
    path=base/'active-binding.private.json'
    if not os.path.lexists(path):return None
    _file(path);value=json.loads(path.read_text(encoding='utf-8'))
    required={'schema','receipt_root','output','snapshot_id','capture_paused','catalog_instance','union_id'}
    if (not isinstance(value,dict) or not required.issubset(value) or set(value)-required-{'initialized'} or
        value['schema']!=SCHEMA or type(value['capture_paused']) is not bool or type(value.get('initialized',False)) is not bool):
        raise ValueError('invalid active binding; original state left untouched')
    receipt=_parents(value['receipt_root']);output=_parents(value['output'])
    if output.parent!=base/'product-sessions' or len(output.name)!=32 or any(c not in '0123456789abcdef' for c in output.name):
        raise ValueError('active output outside dedicated session scope')
    return value


def _active_identity(value):
    # Even paused startup can recover catalog bookkeeping and refresh indexes;
    # once initialized it is a formal mutable state, not an immutable viewer.
    from .union_delivery import _formal,_state_owner
    from .union_archive import cold_input,cold_reader
    receipt=_parents(value['receipt_root'])
    marker=receipt/'DELIVERY.complete.private.json';_file(marker)
    with cold_input(marker):
        if json.loads(marker.read_text(encoding='utf-8')).get('snapshot_id')!=value['snapshot_id']:
            raise ValueError('active restore marker differs')
    _,owner=_formal(receipt/'union')
    if owner['catalog_instance']!=value['catalog_instance']:raise ValueError('active catalog identity differs')
    _state_owner(receipt/'state',owner)
    with cold_input(receipt/'union/archive.wua.sqlite'),closing(cold_reader(receipt/'union/archive.wua.sqlite')) as db:
        row=db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()
        if row is None or row[0]!=value['union_id']:raise ValueError('active union identity differs')
    from .recovery_materials import inspect,verified_provenance_root
    if not inspect(SimpleNamespace(root=receipt,state=receipt/'state',union=receipt/'union'))['takeover_materials_ready']:
        raise ValueError('active recovered binding lacks receipt-covered capture materials; use offline recovery')
    return verified_provenance_root(receipt,value['snapshot_id'])


def mark_binding_initialized(path, *, state, union_root, output_root):
    """Called only after successful ProductCore startup, under its writer lock.

    The host owns binding_lock during constructor setup. Failed initial startup
    intentionally never marks the copy initialized; a fresh restore is required
    if its exact prepared bytes no longer match. This never resumes capture.
    """
    path=Path(path);base=_parents(path.parent)
    if path!=base/'active-binding.private.json':raise ValueError('unexpected active binding marker')
    value=_binding_value(base)
    if value is None:raise ValueError('active binding disappeared during startup')
    receipt=_parents(value['receipt_root'])
    if (receipt/'state'!=_parents(state) or receipt/'union'!=_parents(union_root) or
        _parents(value['output'])!=_parents(output_root)):
        raise ValueError('initialized core differs from prepared recovered binding')
    # The caller already owns the live state's writer lock. Cold/immutable
    # readers are forbidden here: constructor bookkeeping may be in its WAL.
    # Normal read-only SQLite sees the committed startup identities correctly.
    from .backup import _readonly
    with closing(_readonly(receipt/'state/catalog.sqlite',immutable=False)) as db:
        row=db.execute("SELECT value FROM meta WHERE key='next_catalog_instance'").fetchone()
        if row is None or row[0]!=value['catalog_instance']:
            raise ValueError('initialized catalog differs from prepared binding')
    with closing(_readonly(receipt/'union/archive.wua.sqlite',immutable=False)) as db:
        row=db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()
        if row is None or row[0]!=value['union_id']:
            raise ValueError('initialized union differs from prepared binding')
    marker=receipt/'DELIVERY.complete.private.json';_file(marker)
    if json.loads(marker.read_text(encoding='utf-8')).get('snapshot_id')!=value['snapshot_id']:
        raise ValueError('initialized restore marker differs')
    atomic_json(path,dict(value,initialized=True))


def active_binding(base):
    value=_binding_value(base)
    if value is None:return None
    path=base/'active-binding.private.json'
    receipt=_parents(value['receipt_root']);output=_parents(value['output'])
    if value['capture_paused'] and not value.get('initialized',False):
        with_view=OfflineView(receipt)
        try:
            if (with_view.snapshot!=value['snapshot_id'] or with_view.catalog_instance!=value['catalog_instance'] or
                with_view.union_id!=value['union_id']):raise ValueError('binding restore identity changed')
            from .recovery_materials import inspect
            if not inspect(with_view)['takeover_materials_ready']:
                raise ValueError('active recovered binding lacks receipt-covered capture materials; use offline recovery')
            from .recovery_materials import verified_provenance_root
            provenance = verified_provenance_root(receipt,value['snapshot_id'])
        finally:with_view.close()
    else:
        provenance = _active_identity(value)
    result = dict(state=receipt/'state',union_root=receipt/'union',output_root=output,
        start_paused=value['capture_paused'],active_binding_path=path)
    if provenance is not None:result['provenance_root'] = provenance
    return result


class RecoveryCore(DurableJobs):
    capture_capable=False

    def __init__(self,base,*,state,union_root,union_repository,repository_root,paired_repository,reason='offline_requested',offline=None):
        self.base=_parents(base);self.state=_parents(state);self.union_root=_parents(union_root)
        self.union_repository=_parents(union_repository);self.repository_root=_parents(repository_root)
        self.paired_repository=_parents(paired_repository);self.reason=reason
        self.output_root=self.base/'product-recovery';self.managed_root=self.output_root/'unused-managed'
        if any(_overlap(self.output_root,p) for p in (self.state,self.union_root,self.repository_root,self.union_repository,self.paired_repository)):
            raise ValueError('recovery runtime overlaps protected data')
        owner=dict(schema='next-recovery-ui-1',base=str(self.base))
        if self.output_root.exists():
            _file(self.output_root/'OWNER.private.json')
            if json.loads((self.output_root/'OWNER.private.json').read_text(encoding='utf-8'))!=owner:raise ValueError('foreign recovery runtime')
        else:self.output_root.mkdir(parents=True);write_json_new(self.output_root/'OWNER.private.json',owner)
        self.settings=dict(DEFAULTS,auto_capture=False,launch_at_login=False,backup_enabled=False,verify_enabled=False)
        self.reader_gate=ReaderGate();self.offline_view=None;self.endpoint_control=None
        from .image_media import ImageCache
        self.image_cache=ImageCache()
        from .attachment_preview import AttachmentCache
        self.attachment_cache=AttachmentCache()
        self.condition=threading.Condition();self.pending=deque();self.jobs=OrderedDict();self.receipts=OrderedDict()
        self.queue_size=8;self.closing=False;self.busy=False;self.current_job=None;self.maintenance=False
        self.journal=None
        self.ready=threading.Event();self.startup_error=None;self.initial_offline_job=None
        self.thread=threading.Thread(target=self._worker,name='next-recovery-queue',daemon=True);self.thread.start();self.ready.wait()
        if self.startup_error:
            self.close();raise RuntimeError('recovery queue unavailable')
        if offline is not None:
            # Bootstrap must not wait for a potentially very large immutable
            # bundle to be authenticated. The existing durable queue owns the
            # exact same complete verification, including failure receipts.
            try:
                self.initial_offline_job=self.submit(dict(action='open_restored',path=str(offline)))['id']
            except BaseException:
                self.close();raise

    def _validate(self,payload):
        if not isinstance(payload,dict):raise ValueError('job object required')
        action=payload.get('action');params={k:v for k,v in payload.items() if k!='action'}
        allowed=dict(open_restored={'path'},close_restored=set(),webui={'enabled'},
            restore_pair={'snapshot_id','name','repository'},promote_restore={'path','confirm'},prepare_media={'logical_id','snapshot_id','locator','view'},
            prepare_image={'logical_id','sha','expected_md5','view'},load_image_keys={'path'},
            prepare_attachment={'logical_id','sha','view','kind'},
            verify_attachment={'logical_id','sha','view','kind'},export_attachment={'logical_id','sha','view','kind','name'},
            export_raw_asset={'sha','name','view'})
        if action not in allowed or set(params)-allowed[action]:raise ValueError('action unavailable in no-key recovery mode')
        if action in ('open_restored','promote_restore'):params['path']=str(_parents(params.get('path')))
        if action=='promote_restore' and params.get('confirm')!='USE_VERIFIED_COPY':raise ValueError('explicit recovered-copy switch confirmation required')
        if action=='webui' and type(params.get('enabled')) is not bool:raise ValueError('boolean required')
        if action=='prepare_media':
            from .viewer_media import validate_request
            validate_request(params)
            if params.get('view')!='restored':raise ValueError('offline media view required')
        if action=='prepare_image':
            from .image_media import validate_request
            validate_request(params)
            if params.get('view')!='restored':raise ValueError('offline image view required')
        if action=='load_image_keys':
            from .paths import local_absolute
            params['path']=str(local_absolute(params.get('path')))
        if action in ('verify_attachment','export_attachment','prepare_attachment'):
            from .attachment_actions import validate
            validate(params,export=action=='export_attachment')
            if params.get('view')!='restored':raise ValueError('offline attachment view required')
        if action=='export_raw_asset':
            from .raw_assets import validate
            validate(params)
            if params.get('view')!='restored':raise ValueError('offline original view required')
        if action=='restore_pair':
            from .pair_repository import identifier
            identifier(params.get('snapshot_id'));_name(params.get('name'))
            if params.get('repository','rolling') not in ('rolling','legacy'):raise ValueError('unknown repository format')
        return action,params

    def control_snapshot(self,**options):
        from .recovery_materials import requirements
        with self.condition:
            opened=next((job for job in reversed(self.jobs.values()) if job['action']=='open_restored'),None)
            offline_job=None
            if opened:
                record=self.journal.records.get(opened['id']) if self.journal else None
                offline_job={key:opened.get(key) for key in ('id','status','error_type')}
                offline_job['phase']=record['job'].get('phase') if record else opened['status']
            return dict(watching=False,busy=self.busy,current_job=self.current_job,closing=self.closing,
                watch_error=None,summary_valid=False,scope='offline_recovery_no_capture',output_root=str(self.output_root),
                product=dict(mode='recovery',reason=self.reason,settings=dict(self.settings),maintenance=self.maintenance,
                    union=dict(status='unavailable',reason='explicit_offline_copy_required'),schedule_error=None,
                    message_recovery_completed=False,offline_view=self.offline_view.summary() if self.offline_view else None,
                    offline_loading=bool(opened and opened['status'] in ('queued','running')),
                    offline_initial_job=self.initial_offline_job,offline_open_job=offline_job,
                    takeover=requirements(),
                    pipelines=dict(self.journal.pipelines) if self.journal else {},
                    capabilities=['open_restored','close_restored','restore_pair','webui','promote_restore']))

    def _execute(self,action,params,ident):
        if action=='export_raw_asset':
            from .raw_assets import perform
            return perform(self,params)
        if action in ('verify_attachment','export_attachment','prepare_attachment'):
            from .attachment_actions import perform
            return perform(self,action,params)
        if action=='load_image_keys':
            from .image_media import load_keys
            return load_keys(self.image_cache,Path(params['path']))
        if action=='prepare_image':
            from .compact_archive import CompactArchive
            from .union_archive import cold_reader
            with self.reader_gate:
                if self.offline_view is None:raise ValueError('open completed offline copy first')
                with CompactArchive(self.offline_view.union/'archive.wua.sqlite',readonly=True,immutable=True) as archive,\
                     closing(cold_reader(self.offline_view.state/'objects.sqlite')) as objects,\
                     closing(cold_reader(self.offline_view.state/'catalog.sqlite')) as catalog:
                    archive._db.execute('BEGIN')
                    return self.image_cache.prepare(archive,catalog,objects,**{k:params[k] for k in ('logical_id','sha','expected_md5')})
        if action=='prepare_media':
            from .media_preview import prepare
            from .compact_archive import CompactArchive
            from .union_archive import cold_reader
            with self.reader_gate:
                if self.offline_view is None:raise ValueError('open completed offline copy first')
                with CompactArchive(self.offline_view.union/'archive.wua.sqlite',readonly=True,immutable=True) as archive,\
                     closing(cold_reader(self.offline_view.state/'objects.sqlite')) as objects:
                    archive._db.execute('BEGIN')
                    return prepare(archive,objects,self.output_root,**{k:params[k] for k in ('logical_id','snapshot_id','locator')})
        if action=='webui':return self.endpoint_control(params['enabled'])
        if action in ('open_restored','close_restored'):
            with self.reader_gate:
                if action=='close_restored':
                    if self.offline_view:self.offline_view.close();self.offline_view=None
                    return dict(closed=True)
                self.job_phase(ident,'offline_authentication')
                reader=OfflineView(params['path']);old,self.offline_view=self.offline_view,reader
                if old:old.close()
                return reader.summary()
        if action=='promote_restore':
            reader=OfflineView(params['path'])
            try:
                if _overlap(reader.state,self.state) or _overlap(reader.union,self.union_root):raise ValueError('fresh recovered copy required')
                from .recovery_materials import inspect
                materials=inspect(reader,authenticate_source=True)
                if not materials['takeover_materials_ready']:return materials
                # A competing collector must prevent takeover preparation, even
                # when the current state's startup failed for a lock conflict.
                with binding_lock(self.base):
                    current=active_binding(self.base)
                    state=current['state'] if current else self.state
                    union=current['union_root'] if current else self.union_root
                    if _overlap(reader.state,state) or _overlap(reader.union,union):raise ValueError('fresh recovered copy required')
                    with writer_lock(state) if state.exists() else nullcontext():
                        return dict(materials,**self._publish_binding(reader,ident))
            finally:reader.close()
        if action=='restore_pair':
            target=self.output_root/_name(params['name'])
            if target.exists():raise FileExistsError('fresh restore target required')
            if params.get('repository','rolling')=='rolling':
                from .rolling_delivery import restore
                return restore(self.paired_repository,params['snapshot_id'],target)
            from .union_delivery import restore
            return restore(self.repository_root,self.union_repository,params['snapshot_id'],target)
        raise ValueError('unknown recovery job')

    def _publish_binding(self,reader,ident):
        value=dict(schema=SCHEMA,receipt_root=str(reader.root),snapshot_id=reader.snapshot,capture_paused=True,
            output=str(self.base/'product-sessions'/uuid.uuid4().hex),catalog_instance=reader.catalog_instance,union_id=reader.union_id,
            initialized=False)
        binding=self.base/'active-binding.private.json';previous=None
        if binding.exists():_file(binding);previous=json.loads(binding.read_text(encoding='utf-8'))
        write_json_new(self.output_root/('binding-'+ident+'.private.json'),dict(previous=previous,next=value))
        atomic_json(binding,value)
        return dict(binding_prepared=True,restart_required=True,capture_paused=True,old_state_preserved=True,
            login_started=False,receipt_root=str(reader.root))

    def _worker(self):
        try:
            with writer_lock(self.output_root):
                self.journal=Journal(self.output_root/'operations.private.json',self)
                self.ready.set()
                while True:
                    with self.condition:
                        while not self.closing and not self.pending:self.condition.wait()
                        if self.closing:return
                        ident,action,params=self.pending.popleft();self.busy=True
                        self.current_job=dict(id=ident,action=action)
                        self.jobs[ident].update(status='running',started=utcnow())
                    try:
                        result=self._run_durable(action,params,ident,self._execute)
                        with self.condition:self.jobs[ident].update(status='warning' if warning(result) else 'completed',result=_compact_result(result),finished=utcnow())
                    except Exception as exc:
                        with self.condition:self.jobs[ident].update(status='failed',error_type=type(exc).__name__,
                            error='恢复任务未完成；原状态未覆盖，请检查副本和可用空间后重试',finished=utcnow())
                    finally:
                        with self.condition:self.busy=False;self.current_job=None
        except BaseException as exc:self.startup_error=type(exc).__name__
        finally:self.ready.set()

    def close(self):
        with self.condition:
            self.closing=True;self.condition.notify_all()
        if hasattr(self,'thread') and threading.current_thread() is not self.thread:self.thread.join()
        with self.reader_gate:
            if self.offline_view:self.offline_view.close();self.offline_view=None
            self.image_cache.clear()
            self.attachment_cache.clear()
