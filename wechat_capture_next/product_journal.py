"""Bounded durable job receipts, no polling snapshots or automatic job replay."""
from collections import deque
import json
import re

from wechat_capture_v2.common import canonical,utcnow
from .console import Coordinator,_compact_result,_file
from .product_settings import atomic_json

SCHEMA='next-product-task-receipts-1'
FINAL={'completed','warning','failed','interrupted_unconfirmed','interrupted'}
STAGES=dict(capture='capture',sync_union='union',import_source='union',backup_pair='backup',
    deep_verify='deep_verify',index_media='media_voice',restore_pair='restore',backup_cleanup='backup_cleanup')


def warning(value):
    return isinstance(value,dict) and (value.get('pass') is False or value.get('pass_all') is False or
        any(value.get(k) is False for k in ('raw_native_equal','account_label_equal','message_fields_equal')) or
        value.get('status') in ('partial','interrupted','local_complete_assets_pending','saved_unsupported','source_unavailable','file_missing'))


class Journal:
    def __init__(self,path,core):
        self.path=path;self.records={};self.pipelines={}
        if path.exists():
            changed=False
            _file(path);value=json.loads(path.read_text(encoding='utf-8'))
            if (set(value)!={'schema','jobs','receipts','pipelines'} or value['schema']!=SCHEMA or
                not isinstance(value['jobs'],list) or len(value['jobs'])>100 or
                not isinstance(value['receipts'],list) or len(value['receipts'])>400 or not isinstance(value['pipelines'],dict)):
                raise ValueError('invalid durable task journal; preserved for recovery')
            self.pipelines=value['pipelines']
            for record in value['jobs']:
                job=record['job'];params=record['params'];ident=job['id']
                if (not re.fullmatch('[0-9a-f]{32}',ident) or ident in self.records or not isinstance(params,dict) or
                    len(canonical(record).encode())>65536 or job['status'] not in FINAL|{'queued','running'}):
                    raise ValueError('invalid durable task entry')
                if job['status'] in ('queued','running'):
                    changed=True
                    job.update(status='interrupted_unconfirmed',finished=utcnow(),
                        error='上次运行未确认完成；请先检查已有结果，再手动重试。未自动重复执行。')
                    stage=STAGES.get(job.get('action'))
                    if stage:
                        self.pipelines[stage]=dict(self.pipelines.get(stage,{}),outcome='interrupted_unconfirmed',
                            last_attempt=job['finished'],reason='previous_process_completion_unconfirmed',pending=True,
                            error_type=None,next_step='上次处理未确认完成；请检查结果后手动重试。')
                    if job.get('action')=='backup_pair':
                        # Journal and repository acceptance are not one atomic
                        # write. A queued/running backup cannot certify that
                        # cleanup is still green, even before collection_start.
                        previous=self.pipelines.get('backup_cleanup',{})
                        cleanup=dict(previous)
                        if previous.get('last_success') and 'last_success_details' not in cleanup:
                            cleanup['last_success_details']=(_compact_result(previous['details'])
                                if isinstance(previous.get('details'),dict) else None)
                        self.pipelines['backup_cleanup']=dict(cleanup,outcome='interrupted_unconfirmed',
                            last_attempt=job['finished'],reason='backup_or_cleanup_completion_unconfirmed',
                            pending=True,error_type=None,retry=dict(action='backup_cleanup'),
                            details=dict(backup_job_id=ident,backup_completion_unconfirmed=True,
                                         cleanup_completion_unconfirmed=True),
                            next_step='上次备份或空间整理未确认完成；请先检查恢复点和结果，再按需手动核验或整理。未自动重放。')
                self.records[ident]=record;core.jobs[ident]=dict(job)
            for key,fingerprint,ident in value['receipts']:
                if not re.fullmatch('[A-Za-z0-9_-]{8,128}',key) or not re.fullmatch('[0-9a-f]{64}',fingerprint):
                    raise ValueError('invalid durable request receipt')
                core.receipts[key]=(fingerprint,ident)
            # Automatic stages have no queued job to recover. A process that
            # stopped during one must not leave a durable green/running badge.
            for stage,value in self.pipelines.items():
                if value.get('outcome')=='running':
                    self.pipelines[stage]=dict(value,outcome='interrupted_unconfirmed',pending=True,
                        reason='previous_process_completion_unconfirmed',error_type=None,
                        next_step='上次处理未确认完成；请检查结果后重试。')
                    changed=True
            if changed:self.save(core)

    def save(self,core):
        atomic_json(self.path,dict(schema=SCHEMA,jobs=list(self.records.values())[-100:],
            receipts=[[key,*value] for key,value in list(core.receipts.items())[-400:]],pipelines=self.pipelines))

    def accept(self,core,job,params):
        retained={ident:record for ident,record in self.records.items() if ident in core.jobs}
        retained[job['id']]=dict(job=dict(job),params=params)
        previous=self.records;self.records=retained
        try:self.save(core)
        except BaseException:self.records=previous;raise

    def transition(self,core,ident,**changes):
        record=self.records[ident];old=record['job'];record['job']=dict(old,**changes)
        try:self.save(core)
        except BaseException:record['job']=old;raise

    def health(self,core,stage,status,*,reason=None,details=None,error_type=None,retry=None,next_step=None):
        previous=self.pipelines.get(stage,{})
        value=dict(previous,last_attempt=utcnow(),outcome=status,reason=reason,
            pending=status!='completed',error_type=error_type,retry=retry,next_step=next_step,
            details=_compact_result(details) if details is not None else None)
        if previous.get('last_success') and 'last_success_details' not in value:
            value['last_success_details']=_compact_result(previous['details']) if isinstance(previous.get('details'),dict) else None
        if status=='completed':
            value['last_success']=value['last_attempt']
            value['last_success_details']=value['details']
        self.pipelines[stage]=value
        try:self.save(core)
        except BaseException:
            if previous:self.pipelines[stage]=previous
            else:self.pipelines.pop(stage,None)
            raise


class DurableJobs:
    capture_capable=True

    def job_phase(self,ident,phase):
        # Persist transitions, never a periodic progress snapshot.
        with self.condition:
            record=self.journal.records.get(ident)
            if record and record['job'].get('phase')!=phase:
                self.journal.transition(self,ident,phase=phase)

    def submit(self,payload):
        with self.condition:
            previous=set(self.jobs);job=Coordinator.submit(self,payload)
            if self.journal is not None and job['id'] not in previous:
                params={k:v for k,v in payload.items() if k not in ('action','request_id')}
                try:self.journal.accept(self,job,params)
                except BaseException:
                    self.pending=deque(item for item in self.pending if item[0]!=job['id'])
                    self.jobs.pop(job['id'],None)
                    for key,value in list(self.receipts.items()):
                        if value[1]==job['id']:del self.receipts[key]
                    raise
            return job

    def _run_durable(self,action,params,ident,perform):
        with self.condition:
            self.journal.transition(self,ident,status='running',started=utcnow(),phase=action,
                blocks_capture=self.capture_capable)
            stage=STAGES.get(action)
            # Some stages also run automatically, outside explicit jobs. Their
            # owned implementation records the exact operation boundary once.
            if action in getattr(self,'managed_pipeline_actions',()):stage=None
            if stage:self.journal.health(self,stage,'running')
        try:
            result=perform(action,params,ident);status='warning' if warning(result) else 'completed'
            with self.condition:
                self.journal.transition(self,ident,status=status,result=_compact_result(result),finished=utcnow(),phase='finished')
                if stage:self.journal.health(self,stage,status,details=_compact_result(result))
            return result
        except BaseException as error:
            with self.condition:
                self.journal.transition(self,ident,status='failed',error_type=type(error).__name__,finished=utcnow(),
                    phase='failed',error='任务未确认完成；已提交的数据保留，请检查结果后重试。')
                if stage:self.journal.health(self,stage,'failed',reason=type(error).__name__)
            raise

    def jobs_snapshot(self):
        value=Coordinator.jobs_snapshot(self)
        with self.condition:
            for job in value['jobs']:
                record=self.journal.records.get(job['id']) if self.journal else None
                if record:
                    if job['status'] in ('failed','interrupted_unconfirmed','interrupted','warning'):
                        job['retry']=dict(action=job['action'],**record['params'])
                    job['phase']=record['job'].get('phase',job['status'])
                    job['blocks_capture']=record['job'].get('blocks_capture',False)
        return value
