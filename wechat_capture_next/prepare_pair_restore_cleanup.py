"""Prepare a PRIVATE, point-in-time retirement plan; NEVER delete anything.

Only the three named task-owned paired expansions are accepted. Every plan
authenticates retained snapshot payloads and hashes the expansion in both the
semantic read-guard phase and the final exclusive-handle access-probe phase.
It is NOT deletion authority: a human must review and revalidate dependencies,
inventory and hashes before a separate literal-path native cleanup operation.
No archive writer lock, capture service, key loader or cleanup API is used.
"""
import argparse
import ctypes
from ctypes import wintypes
from contextlib import ExitStack
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time

import psutil

from wechat_capture_v2.common import canonical, digest_file, utcnow, write_json_new
from . import pair_repository as repo
from .paths import local_absolute
from .storage_ledger import inventory
from .union_archive import cold_input

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKING_ROOT = PROJECT_ROOT/'working'/'wechat_product_20261022'
ALLOWED_NAMES = frozenset(('paired-current-restored-4k', 'paired-A16-restored', 'paired-B16-restored'))
SCHEMA = 'next-paired-restore-cleanup-plan-1'
GENERATED = frozenset(('DELIVERY.complete.private.json', 'DELIVERY.partial.private.json',
    'state/RESTORE.complete.private.json', 'state/writer.lock', 'union/writer.lock'))
_DENIED = object()
LIFECYCLE_SCHEMA = 'next-cleanup-task-lifecycle-1'
_TASK_EXECUTABLES = frozenset(('capturenext.exe', 'capturenextcore.exe'))
REQUIRED_CONTEXT_FIELDS = frozenset(('asset_binding','includes_secrets','integrity','origin_state',
    'origin_union','protected_roots','provenance_included','source_roots'))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        repo.require(key not in result, 'duplicate JSON key in cleanup evidence')
        result[key] = value
    return result


def _json(path):
    repo.legacy._file(path)
    repo.require(path.stat().st_size <= 32*1024**2, 'oversized cleanup receipt')
    value = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite receipt value')))
    repo.require(isinstance(value, dict), 'receipt object required')
    return value


def _dependencies(root, *, task_pids=()):
    """Only selected task processes have command/cwd text requested.

    Global enumeration requests pid/name/exe/ppid metadata only. Project-local
    executables, recognizable task names, explicitly declared lifecycle PIDs
    and provable descendants form the task set. All other processes remain
    unclassified, without reading their command contents. This cannot discover
    arbitrary anonymous interpreters' global or future logical dependencies.
    """
    ignored = {os.getpid(), *(p.pid for p in psutil.Process().parents())}
    if os.name == 'nt':
        ignored.update((0, 4))
    matches=[];unknown=[];records={};selected=set(task_pids)
    declared=task_pids if isinstance(task_pids,dict) else {}
    project=str(PROJECT_ROOT).replace('\\','/').casefold().rstrip('/')+'/'
    try:
        for process in psutil.process_iter(['pid','name','exe','ppid'],ad_value=_DENIED):
            try:
                info=process.info;records[process.pid]=(process,info)
                if process.pid in declared:
                    expected=declared[process.pid];current=process.create_time()
                    repo.require(expected is not None,'declared task PID appeared without creation identity; preserve expansion')
                    repo.require(current>=expected,'declared task PID identity cannot be confirmed; preserve expansion')
                    if current!=expected:selected.discard(process.pid)
                exe=info.get('exe')
                if ((isinstance(exe,str) and exe.replace('\\','/').casefold().startswith(project)) or
                        str(info.get('name','')).casefold() in _TASK_EXECUTABLES):
                    selected.add(process.pid)
                if any(info.get(k) is _DENIED for k in ('name','exe','ppid')):unknown.append(process.pid)
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied:
                if process.pid in selected:raise ValueError('known/task metadata unavailable; preserve expansion')
                unknown.append(process.pid)
    except psutil.AccessDenied as error:
        raise ValueError('limited process census unavailable; preserve expansion') from error
    # A PPID alone may have been reused. Confirm parent/child creation order
    # before selecting descendants; this still requests no command contents.
    creation={}
    def created(pid):
        if pid not in creation:creation[pid]=records[pid][0].create_time()
        return creation[pid]
    while True:
        children=set()
        for pid,(process,info) in records.items():
            parent=info.get('ppid')
            if pid in selected or type(parent) is not int or parent not in selected or parent not in records:continue
            try:
                if created(pid)>=created(parent):children.add(pid)
            except psutil.NoSuchProcess:continue
            except (psutil.AccessDenied,OSError) as error:
                raise ValueError('possible task descendant identity unavailable; preserve expansion') from error
        expanded=selected|children
        if expanded==selected:break
        selected=expanded
    inspected=[];unclassified=[]
    token=str(root).replace('\\','/').casefold()
    for pid,(process,info) in records.items():
        if pid in ignored:continue
        if pid not in selected:
            unclassified.append(pid);continue
        try:
            repo.require(isinstance(info.get('name'),str) and info['name'] and
                isinstance(info.get('exe'),str) and info['exe'] and type(info.get('ppid')) is int,
                'known/task metadata unavailable; preserve expansion')
            command=process.cmdline();cwd=process.cwd()
            repo.require(isinstance(command,list) and command and all(isinstance(v,str) for v in command) and
                isinstance(cwd,str) and cwd,
                'known/task command or cwd unavailable; preserve expansion')
            inspected.append(pid)
            if any(token in v.replace('\\','/').casefold() for v in [*command,cwd,info.get('exe') or '']):matches.append(pid)
        except psutil.NoSuchProcess:
            continue
        except (psutil.AccessDenied,OSError) as error:
            raise ValueError('known/task command or cwd unavailable; preserve expansion') from error
    repo.require(not matches, 'a running process still references the expansion')
    return dict(observed_at=utcnow(), dependent_pids=matches,
        scope='limited_global_pid_name_exe_ppid_metadata_and_selected_task_command_cwd_only',
        task_selection='project_local_executable_or_declared_lifecycle_pid_or_task_name_or_proven_descendant',
        global_metadata_fields=['pid','name','exe','ppid'],task_text_inspected_pids=sorted(inspected),
        candidate_identity_metadata_fields=['create_time'],
        unclassified_process_pids=sorted(unclassified),uninspectable_unrelated_or_unclassified_pids=sorted(set(unknown)),
        uninspectable_entries_proven_unrelated=False,global_dependency_absence_proven=False,
        unclassified_command_or_cwd_requested=False,
        ignored_planner_and_ancestor_pids=sorted(ignored))


def _process_identity(pid):
    try:
        process = psutil.Process(pid)
        return process.create_time()
    except psutil.NoSuchProcess:
        return None
    except (psutil.AccessDenied, OSError) as error:
        raise ValueError('known task lifecycle unavailable; preserve expansion') from error


def _task_lifecycle(receipt, root):
    repo.require(set(receipt) == {'schema', 'target', 'coverage_complete', 'processes'} and
        receipt['schema'] == LIFECYCLE_SCHEMA and receipt['coverage_complete'] is True and
        local_absolute(receipt['target']) == root and isinstance(receipt['processes'], list) and
        0 < len(receipt['processes']) <= 1000, 'explicit complete task lifecycle receipt required')
    checked=[]; seen=set()
    for item in receipt['processes']:
        repo.require(isinstance(item, dict) and set(item) == {'role', 'pid', 'create_time', 'exit_receipt'} and
            isinstance(item['role'], str) and 0 < len(item['role']) <= 80 and
            type(item['pid']) is int and 0 < item['pid'] < 2**32 and item['pid'] not in seen,
            'invalid or duplicate task lifecycle identity')
        pid=item['pid']; seen.add(pid); created=item['create_time']; exited=item['exit_receipt']
        repo.require(created is None or (type(created) in (float, int) and math.isfinite(created) and created > 0),
            'invalid task creation time')
        if exited is not None:
            repo.require(isinstance(exited, dict) and
                set(exited) == {'pid', 'create_time', 'exited', 'exit_code', 'observed_unix'} and
                exited['pid'] == pid and exited['create_time'] == created and exited['exited'] is True and
                type(exited['exit_code']) is int and type(exited['observed_unix']) in (int, float) and
                math.isfinite(exited['observed_unix']) and 0 < exited['observed_unix'] <= time.time()+60,
                'invalid persistent task exit receipt')
        current=_process_identity(pid)
        repo.require(current is None or (type(current) in (float, int) and math.isfinite(current) and current > 0),
            'known task creation time unavailable')
        if current is not None:
            repo.require(created is not None, 'task PID still exists without creation identity; preserve expansion')
            repo.require(current > created, 'recorded task process remains active or identity differs; preserve expansion')
        checked.append(dict(role=item['role'], pid=pid, create_time=created,
            current_pid_create_time=current, status='pid_absent_now' if current is None else 'original_exited_pid_reused',
            persistent_exit_receipt=exited))
    return dict(task_lifecycle_verified=True, processes=checked,
        scope='operator_declared_complete_task_process_list_pid_creation_identity_and_current_exit_check',
        undeclared_or_future_tasks_absence_proven=False, global_dependency_absence_proven=False,
        observed_at=utcnow())


class _WindowsProbe:
    """Read-only OPEN_EXISTING handles. DELETE is access, never disposition.

    Official contracts: CreateFileW, GetFileInformationByHandleEx (classes
    FileStandardInfo/FileIdInfo/FileFullDirectoryInfo), ReadFile, CloseHandle.
    No privilege adjustment, deletion flag, disposition, or foreign handle API.
    """
    def __init__(self):
        repo.require(os.name == 'nt', 'Windows exclusive access probe required')
        self.kernel=ctypes.WinDLL('kernel32', use_last_error=True)
        signatures={
            'CreateFileW': ([wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,
                wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE],wintypes.HANDLE),
            'GetFileInformationByHandleEx': ([wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD],wintypes.BOOL),
            'ReadFile': ([wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p],wintypes.BOOL),
            'CloseHandle': ([wintypes.HANDLE],wintypes.BOOL)}
        for name,(arguments,result) in signatures.items():
            function=getattr(self.kernel,name);function.argtypes=arguments;function.restype=result

    def open(self,path,directory=False,exclusive=True):
        # share=0 excludes existing readers/writers even when they share DELETE.
        flags=0x00200000 | (0x02000000 if directory else 0)
        handle=self.kernel.CreateFileW(str(path),0x80000000|0x00010000 if exclusive else 0,
            0 if exclusive else 7,None,3,flags,None)
        if handle == ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def close(self,handle):
        if not self.kernel.CloseHandle(handle):raise ctypes.WinError(ctypes.get_last_error())

    def info(self,handle):
        class Identity(ctypes.Structure):
            _fields_=[('volume',ctypes.c_ulonglong),('identity',ctypes.c_ubyte*16)]
        class Standard(ctypes.Structure):
            _fields_=[('allocated',ctypes.c_longlong),('length',ctypes.c_longlong),
                ('links',wintypes.DWORD),('pending',ctypes.c_ubyte),('directory',ctypes.c_ubyte)]
        class Basic(ctypes.Structure):
            _fields_=[('created',ctypes.c_longlong),('accessed',ctypes.c_longlong),
                ('modified',ctypes.c_longlong),('changed',ctypes.c_longlong),('attributes',wintypes.DWORD)]
        identity=Identity();standard=Standard();basic=Basic()
        for kind,value in ((18,identity),(1,standard),(0,basic)):
            if not self.kernel.GetFileInformationByHandleEx(handle,kind,ctypes.byref(value),ctypes.sizeof(value)):
                raise ctypes.WinError(ctypes.get_last_error())
        repo.require(not basic.attributes&0x400 and not standard.pending,
            'linked/reparse or delete-pending target; preserve expansion')
        # CPython's Windows st_dev exposes the 32-bit volume serial; retain the
        # full FILE_ID_INFO volume serial as an additional same-volume binding.
        return dict(device=identity.volume&0xffffffff,volume_serial=identity.volume,
            inode=int.from_bytes(bytes(identity.identity),'little'),
            bytes=standard.length,allocated_bytes=standard.allocated,nlink=standard.links,
            mtime_ns=(basic.modified-116444736000000000)*100,directory=bool(standard.directory))

    def names(self,handle):
        # Enumerate THROUGH our held exclusive directory handle. Reopening the
        # directory by path would conflict with our own share=0 guard.
        class Entry(ctypes.Structure):
            _fields_=[('next',wintypes.DWORD),('index',wintypes.DWORD),
                ('created',ctypes.c_longlong),('accessed',ctypes.c_longlong),('modified',ctypes.c_longlong),
                ('changed',ctypes.c_longlong),('length',ctypes.c_longlong),('allocated',ctypes.c_longlong),
                ('attributes',wintypes.DWORD),('name_bytes',wintypes.DWORD),('ea',wintypes.DWORD),
                ('name',wintypes.WCHAR*1)]
        buffer=ctypes.create_string_buffer(65536);result={};restart=True
        while True:
            success=self.kernel.GetFileInformationByHandleEx(handle,15 if restart else 14,buffer,len(buffer))
            restart=False
            if not success:
                code=ctypes.get_last_error()
                if code == 18:break  # ERROR_NO_MORE_FILES
                raise ctypes.WinError(code)
            offset=0
            while True:
                repo.require(offset+Entry.name.offset<=len(buffer),'invalid directory probe framing')
                item=Entry.from_buffer(buffer,offset)
                repo.require(item.name_bytes%2==0 and item.name_bytes>0 and
                    offset+Entry.name.offset+item.name_bytes<=len(buffer),'invalid directory probe name')
                name=ctypes.string_at(ctypes.addressof(buffer)+offset+Entry.name.offset,item.name_bytes).decode('utf-16-le')
                if name not in ('.','..'):
                    repo.require(name not in result and not item.attributes&0x400 and
                        '/' not in name and '\\' not in name,'new/linked directory entry; preserve expansion')
                    result[name]=bool(item.attributes&0x10)
                if not item.next:break
                repo.require(item.next%8==0 and item.next>=Entry.name.offset+item.name_bytes,
                    'invalid directory probe offset')
                offset+=item.next
        return result

    def sha256(self,handle):
        digest=hashlib.sha256();length=0;buffer=ctypes.create_string_buffer(1024**2);count=wintypes.DWORD()
        while True:
            if not self.kernel.ReadFile(handle,buffer,len(buffer),ctypes.byref(count),None):
                raise ctypes.WinError(ctypes.get_last_error())
            if count.value==0:break
            digest.update(buffer.raw[:count.value]);length+=count.value
        return digest.hexdigest(),length


def _directory_identities(root,evidence):
    result={};native=_WindowsProbe()
    for relative in ['',*evidence['directories']]:
        info=(root/relative).lstat()
        repo.require(stat.S_ISDIR(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,
            'linked or non-directory probe input')
        handle=native.open(root/relative,directory=True,exclusive=False)
        try:
            actual=native.info(handle)
            repo.require(actual['directory'] and (actual['device'],actual['inode'])==(info.st_dev,info.st_ino),
                'directory identity drift before semantic checks')
            result[relative]={k:actual[k] for k in ('device','inode','volume_serial')}
        finally:native.close(handle)
    return result


def _exclusive_probe(root,evidence,hashes,directory_identities,final_checks):
    """All root/directory/file handles retained together, then explicitly closed.

    This point-in-time OS access probe is NOT global logical-dependency absence
    or an atomic authorization for any subsequent independent operation.
    """
    repo.require(local_absolute(root)==root, 'probe target/ancestor path differs')
    native=_WindowsProbe();handles={};file_rows={row['relative']:row for row in evidence['files']}
    repo.require(set(file_rows)==set(hashes) and evidence['deletion_candidate_clean'], 'probe authorization inventory differs')
    with ExitStack() as stack:
        for relative in [*directory_identities,*file_rows]:
            handle=native.open(root/relative,directory=relative in directory_identities)
            stack.callback(native.close,handle);handles[relative]=handle
        def verify_metadata():
            repo.require(local_absolute(root)==root, 'probe target/ancestor path drift')
            for relative,handle in handles.items():
                info=native.info(handle)
                if relative in directory_identities:
                    expected=directory_identities[relative]
                    repo.require(info['directory'] and all(info[k]==expected[k] for k in ('device','inode','volume_serial')),
                        'directory identity drift during exclusive probe')
                else:
                    row=file_rows[relative]
                    repo.require(not info['directory'] and info['nlink']==1 and
                        info['volume_serial']==directory_identities['']['volume_serial'] and
                        all(info[k]==row[k] for k in ('device','inode','bytes','allocated_bytes','nlink','mtime_ns')),
                        'file inventory/identity drift during exclusive probe')
            for relative in directory_identities:
                prefix=relative+'/' if relative else ''
                expected={}
                for child in [*directory_identities,*file_rows]:
                    if child and child.startswith(prefix) and '/' not in child[len(prefix):]:
                        expected[child[len(prefix):]]=child in directory_identities
                repo.require(native.names(handles[relative])==expected,'new/missing path inventory drift during exclusive probe')
        verify_metadata();actual={}
        for relative,row in file_rows.items():
            digest,length=native.sha256(handles[relative]);actual[relative]=digest
            repo.require(digest==hashes[relative] and length==row['bytes'],
                'final exclusive handle hash differs; preserve expansion')
        verify_metadata()
        last_checks=final_checks()
        # A held directory share=0 handle does NOT prevent new child paths.
        # Re-enumerate all held directory handles AFTER the potentially slow
        # lifecycle/text checks, still before releasing any exclusive handle.
        verify_metadata()
        result=dict(target_access_probe_passed=True,observed_at=utcnow(),
            scope='task_target_root_all_directories_and_files_exclusive_read_delete_access_handles',
            access='GENERIC_READ|DELETE',share_mode=0,creation='OPEN_EXISTING',
            directory_backup_semantics=True,reparse_points_refused=True,
            directories_including_root=len(directory_identities),files=len(file_rows),
            full_inventory_and_sha256_rechecked_on_held_handles=True,sha256=actual,
            global_dependency_absence_proven=False,atomic_dependency_absence_proven=False,**last_checks)
    return dict(result,all_owned_probe_handles_closed=True)


def _same_inventory(before, after):
    repo.require(after['deletion_candidate_clean'] and before['entries_sha256'] == after['entries_sha256']
        and before['directories'] == after['directories'] and before['links'] == after['links'],
        'metadata/file tree drift during planning; preserve expansion')


def _file_map(value):
    return {name: dict(bytes=entry['bytes'], sha256=entry['sha256']) for name, entry in value['files'].items()}


def _not_indexed_identity(value):
    return (isinstance(value,dict) and set(value)=={'status','rows_verified'} and
        value['status']=='not_indexed' and type(value['rows_verified']) is int and value['rows_verified']==0)


def _has_identity_schema_objects(database):
    # SQLite resolves ASCII identifiers case-insensitively, but sqlite_master
    # preserves spelling and its name column has a case-sensitive default.
    return database.execute("SELECT 1 FROM sqlite_master WHERE name COLLATE NOCASE IN "
        "('next_viewer_aux_snapshot','next_viewer_aux_row','next_viewer_identity')").fetchone() is not None


def _has_media_schema(database):
    objects=database.execute("SELECT 1 FROM sqlite_master WHERE name COLLATE NOCASE IN "
        "('next_media_snapshot','next_media_row','next_media_voice','next_media_voice_key',"
        "'next_media_voice_lookup')").fetchone()
    markers=database.execute("SELECT 1 FROM archive_meta WHERE lower(key) GLOB 'next_viewer_media_*'").fetchone()
    return objects is not None or markers is not None


def _expected_media_binding(context,receipt_media):
    if 'media_binding' in context:
        expected=context['media_binding']
        repo.require(isinstance(expected,dict) and canonical(receipt_media)==canonical(expected),
            'native media receipt differs')
        return expected
    repo.require(_not_indexed_identity(receipt_media),
        'legacy media receipt requires exact not_indexed zero-row proof')
    return dict(status='not_indexed',rows_verified=0)


def _legacy_identity_summary(receipt_integrity,snapshot_integrity):
    """Structural compatibility only; current read-only proof is still required.

    Old integrity receipts predate this one summary field. No other field is
    omitted, normalized, or compared loosely, and a present identity field in
    the authenticated snapshot never takes this compatibility path.
    """
    repo.require(isinstance(receipt_integrity,dict) and isinstance(snapshot_integrity,dict),
        'union integrity receipt differs from snapshot')
    if canonical(receipt_integrity)==canonical(snapshot_integrity):return False
    repo.require(
        'identities' not in snapshot_integrity and
        set(receipt_integrity)==set(snapshot_integrity)|{'identities'} and
        canonical({k:v for k,v in receipt_integrity.items() if k!='identities'})==canonical(snapshot_integrity) and
        _not_indexed_identity(receipt_integrity['identities']),
        'union integrity receipt differs from snapshot')
    return True


def _complete(receipt, snapshot, expected, context):
    fields = {'schema', 'format', 'snapshot_id', 'receipt_root', 'state_restore', 'union_restore',
        'restored_files', 'attachments_closed', 'referenced_cas_bytes_verified', 'capture_started',
        'login_started', 'provenance_included', 'source_reconnected', 'phone_completeness'}
    repo.require(set(receipt) == fields and receipt['schema'] == repo.SCHEMA and
        receipt['format'] == repo.SCHEMA and receipt['snapshot_id'] == snapshot,
        'completed delivery schema/snapshot differs')
    for field in ('attachments_closed', 'referenced_cas_bytes_verified'):
        repo.require(receipt[field] is True, 'complete attachment closure required')
    for field in ('capture_started', 'login_started', 'source_reconnected', 'phone_completeness'):
        repo.require(receipt[field] is False, 'unexpected delivery safety field')
    actual_files = receipt['restored_files']
    repo.require(isinstance(actual_files, dict) and all(isinstance(entry, dict) and
        set(entry) == {'bytes', 'sha256'} and type(entry['bytes']) is int and
        isinstance(entry['sha256'], str) for entry in actual_files.values()), 'invalid restored file map types')
    repo.require(actual_files == expected and
        type(receipt['provenance_included']) is bool and
        receipt['provenance_included'] == context['provenance_included'], 'complete restored file map differs')
    state = receipt['state_restore']
    repo.require(isinstance(state, dict) and set(state) == {'schema', 'snapshot_id', 'state', 'verification',
        'includes_secrets', 'offline'} and state['schema'] == repo.SCHEMA and state['snapshot_id'] == snapshot
        and state['state'] == 'complete' and state['offline'] is True and
        type(state['includes_secrets']) is bool and state['includes_secrets'] == context['includes_secrets']
        and isinstance(state['verification'], dict) and state['verification'].get('pass') is True,
        'state restore completion proof differs')
    verification = state['verification']
    counts = {'files_verified', 'logical_bytes_verified', 'asset_references_verified',
        'asset_history_references_verified', 'referenced_asset_objects_verified', 'external_asset_owners_verified',
        'external_asset_references_verified', 'current_views_verified', 'reports_verified',
        'attachment_provenance_cycles_verified'}
    repo.require(set(verification) == counts | {'pass', 'history_count_limit', 'message_media_association',
        'historical_ciphertext_recoverable'} and all(type(verification[k]) is int and verification[k] >= 0 for k in counts)
        and verification['history_count_limit'] is None and verification['message_media_association'] == 'not_implemented'
        and verification['historical_ciphertext_recoverable'] is False,
        'unknown or unsafe state verification receipt content')
    union = receipt['union_restore']
    repo.require(isinstance(union, dict) and set(union) == {'metadata_only', 'integrity',
        'attachment_verification', 'media_verification'} and union['metadata_only'] is False,
        'full union restore proof required')
    for integrity in (union['integrity'], context.get('integrity', {})):
        repo.require(isinstance(integrity, dict) and integrity.get('quick_check') == ['ok'] and
            integrity.get('foreign_key_check') == [] and integrity.get('fts_verified') is True,
            'SQLite/FK/FTS success proof required')
    _legacy_identity_summary(union['integrity'],context['integrity'])
    from .union_backup import _binding
    # Identity and all declared whole-union closure fields are authenticated.
    actual, _ = _binding(union['attachment_verification'], context['_owner']['catalog_instance'], context['_owner']['union_id'])
    expected_binding, _ = _binding(context['asset_binding'], context['_owner']['catalog_instance'], context['_owner']['union_id'])
    repo.require(actual == expected_binding and actual['closure_complete'] is True,
        'receipt attachment closure differs from authenticated snapshot')
    _expected_media_binding(context,union['media_verification'])


def _verify_attachment_closure(root, value, receipt):
    from .compact_archive import CompactArchive
    from .union_delivery import _offline, _instance
    from .union_assets import verify_union_assets
    from .union_backup import _binding
    from .viewer_media import verify as verify_media
    with _offline(root/'state', configuration=True) as service, \
            CompactArchive(root/'union/archive.wua.sqlite', readonly=True, immutable=True) as archive:
        archive._db.execute('BEGIN')
        repo.require(_instance(service) == value['owner']['catalog_instance'], 'restored catalog identity differs')
        identity = archive._db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()
        repo.require(identity is not None and identity[0] == value['owner']['union_id'], 'restored union identity differs')
        compatibility=dict(applied=False)
        if _legacy_identity_summary(receipt['union_restore']['integrity'],value['context']['integrity']):
            from .viewer_identity import verify as verify_identity
            current_identity=verify_identity(archive)
            repo.require(_not_indexed_identity(current_identity) and
                current_identity==receipt['union_restore']['integrity']['identities'],
                'legacy identity summary requires current exact not_indexed zero-row proof')
            # verify_identity's not_indexed branch checks the marker. Refuse
            # orphan identity tables as unknown schema/content, even if empty.
            repo.require(not _has_identity_schema_objects(archive._db),
                'legacy identity summary has unknown/orphan identity tables')
            compatibility=dict(applied=True,scope='snapshot_missing_only_identities_summary',
                current_readonly_identity_verification=current_identity,
                other_integrity_fields_exactly_equal=True,fts_reexecuted=False)
        assets = verify_union_assets(archive, service, deep=True)
        repo.require(assets == receipt['union_restore']['attachment_verification'],
            'unknown or changed attachment verification receipt content')
        actual, _ = _binding(assets, value['owner']['catalog_instance'], value['owner']['union_id'])
        expected, _ = _binding(value['context']['asset_binding'], value['owner']['catalog_instance'], value['owner']['union_id'])
        repo.require(actual == expected and assets['closure_complete'] is True, 'current attachment closure failed')
        media = verify_media(archive, service, deep=True)
        expected_media=_expected_media_binding(value['context'],receipt['union_restore']['media_verification'])
        media_compatibility=dict(applied=False)
        if 'media_binding' not in value['context']:
            repo.require(_not_indexed_identity(media) and canonical(media)==canonical(expected_media),
                'legacy media binding requires current exact not_indexed zero-row proof')
            repo.require(not _has_media_schema(archive._db),
                'legacy media binding has schema markers or unknown/orphan media objects')
            media_compatibility=dict(applied=True,scope='snapshot_missing_media_binding',
                current_readonly_media_verification=media,no_media_schema_markers_or_known_objects=True)
        else:
            repo.require(canonical(media)==canonical(expected_media), 'current native media closure differs')
    return dict(attachments_closed=True, native_media_verified=media.get('status') == 'verified',
        legacy_identity_summary_compatibility=compatibility,
        legacy_media_binding_compatibility=media_compatibility,
        native_media_status=media.get('status'), native_media_scope='retained_native_index_not_all_media_associations', readonly=True,
        fts_basis='prior_success_and_exact_snapshot_bytes_not_new_readonly_FTS_execution')


def _measurement(path, receipt, snapshot, target):
    evidence = _json(path)
    repo.require(evidence.get('schema') == 'next-paired-backup-measurement-1' and
        evidence.get('partial') is False and 'error_type' in evidence and evidence['error_type'] is None and
        evidence.get('code_changed_during_run') is False and evidence.get('result') == receipt,
        'independent successful restore measurement required')
    run = evidence.get('run', {})
    hashes = run.get('source_hashes')
    repo.require(run.get('action') == 'restore' and isinstance(hashes, dict) and hashes and
        hashes == evidence.get('source_hashes_after'), 'restore measurement source proof differs')
    for sha in hashes.values():
        repo.identifier(sha)
    repo.require(receipt['snapshot_id'] == snapshot and local_absolute(receipt['receipt_root']) == target and
        local_absolute(evidence.get('space_scope', '')) == target, 'restore measurement target/snapshot differs')
    return dict(path=str(path), sha256=digest_file(path), snapshot_id=snapshot,
        successful_restore_measurement=True, source_hashes_unchanged=True)


def plan(root, repository, snapshot, *, restore_receipt=None, retain_authenticated_repository=False,
         lifecycle_receipt=None, _working_root=None):
    """Return evidence only. ``_working_root`` is an isolated-test seam, not CLI.

    Even with historical restore evidence, the retained snapshot payload is
    fully read back NOW. The alternative explicit retain flag never treats a
    readable manifest as a recoverability proof. Both paths still require this
    expansion's completed restore receipt and current attachment closure.
    """
    repo.require(type(retain_authenticated_repository) is bool, 'retain option must be boolean')
    repo.require(os.name == 'nt', 'Windows deny-write/delete guards are required for this planning tool')
    working = local_absolute(WORKING_ROOT if _working_root is None else _working_root)
    root = local_absolute(root); repository = local_absolute(repository); repo.identifier(snapshot)
    repo.require(root.parent == working and root.name in ALLOWED_NAMES,
        'only explicit task-owned paired expansion whitelist paths may be planned')
    repo.require(not repo.legacy._overlap(root, PROJECT_ROOT/'archives') and
        not repo.legacy._overlap(root, repository), 'expansion overlaps formal archives or retained repository')
    repo.require(restore_receipt is not None or retain_authenticated_repository,
        'independent restore measurement or explicit retained authenticated repository required')
    repo.require(lifecycle_receipt is not None, 'explicit task lifecycle receipt required; preserve expansion')
    lifecycle_path=local_absolute(lifecycle_receipt)
    repo.require(not lifecycle_path.is_relative_to(root) and not lifecycle_path.is_relative_to(repository),
        'task lifecycle receipt must be independent of target/repository')
    evidence = inventory(root)
    repo.require(evidence['deletion_candidate_clean'], 'linked or nonregular expansion must be preserved')
    directory_identities=_directory_identities(root,evidence)
    repo_evidence = inventory(repository)
    repo.require(repo_evidence['deletion_candidate_clean'], 'linked/nonregular retained repository')
    repo.require(not any(r['relative'].endswith(('-journal', '-wal', '-shm')) for r in repo_evidence['files']),
        'retained repository is active/dirty; no writer recovery is permitted')
    names = {r['relative'] for r in evidence['files']}
    hashes = {}
    with ExitStack() as guards, ExitStack() as target_guards:
        # Guard ALL existing bytes before parsing any recovery proof.
        for r in evidence['files']:
            target_guards.enter_context(cold_input(root/r['relative']))
        for r in repo_evidence['files']:
            guards.enter_context(cold_input(repository/r['relative']))
        guards.enter_context(cold_input(lifecycle_path))
        lifecycle_document=_json(lifecycle_path)
        lifecycle_sha=digest_file(lifecycle_path)
        lifecycle_first=_task_lifecycle(lifecycle_document,root)
        # A reused PID is demonstrably a different instance; do not read that
        # process's command merely because an old receipt named its PID.
        task_pids={item['pid']:item['create_time'] for item in lifecycle_first['processes'] if item['status']!='original_exited_pid_reused'}
        dependencies=_dependencies(root,task_pids=task_pids)
        measurement = None
        if restore_receipt is not None:
            measurement = local_absolute(restore_receipt)
            repo.require(not measurement.is_relative_to(root) and not measurement.is_relative_to(repository),
                'restore measurement must be independent of cleanup target/repository')
            guards.enter_context(cold_input(measurement))
        db, owner = guards.enter_context(repo.session(repository, readonly=True))
        db.execute('BEGIN')
        value = repo.manifest(db, snapshot, owner)
        repo.require(db.execute('SELECT 1 FROM generation WHERE snapshot_id=? UNION SELECT 1 FROM pin WHERE snapshot_id=?',
            (snapshot, snapshot)).fetchone() is not None, 'retained snapshot has no accepted generation or pin')
        context = value['context']; expected = _file_map(value)
        repo.require(isinstance(context,dict) and REQUIRED_CONTEXT_FIELDS.issubset(context),
            'missing authenticated paired recovery context fields')
        required = {'state/'+n for n in repo.legacy._REQUIRED} | {'union/archive.wua.sqlite', 'union/OWNER.private.json'}
        repo.require(required.issubset(expected), 'complete paired snapshot required')
        repo.require(not (set(expected) & GENERATED), 'snapshot must not absorb generated restore evidence')
        for name in ('includes_secrets', 'provenance_included'):
            repo.require(type(context.get(name)) is bool, 'missing authenticated recovery scope')
        repo.require(context['includes_secrets'] == ('state/'+repo.legacy.SECRETS in expected) and
            context['provenance_included'] == any(n.startswith('provenance/') for n in expected),
            'authenticated secret/provenance scope differs from file tree')
        protected = [repository, PROJECT_ROOT/'archives']
        for name in ('source_roots', 'protected_roots'):
            repo.require(isinstance(context.get(name), list) and context[name], 'authenticated protection roots required')
            protected.extend(repo.legacy._external_root(p) for p in context[name])
        protected.extend(repo.legacy._external_root(context[n]) for n in ('origin_state', 'origin_union'))
        repo.require(all(not repo.legacy._overlap(root, p) for p in protected), 'expansion overlaps protected source/tree')
        repo.require(set(expected).issubset(names) and names.issubset(set(expected) | GENERATED),
            'missing or unexpected expansion files; preserve for review')
        repo.require({'DELIVERY.complete.private.json', 'DELIVERY.partial.private.json',
            'state/RESTORE.complete.private.json'}.issubset(names), 'required completed restore markers missing')
        directories = {'state/cache', 'state/reports', 'state/tmp'}
        for name in names:
            directories.update(p.as_posix() for p in Path(name).parents if p.as_posix() != '.')
        repo.require(set(evidence['directories']).issubset(directories), 'unrecognized expansion directory')
        for row in evidence['files']:
            name = row['relative']; hashes[name] = digest_file(root/name)
            if name in expected:
                repo.require((row['bytes'], hashes[name]) == (expected[name]['bytes'], expected[name]['sha256']),
                    'expansion hash differs from authenticated snapshot')
            elif name.endswith('writer.lock'):
                repo.require((root/name).read_bytes() in (b'', b'0'), 'unexpected writer lock content')
        receipt = _json(root/'DELIVERY.complete.private.json')
        repo.require(local_absolute(receipt.get('receipt_root', '')) == root, 'delivery receipt target differs')
        _complete(receipt, snapshot, expected, dict(context, _owner=owner))
        repo.require(_json(root/'state/RESTORE.complete.private.json') == receipt['state_restore'],
            'standalone state restore receipt differs')
        repo.require(_json(root/'DELIVERY.partial.private.json') == dict(schema=repo.SCHEMA,
            snapshot_id=snapshot, status='partial'), 'unexpected generated delivery partial marker')
        config = _json(root/'state/config.private.json')
        repo.require(repo.legacy._source_roots(config) == context['source_roots'], 'source configuration/protection differs')
        if config.get('database_root'):
            repo.require(not repo.legacy._overlap(root, repo.legacy._external_root(config['database_root']).parent),
                'expansion overlaps original account directory')
        proof = repo.verify_files(db, value)
        repo.require(proof.get('verified') is True, 'full retained snapshot payload readback required')
        measured = _measurement(measurement, receipt, snapshot, root) if measurement else None
        closure = _verify_attachment_closure(root, value, receipt)
        # The whole tree is still deny-write/delete guarded; never substitute
        # timestamps for the one complete per-file SHA pass above. Re-inventory
        # detects new paths, replaced identities and metadata/link drift.
        _same_inventory(evidence, inventory(root)); _same_inventory(repo_evidence, inventory(repository))
        if measured:
            repo.require(digest_file(measurement) == measured['sha256'], 'measurement hash drift')
        # Close only our semantic target readers before requesting exclusive
        # access. Retained repository and lifecycle evidence remain guarded.
        target_guards.close()
        def final_checks():
            last_lifecycle=_task_lifecycle(lifecycle_document,root)
            last_pids={item['pid']:item['create_time'] for item in last_lifecycle['processes']
                if item['status']!='original_exited_pid_reused'}
            return dict(process_dependencies=_dependencies(root,task_pids=last_pids),task_lifecycle=last_lifecycle)
        probe=_exclusive_probe(root,evidence,hashes,directory_identities,final_checks)
        return dict(schema=SCHEMA, created=utcnow(), target=str(root), retained_repository=str(repository),
            snapshot_id=snapshot, inventory=evidence, sha256=hashes, retained_repository_inventory=repo_evidence,
            retained_repository_payload_verified_now=proof, attachment_closure=closure,
            retained_repository_verification_scope='selected_snapshot_all_files_and_referenced_payloads_not_other_snapshots_or_orphans',
            independent_restore_measurement=measured,
            recovery_basis='successful_restore_measurement_and_current_payload' if measured else 'explicit_retained_repository_current_full_payload',
            held_cold_guards_during_semantic_checks=True, semantic_guards_released_before_exclusive_probe=True,
            initial_process_dependencies=dependencies,process_dependencies=probe['process_dependencies'],
            lifecycle_receipt=dict(path=str(lifecycle_path),sha256=lifecycle_sha),
            task_lifecycle=probe['task_lifecycle'],task_lifecycle_verified=True,target_access_probe=probe,
            target_access_probe_passed=True,global_dependency_absence_proven=False,
            atomic_dependency_absence_proven=False,
            toctou_limitation='All owned probe handles are closed before this plan returns. New processes, paths, mappings or logical dependencies may appear before separately reviewed native PowerShell execution; this is not an atomic deletion gate.',
            deletion_executed=False, deletion_authorized=False, plan_only=True,
            important_legacy_backups_must_be_retained=True, original_sources_must_be_retained=True,
            formal_state_union_provenance_recovery_materials_must_be_retained=True,
            retained_repository_must_be_retained=True,
            execution_prerequisites=['separate human review and exact-target approval',
                'revalidate full inventory/SHA/links, operator-declared complete task lifecycles, readable-text census and exclusive target access immediately before separately approved cleanup',
                'probe scope excludes global logical/kernel/mapped/future dependencies; handles are released and independent PowerShell execution has a TOCTOU interval; any new conflict or drift means preserve',
                'keep authenticated repository, important old backups, unique originals and external restore evidence',
                'use a separately approved native PowerShell literal-path operation; this tool cannot delete'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'repository', 'out'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--snapshot', required=True)
    parser.add_argument('--restore-receipt', type=Path)
    parser.add_argument('--lifecycle-receipt', type=Path, required=True)
    parser.add_argument('--retain-authenticated-repository', action='store_true')
    args = parser.parse_args(argv)
    out = local_absolute(args.out); working = local_absolute(WORKING_ROOT)
    repo.require(out.parent == working and out.name.endswith('.private.json'), 'fresh private plan in task working root required')
    repo.require(not os.path.lexists(out), 'fresh plan filename required')
    result = plan(args.root, args.repository, args.snapshot, restore_receipt=args.restore_receipt,
        retain_authenticated_repository=args.retain_authenticated_repository,lifecycle_receipt=args.lifecycle_receipt)
    repo.require(not any(out.is_relative_to(repo.legacy._external_root(p)) for p in
        [result['target'], result['retained_repository']]), 'plan output overlaps protected input')
    write_json_new(out, result)
    print(json.dumps(dict(plan_only=True, deletion_executed=False,
        files=result['inventory']['file_count'], allocated_bytes=result['inventory']['allocated_bytes'])))


if __name__ == '__main__':
    main()
