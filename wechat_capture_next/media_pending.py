"""Rare-failure recovery cut, not a normal per-poll media database copy.

Normally native rows go straight to WUA/CAS. Only a partially committed native
import which failed needs this short-lived old cut before capture may advance.
It is removed after the exact raw rows and references have finished importing.
"""
import json
import os
from pathlib import Path
import re
import tempfile

from wechat_capture_v2.common import digest_file,write_json_new
from .assets import _parents,_file
from .union_assets import _bind
from .union_archive import cold_input

SCHEMA='next-native-media-pending-1'


def pending_rows(archive):
    from .viewer_media import _exists
    if not _exists(archive):return []
    return list(archive._db.execute("SELECT * FROM next_media_snapshot WHERE status='pending' ORDER BY snapshot_id"))


def _root(archive,service,*,create=False):
    cas,_=_bind(archive,service)
    root=_parents(service.state/'tmp'/'native-media-pending')
    owner=dict(schema=SCHEMA,cas_id=cas,owner=archive._db.execute("SELECT value FROM archive_meta WHERE key='next_viewer_media_owner'").fetchone()[0])
    if not root.exists():
        if not create:return None
        root.mkdir(parents=True);write_json_new(root/'OWNER.private.json',owner)
    _file(root/'OWNER.private.json')
    if json.loads((root/'OWNER.private.json').read_text(encoding='utf-8'))!=owner:raise ValueError('foreign pending media recovery directory')
    for path in root.iterdir():
        _file(path)
        if path.name!='OWNER.private.json' and not re.fullmatch(r'media_[0-9a-f]{64}(\.db|\.[A-Za-z0-9_-]+\.pending)',path.name):
            raise ValueError('unknown pending media recovery entry')
    return root


def _expected(path,sha):
    _file(path)
    with cold_input(path):
        if digest_file(path)!=sha:raise ValueError('pending native cut differs from accepted SHA')


def preserve(archive,service):
    """Call before a subsequent capture may replace a failed import's view."""
    rows=pending_rows(archive)
    if not rows:return dict(preserved_cuts=0,copied_bytes=0)
    root=_root(archive,service,create=True);copied=0
    for row in rows:
        if row['source_id']!=service.config['source_id'] or row['account_alias']!=service.config['account_alias']:
            raise ValueError('pending media source is unavailable; no substitution allowed')
        target=root/(row['snapshot_id']+'.db')
        if target.exists():_expected(target,row['db_sha']);continue
        source=service.view_path(row['relative_path']);_file(source)
        with cold_input(source):
            if digest_file(source)!=row['db_sha']:raise ValueError('accepted old media cut unavailable before capture advance')
            descriptor,name=tempfile.mkstemp(prefix=row['snapshot_id']+'.',suffix='.pending',dir=root)
            temporary=Path(name)
            try:
                with os.fdopen(descriptor,'wb') as output,source.open('rb') as input:
                    while block:=input.read(256*1024):output.write(block);copied+=len(block)
                    output.flush();os.fsync(output.fileno())
                if digest_file(temporary)!=row['db_sha']:raise ValueError('pending native cut readback failed')
                os.rename(temporary,target)
            finally:
                if temporary.exists():temporary.unlink()
    return dict(preserved_cuts=len(rows),copied_bytes=copied,scope='failed_native_import_only_not_polling')


def clear_completed(archive,service,snapshot):
    root=_root(archive,service)
    if root is None:return
    status=archive._db.execute('SELECT status FROM next_media_snapshot WHERE snapshot_id=?',(snapshot,)).fetchone()
    if status is None or status[0]!='active':raise ValueError('cannot clear an unfinished native recovery cut')
    # The active receipt is published only after all exact raw fields, schemas,
    # BLOB target readback and pins. These are now reconstructable intermediates.
    for path in root.iterdir():
        if path.name==snapshot+'.db' or re.fullmatch(re.escape(snapshot)+r'\.[A-Za-z0-9_-]+\.pending',path.name):
            _file(path);path.unlink()


def resume(archive,service):
    rows=pending_rows(archive)
    from .viewer_media import _exists
    if not _exists(archive):return []
    root=_root(archive,service);results=[]
    # The active commit and filesystem cleanup cannot be atomic. A crash after
    # activation may leave a previous cut that is no longer the checkpoint and
    # will never be visited by the current-view import. Only known active
    # receipts authorize deleting their reconstructable recovery files.
    if root is not None:
        completed=set()
        for path in root.iterdir():
            match=re.fullmatch(r'(media_[0-9a-f]{64})(?:\.db|\.[A-Za-z0-9_-]+\.pending)',path.name)
            if match:
                status=archive._db.execute('SELECT status FROM next_media_snapshot WHERE snapshot_id=?',(match[1],)).fetchone()
                if status is not None and status[0]=='active':completed.add(match[1])
        for snapshot in sorted(completed):clear_completed(archive,service,snapshot)
    from .viewer_media import import_voice
    for row in rows:
        if row['source_id']!=service.config['source_id'] or row['account_alias']!=service.config['account_alias']:
            raise ValueError('pending native source differs from current source')
        copy=None if root is None else root/(row['snapshot_id']+'.db')
        path=copy if copy is not None and copy.exists() else service.view_path(row['relative_path'])
        results.append(import_voice(archive,service,source_id=row['source_id'],account_alias=row['account_alias'],relative=row['relative_path'],
            capture_id=row['capture_id'],evidence=json.loads(archive.pool.get_text(row['evidence_id'])),path=path))
        clear_completed(archive,service,row['snapshot_id'])
    return results
