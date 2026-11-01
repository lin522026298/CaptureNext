"""Pinned, read-only access to an explicitly completed restored v2 pair.

No CaptureService constructor, configuration/key load, migration, capture or
client login. Windows deny-write/delete guards span this reader's lifetime.
"""
from contextlib import ExitStack,closing
import json

from wechat_capture_v2.common import digest_file
from . import backup as legacy, pair_repository
from .union_archive import cold_input,cold_reader
from .union_delivery import _formal, _offline, _state_owner


class OfflineView:
    def __init__(self,root):
        self.root=legacy._parents(root);self.guards=ExitStack()
        try:
            receipt=self.root/'DELIVERY.complete.private.json';legacy._file(receipt)
            self.guards.enter_context(cold_input(receipt))
            value=json.loads(receipt.read_text(encoding='utf-8'))
            if (value.get('schema')!=pair_repository.SCHEMA or value.get('attachments_closed') is not True or
                value.get('source_reconnected') is not False):raise ValueError('completed offline paired restore required')
            self.state=self.root/'state';self.union=self.root/'union'
            if (self.state/'RESTORE.partial.private.json').exists() or (self.state/'RESTORE.failure.private.json').exists():
                raise ValueError('incomplete state cannot be viewed as verified restore')
            files=value['restored_files']
            required={'state/'+n for n in legacy._REQUIRED}|{'union/archive.wua.sqlite','union/OWNER.private.json'}
            if not required.issubset(files):raise ValueError('missing restored pair files')
            # Authenticate the complete on-disk restored bundle once, then keep
            # its guarded immutable bytes for all UI reads. Never trust mtime.
            for name,entry in files.items():
                path=self.root/pair_repository.file_name(name);legacy._file(path)
                self.guards.enter_context(cold_input(path))
                if path.stat().st_size!=entry['bytes'] or digest_file(path)!=entry['sha256']:
                    raise ValueError('restored copy differs from verified receipt')
            _,owner=_formal(self.union);_state_owner(self.state,owner)
            self.catalog_instance=owner['catalog_instance']
            with closing(cold_reader(self.union/'archive.wua.sqlite')) as db:
                self.union_id=db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()[0]
            with _offline(self.state):pass
            self.snapshot=value['snapshot_id']
        except BaseException:
            self.guards.close();raise

    def summary(self):
        return dict(mode='offline_readonly',receipt_root=str(self.root),snapshot_id=self.snapshot,
            source_connected=False,capture_started=False,login_started=False,
            files_hash_verified=True,lifetime_write_guards=True)

    def close(self):self.guards.close()
