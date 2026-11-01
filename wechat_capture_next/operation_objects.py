"""Narrow, operation-local reuse of already verified frozen CAS bytes.

Only for the private offline connection owned by backup._frozen. The scope
owns query_only and tracing; do not lend the connection, replace its callback,
load extensions or hold preexisting writable blob handles. Not a persistent
cache or a general proof for arbitrary user-supplied SQLite connections.
"""
from contextlib import contextmanager
import re
import sqlite3


class FrozenObjectProof:
    def __init__(self,db,verification,cas_id=None):
        if not db.in_transaction:raise ValueError('object proof requires owned frozen transaction')
        self.db=db;self.live=True;self.valid=True
        self.cas_id=cas_id
        self.main_path=next(r[2] for r in db.execute('PRAGMA database_list') if r[1]=='main')
        self.files={sha:size for sha,size in db.execute('SELECT hash,bytes FROM file')}
        if (verification.get('pass') is not True or verification.get('files_verified')!=len(self.files) or
            verification.get('logical_bytes_verified')!=sum(self.files.values()) or
            any(not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha) or type(size) is not int or size<0
                for sha,size in self.files.items())):raise ValueError('full object verification result differs from frozen inventory')
        self.changes=db.total_changes
        self.version=db.execute('PRAGMA data_version').fetchone()[0]

    def trace(self,sql):
        text=sql.strip().upper().rstrip(';').strip()
        if not (text.startswith('SELECT ') or text in ('PRAGMA DATA_VERSION','PRAGMA DATABASE_LIST','PRAGMA QUERY_ONLY')):
            self.valid=False  # callback exceptions would be swallowed by SQLite

    def assert_for(self,db,*,cas_id=None):
        try:
            if (db is not self.db or (cas_id is not None and cas_id!=self.cas_id) or not self.live or not self.valid or not db.in_transaction or
                db.total_changes!=self.changes or db.execute('PRAGMA data_version').fetchone()[0]!=self.version):
                raise ValueError('object byte proof is outside its unchanged frozen scope')
        except sqlite3.ProgrammingError as error:
            self.valid=False;raise ValueError('object proof connection closed') from error

    def covers(self,sha,size):
        if not self.live or not self.valid or not self.db.in_transaction or self.db.total_changes!=self.changes:
            raise ValueError('object proof invalidated')
        if self.files.get(sha)!=size:raise ValueError('object not covered by complete byte verification')


@contextmanager
def verified_object_scope(db,verification,*,cas_id=None):
    # A write-capable blobopen otherwise evades total_changes and trace. This
    # connection is exclusive to the scope; query_only also blocks blob writes.
    prior=db.execute('PRAGMA query_only').fetchone()[0]
    proof=FrozenObjectProof(db,verification,cas_id=cas_id)
    db.execute('PRAGMA query_only=ON');db.set_trace_callback(proof.trace)
    try:
        yield proof
    finally:
        proof.live=False;proof.valid=False
        try:
            db.set_trace_callback(None)
            db.execute('PRAGMA query_only='+str(prior))
        except sqlite3.ProgrammingError:pass
