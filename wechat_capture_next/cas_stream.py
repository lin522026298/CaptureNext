"""Publish a read-only native BLOB into the existing chunk CAS, without files.

The caller owns the single writer. Publication is last; readback authenticates
the target, not just the input buffer. No plaintext temporary copy is created.
"""
import hashlib
import zlib

from wechat_capture_v2.objects import CHUNK_BYTES
from .union_assets import verify_published_object


def publish(objects,stream,size):
    if type(size) is not int or size<0:raise ValueError('invalid BLOB size')
    db=objects.db
    if db.in_transaction:raise ValueError('CAS publication needs transaction boundary')
    keys=[];digest=hashlib.sha256();total=0
    db.execute('BEGIN IMMEDIATE')
    try:
        while total<size:
            block=stream.read(min(CHUNK_BYTES,size-total))
            if not isinstance(block,bytes) or not block:raise ValueError('native BLOB short read')
            if len(block)>min(CHUNK_BYTES,size-total):raise ValueError('native BLOB overflow')
            key=hashlib.sha256(block).hexdigest();digest.update(block);total+=len(block);keys.append(key)
            old=db.execute('SELECT bytes,data FROM chunk WHERE hash=?',(key,)).fetchone()
            if old is None:db.execute('INSERT INTO chunk VALUES(?,?,?)',(key,len(block),zlib.compress(block,1)))
            else:
                dec=zlib.decompressobj();value=dec.decompress(old[1],CHUNK_BYTES+1)
                if (old[0]!=len(block) or not dec.eof or dec.unused_data or dec.unconsumed_tail or value!=block):
                    raise ValueError('existing CAS chunk differs')
        if stream.read(1):raise ValueError('native BLOB exceeds declared length')
        sha=digest.hexdigest();expected=(size,len(keys))
        old=db.execute('SELECT bytes,chunk_count FROM file WHERE hash=?',(sha,)).fetchone()
        if old is not None and tuple(old)!=expected:raise ValueError('existing CAS file differs')
        for ordinal,key in enumerate(keys):
            old=db.execute('SELECT chunk_hash FROM file_chunk WHERE file_hash=? AND ordinal=?',(sha,ordinal)).fetchone()
            if old is not None and old[0]!=key:raise ValueError('CAS mapping differs')
            if old is None:db.execute('INSERT INTO file_chunk VALUES(?,?,?)',(sha,ordinal,key))
        if db.execute('SELECT count(*) FROM file_chunk WHERE file_hash=?',(sha,)).fetchone()[0]!=len(keys):
            raise ValueError('CAS mapping has excess chunks')
        db.execute('INSERT OR IGNORE INTO file VALUES(?,?,?)',(sha,*expected))
        db.commit()
    except BaseException:db.rollback();raise
    verify_published_object(db,sha,size)
    return dict(sha256=sha,bytes=size)
