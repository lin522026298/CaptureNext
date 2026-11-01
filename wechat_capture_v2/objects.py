"""Streaming chunk-addressed raw backup. No file/message count caps."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import shutil
import time
import zlib

from .common import digest_file,regular, stamp

CHUNK_BYTES = 256 * 1024  # memory granularity, never an acquisition limit


class PendingImport:
    """Cooperative two-pass file import. Only a published file may be referenced.

    Unreferenced chunks/maps survive cancellation intentionally; there is no GC.
    A time slice is best effort, not a real-time disk/fsync latency guarantee.
    """
    def __init__(self, objects, path):
        self.objects=objects
        self.path=Path(path)
        regular(self.path)
        self.before=stamp(self.path)
        self.size=self.before[2]
        self.offset=0
        self.digest=hashlib.sha256()
        self.chunks=[]
        self.phase='store'
        self.map_offset=0
        self.key=None
        self.result=None

    def advance(self, deadline):
        regular(self.path)
        if stamp(self.path)!=self.before:
            raise RuntimeError('pending asset generation changed')
        worked=False
        db=self.objects.db
        if self.phase=='store' and shutil.disk_usage(self.objects.path.parent).free<64*1024**2+2*CHUNK_BYTES:
            raise OSError('asset_import_paused_low_space')
        # Batch durability per time slice, never fsync each 256 KiB block.
        with db:
            if self.phase in ('store','verify'):
                with self.path.open('rb') as stream:
                    stream.seek(self.offset)
                    while not worked or time.monotonic()<deadline:
                        count=min(CHUNK_BYTES,self.size-self.offset)
                        block=stream.read(count)
                        if len(block)!=count:
                            raise RuntimeError('pending asset short read')
                        self.digest.update(block)
                        self.offset+=len(block)
                        if self.phase=='store' and block:
                            key=hashlib.sha256(block).hexdigest()
                            self.chunks.append(key)
                            if db.execute('SELECT 1 FROM chunk WHERE hash=?',(key,)).fetchone() is None:
                                db.execute('INSERT INTO chunk VALUES(?,?,?)',(key,len(block),zlib.compress(block,1)))
                        worked=True
                        if self.offset==self.size:
                            if self.phase=='store':
                                self.key=self.digest.hexdigest()
                                self.digest=hashlib.sha256()
                                self.offset=0
                                self.phase='verify'
                            else:
                                if self.digest.hexdigest()!=self.key:
                                    raise RuntimeError('pending asset readback hash mismatch')
                                self.phase='map'
                            break
            elif self.phase=='map':
                if db.execute('SELECT 1 FROM file WHERE hash=?',(self.key,)).fetchone():
                    self.map_offset=len(self.chunks)
                while self.map_offset<len(self.chunks) and (not worked or time.monotonic()<deadline):
                    end=min(self.map_offset+128,len(self.chunks))
                    db.executemany('INSERT OR IGNORE INTO file_chunk VALUES(?,?,?)',
                        ((self.key,i,self.chunks[i]) for i in range(self.map_offset,end)))
                    self.map_offset=end
                    worked=True
                if self.map_offset==len(self.chunks):
                    if db.execute('SELECT count(*) FROM file_chunk WHERE file_hash=?',(self.key,)).fetchone()[0]!=len(self.chunks):
                        raise RuntimeError('pending asset mapping mismatch')
                    db.execute('INSERT OR IGNORE INTO file VALUES(?,?,?)',(self.key,self.size,len(self.chunks)))
                    self.result={'sha256':self.key,'bytes':self.size,'chunk_count':len(self.chunks)}
                    self.phase='complete'
            if stamp(self.path)!=self.before:
                raise RuntimeError('pending asset changed before publication')
        return self.result


class Objects:
    def __init__(self, path):
        self.path = Path(path)
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS chunk(hash TEXT PRIMARY KEY, bytes INTEGER NOT NULL, data BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS file(hash TEXT PRIMARY KEY, bytes INTEGER NOT NULL, chunk_count INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS file_chunk(file_hash TEXT NOT NULL, ordinal INTEGER NOT NULL,
                chunk_hash TEXT NOT NULL, PRIMARY KEY(file_hash,ordinal));
        """)

    def add(self, path):
        before = stamp(path)
        total = 0
        digest = hashlib.sha256()
        chunks = []
        with self.db:
            with Path(path).open("rb") as stream:
                for block in iter(lambda: stream.read(CHUNK_BYTES), b""):
                    digest.update(block)
                    total += len(block)
                    key = hashlib.sha256(block).hexdigest()
                    chunks.append(key)
                    if self.db.execute('SELECT 1 FROM chunk WHERE hash=?',(key,)).fetchone() is None:
                        self.db.execute("INSERT INTO chunk VALUES(?,?,?)", (key, len(block), zlib.compress(block, 1)))
            if stamp(path) != before:
                raise RuntimeError("source changed while adding backup object")
            key = digest.hexdigest()
            self.db.execute("INSERT OR IGNORE INTO file VALUES(?,?,?)", (key, total, len(chunks)))
            self.db.executemany("INSERT OR IGNORE INTO file_chunk VALUES(?,?,?)", ((key, i, c) for i, c in enumerate(chunks)))
        return {"sha256": key, "bytes": total, "chunk_count": len(chunks)}

    def restore(self, key, target):
        target = Path(target)
        expected = self.db.execute("SELECT bytes,chunk_count FROM file WHERE hash=?", (key,)).fetchone()
        if expected is None:
            raise KeyError("raw backup object missing")
        total = 0
        digest = hashlib.sha256()
        count = 0
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            for ordinal, chunk_key, size, payload in self.db.execute("""SELECT f.ordinal,c.hash,c.bytes,c.data
                    FROM file_chunk f JOIN chunk c ON c.hash=f.chunk_hash WHERE f.file_hash=? ORDER BY f.ordinal""", (key,)):
                if ordinal != count:
                    raise ValueError("backup chunk sequence incomplete")
                if not 0 <= size <= CHUNK_BYTES:
                    raise ValueError("backup chunk size outside writer format")
                decoder=zlib.decompressobj()
                data = decoder.decompress(payload,CHUNK_BYTES+1)
                if not decoder.eof or decoder.unused_data or len(data) != size or hashlib.sha256(data).hexdigest() != chunk_key:
                    raise ValueError("backup chunk authentication failed")
                output.write(data)
                total += len(data)
                count += 1
                digest.update(data)
        if (total, count) != expected or digest.hexdigest() != key:
            raise ValueError("backup file hash/length mismatch")
        if target.stat().st_size!=total or digest_file(target)!=key:
            raise ValueError('restored target readback hash/length mismatch')
        return {"sha256": key, "bytes": total}

    def close(self):
        self.db.close()

    def verify_all(self):
        """Read/decompress/hash every retained file without allocating a whole file."""
        files=total_bytes=0
        for key,expected_bytes,expected_chunks in self.db.execute('SELECT hash,bytes,chunk_count FROM file ORDER BY hash'):
            digest=hashlib.sha256()
            count=size=0
            for ordinal,chunk_key,chunk_bytes,payload in self.db.execute("""SELECT f.ordinal,c.hash,c.bytes,c.data
                    FROM file_chunk f JOIN chunk c ON c.hash=f.chunk_hash WHERE f.file_hash=? ORDER BY f.ordinal""",(key,)):
                if ordinal!=count or not 0<=chunk_bytes<=CHUNK_BYTES:
                    raise ValueError('object verification: invalid chunk shape')
                decoder=zlib.decompressobj()
                block=decoder.decompress(payload,CHUNK_BYTES+1)
                if not decoder.eof or decoder.unused_data or len(block)!=chunk_bytes or hashlib.sha256(block).hexdigest()!=chunk_key:
                    raise ValueError('object verification: corrupt chunk')
                digest.update(block)
                size+=len(block)
                count+=1
            if (size,count)!=(expected_bytes,expected_chunks) or digest.hexdigest()!=key:
                raise ValueError('object verification: file hash or size mismatch')
            files+=1
            total_bytes+=size
        return {'pass':True,'files_verified':files,'logical_bytes_verified':total_bytes,'history_count_limit':None}
