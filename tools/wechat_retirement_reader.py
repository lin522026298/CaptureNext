"""Optional offline audit VFS; authenticated repository bytes, never writes.

This is NOT imported by the product. APSW is an optional audit dependency.
The caller must authenticate manifests and hold immutable backing-repository
guards for the entire connection lifetime; per-read authentication is not a
claim that unqueried data or an entire restore has been verified.
"""
from collections import OrderedDict
import hashlib
import json
import uuid


class ChunkReader:
    def __init__(self, entry, load, chunk_bytes, cache_bytes=8*1024**2):
        self.entry=entry;self.size=entry['bytes'];self.load=load;self.chunk_bytes=chunk_bytes
        self.cache=OrderedDict();self.cached=0;self.cache_bytes=cache_bytes;self.read_bytes=0
        if type(self.size) is not int or self.size<0 or chunk_bytes<=0:raise ValueError('invalid file shape')
        if len(entry['chunks'])!=(self.size+chunk_bytes-1)//chunk_bytes:raise ValueError('invalid chunk count')
    def block(self,index):
        if index in self.cache:
            value=self.cache.pop(index);self.cache[index]=value;return value
        value=self.load(self.entry['chunks'][index]);self.read_bytes+=len(value)
        if len(value)!=min(self.chunk_bytes,self.size-index*self.chunk_bytes):raise ValueError('chunk boundary mismatch')
        self.cache[index]=value;self.cached+=len(value)
        while self.cached>self.cache_bytes:
            _,old=self.cache.popitem(last=False);self.cached-=len(old)
        return value
    def read(self,amount,offset):
        if type(amount) is not int or type(offset) is not int or amount<0 or offset<0:raise ValueError('invalid read')
        end=min(self.size,offset+amount);parts=[];position=offset
        while position<end:
            index=position//self.chunk_bytes;block=self.block(index);start=position%self.chunk_bytes
            length=min(end-position,len(block)-start);parts.append(block[start:start+length]);position+=length
        return b''.join(parts)+b'\0'*max(0,offset+amount-max(offset,self.size))
    def verify(self):
        digest=hashlib.sha256()
        for index in range(len(self.entry['chunks'])):digest.update(self.block(index))
        if digest.hexdigest()!=self.entry['sha256']:raise ValueError('whole file digest differs')
        return dict(bytes=self.size,sha256=digest.hexdigest())


class TreeReader:
    def __init__(self,entry,blocks):self.entry=entry;self.size=entry['bytes'];self.blocks=blocks;self.read_bytes=0
    def _read(self,key,height,size,start,end):
        if start>=end:return b''
        kind,raw=self.blocks.get(key);self.read_bytes+=len(raw)
        if not height:
            if kind!='D' or len(raw)!=size:raise ValueError('invalid leaf')
            return raw[start:end]
        if kind!='N':raise ValueError('invalid map')
        node=json.loads(raw)
        if node['height']!=height or sum(c[1] for c in node['children'])!=size:raise ValueError('invalid tree shape')
        offset=0;parts=[]
        for child,length in node['children']:
            left=max(0,start-offset);right=min(length,end-offset)
            if left<right:parts.append(self._read(child,height-1,length,left,right))
            offset+=length
            if offset>=end:break
        return b''.join(parts)
    def read(self,amount,offset):
        if type(amount) is not int or type(offset) is not int or amount<0 or offset<0:raise ValueError('invalid read')
        end=min(self.size,offset+amount)
        raw=self._read(self.entry['root'],self.entry['height'],self.size,offset,end) if offset<end else b''
        return raw+b'\0'*(amount-len(raw))
    def verify(self):
        digest=hashlib.sha256();total=0
        for raw in self.blocks.walk(self.entry['root'],self.entry['height'],self.size):digest.update(raw);total+=len(raw)
        if total!=self.size or digest.hexdigest()!=self.entry['sha256']:raise ValueError('whole file digest differs')
        return dict(bytes=total,sha256=digest.hexdigest())


class ReadOnlyVFS:
    """Unique virtual database aliases. Never forwards an unknown file to OS."""
    def __init__(self,readers):
        import apsw
        self.apsw=apsw;self.name='retirement-'+uuid.uuid4().hex;self.readers=readers
        owner=self
        class VirtualFile:
            def __init__(self,reader):self.reader=reader
            def xRead(self,amount,offset):return self.reader.read(amount,offset)
            def xFileSize(self):return self.reader.size
            def xClose(self):pass
            def xLock(self,level):pass
            def xUnlock(self,level):pass
            def xCheckReservedLock(self):return False
            def xFileControl(self,op,pointer):return False
            def xSectorSize(self):return 4096
            def xDeviceCharacteristics(self):return apsw.SQLITE_IOCAP_IMMUTABLE
            def xWrite(self,*args):raise apsw.ReadOnlyError('audit VFS refuses writes')
            def xTruncate(self,*args):raise apsw.ReadOnlyError('audit VFS refuses truncation')
            def xSync(self,*args):raise apsw.ReadOnlyError('audit VFS refuses sync')
        class VFS(apsw.VFS):
            def xFullPathname(self,name):return name
            def xAccess(self,name,flags):return name in owner.readers
            def xOpen(self,name,flags):
                name=name.filename() if isinstance(name,apsw.URIFilename) else name
                if name not in owner.readers or flags[0]&(apsw.SQLITE_OPEN_READWRITE|apsw.SQLITE_OPEN_CREATE):
                    raise apsw.CantOpenError('only registered readonly audit files may be opened')
                flags[1]=apsw.SQLITE_OPEN_READONLY
                return VirtualFile(owner.readers[name])
            def xDelete(self,*args):raise apsw.ReadOnlyError('audit VFS refuses deletion')
        self.vfs=VFS(self.name,'')
    def connect(self,alias):
        if alias not in self.readers:raise ValueError('unknown audit alias')
        db=self.apsw.Connection(alias,vfs=self.name,flags=self.apsw.SQLITE_OPEN_READONLY|self.apsw.SQLITE_OPEN_URI)
        db.execute('PRAGMA query_only=ON');db.execute('PRAGMA temp_store=MEMORY')
        return db
    def close(self):self.vfs.unregister()
