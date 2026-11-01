#!/usr/bin/env python3
"""Version-locked, explicit-PID, read-only Weixin key-cache probe.

No process discovery, launch, injection, debugger, privilege adjustment, network
client, full memory dump or chat query. Pure candidate parsing is fixture-testable.
Windows access uses only QUERY_INFORMATION|VM_READ. Source ZIP/DBs are read-only;
verified key material is saved only in a newly created explicit output directory.
"""
from __future__ import annotations
import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import re
import struct
import time
import zipfile

EXPECTED_SHA256 = '4914a621a810ecbc0a132b6ff8f612658cfce323d3989b3e5fe32d4ff343ba46'
NAME = b'com.Tencent.WCDB.Config.Cipher'
NAME_RVA = 0x892ABC8
VTABLE_RVA = 0x892B118
MASK = bytes.fromhex('d2c7442458020000004889442450488b450048844c2448488944254048584c24')
MASTER_MASK = struct.pack('<QQQQ',0x579c808cf3570c30,0xb9fe56a2649e5f78,
                          0x69811f7f3c296980,0xe8823911784d6d58)
PROFILES = {
    EXPECTED_SHA256: {'version': '4.1.12.26', 'name_rva': NAME_RVA,
                      'vtable_rva': VTABLE_RVA, 'cfg_master_supported': True},
    '10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5': {
        'version': '4.1.15.13', 'name_rva': 0x901CB18, 'vtable_rva': 0x901D068,
        # Config original-key passphrases can still be verified, but this
        # version's global_config/master chain has not been validated.
        'cfg_master_supported': False},
}


@dataclass(frozen=True)
class Candidate:
    material: bytes = field(repr=False)
    method: str
    salt: bytes | None = field(default=None, repr=False)
    passphrase: bool = False


def xor_data(blob: bytes, mask: bytes = MASK) -> bytes:
    return bytes(b ^ mask[i % len(mask)] for i,b in enumerate(blob))


def plausible(pointer: int) -> bool:
    return 0x10000 <= pointer < 0x800000000000


def raw_candidates(decoded: bytes, method: str) -> list[Candidate]:
    result=[]
    if len(decoded) in (32,48):
        result.append(Candidate(decoded[:32],method,decoded[32:] or None))
    for match in re.finditer(rb"[xX]'([0-9a-fA-F]{64}|[0-9a-fA-F]{96})'",decoded):
        raw=bytes.fromhex(match.group(1).decode('ascii'))
        result.append(Candidate(raw[:32],method,raw[32:] or None))
    if len(decoded)==64 and re.fullmatch(rb'[0-9a-fA-F]{64}',decoded):
        result.append(Candidate(bytes.fromhex(decoded.decode('ascii')),method))
    return result


def inspect_config(read, module_base: int, pair_address: int, profile: dict | None = None) -> list[Candidate]:
    """Validate name-pair/node/object/vtable before reading only the two Data blobs."""
    profile = profile or PROFILES[EXPECTED_SHA256]
    pair=read(pair_address,16)
    if pair != struct.pack('<QQ',module_base+profile['name_rva'],len(NAME)):
        return []
    pointer_bytes=read(pair_address-0x10+0x28,8)
    if not pointer_bytes:
        return []
    pointer=struct.unpack('<Q',pointer_bytes)[0]
    if not plausible(pointer):
        return []
    obj=read(pointer,0xA0)
    if not obj or len(obj)!=0xA0 or struct.unpack_from('<Q',obj)[0] != module_base+profile['vtable_rva']:
        return []
    result=[]
    for offset,label in ((0x88,'config.raw'),(8,'config.original')):
        data_ptr,size=struct.unpack_from('<QQ',obj,offset+8)
        if not plausible(data_ptr) or not 0<size<=1024:
            continue
        masked=read(data_ptr,size)
        if not masked or len(masked)!=size:
            continue
        decoded=xor_data(masked)
        result.extend(raw_candidates(decoded,label))
        if label=='config.original' and len(decoded)<=512:
            result.append(Candidate(decoded,label+'.passphrase',passphrase=True))
    return result


def inspect_cfg_master(read, landmark_address: int) -> list[Candidate]:
    """Version-sensitive old pointer-chain hypotheses; every candidate needs DB HMAC."""
    landmark=read(landmark_address,32)
    if not landmark or landmark[:13]!=b'global_config' or struct.unpack_from('<QQ',landmark,16)!=(13,15):
        return []
    result=[]
    for back in (0x138,0x130):
        first=read(landmark_address+16-back,8)
        if not first:
            continue
        owner=struct.unpack('<Q',first)[0]
        if not plausible(owner):
            continue
        second=read(owner+0x68,8)
        if not second:
            continue
        cfg=struct.unpack('<Q',second)[0]
        if not plausible(cfg):
            continue
        value=read(cfg+0x2B8,32)
        if not value:
            continue
        size,capacity=struct.unpack_from('<QQ',value,16)
        if size!=32 or capacity<32 or capacity>1024:
            continue
        data_ptr=struct.unpack_from('<Q',value)[0]
        if not plausible(data_ptr):
            continue
        masked=read(data_ptr,32)
        if masked and len(masked)==32:
            result.append(Candidate(xor_data(masked,MASTER_MASK),f'cfg.master.back_{back:x}',passphrase=True))
    return result


def page1_matches(page: bytes, key: bytes, salt: bytes) -> bool:
    if len(page)!=4096 or len(key)!=32 or len(salt)!=16:
        return False
    mac_key=hashlib.pbkdf2_hmac('sha512',key,bytes(b^0x3A for b in salt),2,dklen=32)
    actual=hmac.new(mac_key,page[16:4032]+struct.pack('<I',1),hashlib.sha512).digest()
    return hmac.compare_digest(actual,page[4032:4096])


def verify_candidates(candidates: list[Candidate], pages: dict[str,bytes],
                      allow_passphrase: bool=False, deadline: float | None=None) -> tuple[list[dict],list[dict]]:
    matched={}
    masters=[]
    seen=set()
    # Prefer concrete raw cache keys over expensive passphrase hypotheses.
    for candidate in sorted(candidates,key=lambda c:(c.passphrase,c.method)):
        identity=(candidate.material,candidate.salt,candidate.passphrase)
        if identity in seen or (candidate.passphrase and not allow_passphrase):
            continue
        seen.add(identity)
        accepted=[]
        for relative,page in pages.items():
            if deadline is not None and time.monotonic()>deadline:
                return list(matched.values()),masters
            if relative in matched:
                continue
            salts=[page[:16]]
            if candidate.salt and candidate.salt not in salts:
                salts.append(candidate.salt)
            for salt in salts:
                key=(hashlib.pbkdf2_hmac('sha512',candidate.material,salt,256000,dklen=32)
                     if candidate.passphrase else candidate.material)
                if page1_matches(page,key,salt):
                    matched[relative]={'relative_path':relative,'verified':True,
                                       'verification_scope':'page1_hmac_only',
                                       'raw_encryption_key_hex':key.hex(),'salt_hex':salt.hex(),
                                       'salt_origin':'database_header' if salt==page[:16] else 'raw_literal',
                                       'page1_sha256':hashlib.sha256(page).hexdigest(),
                                       'method':candidate.method}
                    accepted.append(relative)
                    break
        if candidate.passphrase and accepted:
            masters.append({'method':candidate.method,'material_hex':candidate.material.hex(),
                            'verified_against':accepted})
    return sorted(matched.values(),key=lambda r:r['relative_path']),masters


def source_pages(path: Path) -> dict[str,bytes]:
    """Explicit frozen source only. Never auto-discovers a live account directory."""
    pages={}
    if path.is_dir():
        for file in sorted(path.rglob('*.db')):
            if file.is_symlink():
                continue
            with file.open('rb') as handle:
                page=handle.read(4096)
            if len(page)==4096:
                pages[file.relative_to(path).as_posix()]=page
    else:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if '/10_RAW_SNAPSHOT/' in member.filename and '/db_storage/' in member.filename and member.filename.endswith('.db'):
                    relative=member.filename.split('/db_storage/',1)[1]
                    if relative in pages:
                        raise ValueError('ambiguous duplicate database relative path')
                    with archive.open(member) as handle:
                        page=handle.read(4096)
                    if len(page)==4096:
                        pages[relative]=page
    if not pages:
        raise ValueError('no full database first pages in supplied frozen source')
    return pages


class MODULEENTRY32W(ctypes.Structure):
    _fields_=[('dwSize',wintypes.DWORD),('th32ModuleID',wintypes.DWORD),
              ('th32ProcessID',wintypes.DWORD),('GlblcntUsage',wintypes.DWORD),
              ('ProccntUsage',wintypes.DWORD),('modBaseAddr',ctypes.c_void_p),
              ('modBaseSize',wintypes.DWORD),('hModule',wintypes.HMODULE),
              ('szModule',wintypes.WCHAR*256),('szExePath',wintypes.WCHAR*260)]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_=[('BaseAddress',ctypes.c_void_p),('AllocationBase',ctypes.c_void_p),
              ('AllocationProtect',wintypes.DWORD),('RegionSize',ctypes.c_size_t),
              ('State',wintypes.DWORD),('Protect',wintypes.DWORD),('Type',wintypes.DWORD)]


class ReadOnlyProcess:
    def __init__(self,pid:int):
        if os.name!='nt' or ctypes.sizeof(ctypes.c_void_p)!=8:
            raise RuntimeError('requires 64-bit Python on Windows')
        self.k=ctypes.WinDLL('kernel32',use_last_error=True)
        self.k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
        self.k.OpenProcess.restype=wintypes.HANDLE
        self.k.CloseHandle.argtypes=[wintypes.HANDLE]
        self.k.CreateToolhelp32Snapshot.argtypes=[wintypes.DWORD,wintypes.DWORD]
        self.k.CreateToolhelp32Snapshot.restype=wintypes.HANDLE
        for name in ('Module32FirstW','Module32NextW'):
            fn=getattr(self.k,name)
            fn.argtypes=[wintypes.HANDLE,ctypes.POINTER(MODULEENTRY32W)]
            fn.restype=wintypes.BOOL
        self.k.ReadProcessMemory.argtypes=[wintypes.HANDLE,ctypes.c_void_p,ctypes.c_void_p,
                                          ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
        self.k.ReadProcessMemory.restype=wintypes.BOOL
        self.k.VirtualQueryEx.argtypes=[wintypes.HANDLE,ctypes.c_void_p,
                                       ctypes.POINTER(MEMORY_BASIC_INFORMATION),ctypes.c_size_t]
        self.k.VirtualQueryEx.restype=ctypes.c_size_t
        self.pid=pid
        self.handle=self.k.OpenProcess(0x0400|0x0010,False,pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.handle:
            self.k.CloseHandle(self.handle)
            self.handle=None

    def read(self,address:int,size:int) -> bytes | None:
        if not plausible(address) or not 0<size<=1048576:
            return None
        buf=ctypes.create_string_buffer(size)
        count=ctypes.c_size_t()
        self.k.ReadProcessMemory(self.handle,address,buf,size,ctypes.byref(count))
        return buf.raw[:count.value] if count.value else None

    def module(self):
        snapshot=self.k.CreateToolhelp32Snapshot(0x08|0x10,self.pid)
        if snapshot==ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        entry=MODULEENTRY32W()
        entry.dwSize=ctypes.sizeof(entry)
        found=None
        names=[]
        try:
            ok=self.k.Module32FirstW(snapshot,ctypes.byref(entry))
            while ok:
                names.append(entry.szModule.casefold())
                if entry.szModule.casefold()=='weixin.dll':
                    found=(entry.modBaseAddr,entry.modBaseSize,Path(entry.szExePath))
                ok=self.k.Module32NextW(snapshot,ctypes.byref(entry))
        finally:
            self.k.CloseHandle(snapshot)
        if 'weixin.exe' not in names or found is None:
            raise RuntimeError('explicit PID is not a Weixin.exe with Weixin.dll')
        return found

    def regions(self):
        address=0x10000
        while address<0x800000000000:
            mbi=MEMORY_BASIC_INFORMATION()
            if not self.k.VirtualQueryEx(self.handle,address,ctypes.byref(mbi),ctypes.sizeof(mbi)):
                break
            base=int(mbi.BaseAddress or 0)
            size=int(mbi.RegionSize)
            if size<=0 or base+size<=address:
                break
            if mbi.State==0x1000 and not mbi.Protect&(0x100|0x01) and mbi.Protect&0xFF in (2,4,8,0x20,0x40,0x80):
                yield base,size,int(mbi.Type)
            address=base+size


def file_hash(path:Path) -> str:
    digest=hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda:handle.read(4*1024*1024),b''):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid',required=True,type=int)
    ap.add_argument('--expected-host',required=True)
    ap.add_argument('--frozen-source',required=True,type=Path)
    ap.add_argument('--out-dir',required=True,type=Path)
    ap.add_argument('--max-mib',type=int,default=2048)
    ap.add_argument('--seconds',type=int,default=180)
    ap.add_argument('--try-passphrase',action='store_true')
    args=ap.parse_args()
    if platform.node().casefold()!=args.expected_host.casefold():
        ap.error('hostname guard mismatch; no target process opened')
    if args.pid<=0 or not 1<=args.max_mib<=8192 or not 10<=args.seconds<=600:
        ap.error('invalid explicit PID or bounded resource limits')
    pages=source_pages(args.frozen_source)
    args.out_dir.mkdir(parents=True,exist_ok=False)
    status={'schema':'weixin-readonly-runtime-status-1','pid':args.pid,'process_access':'QUERY_INFORMATION|VM_READ',
            'database_count':len(pages),'bytes_read_for_search':0,'name_pairs':0,'cfg_landmarks':0,
            'verified_database_count':0,'full_memory_dump':False,'complete':False}
    process=None
    try:
        process=ReadOnlyProcess(args.pid)
        base,module_size,path=process.module()
        digest=file_hash(path)
        status.update(module_sha256=digest,module_bytes=path.stat().st_size)
        profile = PROFILES.get(digest)
        if profile is None:
            raise RuntimeError('module hash differs from audited profile; no cache scan performed')
        status.update(profile_version=profile['version'], cfg_master_supported=profile['cfg_master_supported'])
        if process.read(base+profile['name_rva'],len(NAME))!=NAME:
            raise RuntimeError('audited in-memory name anchor does not match')
        pair=struct.pack('<QQ',base+profile['name_rva'],len(NAME))
        deadline=time.monotonic()+args.seconds
        candidates=[]
        pairs=set()
        landmarks=set()
        regions=sorted(process.regions(),key=lambda r:(r[2]!=0x20000,r[0]))
        budget=args.max_mib*1024*1024
        for address,size,kind in regions:
            if time.monotonic()>deadline or status['bytes_read_for_search']>=budget:
                status['resource_limit_reached']=True
                break
            offset=0
            carry=b''
            while offset<size:
                if time.monotonic()>deadline or status['bytes_read_for_search']>=budget:
                    break
                length=min(1048576,size-offset,budget-status['bytes_read_for_search'])
                data=process.read(address+offset,length) or b''
                status['bytes_read_for_search']+=length
                blob=carry+data
                origin=address+offset-len(carry)
                start=0
                while (pos:=blob.find(pair,start))>=0:
                    found=origin+pos
                    if found not in pairs and len(pairs)<4096:
                        pairs.add(found)
                        candidates.extend(inspect_config(process.read,base,found,profile))
                    start=pos+1
                if args.try_passphrase and profile['cfg_master_supported'] and address<base+module_size and address+size>base:
                    start=0
                    while (pos:=blob.find(b'global_config',start))>=0:
                        found=origin+pos
                        if found not in landmarks and len(landmarks)<64:
                            landmarks.add(found)
                            candidates.extend(inspect_cfg_master(process.read,found))
                        start=pos+1
                carry=data[-31:] if len(data)==length else b''
                offset+=length
        status['resource_limit_reached']=(time.monotonic()>deadline or status['bytes_read_for_search']>=budget)
        status['search_complete']=not status['resource_limit_reached']
        # Give the bounded KDF/verification phase its own short budget.
        entries,masters=verify_candidates(candidates,pages,args.try_passphrase,time.monotonic()+args.seconds)
        secret=args.out_dir/'90_SECRETS_PLAINTEXT_RESTRICTED'
        secret.mkdir()
        keyring={'schema':'wechat-keyring-1','databases':entries,'verified_master_candidates':masters,
                 'entries':[{'key_id':f'key-{i+1}','key_hex':r['raw_encryption_key_hex'],
                             'byte_length':32,'status':'verified','verification_scope':'page1_hmac_only',
                             'verified_against':[{'relative_path':r['relative_path'],'page1_sha256':r['page1_sha256'],
                                                  'checks':['first_page_hmac_sha512']}],
                             'method':{'type':'read_process_memory','tool':Path(__file__).name,'detail':r['method']}}
                            for i,r in enumerate(entries)]}
        target=secret/'keyring.json'
        temporary=secret/'keyring.json.pending'
        with temporary.open('x',encoding='utf8') as handle:
            json.dump(keyring,handle,indent=2)
        temporary.rename(target)
        status.update(name_pairs=len(pairs),cfg_landmarks=len(landmarks),candidate_count=len(candidates),
                      verified_database_count=len(entries),verified_master_count=len(masters),complete=True)
    except Exception as exc:
        status['error_type']=type(exc).__name__
        status['error']=str(exc)
    finally:
        if process:
            process.close()
        with (args.out_dir/'STATUS.json').open('x',encoding='utf8') as handle:
            json.dump(status,handle,indent=2)
    print(json.dumps(status))
    return 0 if status['complete'] else 1


if __name__=='__main__':
    raise SystemExit(main())
