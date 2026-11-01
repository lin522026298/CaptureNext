"""Read-only, no-follow inventories for reviewable local storage accounting.

This module never deletes. A separately reviewed literal-path PowerShell plan
must revalidate the manifest before any authorized deletion.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import stat
import time


def _allocated(path):
    if os.name != 'nt':
        info=os.lstat(path)
        return getattr(info,'st_blocks',0)*512
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,
        ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype=wintypes.HANDLE
    class Standard(ctypes.Structure):
        _fields_=[('allocation',ctypes.c_longlong),('length',ctypes.c_longlong),
                  ('links',wintypes.DWORD),('pending',ctypes.c_ubyte),('directory',ctypes.c_ubyte)]
    kernel.GetFileInformationByHandleEx.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
    kernel.GetFileInformationByHandleEx.restype=wintypes.BOOL
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    kernel.CloseHandle.restype=wintypes.BOOL
    handle=kernel.CreateFileW(str(path),0x80,7,None,3,0x00200000,None)
    if handle==ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        value=Standard()
        if not kernel.GetFileInformationByHandleEx(handle,1,ctypes.byref(value),ctypes.sizeof(value)):
            raise ctypes.WinError(ctypes.get_last_error())
        return value.allocation
    finally:
        kernel.CloseHandle(handle)


def inventory(root):
    root=Path(os.path.abspath(root))
    for parent in reversed((root,*root.parents)):
        info=os.lstat(parent)
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise ValueError('inventory root/ancestor is a reparse point')
    if not root.is_dir():
        raise ValueError('inventory root must be a directory')
    files=[];directories=[];links=[];groups={};seen=set();allocation=0
    def walk(directory):
        nonlocal allocation
        with os.scandir(directory) as entries:
            for entry in sorted(entries,key=lambda x:x.name):
                path=Path(entry.path);info=os.lstat(path)
                relative=str(path.relative_to(root)).replace('\\','/')
                identity=(info.st_dev,info.st_ino)
                if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
                    links.append(dict(relative=relative,kind='reparse',target=os.readlink(path)))
                    continue
                if stat.S_ISDIR(info.st_mode):
                    directories.append(relative);walk(path);continue
                if not stat.S_ISREG(info.st_mode):
                    links.append(dict(relative=relative,kind='nonregular'));continue
                allocated=_allocated(path)
                row=dict(relative=relative,bytes=info.st_size,allocated_bytes=allocated,
                         device=info.st_dev,inode=info.st_ino,nlink=info.st_nlink,
                         mtime_ns=info.st_mtime_ns)
                files.append(row)
                key=relative.split('/')[0]
                group=groups.setdefault(key,dict(files=0,logical_bytes=0,allocated_bytes=0))
                group['files']+=1;group['logical_bytes']+=info.st_size
                # Hardlinked allocation is counted only once in this inventory;
                # external links make its eventual freed bytes unknown.
                if identity not in seen:
                    allocation+=allocated;group['allocated_bytes']+=allocated;seen.add(identity)
    walk(root)
    result=dict(schema='next-storage-inventory-1',root=str(root),observed_unix=time.time(),
        files=files,directories=directories,links=links,groups=groups,
        file_count=len(files),logical_bytes=sum(x['bytes'] for x in files),
        allocated_bytes=allocation,hardlinked_files=sum(x['nlink']!=1 for x in files),
        deletion_candidate_clean=not links and all(x['nlink']==1 for x in files))
    result['entries_sha256']=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return result


def verify_inventory(manifest):
    current=inventory(manifest['root'])
    if (current['entries_sha256']!=manifest['entries_sha256'] or
            current['directories']!=manifest['directories'] or current['links']!=manifest['links']):
        raise ValueError('inventory changed since review; do not delete')
    return current


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path)
    parser.add_argument('--out',type=Path)
    parser.add_argument('--verify',type=Path)
    args=parser.parse_args()
    if args.verify:
        report=verify_inventory(json.loads(args.verify.read_text(encoding='utf-8')))
    else:
        if not args.root or not args.out:parser.error('--root and --out required')
        report=inventory(args.root)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        with args.out.open('x',encoding='utf-8') as output:
            json.dump(report,output,ensure_ascii=False,indent=2)
    print(json.dumps({key:report[key] for key in ('root','file_count','logical_bytes','allocated_bytes',
        'hardlinked_files','deletion_candidate_clean','groups')},ensure_ascii=False))
