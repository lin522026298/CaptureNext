"""Read-only same-cut page collateral measurement; no chat values in results.

This estimates NEW compressed leaf payload, not repository/physical disk writes.
The actual paired repository benchmark/restore must be reported separately.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import time
import zlib

import psutil
from wechat_capture_v2.common import write_json_new
from .backup import _file, _parents
from .pair_repository import ALLOWED_BLOCKS
from .union_archive import cold_input


def compare(before,after):
    """One read per file; compare 1 MiB windows and their page-aligned leaves."""
    before,after=map(Path,(before,after));_file(before);_file(after)
    rows={n:dict(changed_blocks=0,changed_block_bytes=0,new_compressed_payload_bytes=0) for n in ALLOWED_BLOCKS}
    logical_changed=page_changed=page_bytes=0;old_hash=hashlib.sha256();new_hash=hashlib.sha256()
    with before.open('rb') as old,after.open('rb') as new:
        while True:
            a=old.read(1024*1024);b=new.read(1024*1024)
            if not a and not b:break
            old_hash.update(a);new_hash.update(b)
            logical_changed+=sum(x!=y for x,y in zip(a,b))+abs(len(a)-len(b))
            for n,row in rows.items():
                for offset in range(0,max(len(a),len(b)),n):
                    x,y=a[offset:offset+n],b[offset:offset+n]
                    if x!=y:
                        row['changed_blocks']+=1;row['changed_block_bytes']+=len(y)
                        if y:row['new_compressed_payload_bytes']+=len(zlib.compress(y,1))
                        if n==4096:page_changed+=1;page_bytes+=len(y)
    return dict(before_bytes=before.stat().st_size,after_bytes=after.stat().st_size,
        before_sha256=old_hash.hexdigest(),after_sha256=new_hash.hexdigest(),
        differing_byte_positions=logical_changed,changed_4k_pages=page_changed,changed_4k_bytes=page_bytes,
        aligned_leaf_collateral={str(k):v for k,v in rows.items()},
        excludes_tree_maps_indexes_allocation_and_cross_file_dedup=True)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('before-state','before-union','state','union','out'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args(argv);a.out=_parents(a.out.parent)/a.out.name
    own=psutil.Process();io0=own.io_counters();cpu0=own.cpu_times();start=time.monotonic()
    pairs={'catalog':(a.before_state/'catalog.sqlite',a.state/'catalog.sqlite'),
           'union':(a.before_union/'archive.wua.sqlite',a.union/'archive.wua.sqlite')}
    with ExitStack() as stack:
        for pair in pairs.values():
            for path in pair:stack.enter_context(cold_input(path))
        result={name:compare(*pair) for name,pair in pairs.items()}
    io1=own.io_counters();cpu1=own.cpu_times()
    result=dict(schema='next-backup-page-collateral-1',files=result,elapsed_seconds=time.monotonic()-start,
        cpu_seconds=cpu1.user+cpu1.system-cpu0.user-cpu0.system,
        process_logical_read_bytes=io1.read_bytes-io0.read_bytes,process_logical_write_bytes=io1.write_bytes-io0.write_bytes,
        physical_disk_write_bytes=None,process_hard_fault_bytes=None,
        scope='actual_same_before_after_files_one_read_each_no_source_mutation')
    write_json_new(a.out,result)
    print(json.dumps(result))


if __name__=='__main__':main()
