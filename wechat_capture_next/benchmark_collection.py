"""Explicit owned repository cleanup measurement; never touches source files.

The freelist-only mode only compacts pages already released by committed
SQLite transactions. It does not retire snapshots, delete blocks, or claim a
fresh full payload authentication. Full collection uses repository.govern.
"""
import argparse
import json
from pathlib import Path
import time

from wechat_capture_v2.common import digest_file,write_json_new,utcnow
from . import pair_repository as repository,pair_collection
from .benchmark_pair import measure


def free_pages(repo,seconds=300):
    repo=repository.local_absolute(repo)
    with repository.session(repo) as (db,owner):
        before={row[0]:repository.manifest(db,row[0],owner) for row in db.execute('SELECT id FROM snapshot')}
        blocks=db.execute('SELECT count(*) FROM block').fetchone()[0]
        first=db.execute('PRAGMA freelist_count').fetchone()[0];remaining=first;reclaimed=rounds=0
        deadline=time.monotonic()+seconds
        while remaining and time.monotonic()<deadline:
            result=repository._reclaim(db,repo,seconds=min(2,deadline-time.monotonic()))
            rounds+=1;reclaimed+=result.get('file_bytes_reclaimed',0)
            current=db.execute('PRAGMA freelist_count').fetchone()[0]
            if result.get('cleanup_error') or current>=remaining:break
            remaining=current
        after={row[0]:repository.manifest(db,row[0],owner) for row in db.execute('SELECT id FROM snapshot')}
        repository.require(before==after and db.execute('SELECT count(*) FROM block').fetchone()[0]==blocks,
            'freelist-only maintenance changed retained snapshot or block inventory')
        return dict(freelist_pages_before=first,freelist_pages_after=remaining,file_bytes_reclaimed=reclaimed,
            cleanup_pending=remaining>0,reclaim_rounds=rounds,retained_manifests_and_block_count_unchanged=True,
            snapshots_retired=0,blocks_deleted=0,full_payload_authentication_executed_now=False,
            verification_scope='SQLite_free_page_compaction_only_not_a_content_certificate')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,required=True);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--seconds',type=float,default=300);parser.add_argument('--free-pages-only',action='store_true')
    args=parser.parse_args(argv)
    import math
    if not math.isfinite(args.seconds) or not 0<args.seconds<=86400:raise ValueError('bounded positive duration required')
    if args.out.exists():raise FileExistsError('fresh private receipt required')
    sources=(Path(__file__),Path(repository.__file__),Path(pair_collection.__file__))
    hashes=lambda:{path.name:digest_file(path) for path in sources}
    before=hashes()
    write_json_new(args.out.with_name(args.out.stem+'.RUN.private.json'),dict(started=utcnow(),source_hashes=before,free_pages_only=args.free_pages_only))
    operation=(lambda:free_pages(args.repo,args.seconds)) if args.free_pages_only else (lambda:repository.govern(args.repo,seconds=args.seconds))
    value=measure(operation,args.repo,samples_path=args.out.with_name(args.out.stem+'.samples.private.jsonl'))
    value.update(source_hashes_before=before,source_hashes_after=hashes(),code_changed_during_run=before!=hashes())
    write_json_new(args.out,value)
    print(json.dumps(dict(partial=value['partial'],elapsed_seconds=value['elapsed_seconds'],settled_net_bytes=value['settled_net_bytes'],
        cleanup_pending=(value.get('result') or {}).get('cleanup_pending'))))
    return int(value['partial'] or (value.get('result') or {}).get('cleanup_pending',False))


if __name__=='__main__':raise SystemExit(main())
