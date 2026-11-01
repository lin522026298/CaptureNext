"""Explicit owned product startup/sync acceptance, no UI or automatic watch.

Mutates only the named current state/union and a fresh private output. This is
not a throughput or full phone-history claim. It never logs chats or names.
"""
import argparse
import json
from pathlib import Path
import time

from wechat_capture_v2.common import write_json_new
from .product import ProductCore
from .product_host import product_read
from .compact_archive import CompactArchive
from . import viewer_identity,viewer_media


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('state','union','state_repo','union_repo','paired_repo','output','out'):p.add_argument('--'+name.replace('_','-'),type=Path,required=True)
    p.add_argument('--capture',action='store_true');a=p.parse_args(argv)
    from .paths import local_absolute
    for name in ('state','union','state_repo','union_repo','paired_repo','output','out'):setattr(a,name,local_absolute(getattr(a,name),allow_relative=True))
    if a.output.exists() or a.out.exists():raise FileExistsError('fresh private probe output required')
    start=time.monotonic();result=dict(scope='explicit_current_product_startup_sync',watch_started=False,phone_completeness=False)
    core=None
    try:
        core=ProductCore(a.state,a.output,union_root=a.union,repository_root=a.state_repo,union_repository=a.union_repo,
            paired_repository=a.paired_repo,managed_root=a.output.with_name(a.output.name+'-managed'),start_paused=True)
        def settle():
            deadline=time.monotonic()+600
            while time.monotonic()<deadline:
                jobs=core.jobs_snapshot()['jobs']
                if not core.busy and all(j['status'] not in ('queued','running') for j in jobs):return jobs
                time.sleep(.1)
            raise TimeoutError('owned sync probe still pending; no duplicate writer started')
        jobs=settle()
        if a.capture:core.submit(dict(action='capture',full=True,assets=True));jobs=settle()
        status=core.control_snapshot();result['jobs']=[dict(action=j['action'],status=j['status'],error_type=j.get('error_type')) for j in jobs]
        result['identities']=status['product']['identities'];result['union']=status['product']['union']
        result['summary']=status.get('summary');result['watch_error']=status.get('watch_error')
        core.close();core=None
        from .union_delivery import _offline
        from .state_guard import writer_lock
        with writer_lock(a.state),writer_lock(a.union),_offline(a.state) as offline,CompactArchive(a.union/'archive.wua.sqlite',readonly=True,immutable=True) as archive:
            result['identity_verification']=viewer_identity.verify(archive)
            result['media_verification']=viewer_media.verify(archive,offline,deep=True)
        result['pass_all']=all(j['status']=='completed' for j in jobs) and result['identities'].get('status')=='ready' and result['union'].get('status')=='caught_up'
    except Exception as error:result.update(pass_all=False,error_type=type(error).__name__)
    finally:
        if core:core.close()
    result['elapsed_seconds']=time.monotonic()-start;write_json_new(a.out,result)
    print(json.dumps(dict(pass_all=result['pass_all'],elapsed_seconds=result['elapsed_seconds'],error_type=result.get('error_type'))))
    return int(not result['pass_all'])


if __name__=='__main__':raise SystemExit(main())
