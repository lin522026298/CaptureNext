"""Explicit owned one-time navigation index upgrade, no acquisition or keys."""
import argparse
from pathlib import Path
import json
from wechat_capture_v2.common import write_json_new
from .benchmark_pair import measure
from .union_delivery import _offline,_formal,_state_owner
from .compact_archive import CompactArchive
from .state_guard import writer_lock
from .viewer_access import ensure


def upgrade(state,union):
    with writer_lock(state),writer_lock(union):
        path,owner=_formal(union);_state_owner(state,owner)
        with _offline(state) as service,CompactArchive(path) as archive:
            before=archive.stats();result=ensure(archive)
            if archive.stats()!=before:raise ValueError('navigation index changed domain counts')
            checks=[r[0] for r in archive._db.execute('PRAGMA quick_check')]
            if checks!=['ok']:raise ValueError('navigation index quick check failed')
            return dict(result,stats_unchanged=True,quick_check=checks,capture_started=False,login_started=False)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('state','union','out'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args(argv)
    from .paths import local_absolute
    a.state=local_absolute(a.state,allow_relative=True);a.union=local_absolute(a.union,allow_relative=True)
    if a.out.exists():raise FileExistsError('fresh evidence required')
    value=measure(lambda:upgrade(a.state,a.union),a.union,samples_path=a.out.with_suffix('.samples.private.jsonl'))
    write_json_new(a.out,value);print(json.dumps(dict(partial=value['partial'],elapsed_seconds=value['elapsed_seconds'],settled_net_bytes=value['settled_net_bytes'])))


if __name__=='__main__':main()
