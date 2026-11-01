"""Owned local UI acceptance host for a completed, immutable restore.

No capture, authentication or live-state writer is constructed. Console output
is only the loopback URL; the authentication token remains in the local page.
All task journals/previews are under a fresh, explicit working base.
"""
import argparse
from pathlib import Path
import sys

from wechat_capture_next.paths import local_absolute
from wechat_capture_next.recovery_core import RecoveryCore
from wechat_capture_next.product_host import ProductHost


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restored',type=Path,required=True)
    parser.add_argument('--base',type=Path,required=True)
    args=parser.parse_args(argv)
    base=local_absolute(args.base);restored=local_absolute(args.restored)
    workspace=Path(__file__).resolve().parents[2]
    if base.exists() or not base.is_relative_to(workspace/'working') or base==workspace/'working':
        raise ValueError('fresh project working fixture base required')
    formal=workspace/'archives/wechat-next';host=None;core=None
    try:
        core=RecoveryCore(base,state=formal/'state',union_root=formal/'unified',
            repository_root=formal/'backups/state',union_repository=formal/'backups/unified',
            paired_repository=formal/'backups/paired-v2',offline=restored)
        host=ProductHost(core)
        print(host.desktop[0].base_url,flush=True)
        for line in sys.stdin:
            if line.strip()=='quit':break
    finally:
        if host:host.close()
        elif core:core.close()


if __name__=='__main__':main()
