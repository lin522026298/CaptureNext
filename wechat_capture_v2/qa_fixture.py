"""Create a clearly synthetic, isolated end-to-end UI acceptance workspace."""
from __future__ import annotations
import argparse
from contextlib import closing
from pathlib import Path
import sqlite3
from .common import canonical,write_json_new
from .tests.test_backend import KEY,make_plain,encrypt
from .tests.test_integration import reserve80
from .service import initialize,CaptureService


def create(root,count=100):
    root=Path(root).resolve();root.mkdir(parents=True,exist_ok=False)
    live=root/'synthetic-live';dbroot=live/'db_storage';(dbroot/'message').mkdir(parents=True)
    plain=root/'synthetic-plain.db';make_plain(plain,count=count);reserve80(plain)
    data=plain.read_bytes()
    (dbroot/'message'/'message_0.db').write_bytes(b''.join(encrypt(data[o:o+4096],o//4096+1) for o in range(0,len(data),4096)))
    (live/'synthetic-media.bin').write_bytes(bytes(range(256))*4096)
    keyring=root/'synthetic-keyring.json'
    write_json_new(keyring,{'databases':[{'relative_path':'message/message_0.db','verified':True,'raw_encryption_key_hex':KEY.hex()}]})
    initialize(root/'state',dbroot,keyring,source_id='ui-synthetic-only',account_alias='ui-synthetic-only',asset_root=live,self_username='wxid_synthetic_self')
    service=CaptureService(root/'state')
    try:service.capture(force=True,assets=True)
    finally:service.close()
    return root/'state'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    print(canonical({'synthetic_state':str(create(args.out))}))
