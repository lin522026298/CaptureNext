"""Initialize from an already authorized legacy manifest without exposing identities.

The manifest, keyring and existing archives are opened read-only. This is an
operator convenience, not implicit account discovery inside the collector.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .common import canonical,directory
from .service import initialize


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state",required=True,type=Path)
    parser.add_argument("--manifest",required=True,type=Path)
    parser.add_argument("--keyring",required=True,type=Path)
    parser.add_argument("--data-parent",required=True,type=Path)
    parser.add_argument("--account-folder-sha256",required=True)
    args=parser.parse_args()
    manifest=json.loads(args.manifest.read_text(encoding="utf-8-sig"))
    matches=[item for item in directory(args.data_parent).iterdir() if item.is_dir() and
        hashlib.sha256(item.name.encode()).hexdigest().lower()==args.account_folder_sha256.lower()]
    if len(matches)!=1:
        raise ValueError("explicit account-folder digest did not select exactly one account")
    account=directory(matches[0])
    # The verified legacy self identity must also fit the selected account path.
    self_username=manifest.get("self_username")
    if not self_username or not account.name.startswith(self_username+"_"):
        raise ValueError("legacy self-identity does not match selected account directory")
    initialize(args.state,account/"db_storage",args.keyring,source_id="currentpc-capture-v2",
        account_alias=manifest["account_alias"],self_username=self_username,asset_root=account)
    print(canonical({"initialized":True,"account_binding_verified":True,"legacy_modified":False}))


if __name__=="__main__":
    main()
