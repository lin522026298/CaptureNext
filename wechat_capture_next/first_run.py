"""Portable first-run configuration; no account discovery or process access."""
import argparse
import json
from pathlib import Path

from .paths import local_absolute
from .service import initialize


def configure(root, database_root, keyring, *, account_alias, source_id,
              self_username=None, asset_root=None):
    root = local_absolute(root, allow_relative=True)
    if not root.is_dir():
        raise ValueError('existing local application directory required')
    database_root = local_absolute(database_root, allow_relative=True)
    if asset_root is None and database_root.name.casefold()=='db_storage':
        asset_root=database_root.parent
    asset_root = local_absolute(asset_root, allow_relative=True) if asset_root is not None else None
    # Every runtime/output directory lives beneath root. Protect the ENTIRE
    # live account, including sibling media/config files, before any write.
    for source in (database_root.parent, asset_root):
        if source is not None and (root.is_relative_to(source) or source.is_relative_to(root)):
            raise ValueError('application root must be separate from the complete source account')
    state = root / 'archives' / 'wechat-next' / 'state'
    # Fail before creating state if a running/recovered installation owns it.
    from .recovery_core import active_binding
    if active_binding(root / 'archives' / 'wechat-next'):
        raise ValueError('recovered installation already configured')
    if state.exists():
        raise FileExistsError('already configured; existing state is never replaced')
    for name in ('unified','provenance','active-binding.private.json'):
        if (state.parent/name).exists():
            raise FileExistsError('existing formal material cannot be adopted by first-run setup')
    for value in (account_alias, source_id):
        if not isinstance(value, str) or not value.strip() or len(value) > 200:
            raise ValueError('nonempty stable source and account aliases required')
    # These are local input paths, never copied into public distribution files.
    keyring = local_absolute(keyring, allow_relative=True)
    from .console import _file
    _file(keyring)
    # Otherwise an arbitrarily named original keyring could be scanned as an
    # attachment and re-enter keyless backups via the complete object store.
    if keyring.is_relative_to(database_root.parent) or (asset_root is not None and keyring.is_relative_to(asset_root)):
        raise ValueError('keep keyring outside the monitored source account')
    from wechat_capture_v2.common import safe_relative
    payload = json.loads(keyring.read_text(encoding='utf-8-sig'))
    entries = payload.get('databases') if isinstance(payload, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError('keyring must contain database entries')
    names = set()
    for entry in entries:
        relative = safe_relative(entry['relative_path'])
        if relative in names or entry.get('verified') is not True:
            raise ValueError('unique verified database key entries required')
        names.add(relative)
        if len(bytes.fromhex(entry['raw_encryption_key_hex'])) != 32:
            raise ValueError('32-byte raw database keys required')
        if not (database_root / relative).is_file():
            raise ValueError('keyring references unavailable source database')
    # No full capture or login is implicit in configuration. Actual capture
    # authenticates every page; a keyring's verified flag is not trusted proof.
    config = initialize(state, database_root, keyring, source_id=source_id,
        account_alias=account_alias, self_username=self_username, asset_root=asset_root)
    # Fresh installations have no pre-migration catalog/legacy-bag capsules.
    # Persist this distinction in backed-up configuration, rather than infer
    # that missing provenance on an existing installation is harmless.
    from .product_settings import atomic_json
    atomic_json(state/'config.private.json',dict(config,standalone_install=True))
    return {'configured': True, 'source_modified': False,
        'keys_local_only': True, 'capture_started': False}


def default_provenance(state, base):
    """Only an explicit new installation may omit legacy provenance inputs."""
    from .console import _file
    path = Path(state)/'config.private.json'
    if path.exists():
        _file(path)
        if json.loads(path.read_text(encoding='utf-8')).get('standalone_install') is True:
            return None
    return Path(base)/'provenance'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--database-root', type=Path)
    parser.add_argument('--keyring', type=Path)
    parser.add_argument('--account-alias')
    parser.add_argument('--source-id')
    parser.add_argument('--self-username')
    parser.add_argument('--asset-root', type=Path)
    args = parser.parse_args(argv)
    for name, prompt in (('database_root', 'WeChat db_storage directory'),
                        ('keyring', 'Authorized keyring JSON file'),
                        ('account_alias', 'Stable account alias (not nickname)'),
                        ('source_id', 'Unique source alias (this computer)')):
        if getattr(args, name) is None:
            value = input(prompt + ': ').strip().strip('"')
            setattr(args, name, Path(value) if name in ('database_root', 'keyring') else value)
    try:
        result = configure(**vars(args))
    except Exception as error:
        # Do not echo JSON, raw keys, account names, filesystem paths or traces.
        print(json.dumps({'configured': False, 'error_type': type(error).__name__}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
