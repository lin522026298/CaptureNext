"""Independent repository metadata listings, never a payload health claim."""
from contextlib import closing


def _legacy(path):
    from . import union_backup as backup
    from .backup import _readonly
    repository, owner = backup._repository(path)
    with closing(_readonly(repository / backup.DATABASE, immutable=False)) as db:
        backup._check(db, owner)
        rows = []
        for ident, created in db.execute('SELECT id,created FROM snapshot ORDER BY rowid DESC'):
            backup._manifest(db, ident, owner)
            rows.append(dict(snapshot_id=ident, created=created, repository='legacy',
                             pinned=True, legacy_protected=True,includes_secrets=None,provenance_included=None,
                             materials_scope='legacy_union_metadata_only_pair_state_required'))
        return rows


def listing(core):
    rows, repositories = [], {}
    for name, path in (('rolling', core.paired_repository), ('legacy', core.union_repository)):
        if path is None or not path.exists():
            repositories[name] = dict(status='absent', contents_verified=False)
            continue
        try:
            if name == 'rolling':
                from .pair_repository import snapshots
                found = [dict(row, repository=name, created=row['verified_at']) for row in snapshots(path)]
            else:
                found = _legacy(path)
            rows.extend(found)
            repositories[name] = dict(status='listed', snapshots=len(found), contents_verified=False)
        except Exception as error:
            # One inaccessible/corrupt repository must not hide healthy ones.
            # No raw exception text, source paths, or archived content in UI.
            repositories[name] = dict(status='unavailable', error_type=type(error).__name__,
                contents_verified=False, next_step='保留该仓库，不自动清理；可先选择另一健康仓库的恢复点，并检查故障仓库。')
    return dict(snapshots=rows, repositories=repositories, contents_verified=False,
                integrity_scope='manifest_metadata_only_not_restore_verification')
