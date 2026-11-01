"""Rebuildable narrow access index; never a new identity or merge decision."""
INDEX='next_viewer_representative_access'
COLUMNS=('representative_observation_id','logical_id','conflict_count')


def present(archive):
    row=archive._db.execute("SELECT tbl_name FROM sqlite_master WHERE type='index' AND name=?",(INDEX,)).fetchone()
    if row is None:return False
    if row[0]!='logical_record' or tuple(r[2] for r in archive._db.execute('PRAGMA index_info('+INDEX+')'))!=COLUMNS:
        raise ValueError('unexpected viewer access index; preserved for maintenance')
    return True


def ensure(archive):
    if present(archive):return dict(created=False)
    if archive.readonly:raise ValueError('viewer index creation requires the owned writer')
    db=archive._db;previous=db.execute('PRAGMA temp_store').fetchone()[0]
    try:
        db.execute('PRAGMA temp_store=MEMORY')
        with archive.transaction():db.execute('CREATE INDEX '+INDEX+' ON logical_record('+','.join(COLUMNS)+')')
    finally:db.execute('PRAGMA temp_store='+str(previous))
    return dict(created=True,scope='rebuildable_navigation_index_no_message_changes')
