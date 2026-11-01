"""Conservative changed-page -> affected-table planning; never a row watermark.

Both generations' dbstat ownership are consulted (including freed pages and
overflow). A schema/Name2Id change or any unknown page falls back to all tables.
Missing dbstat is a full-scan fallback, not a reduced-coverage success.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3

from .common import readonly_database


def changed_tables(previous, current):
    changed=set()
    with Path(previous).open("rb") as old,Path(current).open("rb") as new:
        number=0
        while True:
            left,right=old.read(4096),new.read(4096)
            if not left and not right:
                break
            number+=1
            if left!=right:
                changed.add(number)
    if not changed:
        return {"tables":[],"reason":"plaintext_identical","changed_pages":0}
    try:
        with closing(readonly_database(previous)) as left,closing(readonly_database(current)) as right:
            sql="SELECT type,name,tbl_name,rootpage,sql FROM sqlite_master ORDER BY type,name"
            schema_left=[tuple(row) for row in left.execute(sql)]
            schema_right=[tuple(row) for row in right.execute(sql)]
            if schema_left!=schema_right:
                return {"tables":None,"reason":"schema_changed","changed_pages":len(changed)}
            table_for={row[1]:row[2] for row in schema_right}
            table_for.update(sqlite_schema="sqlite_schema",sqlite_master="sqlite_schema")
            owners=set()
            covered=set()
            for db in (left,right):
                for name,number in db.execute("SELECT name,pageno FROM dbstat"):
                    if number in changed:
                        covered.add(number)
                        owners.add(table_for.get(name,name))
            if changed-covered:
                return {"tables":None,"reason":"unknown_changed_page","changed_pages":len(changed)}
            if "Name2Id" in owners:
                return {"tables":None,"reason":"identity_mapping_changed","changed_pages":len(changed)}
            message_tables={row[1] for row in schema_right if row[0]=="table" and row[1].startswith("Msg_")}
            return {"tables":sorted(message_tables & owners),"reason":"both_generation_page_ownership",
                    "changed_pages":len(changed)}
    except (OSError,sqlite3.DatabaseError):
        return {"tables":None,"reason":"page_planner_unavailable","changed_pages":len(changed)}
