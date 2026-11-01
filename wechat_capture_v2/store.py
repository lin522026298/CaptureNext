"""Append-only message versions plus transactional full-scan checkpoints.

    No maximum message/time/sequence watermarks are used to select rows.
    Every changed shard is scanned to exhaustion; interrupted scans roll back.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid
import zlib

from wua.weixin4 import Weixin4Database

from .common import canonical, decoded, encoded, utcnow

SCHEMA = "wechat-capture-v2-1"


class Catalog:
    def __init__(self, path):
        self.path = Path(path)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS cycle(id TEXT PRIMARY KEY,started TEXT NOT NULL,finished TEXT,
            mode TEXT NOT NULL,status TEXT NOT NULL,report_json TEXT);
        CREATE TABLE IF NOT EXISTS db_capture(id TEXT PRIMARY KEY,cycle_id TEXT NOT NULL REFERENCES cycle(id),
            source_id TEXT NOT NULL,relative_path TEXT NOT NULL,signature TEXT NOT NULL,
            evidence_json TEXT NOT NULL,message_count INTEGER NOT NULL,accepted TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS checkpoint(source_id TEXT NOT NULL,relative_path TEXT NOT NULL,
            capture_id TEXT NOT NULL REFERENCES db_capture(id),signature TEXT NOT NULL,stamp_json TEXT NOT NULL,
            PRIMARY KEY(source_id,relative_path));
        CREATE TABLE IF NOT EXISTS version(id TEXT PRIMARY KEY,source_id TEXT NOT NULL,account TEXT NOT NULL,
            relative_path TEXT NOT NULL,table_name TEXT NOT NULL,locator_json TEXT NOT NULL,row_hash TEXT NOT NULL,
            raw_z BLOB NOT NULL,normalized_json TEXT NOT NULL,first_capture TEXT NOT NULL REFERENCES db_capture(id));
        CREATE TABLE IF NOT EXISTS head(source_id TEXT NOT NULL,relative_path TEXT NOT NULL,table_name TEXT NOT NULL,
            locator_json TEXT NOT NULL,version_id TEXT NOT NULL REFERENCES version(id),capture_id TEXT NOT NULL,
            active INTEGER NOT NULL,PRIMARY KEY(source_id,relative_path,table_name,locator_json));
        CREATE INDEX IF NOT EXISTS head_capture ON head(capture_id);
        CREATE TABLE IF NOT EXISTS interpretation(version_id TEXT NOT NULL REFERENCES version(id),
            normalization_hash TEXT NOT NULL,normalized_json TEXT NOT NULL,
            first_capture TEXT NOT NULL REFERENCES db_capture(id),PRIMARY KEY(version_id,normalization_hash));
        CREATE TABLE IF NOT EXISTS interpretation_head(version_id TEXT PRIMARY KEY REFERENCES version(id),
            normalization_hash TEXT NOT NULL,capture_id TEXT NOT NULL REFERENCES db_capture(id));
        CREATE INDEX IF NOT EXISTS head_active ON head(active);
        CREATE INDEX IF NOT EXISTS cycle_status ON cycle(status);
        CREATE INDEX IF NOT EXISTS version_first_capture ON version(first_capture);
        CREATE INDEX IF NOT EXISTS interpretation_first_capture ON interpretation(first_capture);
        CREATE TABLE IF NOT EXISTS transition(id INTEGER PRIMARY KEY,capture_id TEXT NOT NULL REFERENCES db_capture(id),
            version_id TEXT NOT NULL REFERENCES version(id),kind TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS asset(source_id TEXT NOT NULL,relative_path TEXT NOT NULL,file_sha TEXT NOT NULL,
            bytes INTEGER NOT NULL,stamp_json TEXT NOT NULL,cycle_id TEXT NOT NULL,
            PRIMARY KEY(source_id,relative_path));
        CREATE TABLE IF NOT EXISTS asset_history(source_id TEXT NOT NULL,relative_path TEXT NOT NULL,file_sha TEXT NOT NULL,
            bytes INTEGER NOT NULL,cycle_id TEXT NOT NULL,PRIMARY KEY(source_id,relative_path,file_sha));
        CREATE TRIGGER IF NOT EXISTS version_no_update BEFORE UPDATE ON version
            BEGIN SELECT RAISE(ABORT,'raw versions are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS version_no_delete BEFORE DELETE ON version
            BEGIN SELECT RAISE(ABORT,'raw versions are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS interpretation_no_update BEFORE UPDATE ON interpretation
            BEGIN SELECT RAISE(ABORT,'interpretations are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS interpretation_no_delete BEFORE DELETE ON interpretation
            BEGIN SELECT RAISE(ABORT,'interpretations are immutable'); END;
        """)
        self.db.execute("INSERT OR IGNORE INTO meta VALUES('schema',?)", (SCHEMA,))
        self.db.commit()
        if self.db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()[0] != SCHEMA:
            raise ValueError("unsupported capture catalog schema")

    def begin_cycle(self, mode):
        ident = uuid.uuid4().hex
        with self.db:
            self.db.execute("INSERT INTO cycle VALUES(?,?,NULL,?,'running',NULL)", (ident, utcnow(), mode))
        return ident

    def finish_cycle(self, ident, report):
        with self.db:
            self.db.execute("UPDATE cycle SET finished=?,status=?,report_json=? WHERE id=?",
                            (utcnow(), report["status"], canonical(report), ident))

    def checkpoint(self, source_id, relative):
        row = self.db.execute("SELECT * FROM checkpoint WHERE source_id=? AND relative_path=?", (source_id, relative)).fetchone()
        return dict(row) if row else None

    def ingest(self, *, cycle, source_id, account, relative, path, evidence, signature, stamp_value,
               self_username=None, fail_after=None, selected_tables=None):
        capture = uuid.uuid4().hex
        stats = Counter(rows=0, new_versions=0, changed_heads=0, unchanged_heads=0, disappeared_heads=0)
        # Exact source identity cannot silently switch under an existing account.
        with self.db:
            # Presence belongs to this source scan, not a rewrite of every
            # unchanged persistent head. The checkpoint proves last observation;
            # head.capture_id denotes its last write (historical rows may predate
            # this optimization), not necessarily its latest source observation.
            self.db.execute('CREATE TEMP TABLE IF NOT EXISTS scan_seen(table_name TEXT NOT NULL,locator_json TEXT NOT NULL,PRIMARY KEY(table_name,locator_json)) WITHOUT ROWID')
            self.db.execute('DELETE FROM scan_seen')
            self.db.execute("INSERT INTO db_capture VALUES(?,?,?,?,?,?,0,?)",
                (capture, cycle, source_id, relative, signature, canonical(evidence), utcnow()))
            with Weixin4Database(path, db_relative_path=relative, account_alias=account,
                                 self_username=self_username) as reader:
                # Only the new reader instance is filtered; legacy source and
                # its complete-schema fingerprint are never modified.
                if selected_tables is not None:
                    selected_tables=set(selected_tables)
                    reader.schemas={name:sql for name,sql in reader.schemas.items() if name in selected_tables}
                for item in reader.observations():
                    raw = canonical(encoded(item["raw_record"]))
                    row_hash = hashlib.sha256(raw.encode()).hexdigest()
                    locator = canonical(item["native_locator"])
                    table = item["table_name"]
                    self.db.execute('INSERT INTO scan_seen VALUES(?,?)',(table,locator))
                    ident = hashlib.sha256(canonical([source_id,account,relative,table,locator,row_hash]).encode()).hexdigest()
                    normalized = {key: val for key, val in item.items() if key not in
                        ("raw_record", "input_database_sha256", "input_schema_sha256")}
                    normalized_json=canonical(normalized)
                    exists=self.db.execute("""SELECT coalesce(i.normalized_json,v.normalized_json) FROM version v
                        LEFT JOIN interpretation_head h ON h.version_id=v.id
                        LEFT JOIN interpretation i ON i.version_id=h.version_id AND i.normalization_hash=h.normalization_hash
                        WHERE v.id=?""",(ident,)).fetchone()
                    changed=0
                    if exists is None:
                        changed = self.db.execute("INSERT INTO version VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (ident,source_id,account,relative,table,locator,row_hash,zlib.compress(raw.encode(),1),
                             normalized_json,capture)).rowcount
                    reinterpreted=exists is not None and exists[0]!=normalized_json
                    if reinterpreted:
                        normal_hash=hashlib.sha256(normalized_json.encode()).hexdigest()
                        self.db.execute("INSERT OR IGNORE INTO interpretation VALUES(?,?,?,?)",
                                        (ident,normal_hash,normalized_json,capture))
                        self.db.execute("""INSERT INTO interpretation_head VALUES(?,?,?) ON CONFLICT(version_id)
                            DO UPDATE SET normalization_hash=excluded.normalization_hash,capture_id=excluded.capture_id""",
                                        (ident,normal_hash,capture))
                        stats['new_interpretations']+=1
                    stats["new_versions"] += changed
                    old = self.db.execute("SELECT version_id,active FROM head WHERE source_id=? AND relative_path=? AND table_name=? AND locator_json=?",
                                          (source_id,relative,table,locator)).fetchone()
                    kind = "new" if old is None else "changed" if old[0] != ident else "reappeared" if not old[1] else "unchanged"
                    if kind == "unchanged" and reinterpreted:
                        kind = "reinterpreted"
                    if kind != "unchanged":
                        self.db.execute("INSERT INTO transition(capture_id,version_id,kind) VALUES(?,?,?)", (capture,ident,kind))
                        stats["changed_heads"] += 1
                    else:
                        stats["unchanged_heads"] += 1
                    if kind!='unchanged':
                        self.db.execute("""INSERT INTO head VALUES(?,?,?,?,?,?,1) ON CONFLICT(source_id,relative_path,table_name,locator_json)
                            DO UPDATE SET version_id=excluded.version_id,capture_id=excluded.capture_id,active=1""",
                            (source_id,relative,table,locator,ident,capture))
                    stats["rows"] += 1
                    if fail_after is not None and stats["rows"] >= fail_after:
                        raise RuntimeError("synthetic interrupted scan")
                reader_report = reader.report()
                evidence={**evidence,"reader":reader_report}
                self.db.execute("UPDATE db_capture SET evidence_json=? WHERE id=?",(canonical(evidence),capture))
            self.db.execute("CREATE TEMP TABLE IF NOT EXISTS scan_tables(name TEXT PRIMARY KEY)")
            self.db.execute("DELETE FROM scan_tables")
            if selected_tables is None:
                self.db.execute("INSERT INTO scan_tables SELECT DISTINCT table_name FROM head WHERE source_id=? AND relative_path=?",(source_id,relative))
            else:
                self.db.executemany("INSERT INTO scan_tables VALUES(?)",((name,) for name in selected_tables))
            stats["disappeared_heads"] = self.db.execute("""INSERT INTO transition(capture_id,version_id,kind)
                SELECT ?,version_id,'disappeared' FROM head WHERE source_id=? AND relative_path=? AND active=1
                    AND NOT EXISTS(SELECT 1 FROM scan_seen s WHERE s.table_name=head.table_name AND s.locator_json=head.locator_json)
                    AND table_name IN(SELECT name FROM scan_tables)""",
                (capture,source_id,relative)).rowcount
            self.db.execute("""UPDATE head SET active=0,capture_id=? WHERE source_id=? AND relative_path=? AND active=1
                AND NOT EXISTS(SELECT 1 FROM scan_seen s WHERE s.table_name=head.table_name AND s.locator_json=head.locator_json)
                AND table_name IN(SELECT name FROM scan_tables)""",
                            (capture,source_id,relative))
            active=self.db.execute("SELECT count(*) FROM head WHERE source_id=? AND relative_path=? AND active=1",(source_id,relative)).fetchone()[0]
            self.db.execute("UPDATE db_capture SET message_count=? WHERE id=?", (active,capture))
            self.db.execute("""INSERT INTO checkpoint VALUES(?,?,?,?,?) ON CONFLICT(source_id,relative_path)
                DO UPDATE SET capture_id=excluded.capture_id,signature=excluded.signature,stamp_json=excluded.stamp_json""",
                (source_id,relative,capture,signature,canonical(stamp_value)))
        return {"capture_id":capture, **stats, "reader":reader_report}

    def raw_only(self, *, cycle, source_id, relative, signature, evidence, stamp_value):
        capture = uuid.uuid4().hex
        with self.db:
            self.db.execute("INSERT INTO db_capture VALUES(?,?,?,?,?,?,0,?)",
                (capture,cycle,source_id,relative,signature,canonical(evidence),utcnow()))
            self.db.execute("""INSERT INTO checkpoint VALUES(?,?,?,?,?) ON CONFLICT(source_id,relative_path)
                DO UPDATE SET capture_id=excluded.capture_id,signature=excluded.signature,stamp_json=excluded.stamp_json""",
                (source_id,relative,capture,signature,canonical(stamp_value)))
        return {"capture_id":capture,"rows":0,"new_versions":0,"raw_authenticated_only":True}

    def summary(self,ignore_cycle=None):
        return {"versions":self.db.execute("SELECT count(*) FROM version").fetchone()[0],
                "active_messages":self.db.execute("SELECT count(*) FROM head WHERE active=1").fetchone()[0],
                "captures":self.db.execute("SELECT count(*) FROM db_capture").fetchone()[0],
                "assets":self.db.execute("SELECT count(*) FROM asset").fetchone()[0],
                "running_or_interrupted_cycles":self.db.execute("SELECT count(*) FROM cycle WHERE status IN ('running','interrupted') AND (? IS NULL OR id!=?)",(ignore_cycle,ignore_cycle)).fetchone()[0]}

    def versions(self):
        for row in self.db.execute("""SELECT v.*,coalesce(i.normalized_json,v.normalized_json) AS latest_normalized
                FROM version v LEFT JOIN interpretation_head h ON h.version_id=v.id
                LEFT JOIN interpretation i ON i.version_id=h.version_id AND i.normalization_hash=h.normalization_hash
                ORDER BY v.first_capture,v.id"""):
            normalized = json.loads(row["latest_normalized"])
            normalized["raw_record"] = decoded(json.loads(zlib.decompress(row["raw_z"])))
            normalized["capture_id"] = row["first_capture"]
            normalized["source_id"] = row["source_id"]
            yield normalized

    def close(self):
        self.db.close()
