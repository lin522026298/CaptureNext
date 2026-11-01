"""Deterministic SQLite archive core, with no network or third-party dependencies.

Adapters supply stable account/conversation identities, not display names. A
conversation is accepted as stable only when ``conversation_id_is_stable=True``
or it has a recognised wxid_/gh_/@chatroom form. Missing/unknown identities never
form automatic links. This deliberately favours false negatives over false
positive merges. The current rule has no alias-resolution or sequence alignment.

``raw_record`` must contain the complete original row, including its binary
columns. Binary values are losslessly represented by base64, length and SHA-256
in the stored JSON. Observation IDs bind the snapshot, relative database path,
table, native locator and raw-record hash. Reinterpreting an existing observation
with different normalised input is rejected; it must not silently overwrite it.

All derived state can be rebuilt from observations. No wall-clock timestamps
are written, and a completely repeated import/rebuild performs no data writes.
``semantic_digest`` is independent of ingestion order and optional FTS support;
it is not the physical SQLite file hash. Source coverage is always described as
observed rows, never as proof of a complete acquisition.
"""

from __future__ import annotations

import base64
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import sqlite3
from typing import Any
import unicodedata

SCHEMA_VERSION = "wua-observations-1"
RULE_VERSION = "wua-strong-1"
_UNKNOWN = {"", "unknown", "null", "none", "?", "unresolved", "0", "-1", "n/a"}
_DERIVED_TABLES = (
    "logical_message", "message_link", "conflict", "dedupe_candidate"
)


def _encode(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
        return {"$wua_binary": {
            "encoding": "base64", "data": base64.b64encode(data).decode("ascii"),
            "byte_length": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        }}
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite JSON numbers are not supported")
        return value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("raw/metadata JSON object keys must be strings")
        return {key: _encode(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_encode(item) for item in value]
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def _json(value: Any) -> str:
    return json.dumps(_encode(value), ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def _hash(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _known(value: Any) -> bool:
    return value is not None and str(value).strip().lower() not in _UNKNOWN


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list, tuple, bytes, bytearray, memoryview, bool)):
        raise TypeError("identity/type/body fields must be strings or numbers")
    return str(value)


def _identifier(metadata: Mapping[str, Any], key: str) -> str:
    value = metadata.get(key)
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("db_relative_path must be a relative path")
    path = value.replace("\\", "/")
    if path.startswith("/") or ":" in path or ".." in path.split("/"):
        raise ValueError("db_relative_path must not escape the source snapshot")
    result = str(PurePosixPath(path))
    if result == ".":
        raise ValueError("db_relative_path must identify a file")
    return result


def _event_time(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise TypeError("event_time must be UTC seconds or timezone-aware ISO-8601")
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ValueError("event_time must be finite")
        moment = datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, str):
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise ValueError("event_time ISO-8601 must contain an explicit timezone")
        moment = moment.astimezone(timezone.utc)
    else:
        raise TypeError("event_time must be UTC seconds or timezone-aware ISO-8601")
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _time_us(value: str | None) -> int | None:
    if value is None:
        return None
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    delta = moment - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _server_id(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int) or (isinstance(value, str) and
                                  re.fullmatch(r"[+-]?\d+", value)):
        integer = int(value)
        return str(integer) if integer else None
    return None


def _stable_conversation(row: Mapping[str, Any]) -> bool:
    value = row.get("conversation_id")
    if not _known(value) or row.get("conversation_id_is_stable") is False:
        return False
    return (row.get("conversation_id_is_stable") is True or
            bool(re.fullmatch(r"(?:wxid_|gh_).+|.+@chatroom", str(value))))


def _strong_key(row: Mapping[str, Any]) -> tuple[str, ...] | None:
    required = ("account_alias", "conversation_id", "sender_id", "direction", "message_type")
    if (not all(_known(row.get(key)) for key in required) or
            not _stable_conversation(json.loads(row["normalized_json"])) or
            not row.get("server_id")):
        return None
    return tuple(row[key] for key in required) + (row["server_id"],)


_SCHEMA = """
CREATE TABLE archive_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE source_device (
    source_id TEXT PRIMARY KEY, metadata_json TEXT NOT NULL
);
CREATE TABLE source_snapshot (
    snapshot_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES source_device(source_id),
    metadata_json TEXT NOT NULL
);
CREATE TABLE message_observation (
    observation_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES source_snapshot(snapshot_id),
    db_relative_path TEXT NOT NULL, table_name TEXT NOT NULL,
    native_locator_json TEXT NOT NULL, row_hash TEXT NOT NULL,
    raw_record_json TEXT NOT NULL, normalized_json TEXT NOT NULL,
    account_alias TEXT, conversation_id TEXT, sender_id TEXT, direction TEXT,
    event_time TEXT, raw_time_json TEXT NOT NULL, time_unit TEXT,
    message_type TEXT, server_id TEXT, body_text TEXT,
    UNIQUE(snapshot_id, db_relative_path, table_name, native_locator_json, row_hash)
);
CREATE INDEX observation_locator ON message_observation
    (snapshot_id, db_relative_path, table_name, native_locator_json);
CREATE INDEX observation_snapshot ON message_observation(snapshot_id);
CREATE TABLE logical_message (
    logical_id TEXT PRIMARY KEY,
    representative_observation_id TEXT NOT NULL REFERENCES message_observation(observation_id),
    account_alias TEXT, conversation_id TEXT, sender_id TEXT, direction TEXT,
    event_time TEXT, message_type TEXT, server_id TEXT, body_text TEXT,
    observation_count INTEGER NOT NULL, source_count INTEGER NOT NULL,
    snapshot_count INTEGER NOT NULL, conflict_count INTEGER NOT NULL,
    rule_version TEXT NOT NULL
);
CREATE INDEX logical_timeline ON logical_message(event_time, logical_id);
CREATE TABLE message_link (
    observation_id TEXT PRIMARY KEY REFERENCES message_observation(observation_id),
    logical_id TEXT NOT NULL REFERENCES logical_message(logical_id),
    rule_version TEXT NOT NULL, rule_name TEXT NOT NULL,
    confidence TEXT NOT NULL, evidence_json TEXT NOT NULL
);
CREATE INDEX link_logical ON message_link(logical_id);
CREATE VIEW dedupe_decision AS SELECT * FROM message_link;
CREATE TABLE conflict (
    logical_id TEXT NOT NULL REFERENCES logical_message(logical_id),
    field TEXT NOT NULL, values_json TEXT NOT NULL,
    rule_version TEXT NOT NULL, PRIMARY KEY(logical_id, field)
);
CREATE TABLE dedupe_candidate (
    candidate_id TEXT PRIMARY KEY,
    left_logical_id TEXT NOT NULL REFERENCES logical_message(logical_id),
    right_logical_id TEXT NOT NULL REFERENCES logical_message(logical_id),
    confidence TEXT NOT NULL, rule_name TEXT NOT NULL,
    evidence_json TEXT NOT NULL, rule_version TEXT NOT NULL,
    CHECK(left_logical_id < right_logical_id)
);
CREATE TRIGGER observation_no_update BEFORE UPDATE ON message_observation
BEGIN SELECT RAISE(ABORT, 'message_observation is immutable'); END;
CREATE TRIGGER observation_no_delete BEFORE DELETE ON message_observation
BEGIN SELECT RAISE(ABORT, 'message_observation is immutable'); END;
CREATE TRIGGER snapshot_no_update BEFORE UPDATE ON source_snapshot
BEGIN SELECT RAISE(ABORT, 'source_snapshot is immutable'); END;
CREATE TRIGGER snapshot_no_delete BEFORE DELETE ON source_snapshot
BEGIN SELECT RAISE(ABORT, 'source_snapshot is immutable'); END;
CREATE TRIGGER source_no_update BEFORE UPDATE ON source_device
BEGIN SELECT RAISE(ABORT, 'source_device is immutable'); END;
CREATE TRIGGER source_no_delete BEFORE DELETE ON source_device
BEGIN SELECT RAISE(ABORT, 'source_device is immutable'); END;
"""


class ArchiveStore:
    """Open/create a canonical archive; use ``readonly=True`` for a viewer.

    Metadata requires source_meta['source_id'] and snapshot_meta['snapshot_id'].
    Snapshot IDs are globally unique. Reusing an ID with different metadata is
    an error, not an implicit metadata update. A changed device descriptor can
    use a new source_id while retaining physical-device identity in its metadata.
    """

    def __init__(self, path: str | Path, *, readonly: bool = False):
        self.path = str(path)
        self.readonly = readonly
        if readonly:
            if self.path == ":memory:":
                raise ValueError("an in-memory archive cannot be opened readonly")
            uri = Path(path).resolve().as_uri() + "?mode=ro"
            self._db = sqlite3.connect(uri, uri=True, isolation_level=None)
        else:
            self._db = sqlite3.connect(self.path, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys=ON")
        try:
            exists = self._db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='archive_meta'"
            ).fetchone()
            if not exists:
                if readonly:
                    raise ValueError("not a WUA observation archive")
                # Do not initialise over a foreign database.
                if self._db.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
                    raise ValueError("refusing to initialise a non-empty foreign database")
                self._db.executescript("BEGIN IMMEDIATE;\n" + _SCHEMA)
                self._db.executemany("INSERT INTO archive_meta VALUES (?,?)", [
                    ("schema_version", SCHEMA_VERSION), ("rule_version", RULE_VERSION)])
                self._create_fts()
                self._db.execute("COMMIT")
            version = self._db.execute(
                "SELECT value FROM archive_meta WHERE key='schema_version'"
            ).fetchone()
            if version is None or version[0] != SCHEMA_VERSION:
                raise ValueError("unsupported WUA observation schema")
            version = self._db.execute(
                "SELECT value FROM archive_meta WHERE key='rule_version'"
            ).fetchone()
            if version is None or version[0] != RULE_VERSION:
                raise ValueError("unsupported WUA deduplication rule version")
            fts = self._db.execute(
                "SELECT sql FROM sqlite_master WHERE name='message_fts' AND type='table'"
            ).fetchone()
            self.fts_enabled = fts is not None
            self.fts_tokenizer = ("trigram" if fts and "trigram" in fts[0] else
                                  "unicode61" if fts else None)
        except BaseException:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            self._db.close()
            raise

    def _create_fts(self) -> None:
        for tokenizer in ("trigram", "unicode61"):
            try:
                self._db.execute(
                    "CREATE VIRTUAL TABLE message_fts USING fts5("
                    f"logical_id UNINDEXED, body_text, tokenize='{tokenizer}')")
                return
            except sqlite3.OperationalError as error:
                if "no such module" in str(error).lower():
                    return
                if "tokenizer" not in str(error).lower():
                    raise

    def _writable(self) -> None:
        if self.readonly:
            raise PermissionError("the archive was opened read-only")

    @staticmethod
    def _prepare_row(snapshot_id: str, row: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(row, Mapping) or "raw_record" not in row:
            raise ValueError("each observation requires its complete raw_record")
        required = ("db_relative_path", "table_name", "native_locator")
        if not all(key in row for key in required):
            raise ValueError("observation requires database path, table and native locator")
        if row["native_locator"] is None or row["native_locator"] == "":
            raise ValueError("native_locator must be present; zero and negative IDs are valid")
        table = row["table_name"]
        if not isinstance(table, str) or not table or "\x00" in table:
            raise ValueError("table_name must be a non-empty string")
        relative = _relative_path(row["db_relative_path"])
        raw_json = _json(row["raw_record"])
        row_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
        locator_json = _json(row["native_locator"])
        normalized = {key: value for key, value in row.items() if key != "raw_record"}
        normalized["db_relative_path"] = relative
        result = {
            "observation_id": "obs_" + _hash(
                [snapshot_id, relative, table, json.loads(locator_json), row_hash]),
            "snapshot_id": snapshot_id, "db_relative_path": relative, "table_name": table,
            "native_locator_json": locator_json, "row_hash": row_hash,
            "raw_record_json": raw_json, "normalized_json": _json(normalized),
            "event_time": _event_time(row.get("event_time")),
            "raw_time_json": _json(row.get("raw_time")),
            "server_id": _server_id(row.get("server_id")),
        }
        for key in ("account_alias", "conversation_id", "sender_id", "direction",
                    "time_unit", "message_type", "body_text"):
            result[key] = _text(row.get(key))
        return result

    def import_observations(self, source_meta: Mapping[str, Any],
                            snapshot_meta: Mapping[str, Any],
                            rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
        """Atomically import one snapshot batch and rebuild its derived state.

        A later batch may add old messages and revised raw rows at an existing
        locator. Nothing is truncated by time or local-ID high-water marks.
        Errors roll back metadata, observations and the logical layer together.
        """
        self._writable()
        source_id = _identifier(source_meta, "source_id")
        snapshot_id = _identifier(snapshot_meta, "snapshot_id")
        if ("source_id" in snapshot_meta and snapshot_meta["source_id"] != source_id):
            raise ValueError("snapshot source_id does not match source_meta")
        source_json, snapshot_json = _json(source_meta), _json(snapshot_meta)
        counts = {"input_rows": 0, "added_observations": 0,
                  "replayed_observations": 0, "revised_observations": 0,
                  "added_sources": 0, "added_snapshots": 0}
        self._db.execute("BEGIN IMMEDIATE")
        try:
            previous = self._db.execute(
                "SELECT metadata_json FROM source_device WHERE source_id=?", (source_id,)
            ).fetchone()
            if previous and previous[0] != source_json:
                raise ValueError("source metadata is immutable; use a new source_id")
            if not previous:
                self._db.execute("INSERT INTO source_device VALUES (?,?)", (source_id, source_json))
                counts["added_sources"] = 1
            previous = self._db.execute(
                "SELECT source_id,metadata_json FROM source_snapshot WHERE snapshot_id=?",
                (snapshot_id,)).fetchone()
            if previous and tuple(previous) != (source_id, snapshot_json):
                raise ValueError("snapshot metadata is immutable; use a new snapshot_id")
            if not previous:
                self._db.execute("INSERT INTO source_snapshot VALUES (?,?,?)",
                                 (snapshot_id, source_id, snapshot_json))
                counts["added_snapshots"] = 1
            for row in rows:
                counts["input_rows"] += 1
                prepared = self._prepare_row(snapshot_id, row)
                previous = self._db.execute(
                    "SELECT * FROM message_observation WHERE observation_id=?",
                    (prepared["observation_id"],)).fetchone()
                if previous:
                    if dict(previous) != prepared:
                        raise ValueError("existing raw observation has a different normalised interpretation")
                    counts["replayed_observations"] += 1
                    continue
                revised = self._db.execute(
                    "SELECT 1 FROM message_observation WHERE snapshot_id=? AND db_relative_path=? "
                    "AND table_name=? AND native_locator_json=? LIMIT 1",
                    (snapshot_id, prepared["db_relative_path"], prepared["table_name"],
                     prepared["native_locator_json"])).fetchone()
                counts["revised_observations"] += int(revised is not None)
                columns = ",".join(prepared)
                self._db.execute(
                    f"INSERT INTO message_observation ({columns}) VALUES ("
                    + ",".join("?" for _ in prepared) + ")", tuple(prepared.values()))
                counts["added_observations"] += 1
            rebuild = self._rebuild()
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        counts.update(rebuild)
        counts["idempotent_replay"] = not any(counts[key] for key in
            ("added_observations", "added_sources", "added_snapshots")) and not rebuild["rebuild_changed"]
        return counts

    def _desired_state(self) -> dict[str, list[tuple[Any, ...]]]:
        observations = [dict(row) for row in self._db.execute(
            "SELECT o.*,s.source_id FROM message_observation o JOIN source_snapshot s "
            "ON o.snapshot_id=s.snapshot_id ORDER BY o.observation_id")]
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in observations:
            anchor = _strong_key(row)
            identity = [RULE_VERSION, "strong", anchor] if anchor else [
                RULE_VERSION, "single", row["observation_id"]]
            logical_id = "msg_" + _hash(identity)
            row["_anchor"] = anchor
            row["_logical_id"] = logical_id
            groups[logical_id].append(row)
        desired: dict[str, list[tuple[Any, ...]]] = {name: [] for name in _DERIVED_TABLES}
        for logical_id, members in sorted(groups.items()):
            representative = members[0]  # observations are ordered by stable ID
            conflicts = []
            for field in ("body_text", "event_time"):
                values: dict[str, list[str]] = defaultdict(list)
                for member in members:
                    values[_json(member[field])].append(member["observation_id"])
                if len(values) > 1:
                    evidence = [{"value": json.loads(value), "observation_ids": ids}
                                for value, ids in sorted(values.items())]
                    conflicts.append((logical_id, field, _json(evidence), RULE_VERSION))
            desired["conflict"].extend(conflicts)
            values = [representative[key] for key in (
                "account_alias", "conversation_id", "sender_id", "direction", "event_time",
                "message_type", "server_id", "body_text")]
            desired["logical_message"].append(tuple([
                logical_id, representative["observation_id"], *values, len(members),
                len({row["source_id"] for row in members}),
                len({row["snapshot_id"] for row in members}), len(conflicts), RULE_VERSION]))
            for member in members:
                anchor = member["_anchor"]
                evidence = {"representative_rule": "lexicographic_min_observation_id",
                            "representative_observation_id": representative["observation_id"]}
                if anchor:
                    evidence["strong_anchor"] = dict(zip(("account_alias", "conversation_id",
                        "sender_id", "direction", "message_type", "server_id"), anchor))
                desired["message_link"].append((member["observation_id"], logical_id,
                    RULE_VERSION, "strong_server_identity" if anchor else "unmerged_observation",
                    "strong" if anchor else "none", _json(evidence)))
        desired["dedupe_candidate"] = self._candidates(observations)
        return {name: sorted(rows) for name, rows in desired.items()}

    @staticmethod
    def _candidates(observations: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
        # Bucketing and a narrow sliding time window avoid a corpus-wide N^2 scan.
        buckets: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = defaultdict(list)
        for row in observations:
            if not _known(row["account_alias"]) or not row["body_text"]:
                continue
            timestamp = _time_us(row["event_time"])
            if timestamp is None:
                continue
            body = " ".join(unicodedata.normalize("NFC", row["body_text"]).split())
            if body:
                buckets[(row["account_alias"], body)].append((timestamp, row))
        candidates: dict[str, tuple[Any, ...]] = {}
        for bucket in buckets.values():
            bucket.sort(key=lambda item: (item[0], item[1]["observation_id"]))
            left_bound = 0
            for right_index, (right_time, right) in enumerate(bucket):
                while bucket[left_bound][0] < right_time - 2_000_000:
                    left_bound += 1
                for left_time, left in bucket[left_bound:right_index]:
                    if left["_logical_id"] == right["_logical_id"]:
                        continue
                    if (left["server_id"] and right["server_id"] and
                            left["server_id"] != right["server_id"]):
                        continue
                    left_stable = _stable_conversation(json.loads(left["normalized_json"]))
                    right_stable = _stable_conversation(json.loads(right["normalized_json"]))
                    if (left_stable and right_stable and
                            left["conversation_id"] != right["conversation_id"]):
                        continue
                    medium = (left_stable and right_stable and all(
                        _known(left[key]) and left[key] == right[key] for key in
                        ("conversation_id", "sender_id", "direction", "message_type")))
                    confidence = "medium" if medium else "weak"
                    pair = sorted([left["_logical_id"], right["_logical_id"]])
                    candidate_id = "candidate_" + _hash([RULE_VERSION, pair, confidence])
                    # There may be many observation-pairs for a logical pair. A
                    # deterministic smallest witness is sufficient, not a merge.
                    evidence = _json({"observation_ids": sorted([
                        left["observation_id"], right["observation_id"]]),
                        "time_delta_microseconds": right_time - left_time,
                        "normalization": "NFC-and-collapsed-whitespace",
                        "automatic_merge": False})
                    candidate = (candidate_id, *pair, confidence,
                                 "same_normalized_body_narrow_time", evidence, RULE_VERSION)
                    if candidate_id not in candidates or candidate < candidates[candidate_id]:
                        candidates[candidate_id] = candidate
        return sorted(candidates.values())

    def _rebuild(self) -> dict[str, Any]:
        desired = self._desired_state()
        old = {name: sorted(tuple(row) for row in self._db.execute(f"SELECT * FROM {name}"))
               for name in _DERIVED_TABLES}
        changed = old != desired
        fts_rows = []
        fts_changed = False
        if self.fts_enabled:
            logical_for_observation = {row[0]: row[1] for row in desired["message_link"]}
            all_bodies: dict[str, set[str]] = defaultdict(set)
            for observation_id, body in self._db.execute(
                    "SELECT observation_id,body_text FROM message_observation"):
                if body:
                    all_bodies[logical_for_observation[observation_id]].add(body)
            fts_rows = [(logical_id, "\n".join(sorted(bodies)))
                        for logical_id, bodies in sorted(all_bodies.items())]
            fts_changed = fts_rows != [tuple(row) for row in self._db.execute(
                "SELECT logical_id,body_text FROM message_fts ORDER BY logical_id")]
        added_logical = len({row[0] for row in desired["logical_message"]} -
                            {row[0] for row in old["logical_message"]})
        if changed:
            for name in ("dedupe_candidate", "conflict", "message_link", "logical_message"):
                self._db.execute(f"DELETE FROM {name}")
            for name in _DERIVED_TABLES:
                if desired[name]:
                    placeholders = ",".join("?" for _ in desired[name][0])
                    self._db.executemany(f"INSERT INTO {name} VALUES ({placeholders})", desired[name])
        if fts_changed:
            self._db.execute("DELETE FROM message_fts")
            self._db.executemany("INSERT INTO message_fts VALUES (?,?)", fts_rows)
        return {"rebuild_changed": changed or fts_changed, "added_logical_messages": added_logical,
                "totals": self.stats()}

    def rebuild_logical(self, *, rule_version: str = RULE_VERSION) -> dict[str, Any]:
        """Reconstruct the entire logical layer; unsupported rules are rejected."""
        self._writable()
        if rule_version != RULE_VERSION:
            raise ValueError("unsupported deduplication rule version")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            result = self._rebuild()
            self._db.execute("COMMIT")
            return result
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    def stats(self) -> dict[str, Any]:
        counts = {name: self._db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                  for name, table in (("sources", "source_device"), ("snapshots", "source_snapshot"),
                      ("observations", "message_observation"), ("logical_messages", "logical_message"),
                      ("conflicts", "conflict"), ("candidates", "dedupe_candidate"))}
        counts["automatic_duplicate_links"] = counts["observations"] - counts["logical_messages"]
        counts["candidate_confidence"] = dict(self._db.execute(
            "SELECT confidence,COUNT(*) FROM dedupe_candidate GROUP BY confidence ORDER BY confidence"))
        counts["rule_version"] = RULE_VERSION
        return counts

    def list_messages(self, *, limit: int = 100, offset: int = 0,
                      account_alias: str | None = None, conversation_id: str | None = None,
                      source_id: str | None = None, snapshot_id: str | None = None,
                      sender_id: str | None = None, message_type: str | int | None = None,
                      since: Any = None, until: Any = None, search: str | None = None,
                      conflicts_only: bool = False) -> list[dict[str, Any]]:
        """Read-only, stable UTC timeline pagination; unknown times sort last.

        ``since`` is inclusive, ``until`` exclusive. Search is a literal substring
        over *all* observations, including conflicting nonrepresentative bodies.
        Trigram FTS is used for eligible strings when available, with LIKE as a
        literal verification. Short strings/special characters use LIKE alone.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer between 1 and 1000")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be a nonnegative integer")
        if search is not None and not isinstance(search, str):
            raise TypeError("search must be a string")
        conditions, parameters = [], []
        for name, value in (("account_alias", account_alias), ("conversation_id", conversation_id),
                            ("sender_id", sender_id), ("message_type", message_type)):
            if value is not None:
                conditions.append(f"m.{name}=?")
                parameters.append(str(value))
        if source_id is not None or snapshot_id is not None:
            source_conditions = ["l.logical_id=m.logical_id"]
            for name, value in (("s.source_id", source_id), ("s.snapshot_id", snapshot_id)):
                if value is not None:
                    source_conditions.append(name + "=?")
                    parameters.append(value)
            conditions.append("EXISTS (SELECT 1 FROM message_link l JOIN message_observation o "
                "ON l.observation_id=o.observation_id JOIN source_snapshot s ON o.snapshot_id=s.snapshot_id "
                "WHERE " + " AND ".join(source_conditions) + ")")
        for operator, value in ((">=", since), ("<", until)):
            if value is not None:
                conditions.append(f"m.event_time {operator} ?")
                parameters.append(_event_time(value))
        if conflicts_only:
            conditions.append("m.conflict_count > 0")
        if search:
            # Restrict acceleration to characters with exact trigram behaviour.
            if (self.fts_tokenizer == "trigram" and len(search) >= 3 and
                    re.fullmatch(r"[A-Za-z0-9\u4e00-\u9fff ]+", search)):
                conditions.append("m.logical_id IN (SELECT logical_id FROM message_fts "
                                  "WHERE message_fts MATCH ?)")
                parameters.append('"' + search + '"')
            literal = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            conditions.append("EXISTS (SELECT 1 FROM message_link sl JOIN message_observation so "
                "ON sl.observation_id=so.observation_id WHERE sl.logical_id=m.logical_id "
                "AND so.body_text LIKE ? ESCAPE '\\')")
            parameters.append("%" + literal + "%")
        query = "SELECT m.* FROM logical_message m"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += (" ORDER BY (m.event_time IS NULL),m.event_time,"
                  "m.representative_observation_id,m.logical_id LIMIT ? OFFSET ?")
        return [dict(row) for row in self._db.execute(query, [*parameters, limit, offset])]

    def get_observations(self, logical_id: str) -> list[dict[str, Any]]:
        """Expand source provenance, raw values, and the decision for one message."""
        rows = self._db.execute(
            "SELECT o.*,s.source_id,s.metadata_json AS snapshot_metadata_json,"
            "d.metadata_json AS source_metadata_json,l.rule_name,l.confidence,l.evidence_json "
            "FROM message_link l JOIN message_observation o ON l.observation_id=o.observation_id "
            "JOIN source_snapshot s ON o.snapshot_id=s.snapshot_id "
            "JOIN source_device d ON s.source_id=d.source_id "
            "WHERE l.logical_id=? ORDER BY o.observation_id", (logical_id,))
        result = []
        for row in rows:
            item = dict(row)
            for key, output in (("raw_record_json", "raw_record"),
                ("native_locator_json", "native_locator"), ("raw_time_json", "raw_time"),
                ("normalized_json", "normalized_input"), ("snapshot_metadata_json", "snapshot_meta"),
                ("source_metadata_json", "source_meta"), ("evidence_json", "dedupe_evidence")):
                item[output] = json.loads(item[key])
            result.append(item)
        return result

    def get_conflicts(self, logical_id: str | None = None) -> list[dict[str, Any]]:
        query, parameters = "SELECT * FROM conflict", []
        if logical_id is not None:
            query += " WHERE logical_id=?"
            parameters.append(logical_id)
        result = []
        for row in self._db.execute(query + " ORDER BY logical_id,field", parameters):
            item = dict(row)
            item["values"] = json.loads(item.pop("values_json"))
            result.append(item)
        return result

    def list_candidates(self, *, confidence: str | None = None, limit: int = 100,
                        offset: int = 0) -> list[dict[str, Any]]:
        if (isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000 or
                isinstance(offset, bool) or not isinstance(offset, int) or offset < 0):
            raise ValueError("invalid candidate pagination")
        if confidence not in (None, "medium", "weak"):
            raise ValueError("candidate confidence must be medium or weak")
        query, parameters = "SELECT * FROM dedupe_candidate", []
        if confidence is not None:
            query += " WHERE confidence=?"
            parameters.append(confidence)
        query += " ORDER BY candidate_id LIMIT ? OFFSET ?"
        result = []
        for row in self._db.execute(query, [*parameters, limit, offset]):
            item = dict(row)
            item["evidence"] = json.loads(item.pop("evidence_json"))
            result.append(item)
        return result

    def coverage(self) -> dict[str, Any]:
        """Observed-row matrix; absent rows do not prove absence in any device."""
        sources = []
        for row in self._db.execute(
            "SELECT s.*,d.metadata_json AS source_metadata_json,COUNT(o.observation_id) AS observation_count "
            "FROM source_snapshot s JOIN source_device d ON s.source_id=d.source_id "
            "LEFT JOIN message_observation o ON s.snapshot_id=o.snapshot_id "
            "GROUP BY s.snapshot_id ORDER BY s.source_id,s.snapshot_id"):
            sources.append({"source_id": row["source_id"], "snapshot_id": row["snapshot_id"],
                "source_meta": json.loads(row["source_metadata_json"]),
                "snapshot_meta": json.loads(row["metadata_json"]),
                "observation_count": row["observation_count"],
                "coverage_status": "observed_rows_only", "acquisition_completeness": "not_assessed"})
        matrix = [dict(row) for row in self._db.execute(
            "SELECT s.source_id,o.snapshot_id,o.account_alias,o.conversation_id,"
            "CASE WHEN o.event_time IS NULL THEN 'unknown' ELSE substr(o.event_time,1,7) END AS month_utc,"
            "o.message_type,COUNT(*) AS observations,COUNT(DISTINCT l.logical_id) AS logical_messages "
            "FROM message_observation o JOIN source_snapshot s ON o.snapshot_id=s.snapshot_id "
            "JOIN message_link l ON o.observation_id=l.observation_id "
            "GROUP BY s.source_id,o.snapshot_id,o.account_alias,o.conversation_id,month_utc,o.message_type "
            "ORDER BY s.source_id,o.snapshot_id,o.account_alias,o.conversation_id,month_utc,o.message_type")]
        return {"status": "observed_rows_only", "sources": sources, "matrix": matrix,
                "totals": self.stats(), "unparsed_rows": None,
                "caveat": "No completeness or source-absence inference is made from imported rows."}

    def semantic_digest(self) -> str:
        """SHA-256 over canonical ordered semantic tables, excluding FTS internals."""
        digest = hashlib.sha256()
        for name in ("archive_meta", "source_device", "source_snapshot", "message_observation",
                     *_DERIVED_TABLES):
            digest.update((_json(name) + "\n").encode("utf-8"))
            for row in self._db.execute(f"SELECT * FROM {name} ORDER BY 1,2"):
                digest.update((_json(list(row)) + "\n").encode("utf-8"))
        return digest.hexdigest()

    def integrity_check(self) -> dict[str, Any]:
        return {"quick_check": [row[0] for row in self._db.execute("PRAGMA quick_check")],
                "foreign_key_check": [tuple(row) for row in self._db.execute("PRAGMA foreign_key_check")]}

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "ArchiveStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
