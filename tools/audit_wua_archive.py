"""Independently verify a frozen WUA archive using only the standard library.

Inputs are read-only and immutable, with nonempty WAL/journal files rejected.
No WUA implementation or private helper is imported. Original message values
and absolute input paths are never included in reports; source and failure
references are one-way SHA-256 labels. Reports require a new output path and
are exclusively created, never overwritten.

Run from the project root, for example:
    python tools/audit_wua_archive.py --archive archive.sqlite --output audit.json
Optional --baseline checks preservation of an older WUA archive. Repeat
--source-root SOURCE_ID=SQLITE_ROOT once per complete native decrypted tree.
The native check counts ordinary Msg tables, not custom FTS/media completeness.
Exit status: 0 passed, 1 completed with failed checks, 2 could not complete.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path
import re
import sqlite3
import sys
import time
import unicodedata


RULE = "wua-strong-1"
UNKNOWN = {"", "unknown", "null", "none", "?", "unresolved", "0", "-1", "n/a"}
SEMANTIC = ("archive_meta", "source_device", "source_snapshot", "message_observation",
            "logical_message", "message_link", "conflict", "dedupe_candidate")
MSG_TABLE = re.compile(r"Msg_[0-9a-fA-F]{32}\Z")
DECODE_LABELS = frozenset({
    "null", "sqlite-text", "unsupported-value-type", "input-size-limit",
    "unsupported-wcdb-compression", "decompressed-size-limit",
    "zstandard-unavailable", "invalid-zstd-or-utf8", "zstd-utf8",
    "blob-utf8", "unparsed-binary", "not_recorded",
})


def opaque_reference(kind, value):
    """Never echo an input identifier, even from a malformed archive."""
    payload = json.dumps([kind, value], ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), default=str)
    return kind + "_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def direction_label(value):
    return value if value in ("incoming", "outgoing", "unknown") else (
        "missing" if value is None else "other")


def decode_label(value):
    return value if isinstance(value, str) and value in DECODE_LABELS else "other"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def value_hash(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def open_frozen(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise ValueError("input must be a regular file")
    for suffix in ("-wal", "-journal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() and sidecar.stat().st_size:
            raise ValueError("input has an unfinished nonempty SQLite sidecar")
    connection = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA temp_store=MEMORY")
    return connection


def known(value):
    return value is not None and str(value).strip().lower() not in UNKNOWN


def stable(normalized):
    value = normalized.get("conversation_id")
    return (known(value) and normalized.get("conversation_id_is_stable") is not False
            and (normalized.get("conversation_id_is_stable") is True
                 or re.fullmatch(r"(?:wxid_|gh_).+|.+@chatroom", str(value)) is not None))


def anchor(row, normalized):
    fields = ("account_alias", "conversation_id", "sender_id", "direction", "message_type")
    if stable(normalized) and all(known(row[k]) for k in fields) and row["server_id"]:
        return tuple(row[k] for k in fields) + (row["server_id"],)
    return None


def time_value(value):
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        moment = datetime.fromtimestamp(value, timezone.utc)
    else:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def micros(value):
    if value is None:
        return None
    delta = datetime.fromisoformat(value.replace("Z", "+00:00")) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


def server_value(value):
    if not isinstance(value, bool) and (isinstance(value, int) or
            isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value)):
        return str(int(value)) if int(value) else None
    return None


def body_key(value):
    return " ".join(unicodedata.normalize("NFC", value).split()) if value else ""


class Audit:
    def __init__(self):
        self.checked = Counter()
        self.failed = Counter()
        self.samples = defaultdict(list)

    def check(self, name, condition, opaque_id=None):
        self.checked[name] += 1
        if not condition:
            self.failed[name] += 1
            if opaque_id and len(self.samples[name]) < 10:
                self.samples[name].append(opaque_reference("ref", opaque_id))

    def binary(self, value, opaque_id):
        if isinstance(value, dict):
            if set(value) == {"$wua_binary"}:
                try:
                    marker = value["$wua_binary"]
                    data = base64.b64decode(marker["data"], validate=True)
                    valid = (marker["encoding"] == "base64" and len(data) == marker["byte_length"]
                             and hashlib.sha256(data).hexdigest() == marker["sha256"])
                except (TypeError, KeyError, ValueError):
                    valid = False
                self.check("binary_marker_hash_length", valid, opaque_id)
            else:
                for item in value.values():
                    self.binary(item, opaque_id)
        elif isinstance(value, list):
            for item in value:
                self.binary(item, opaque_id)


def validate_observation(row, audit):
    oid = row["observation_id"]
    normalized = json.loads(row["normalized_json"])
    raw = json.loads(row["raw_record_json"])
    locator = json.loads(row["native_locator_json"])
    for key in ("normalized_json", "raw_record_json", "native_locator_json", "raw_time_json"):
        audit.check("canonical_json", canonical(json.loads(row[key])) == row[key], oid)
    audit.binary(raw, oid)
    audit.check("raw_record_hash", value_hash(raw) == row["row_hash"], oid)
    expected_oid = "obs_" + value_hash([row["snapshot_id"], row["db_relative_path"],
        row["table_name"], locator, row["row_hash"]])
    audit.check("observation_identity", expected_oid == oid, oid)
    audit.check("normalized_locator", normalized.get("native_locator") == locator, oid)
    audit.check("normalized_path_table", all(normalized.get(k) == row[k]
        for k in ("db_relative_path", "table_name")), oid)
    audit.check("normalized_time", time_value(normalized.get("event_time")) == row["event_time"], oid)
    audit.check("normalized_raw_time", canonical(normalized.get("raw_time")) == row["raw_time_json"], oid)
    audit.check("normalized_server_id", server_value(normalized.get("server_id")) == row["server_id"], oid)
    audit.check("normalized_text_fields", all(
        (None if normalized.get(k) is None else str(normalized[k])) == row[k]
        for k in ("account_alias", "conversation_id", "sender_id", "direction",
                  "time_unit", "message_type", "body_text")), oid)
    if normalized.get("adapter") == "weixin4-msg-1":
        audit.check("adapter_direction_vocabulary", row["direction"] in ("incoming", "outgoing", "unknown"), oid)
    anch = anchor(row, normalized)
    expected_lid = "msg_" + value_hash([RULE, "strong", anch] if anch else [RULE, "single", oid])
    audit.check("logical_identity", row["logical_id"] == expected_lid, oid)
    audit.check("link_strength", row["confidence"] == ("strong" if anch else "none")
        and row["rule_name"] == ("strong_server_identity" if anch else "unmerged_observation")
        and row["link_rule_version"] == RULE, oid)
    evidence = json.loads(row["evidence_json"])
    if anch:
        audit.check("link_anchor_evidence", evidence.get("strong_anchor") == dict(zip(
            ("account_alias", "conversation_id", "sender_id", "direction", "message_type", "server_id"), anch)), oid)
    else:
        audit.check("singleton_no_claimed_anchor", "strong_anchor" not in evidence, oid)
    return normalized, anch, evidence


def audit_archive(connection, audit):
    audit.check("quick_check", [r[0] for r in connection.execute("PRAGMA quick_check")] == ["ok"])
    audit.check("foreign_keys", not list(connection.execute("PRAGMA foreign_key_check")))
    meta = dict(connection.execute("SELECT key,value FROM archive_meta"))
    audit.check("versions", meta.get("schema_version") == "wua-observations-1" and meta.get("rule_version") == RULE)
    counts = {name: connection.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0] for name in SEMANTIC}
    audit.check("one_link_per_observation", counts["message_observation"] == counts["message_link"] and
        connection.execute("SELECT COUNT(*) FROM message_observation o LEFT JOIN message_link l USING(observation_id) WHERE l.observation_id IS NULL").fetchone()[0] == 0)
    for table, column in (("source_device", "source_id"), ("source_snapshot", "snapshot_id")):
        for row in connection.execute(f'SELECT * FROM "{table}"'):
            data = json.loads(row["metadata_json"])
            audit.check("metadata_identity", data.get(column) == row[column])
            if table == "source_snapshot" and "source_id" in data:
                audit.check("snapshot_source_identity", data["source_id"] == row["source_id"])
    metrics = Counter()
    directions = Counter()
    decode = Counter()
    source_counts = Counter()
    pair_overlaps = Counter()
    singleton_reasons = Counter()
    query = ("SELECT o.*,s.source_id,l.logical_id,l.confidence,l.rule_name,l.evidence_json,"
             "l.rule_version AS link_rule_version FROM message_observation o "
             "JOIN source_snapshot s USING(snapshot_id) JOIN message_link l USING(observation_id) "
             "ORDER BY l.logical_id,o.observation_id")
    for logical_id, group in itertools.groupby(connection.execute(query), lambda r: r["logical_id"]):
        rows = list(group)
        logical = connection.execute("SELECT * FROM logical_message WHERE logical_id=?", (logical_id,)).fetchone()
        audit.check("logical_exists", logical is not None, logical_id)
        source_set = set()
        snapshot_set = set()
        anchors = set()
        values = {field: defaultdict(list) for field in ("body_text", "event_time")}
        for row in rows:
            normalized, anch, evidence = validate_observation(row, audit)
            anchors.add(anch)
            directions[direction_label(row["direction"])] += 1
            decode[decode_label(normalized.get("body_decode_status", "not_recorded"))] += 1
            source_counts[row["source_id"]] += 1
            source_set.add(row["source_id"])
            snapshot_set.add(row["snapshot_id"])
            for field in values:
                values[field][canonical(row[field])].append(row["observation_id"])
            audit.check("representative_link_evidence", evidence.get("representative_rule") == "lexicographic_min_observation_id"
                and evidence.get("representative_observation_id") == rows[0]["observation_id"], row["observation_id"])
            if anch is None:
                if not known(row["direction"]):
                    singleton_reasons["unknown_direction"] += 1
                if not known(row["sender_id"]):
                    singleton_reasons["unknown_sender"] += 1
                if not stable(normalized):
                    singleton_reasons["unstable_or_unknown_conversation"] += 1
                if not row["server_id"]:
                    singleton_reasons["no_nonzero_integer_server_id"] += 1
        audit.check("group_uniform_strong_key", len(anchors) == 1 and (None not in anchors or len(rows) == 1), logical_id)
        metrics["logical_groups_examined"] += 1
        metrics["observations_examined"] += len(rows)
        metrics["cross_source_logical_groups"] += int(len(source_set) > 1)
        metrics["cross_source_bridge_links"] += len(source_set) - 1
        metrics["within_source_extra_observations"] += len(rows) - len(source_set)
        metrics["cross_snapshot_logical_groups"] += int(len(snapshot_set) > 1)
        metrics["singleton_groups"] += int(len(rows) == 1)
        for left, right in itertools.combinations(sorted(source_set), 2):
            pair_overlaps[(left, right)] += 1
        expected_conflicts = {}
        for field, groups in values.items():
            if len(groups) > 1:
                expected_conflicts[field] = [{"value": json.loads(value), "observation_ids": ids}
                    for value, ids in sorted(groups.items())]
        actual_conflicts = {r["field"]: json.loads(r["values_json"]) for r in connection.execute(
            "SELECT field,values_json FROM conflict WHERE logical_id=?", (logical_id,))}
        audit.check("conflicts_exhaustive_exact", expected_conflicts == actual_conflicts, logical_id)
        if expected_conflicts:
            metrics["logical_groups_with_conflicts"] += 1
            metrics["cross_source_groups_with_conflicts"] += int(len(source_set) > 1)
        for field in expected_conflicts:
            metrics["conflict_field_" + field] += 1
        if logical:
            audit.check("representative_min_id", logical["representative_observation_id"] == rows[0]["observation_id"], logical_id)
            audit.check("representative_fields", all(logical[k] == rows[0][k] for k in
                ("account_alias", "conversation_id", "sender_id", "direction", "event_time", "message_type", "server_id", "body_text")), logical_id)
            audit.check("logical_aggregate_counts", (logical["observation_count"], logical["source_count"], logical["snapshot_count"],
                logical["conflict_count"], logical["rule_version"]) == (len(rows), len(source_set), len(snapshot_set), len(expected_conflicts), RULE), logical_id)
        if metrics["logical_groups_examined"] % 20000 == 0:
            print("Audited logical groups:", metrics["logical_groups_examined"], flush=True)
    audit.check("all_logicals_visited", metrics["logical_groups_examined"] == counts["logical_message"])
    audit.check("all_observations_visited", metrics["observations_examined"] == counts["message_observation"])
    audit.check("duplicate_savings_decomposition", counts["message_observation"] - counts["logical_message"] ==
        metrics["cross_source_bridge_links"] + metrics["within_source_extra_observations"])
    candidate_levels = Counter()
    for candidate in connection.execute("SELECT * FROM dedupe_candidate ORDER BY candidate_id"):
        cid = candidate["candidate_id"]
        evidence = json.loads(candidate["evidence_json"])
        pair = [candidate["left_logical_id"], candidate["right_logical_id"]]
        witness = evidence.get("observation_ids", [])
        audit.check("candidate_never_automatic", evidence.get("automatic_merge") is False, cid)
        audit.check("candidate_versions_names", candidate["rule_version"] == RULE and
            candidate["rule_name"] == "same_normalized_body_narrow_time", cid)
        audit.check("candidate_pair_order", pair[0] < pair[1], cid)
        audit.check("candidate_identity", cid == "candidate_" + value_hash([RULE, pair, candidate["confidence"]]), cid)
        audit.check("candidate_witness_shape", len(witness) == 2 and witness == sorted(set(witness)), cid)
        if len(witness) != 2:
            continue
        members = list(connection.execute("SELECT o.*,l.logical_id FROM message_observation o JOIN message_link l USING(observation_id) WHERE o.observation_id IN (?,?) ORDER BY o.observation_id", witness))
        audit.check("candidate_witness_members", len(members) == 2 and sorted(r["logical_id"] for r in members) == pair, cid)
        if len(members) != 2:
            continue
        left, right = members
        left_n, right_n = (json.loads(r["normalized_json"]) for r in members)
        delta = None if left["event_time"] is None or right["event_time"] is None else abs(micros(left["event_time"]) - micros(right["event_time"]))
        audit.check("candidate_time_body_account", delta is not None and delta <= 2000000 and
            delta == evidence.get("time_delta_microseconds") and known(left["account_alias"]) and
            left["account_alias"] == right["account_alias"] and bool(body_key(left["body_text"])) and
            body_key(left["body_text"]) == body_key(right["body_text"]), cid)
        audit.check("candidate_noncontradictory_server", not (left["server_id"] and right["server_id"] and left["server_id"] != right["server_id"]), cid)
        audit.check("candidate_noncontradictory_conversation", not (stable(left_n) and stable(right_n)
            and left["conversation_id"] != right["conversation_id"]), cid)
        medium = stable(left_n) and stable(right_n) and all(known(left[k]) and left[k] == right[k]
            for k in ("conversation_id", "sender_id", "direction", "message_type"))
        audit.check("candidate_level", candidate["confidence"] == ("medium" if medium else "weak"), cid)
        candidate_levels[candidate["confidence"]] += 1
    server_splits = Counter()
    split_query = ("SELECT COUNT(DISTINCT o.sender_id),COUNT(DISTINCT o.direction),COUNT(DISTINCT o.message_type),"
        "SUM(l.confidence='none'),COUNT(DISTINCT s.source_id),COUNT(DISTINCT l.logical_id) "
        "FROM message_observation o JOIN message_link l USING(observation_id) JOIN source_snapshot s USING(snapshot_id) "
        "WHERE o.server_id IS NOT NULL GROUP BY o.account_alias,o.conversation_id,o.server_id "
        "HAVING COUNT(DISTINCT l.logical_id)>1")
    for senders, dirs, types, unanchored, sources, logicals in connection.execute(split_query):
        server_splits["groups"] += 1
        server_splits["sender_varies"] += int(senders > 1)
        server_splits["direction_varies"] += int(dirs > 1)
        server_splits["message_type_varies"] += int(types > 1)
        server_splits["includes_unanchored_observations"] += int(unanchored > 0)
        server_splits["spans_sources"] += int(sources > 1)
    digest = hashlib.sha256()
    for table in SEMANTIC:
        digest.update((canonical(table) + "\n").encode("utf-8"))
        for row in connection.execute(f'SELECT * FROM "{table}" ORDER BY 1,2'):
            digest.update((canonical(list(row)) + "\n").encode("utf-8"))
    return {"table_counts": counts, "merge_metrics": dict(metrics), "source_observation_counts": {opaque_reference("source", source): count for source, count in source_counts.items()},
            "direction_counts": dict(directions), "decode_status_counts": dict(decode),
            "unanchored_reasons_nonexclusive": dict(singleton_reasons), "candidate_confidence": dict(candidate_levels),
            "same_account_conversation_server_multiple_logical_groups": server_splits["groups"],
            "same_server_split_reasons_nonexclusive": dict(server_splits),
            "source_pair_overlap_logical_groups": [{"left_source": opaque_reference("source", p[0]), "right_source": opaque_reference("source", p[1]), "logical_groups": n}
                for p, n in sorted(pair_overlaps.items())], "semantic_digest": digest.hexdigest()}


def compare_baseline(connection, baseline_path, audit):
    before = file_hash(baseline_path)
    baseline = open_frozen(baseline_path)
    try:
        totals = Counter()
        for table, identity in (("source_device", "source_id"), ("source_snapshot", "snapshot_id"), ("message_observation", "observation_id")):
            columns = [r[1] for r in baseline.execute(f'PRAGMA table_info("{table}")')]
            query = f'SELECT * FROM "{table}" WHERE "{identity}"=?'
            for old in baseline.execute(f'SELECT * FROM "{table}" ORDER BY "{identity}"'):
                now = connection.execute(query, (old[identity],)).fetchone()
                audit.check("baseline_" + table + "_exact_preservation", now is not None and
                    all(old[c] == now[c] for c in columns), old[identity] if table == "message_observation" else None)
                totals[table] += 1
        after = file_hash(baseline_path)
        audit.check("baseline_file_hash_unchanged", before == after)
        return {"baseline_sha256": before, "unchanged": before == after, "rows_checked": dict(totals)}
    finally:
        baseline.close()


def native_counts(source_id, root, connection, audit):
    root = Path(root).resolve(strict=True)
    total = Counter()
    files = []
    archive_fingerprints = defaultdict(dict)
    for fingerprint, table, count in connection.execute(
        "SELECT json_extract(o.normalized_json,'$.input_database_sha256'),o.table_name,COUNT(*) "
        "FROM message_observation o JOIN source_snapshot s USING(snapshot_id) WHERE s.source_id=? "
        "GROUP BY json_extract(o.normalized_json,'$.input_database_sha256'),o.table_name", (source_id,)):
        archive_fingerprints[fingerprint][table] = count
    for path in sorted(root.rglob("*.db")):
        with path.open("rb") as handle:
            if handle.read(16) != b"SQLite format 3\x00":
                continue
        before = file_hash(path)
        native = open_frozen(path)
        try:
            tables = [r[0] for r in native.execute("SELECT name FROM sqlite_master WHERE type='table'") if MSG_TABLE.fullmatch(r[0])]
            native_table_counts = {name: native.execute('SELECT COUNT(*) FROM "' + name + '"').fetchone()[0]
                                   for name in tables}
            rows = sum(native_table_counts.values())
        finally:
            native.close()
        audit.check("native_frozen_hash_unchanged", file_hash(path) == before)
        total["sqlite_files_examined"] += 1
        total["message_tables"] += len(tables)
        total["message_rows"] += rows
        if tables:
            archive_table_counts = archive_fingerprints.get(before, {})
            audit.check("native_database_sha_bound_table_counts", archive_table_counts == native_table_counts)
            files.append({"sha256": before, "message_tables": len(tables), "message_rows": rows})
    archive_rows = connection.execute("SELECT COUNT(*) FROM message_observation o JOIN source_snapshot s USING(snapshot_id) WHERE s.source_id=?", (source_id,)).fetchone()[0]
    audit.check("native_source_sql_row_count", total["message_rows"] == archive_rows and total["message_tables"] > 0)
    return {"source_id": opaque_reference("source", source_id), "native_counts": dict(total), "archive_observations": archive_rows,
            "counts_match": total["message_rows"] == archive_rows, "message_databases": files}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--archive", type=Path, required=True,
                        help="Closed standalone WUA archive; opened read-only.")
    parser.add_argument("--baseline", type=Path,
                        help="Optional older WUA archive to compare without changing it.")
    parser.add_argument("--source-root", action="append", default=[],
                        metavar="SOURCE_ID=SQLITE_ROOT",
                        help="One complete decrypted ordinary SQLite tree per source.")
    parser.add_argument("--output", type=Path, required=True,
                        help="New JSON report path; existing files/symlinks are refused.")
    args = parser.parse_args(argv)
    try:
        # Check before reading potentially large inputs. Exclusive creation
        # below remains authoritative if another process creates the path.
        if args.output.exists() or args.output.is_symlink():
            print("Refusing to overwrite an existing --output path.", file=sys.stderr)
            return 2
        roots = []
        for item in args.source_root:
            if "=" not in item:
                raise ValueError("source-root format")
            source_id, root = item.split("=", 1)
            if not source_id or not root:
                raise ValueError("source-root format")
            roots.append((source_id, root))
        began = time.monotonic()
        initial = file_hash(args.archive)
        connection = open_frozen(args.archive)
        audit = Audit()
        try:
            summary = audit_archive(connection, audit)
            baseline = compare_baseline(connection, args.baseline, audit) if args.baseline else None
            native = [native_counts(source_id, root, connection, audit)
                      for source_id, root in roots]
        finally:
            connection.close()
        final = file_hash(args.archive)
        audit.check("archive_file_hash_unchanged", initial == final)
        report = {
            "schema": "independent-wua-archive-audit-1", "read_only": True,
            "input_sha256": initial, "input_sha256_after": final,
            "elapsed_seconds": round(time.monotonic() - began, 3),
            "scope": "Observed ordinary Msg tables only; not phone capture, media association, custom FTS completeness, or historical absence proof.",
            "identifier_policy": "Source and failure references are one-way SHA-256 labels; no original message values, database filenames, or absolute input paths.",
            "summary": summary, "baseline_preservation": baseline, "native_sql_counts": native,
            "checks_performed": dict(sorted(audit.checked.items())),
            "failed_check_counts": dict(sorted(audit.failed.items())),
            "failure_samples_opaque_ids_only": dict(audit.samples), "passed": not audit.failed,
        }
        payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(payload)
        print(json.dumps({
            "passed": report["passed"],
            "summary": {key: summary[key] for key in
                        ("table_counts", "merge_metrics", "candidate_confidence")},
            "failed_check_counts": report["failed_check_counts"],
            "elapsed_seconds": report["elapsed_seconds"],
        }, ensure_ascii=False, indent=2))
        return 0 if report["passed"] else 1
    except FileExistsError:
        print("Refusing to overwrite an existing --output path.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Audit interrupted; no input data was written.", file=sys.stderr)
        return 130
    except Exception as error:
        # Do not echo exception messages: malformed input can put message text
        # or private absolute paths into those messages.
        print("Audit could not complete (" + type(error).__name__ +
              "); input values and paths are omitted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

