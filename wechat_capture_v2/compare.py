"""Independent native-SQL comparison against the preserved legacy decoder.

This reader does not call Weixin4Database.observations or the collector's row
hash/normalization implementation when deriving the expected record set.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
import zlib

from tools.decrypt_weixin4_database import decrypt_copy

from .common import decoded, digest_file, readonly_database, safe_relative, utcnow, write_json_new


def exact_equal(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(exact_equal(left[k],right[k]) for k in left)
    if isinstance(left, float):
        return left.hex() == right.hex()
    return left == right


def compare_native(catalog, source_id, relative, baseline):
    db = readonly_database(baseline)
    report = {"baseline_database_sha256":digest_file(baseline),"expected_rows":0,"matched_rows":0,
              "missing_rows":0,"different_raw_rows":0,"message_tables":0,"samples_hashed":[]}
    try:
        for table, sql in db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"):
            if not re.fullmatch(r"Msg_[0-9a-fA-F]{32}",table):
                continue
            report["message_tables"] += 1
            quoted = '"' + table.replace('"','""') + '"'
            for record in db.execute("SELECT rowid AS __independent_rowid__,* FROM " + quoted + " ORDER BY rowid"):
                expected = dict(record)
                rowid = expected.pop("__independent_rowid__")
                locator = json.dumps({"rowid":rowid,"local_id":expected["local_id"]},sort_keys=True,separators=(",",":"))
                row = catalog.db.execute("""SELECT v.raw_z FROM head h JOIN version v ON v.id=h.version_id
                    WHERE h.source_id=? AND h.relative_path=? AND h.table_name=? AND h.locator_json=? AND h.active=1""",
                    (source_id,relative,table,locator)).fetchone()
                report["expected_rows"] += 1
                if row is None:
                    report["missing_rows"] += 1
                elif not exact_equal(decoded(json.loads(zlib.decompress(row[0]))), expected):
                    report["different_raw_rows"] += 1
                else:
                    report["matched_rows"] += 1
                    continue
                if len(report["samples_hashed"]) < 12:
                    report["samples_hashed"].append(hashlib.sha256((table+":"+locator).encode()).hexdigest())
        report["active_collected_rows"] = catalog.db.execute("SELECT count(*) FROM head WHERE source_id=? AND relative_path=? AND active=1",
                                                            (source_id,relative)).fetchone()[0]
        report["unexpected_active_rows"] = report["active_collected_rows"] - (report["expected_rows"] - report["missing_rows"])
        report["pass"] = (report["missing_rows"] == report["different_raw_rows"] == report["unexpected_active_rows"] == 0)
    finally:
        db.close()
    return report


def verify_legacy(service, output, *, cycle=None):
    """Fresh outputs only. Raw sources come from precisely the collector's cut.

    Comparing against a different wall-clock snapshot would conflate new
    messages with collector omissions. Each report binds the exact source cut.
    """
    output = service.validate_output(output)
    output.mkdir(parents=True,exist_ok=False)
    result = {"schema":"capture-legacy-comparison-1","started":utcnow(),"databases":[],"pass":True,
              "comparison_scope":"same_frozen_ciphertext_cut_full_native_rows","phone_completeness":False}
    query = """SELECT d.* FROM checkpoint c JOIN db_capture d ON d.id=c.capture_id
        WHERE c.source_id=? ORDER BY c.relative_path"""
    for row in service.catalog.db.execute(query,(service.config["source_id"],)):
        if cycle is not None and row["cycle_id"] != cycle:
            continue
        relative = safe_relative(row["relative_path"])
        evidence = json.loads(row["evidence_json"])
        if not evidence.get("authentication",{}).get("structured_readable"):
            result["databases"].append({"relative_path":relative,"status":"authenticated_raw_custom_runtime_unsupported",
                                        "plaintext_sha256":evidence.get("plaintext",{}).get("sha256")})
            continue
        name = hashlib.sha256(relative.encode()).hexdigest()
        folder = output / name
        folder.mkdir()
        main = folder / "source.db"
        service.objects.restore(evidence["raw"]["main"]["sha256"],main)
        wal = None
        if evidence["raw"].get("wal_committed"):
            wal = folder / "source.db-wal"
            service.objects.restore(evidence["raw"]["wal_committed"]["sha256"],wal)
        baseline = folder / "legacy.db"
        try:
            legacy = decrypt_copy(main,baseline,service.keys[relative],wal)
            compared = compare_native(service.catalog,service.config["source_id"],relative,baseline)
            compared.update(relative_path=relative,capture_id=row["id"],
                complete_plaintext_bytes_equal=(digest_file(baseline)==evidence["plaintext"]["sha256"]),
                legacy_all_pages_authenticated=legacy["raw_database"]["all_pages_hmac_sha512"])
            compared["pass"] = compared["pass"] and compared["complete_plaintext_bytes_equal"]
            result["databases"].append(compared)
            result["pass"] = result["pass"] and compared["pass"]
        except Exception as exc:
            result["pass"] = False
            result["databases"].append({"relative_path":relative,"pass":False,"error_type":type(exc).__name__,
                                        "detail_private":str(exc),"capture_id":row["id"]})
    result["finished"] = utcnow()
    result["expected_message_rows"] = sum(row.get("expected_rows",0) for row in result["databases"])
    result["matched_message_rows"] = sum(row.get("matched_rows",0) for row in result["databases"])
    if not result["databases"]:
        result["pass"] = False
        result["error_type"] = "no_database_captures_to_compare"
    write_json_new(output / "COMPARISON.json",result)
    return result
