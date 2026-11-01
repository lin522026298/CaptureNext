#!/usr/bin/env python3
"""Independently verify a Weixin 4.x raw database key and decrypted SQLite."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import struct

try:
    from .sqlite_wal import audit_wal
except ImportError:
    from sqlite_wal import audit_wal


PAGE_SIZE = 4096
SALT_SIZE = 16
RESERVE_SIZE = 80
HMAC_SIZE = 64
WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def derive_mac_key(raw_key: bytes, database_salt: bytes) -> bytes:
    mac_salt = bytes(value ^ 0x3A for value in database_salt)
    return hashlib.pbkdf2_hmac("sha512", raw_key, mac_salt, 2, dklen=32)


def page_hmac_matches(
    page: bytes, page_number: int, raw_key: bytes, database_salt: bytes
) -> bool:
    if len(page) != PAGE_SIZE or len(raw_key) != 32 or len(database_salt) != 16:
        return False
    payload_start = SALT_SIZE if page_number == 1 else 0
    digest = hmac.new(
        derive_mac_key(raw_key, database_salt),
        page[payload_start : PAGE_SIZE - HMAC_SIZE],
        hashlib.sha512,
    )
    digest.update(struct.pack("<I", page_number))
    return hmac.compare_digest(digest.digest(), page[PAGE_SIZE - HMAC_SIZE :])


def load_key(keyring: Path, database_relative_path: str) -> tuple[bytes, dict]:
    payload = json.loads(keyring.read_text(encoding="utf-8-sig"))
    matches = [
        row
        for row in payload.get("databases", [])
        if row.get("relative_path") == database_relative_path
        and row.get("verified")
        and row.get("raw_encryption_key_hex")
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one verified key entry, got {len(matches)}")
    key_hex = matches[0]["raw_encryption_key_hex"]
    if len(key_hex) != 64:
        raise ValueError("raw key is not 32 bytes")
    return bytes.fromhex(key_hex), matches[0]


def verify_main_database(database: Path, raw_key: bytes) -> dict:
    size = database.stat().st_size
    if size < PAGE_SIZE or size % PAGE_SIZE:
        raise ValueError("database size is not a positive multiple of 4096")
    page_count = size // PAGE_SIZE
    failed_pages = []
    with database.open("rb") as handle:
        first_page = handle.read(PAGE_SIZE)
        salt = first_page[:SALT_SIZE]
        if not page_hmac_matches(first_page, 1, raw_key, salt):
            failed_pages.append(1)
        for page_number in range(2, page_count + 1):
            page = handle.read(PAGE_SIZE)
            if not page_hmac_matches(page, page_number, raw_key, salt):
                failed_pages.append(page_number)
    return {
        "bytes": size,
        "sha256": sha256_file(database),
        "salt_hex": salt.hex(),
        "page_count": page_count,
        "hmac_sha512_failed_pages": failed_pages,
        "all_pages_hmac_sha512": not failed_pages,
    }


def inspect_wal(wal: Path | None, raw_key: bytes, database_salt: bytes) -> dict:
    if wal is None or not wal.is_file():
        return {"present": False}
    blob = wal.read_bytes()
    return {"present": True, "bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest(),
            **audit_wal(blob, PAGE_SIZE,
                        lambda page, number: page_hmac_matches(page, number, raw_key, database_salt))}


def inspect_sqlite(database: Path) -> dict:
    uri = database.resolve().as_uri() + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        cursor = connection.cursor()
        quick_check = [row[0] for row in cursor.execute("PRAGMA quick_check")]
        tables = [
            row[0]
            for row in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        row_counts = {}
        for table in tables:
            quoted = table.replace('"', '""')
            row_counts[table] = cursor.execute(
                f'SELECT count(*) FROM "{quoted}"'
            ).fetchone()[0]
        object_count = cursor.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
        return {
            "bytes": database.stat().st_size,
            "sha256": sha256_file(database),
            "sqlite_master_object_count": object_count,
            "table_count": len(tables),
            "table_row_counts": row_counts,
            "total_rows": sum(row_counts.values()),
            "quick_check": quick_check,
            "pass": quick_check == ["ok"],
        }
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keyring", required=True, type=Path)
    parser.add_argument("--database-relative-path", required=True)
    parser.add_argument("--raw-database", required=True, type=Path)
    parser.add_argument("--wal", type=Path)
    parser.add_argument("--decrypted-database", required=True, type=Path)
    args = parser.parse_args()

    raw_key, key_entry = load_key(args.keyring, args.database_relative_path)
    main_result = verify_main_database(args.raw_database, raw_key)
    wal_result = inspect_wal(args.wal, raw_key, bytes.fromhex(main_result["salt_hex"]))
    sqlite_result = inspect_sqlite(args.decrypted_database)
    result = {
        "database_relative_path": args.database_relative_path,
        "key_entry_verified": bool(key_entry.get("verified")),
        "key_material_in_output": False,
        "keyring_salt_matches_database": key_entry.get("salt_hex")
        == main_result["salt_hex"],
        "raw_database": main_result,
        "wal": wal_result,
        "decrypted_database": sqlite_result,
    }
    result["pass"] = (
        result["key_entry_verified"]
        and result["keyring_salt_matches_database"]
        and main_result["all_pages_hmac_sha512"]
        and not wal_result.get("hmac_failed_frames", [])
        and (not wal_result.get("present") or wal_result.get("pass", False))
        and sqlite_result["pass"]
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
