#!/usr/bin/env python3
"""Read-only probes for an old WeChat 3.x delivery.

The tool inspects a plaintext SQLite metadata database and can test bounded
32-byte candidate material against an encrypted ``MicroMsg.db`` first page.
It never modifies the supplied databases or candidate files.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
import struct
from typing import Any, Iterable


PAGE_SIZE = 4096
RESERVED_SIZE = 48
HEX_KEY = re.compile(rb"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64})(?![0-9A-Fa-f])")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def first_page_hmac_matches(key: bytes, first_page: bytes) -> bool:
    """Validate a 32-byte key using the WeChat SQLCipher 3 page-one HMAC."""
    if len(key) != 32 or len(first_page) != PAGE_SIZE:
        return False
    salt = first_page[:16]
    encryption_key = hashlib.pbkdf2_hmac("sha1", key, salt, 64_000, 32)
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha1", encryption_key, mac_salt, 2, 32)
    digest = hmac.new(
        mac_key,
        first_page[16 : PAGE_SIZE - RESERVED_SIZE],
        hashlib.sha1,
    )
    digest.update(struct.pack("<I", 1))
    return hmac.compare_digest(
        digest.digest(),
        first_page[PAGE_SIZE - RESERVED_SIZE : PAGE_SIZE - RESERVED_SIZE + 20],
    )


def safe_value(value: Any) -> Any:
    if value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, bytes):
        return {
            "kind": "blob",
            "bytes": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
            "hex_prefix": value[:32].hex(),
        }
    text = str(value)
    return {
        "kind": "text",
        "chars": len(text),
        "sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
        "preview": text[:160],
    }


def inspect_sqlite(path: Path) -> dict[str, Any]:
    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        cursor = connection.cursor()
        result: dict[str, Any] = {
            "path": str(path.resolve()),
            "sha256": sha256_file(path),
            "quick_check": [row[0] for row in cursor.execute("PRAGMA quick_check")],
            "tables": [],
        }
        table_rows = cursor.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        for name, sql in table_rows:
            quoted = name.replace('"', '""')
            columns = cursor.execute(f'PRAGMA table_info("{quoted}")').fetchall()
            row_count = cursor.execute(f'SELECT count(*) FROM "{quoted}"').fetchone()[0]
            rows = cursor.execute(f'SELECT * FROM "{quoted}" LIMIT 20').fetchall()
            result["tables"].append(
                {
                    "name": name,
                    "sql": sql,
                    "columns": [
                        {"name": column[1], "type": column[2]} for column in columns
                    ],
                    "row_count": row_count,
                    "sample": [[safe_value(value) for value in row] for row in rows],
                }
            )
        return result
    finally:
        connection.close()


def candidate_stream(path: Path, all_windows: bool) -> Iterable[tuple[str, bytes]]:
    data = path.read_bytes()
    seen: set[bytes] = set()

    if len(data) == 32:
        seen.add(data)
        yield "whole-file", data

    for match in HEX_KEY.finditer(data):
        candidate = bytes.fromhex(match.group(1).decode("ascii"))
        if candidate not in seen:
            seen.add(candidate)
            yield f"hex-text@{match.start(1)}", candidate

    if all_windows and len(data) >= 32:
        for offset in range(0, len(data) - 31):
            candidate = data[offset : offset + 32]
            if candidate not in seen:
                seen.add(candidate)
                yield f"raw-window@{offset}", candidate


def validate_candidates(
    database: Path, candidate_paths: list[Path], all_windows: bool
) -> dict[str, Any]:
    with database.open("rb") as handle:
        first_page = handle.read(PAGE_SIZE)
    if len(first_page) != PAGE_SIZE:
        raise ValueError(f"database is shorter than one page: {database}")

    tested = 0
    matches: list[dict[str, str]] = []
    for path in candidate_paths:
        for source, candidate in candidate_stream(path, all_windows):
            tested += 1
            if first_page_hmac_matches(candidate, first_page):
                matches.append(
                    {
                        "candidate_file": str(path.resolve()),
                        "candidate_source": source,
                        "key_hex": candidate.hex(),
                    }
                )
    return {
        "database": str(database.resolve()),
        "database_sha256": sha256_file(database),
        "candidate_files": [str(path.resolve()) for path in candidate_paths],
        "all_32_byte_windows": all_windows,
        "candidates_tested": tested,
        "matches": matches,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    sqlite_parser = subparsers.add_parser("inspect-sqlite")
    sqlite_parser.add_argument("database", type=Path)

    candidate_parser = subparsers.add_parser("validate-candidates")
    candidate_parser.add_argument("database", type=Path)
    candidate_parser.add_argument("candidate_files", nargs="+", type=Path)
    candidate_parser.add_argument(
        "--all-windows",
        action="store_true",
        help="test every overlapping 32-byte window in each bounded candidate file",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "inspect-sqlite":
        result = inspect_sqlite(args.database)
    else:
        result = validate_candidates(
            args.database, args.candidate_files, args.all_windows
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
