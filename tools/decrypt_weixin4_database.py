"""Decrypt one frozen 4.x copy, validating every HMAC and committed WAL frame.

Profile: 4096-byte pages, 16-byte file salt, 80-byte reserve, AES-256-CBC,
HMAC-SHA512. Other cipher profiles fail closed. Never opens a live database.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from .verify_weixin4_database import (PAGE_SIZE, RESERVE_SIZE, load_key,
        page_hmac_matches, verify_main_database, sha256_file, inspect_sqlite)
    from .sqlite_wal import audit_wal
except ImportError:
    from verify_weixin4_database import (PAGE_SIZE, RESERVE_SIZE, load_key,
        page_hmac_matches, verify_main_database, sha256_file, inspect_sqlite)
    from sqlite_wal import audit_wal


def decrypt_page(page: bytes, number: int, raw_key: bytes, salt: bytes) -> bytes:
    if not page_hmac_matches(page, number, raw_key, salt):
        raise ValueError("page HMAC failed")
    start = 16 if number == 1 else 0
    end = PAGE_SIZE - RESERVE_SIZE
    decryptor = Cipher(algorithms.AES(raw_key), modes.CBC(page[end:end + 16])).decryptor()
    plaintext = decryptor.update(page[start:end]) + decryptor.finalize()
    return (b"SQLite format 3\x00" if number == 1 else b"") + plaintext + bytes(RESERVE_SIZE)


def decrypt_copy(database: Path, output: Path, raw_key: bytes, wal: Path | None = None) -> dict:
    database = Path(database).resolve(strict=True)
    output = Path(output).resolve()
    pending = output.with_name(output.name + ".pending")
    if output.exists() or pending.exists() or output == database:
        raise FileExistsError("output/pending exists or input aliases output")
    main = verify_main_database(database, raw_key)
    if not main["all_pages_hmac_sha512"]:
        raise ValueError("main database HMAC failure; no output created")
    with database.open("rb") as handle:
        salt = handle.read(16)
    wal_blob = b""
    wal_result = {"present": False}
    if wal is not None:
        wal = Path(wal).resolve(strict=True)
        if wal.stat().st_size > 512 * 1024 * 1024:
            raise ValueError("WAL exceeds bounded 512 MiB implementation")
        wal_blob = wal.read_bytes()
        wal_result = {"present": True, "sha256": sha256_file(wal),
                      **audit_wal(wal_blob, PAGE_SIZE,
                                  lambda page, number: page_hmac_matches(page, number, raw_key, salt))}
        if not wal_result["pass"]:
            raise ValueError("WAL checksum/shape/HMAC validation failed; no output created")
    with database.open("rb") as source, pending.open("xb") as target:
        for number in range(1, main["page_count"] + 1):
            target.write(decrypt_page(source.read(PAGE_SIZE), number, raw_key, salt))
        committed_pages = wal_result.get("committed_database_pages")
        for number, frame in sorted(wal_result.get("committed_page_frames", {}).items()):
            start = 32 + (frame - 1) * (24 + PAGE_SIZE) + 24
            target.seek((number - 1) * PAGE_SIZE)
            target.write(decrypt_page(wal_blob[start:start + PAGE_SIZE], number, raw_key, salt))
        if committed_pages is not None:
            target.truncate(committed_pages * PAGE_SIZE)
        target.flush()
        os.fsync(target.fileno())
    with pending.open("rb") as handle:
        header = handle.read(100)
    if struct.unpack_from(">H", header, 16)[0] != PAGE_SIZE or header[20] != RESERVE_SIZE:
        raise ValueError("decrypted header does not match audited cipher profile; pending retained")
    sql = inspect_sqlite(pending)
    if not sql["pass"]:
        raise ValueError("decrypted SQLite quick_check failed; pending retained")
    if sha256_file(database) != main["sha256"] or (wal is not None and sha256_file(wal) != wal_result["sha256"]):
        raise RuntimeError("frozen input changed; pending retained")
    pending.rename(output)
    return {"profile": "weixin4-4096-reserve80-raw32", "raw_database": main,
            "wal": wal_result, "plaintext": sql, "pass": True,
            "originals_modified": False, "key_material_in_report": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--wal", type=Path)
    parser.add_argument("--keyring", required=True, type=Path)
    parser.add_argument("--relative-path", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if args.report.exists():
        parser.error("report already exists")
    key, _ = load_key(args.keyring, args.relative_path)
    result = decrypt_copy(args.database, args.out, key, args.wal)
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    print(json.dumps({"pass": result["pass"], "pages": result["raw_database"]["page_count"],
                      "wal_commit_frame": result["wal"].get("last_commit_frame", 0)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
