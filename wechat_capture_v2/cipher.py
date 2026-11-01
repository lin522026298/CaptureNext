"""Streaming authenticated SQLCipher/WAL materialization for a frozen copy.

Unlike the legacy decoder, WAL length is not limited to 512 MiB. Read batches
bound memory only; WAL commit boundaries and all page HMACs remain mandatory.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import sqlite3
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from tools.sqlite_wal import checksum
from .common import digest_file, readonly_database, regular

PAGE = 4096
RESERVE = 80
STRIDE = PAGE + 24


class PageCipher:
    def __init__(self, key, salt):
        if len(key) != 32 or len(salt) != 16:
            raise ValueError("unsupported raw key/salt length")
        self.key = key
        self.mac_key = hashlib.pbkdf2_hmac("sha512", key, bytes(x ^ 0x3A for x in salt), 2, dklen=32)

    def decrypt(self, page, number):
        if len(page) != PAGE or not 1 <= number < 0xFFFFFFFF:
            raise ValueError("invalid encrypted page shape/number")
        start = 16 if number == 1 else 0
        mac = hmac.new(self.mac_key, page[start:PAGE-64], hashlib.sha512)
        mac.update(struct.pack("<I", number))
        if not hmac.compare_digest(mac.digest(), page[PAGE-64:]):
            raise ValueError("encrypted page HMAC failed")
        end = PAGE - RESERVE
        dec = Cipher(algorithms.AES(self.key), modes.CBC(page[end:end+16])).decryptor()
        return (b"SQLite format 3\x00" if number == 1 else b"") + dec.update(page[start:end]) + dec.finalize() + bytes(RESERVE)


def wal_prefix(wal, cipher=None):
    """Find a verified committed prefix in bounded memory, retaining no page map.

    A trailing in-progress frame is excluded, never applied. A reset is guarded
    independently by source.capture_pair's second-pass prefix comparison.
    """
    regular(wal)
    size = Path(wal).stat().st_size
    result = {"physical_bytes": size, "committed_bytes": 0, "last_commit_frame": 0,
              "committed_database_pages": None, "valid_frames": 0, "tail_reason": None}
    if size == 0:
        result["tail_reason"] = "empty"
        return result
    with Path(wal).open("rb") as stream:
        header = stream.read(32)
        if len(header) != 32:
            raise ValueError("incomplete WAL header")
        magic, version, page_size = struct.unpack_from(">III", header)
        if magic not in (0x377F0682, 0x377F0683) or version != 3007000 or page_size != PAGE:
            raise ValueError("unsupported WAL header")
        big = magic == 0x377F0683
        state = checksum(header[:24], big_endian=big)
        if state != struct.unpack_from(">II", header, 24):
            raise ValueError("WAL header checksum failed")
        salts = header[16:24]
        frame = 0
        while stream.tell() < size:
            data = stream.read(STRIDE)
            if len(data) < STRIDE:
                result["tail_reason"] = "incomplete_uncommitted_tail"
                break
            frame += 1
            fh, page = data[:24], data[24:]
            number, pages = struct.unpack_from(">II", fh)
            if fh[8:16] != salts:
                result["tail_reason"] = "stale_generation_tail"
                break
            if number in (0, 0xFFFFFFFF) or pages == 0xFFFFFFFF:
                result["tail_reason"] = "invalid_frame_tail"
                break
            expected = checksum(fh[:8] + page, state, big)
            if expected != struct.unpack_from(">II", fh, 16):
                result["tail_reason"] = "checksum_tail"
                break
            if cipher is not None:
                # Authenticate even currently uncommitted complete valid frames.
                cipher.decrypt(page, number)
            state = expected
            result["valid_frames"] = frame
            if pages:
                result.update(last_commit_frame=frame, committed_database_pages=pages,
                              committed_bytes=32 + frame * STRIDE)
    return result


def materialize(database, output, key, wal=None):
    database, output = Path(database), Path(output)
    if output.exists():
        raise FileExistsError("plaintext output already exists")
    size = regular(database).st_size
    if not size or size % PAGE:
        raise ValueError("unsupported main database size")
    with database.open("rb") as stream:
        salt = stream.read(16)
    cipher = PageCipher(key, salt)
    before = digest_file(database)
    wal_before = digest_file(wal) if wal is not None else None
    audit = wal_prefix(wal, cipher) if wal is not None else {"last_commit_frame": 0,
            "committed_database_pages": None, "committed_bytes": 0, "tail_reason": "absent"}
    with database.open("rb") as source, output.open("xb") as target:
        for number in range(1, size // PAGE + 1):
            target.write(cipher.decrypt(source.read(PAGE), number))
        if wal is not None and audit["last_commit_frame"]:
            with Path(wal).open("rb") as stream:
                stream.seek(32)
                for _ in range(audit["last_commit_frame"]):
                    frame = stream.read(STRIDE)
                    number = struct.unpack_from(">I", frame)[0]
                    target.seek((number - 1) * PAGE)
                    target.write(cipher.decrypt(frame[24:], number))
                    commit_pages = struct.unpack_from(">I", frame, 4)[0]
                    if commit_pages:
                        # A shrink followed by expansion must not resurrect
                        # obsolete pages from a previous transaction.
                        target.truncate(commit_pages * PAGE)
            target.truncate(audit["committed_database_pages"] * PAGE)
        target.flush()
        os.fsync(target.fileno())
    if before != digest_file(database) or (wal is not None and wal_before != digest_file(wal)):
        raise RuntimeError("frozen encrypted input changed")
    with output.open("rb") as stream:
        head = stream.read(100)
    if struct.unpack_from(">H", head, 16)[0] != PAGE or head[20] != RESERVE:
        raise ValueError("decrypted SQLite header profile mismatch")
    db = readonly_database(output)
    try:
        try:
            checks = [r[0] for r in db.execute("PRAGMA quick_check")]
        except sqlite3.OperationalError as exc:
            if "MMFtsTokenizer" not in str(exc):
                raise
            checks = ["unsupported_custom_tokenizer"]
        if checks not in (["ok"], ["unsupported_custom_tokenizer"]):
            raise ValueError("decrypted database structural check failed")
    finally:
        db.close()
    return {"profile": "weixin4-4096-reserve80-raw32", "main_sha256": before,
            "main_pages_authenticated": size // PAGE, "wal_sha256": wal_before, "wal": audit,
            "plaintext_sha256": digest_file(output), "quick_check": checks,
            "structured_readable": checks == ["ok"], "all_main_pages_hmac": True}
