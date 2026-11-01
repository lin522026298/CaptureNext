"""Execution-free WAL validation and committed-page selection, not in-place replay.

SQLite file format sections 4.1-4.5: checksums cover stored (encrypted, for
SQLCipher) page bytes. An optional validator checks the separate page HMAC.
"""
from __future__ import annotations
import struct
from typing import Callable


def checksum(data: bytes, state: tuple[int, int] = (0, 0), big_endian: bool = False) -> tuple[int, int]:
    if len(data) % 8:
        raise ValueError("WAL checksum input must be a multiple of 8 bytes")
    a, b = state
    for x, y in struct.iter_unpack(">II" if big_endian else "<II", data):
        a = (a + x + b) & 0xFFFFFFFF
        b = (b + y + a) & 0xFFFFFFFF
    return a, b


def audit_wal(blob: bytes, expected_page_size: int = 4096,
              page_validator: Callable[[bytes, int], bool] | None = None) -> dict:
    result = {"header_valid": False, "header_checksum_valid": False,
              "physical_frames": 0, "current_generation_frames": 0,
              "checksum_valid_frames": 0, "commit_frames": 0,
              "last_commit_frame": 0, "committed_database_pages": None,
              "committed_page_frames": {}, "uncommitted_valid_frames": 0,
              "hmac_failed_frames": [], "checksum_failed_frame": None,
              "trailing_frames_after_salt_mismatch": 0, "trailing_bytes": 0,
              "ignored_bytes_after_salt_mismatch": 0,
              "stop_reason": None, "pass": False}
    if not blob:
        # SQLite wal_checkpoint(TRUNCATE) legitimately leaves an empty WAL.
        result.update({"stop_reason": "empty_wal", "pass": True})
        return result
    if len(blob) < 32:
        result["stop_reason"] = "short_header"
        return result
    magic, version, page_size = struct.unpack_from(">III", blob)
    result.update(magic_hex=f"0x{magic:08x}", page_size=page_size, format_version=version)
    if magic not in (0x377F0682, 0x377F0683) or version != 3007000 or page_size != expected_page_size:
        result["stop_reason"] = "unsupported_header"
        return result
    endian = magic == 0x377F0683
    state = checksum(blob[:24], big_endian=endian)
    if state != struct.unpack_from(">II", blob, 24):
        result["stop_reason"] = "header_checksum"
        return result
    result["header_valid"] = result["header_checksum_valid"] = True
    stride = 24 + page_size
    physical, trailing = divmod(len(blob)-32, stride)
    result.update(physical_frames=physical, trailing_bytes=trailing)
    salts = blob[16:24]
    committed, pending = {}, {}
    for index in range(1, physical + 1):
        start = 32 + (index - 1) * stride
        header = blob[start:start+24]
        page = blob[start+24:start+stride]
        number, commit_size = struct.unpack_from(">II", header)
        if header[8:16] != salts:
            result["trailing_frames_after_salt_mismatch"] = physical-index+1
            result["ignored_bytes_after_salt_mismatch"] = len(blob)-start
            result["stop_reason"] = "salt_mismatch_stale_tail"
            break
        result["current_generation_frames"] += 1
        if number == 0 or number == 0xFFFFFFFF or commit_size == 0xFFFFFFFF:
            result["stop_reason"] = "invalid_page_number"
            break
        next_state = checksum(header[:8]+page, state, endian)
        if next_state != struct.unpack_from(">II", header, 16):
            result["checksum_failed_frame"] = index
            result["stop_reason"] = "frame_checksum"
            break
        state = next_state
        result["checksum_valid_frames"] += 1
        if page_validator is not None and not page_validator(page, number):
            result["hmac_failed_frames"].append(index)
            result["stop_reason"] = "page_hmac"
            break
        pending[number] = index
        if commit_size:
            committed.update(pending)
            committed = {p: f for p, f in committed.items() if p <= commit_size}
            pending.clear()
            result["commit_frames"] += 1
            result["last_commit_frame"] = index
            result["committed_database_pages"] = commit_size
    valid = result["checksum_valid_frames"] - bool(result["hmac_failed_frames"])
    result["uncommitted_valid_frames"] = valid - result["last_commit_frame"]
    result["committed_page_frames"] = committed
    # A stale-generation frame ends the current WAL, including arbitrary
    # preallocated/partial bytes after it. Those bytes cannot enter a commit.
    # Without that boundary, an incomplete physical frame remains a failure.
    result["pass"] = (result["stop_reason"] == "salt_mismatch_stale_tail" or
                      (result["stop_reason"] is None and trailing == 0))
    return result
