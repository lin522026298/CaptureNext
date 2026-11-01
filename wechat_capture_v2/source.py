"""Read-only live-file acquisition with stable main + committed-WAL prefix."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .cipher import wal_prefix
from .common import digest_file, regular, stamp


def verify_unchanged_pair(source,evidence):
    """Re-use a previously authenticated cut only after two full byte hashes.

    This is a read-only content proof, NOT an mtime/sequence shortcut. Explicit
    operator full reconciliation still bypasses it and reads all native rows.
    """
    if not evidence.get('authentication',{}).get('all_main_pages_hmac'):
        return None
    raw=evidence.get('raw',{})
    if not raw.get('main'):
        return None
    source=Path(source);wal=Path(str(source)+'-wal')
    try:
        before=(stamp(source),stamp(wal) if wal.exists() else None)
        if (before[1] is not None)!=bool(raw.get('wal_raw')):
            return None
        expected_main=raw['main']['sha256']
        expected_wal=raw.get('wal_raw',{}).get('sha256')
        for _ in range(2):
            if digest_file(source)!=expected_main or (before[1] is not None and digest_file(wal)!=expected_wal):
                return None
            if (stamp(source),stamp(wal) if wal.exists() else None)!=before:
                return None
        return {'method':'two_pass_full_main_and_raw_wal_sha256','main_sha256':expected_main,
                'raw_wal_sha256':expected_wal,'previous_all_pages_authentication_reused':True}
    except (OSError,ValueError):
        return None


def copy_prefix(source, target, count=None):
    source, target = Path(source), Path(target)
    regular(source)
    if count is None:
        count = source.stat().st_size
    digest = hashlib.sha256()
    with source.open("rb") as original, target.open("xb") as output:
        remaining = count
        while remaining:
            data = original.read(min(1024 * 1024, remaining))
            if not data:
                raise RuntimeError("source truncated during capture")
            output.write(data)
            digest.update(data)
            remaining -= len(data)
        output.flush()
        os.fsync(output.fileno())
    return digest.hexdigest()


def prefix_hash(path, count):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while count:
            data = stream.read(min(1024 * 1024, count))
            if not data:
                raise RuntimeError("live source prefix shrank")
            digest.update(data)
            count -= len(data)
    return digest.hexdigest()


def capture_pair(source, destination):
    """A WAL may append while copying; its captured committed prefix must persist.

    The entire main file is re-hashed after capture. The selected WAL prefix is
    also read back from live source, detecting checkpoint/reset races. Resource
    retry counts are managed by the caller, never used to cut message history.
    """
    source, destination = Path(source), Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    before = stamp(source)
    main = destination / "main.db"
    main_sha = copy_prefix(source, main)
    wal_live = Path(str(source) + "-wal")
    raw_wal, committed_wal = None, None
    audit = {"tail_reason": "absent", "last_commit_frame": 0, "committed_bytes": 0}
    prefix_sha, raw_wal_sha = None, None
    if wal_live.exists():
        raw_wal = destination / "raw.wal"
        raw_wal_sha = copy_prefix(wal_live, raw_wal)
        audit = wal_prefix(raw_wal)
        if audit["tail_reason"] in ("checksum_tail", "invalid_frame_tail"):
            raise RuntimeError("invalid/torn WAL tail: retry without advancing progress")
        committed_wal = destination / "committed.wal"
        prefix_sha = copy_prefix(raw_wal, committed_wal, audit["committed_bytes"])
        # With no commit yet, still bind the generation header when present.
        verify_length = audit["committed_bytes"] or min(32, raw_wal.stat().st_size)
        if prefix_hash(wal_live, verify_length) != prefix_hash(raw_wal, verify_length):
            raise RuntimeError("WAL prefix/reset changed during capture")
    elif wal_live.exists():
        raise RuntimeError("WAL appeared during capture")
    if stamp(source) != before or digest_file(source) != main_sha:
        raise RuntimeError("main file checkpoint/change during capture")
    # A main re-read may overlap a reset; check the WAL once more afterwards.
    if raw_wal is not None:
        verify_length = audit["committed_bytes"] or min(32, raw_wal.stat().st_size)
        if not wal_live.exists() or prefix_hash(wal_live, verify_length) != prefix_hash(raw_wal, verify_length):
            raise RuntimeError("WAL generation changed after main verification")
    elif wal_live.exists():
        raise RuntimeError("WAL appeared after capture")
    return {"main": main, "raw_wal": raw_wal, "wal": committed_wal,
            "main_sha256": main_sha, "raw_wal_sha256": raw_wal_sha,
            "wal_sha256": prefix_sha, "source_stamp": before, "wal_capture": audit,
            "signature": hashlib.sha256((main_sha + ":" + (prefix_sha or "absent")).encode()).hexdigest()}
