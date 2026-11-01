"""Portable BagIt 1.0 export of canonical WUA data, never of secret keyrings."""
from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path, PurePosixPath
import sqlite3

from .store import ArchiveStore
from .weixin4 import file_sha256

TABLES = ("archive_meta", "source_device", "source_snapshot", "message_observation",
          "logical_message", "message_link", "conflict", "dedupe_candidate")


def _json_file(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")


def _manifest(root, path, paths):
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for item in sorted(paths, key=lambda p: p.relative_to(root).as_posix()):
            handle.write(file_sha256(item) + "  " + item.relative_to(root).as_posix() + "\n")


def verify_bag(root: str | Path) -> dict:
    root = Path(root).resolve(strict=True)
    checked = {}
    for manifest in ("manifest-sha256.txt", "tagmanifest-sha256.txt"):
        items = {}
        for line in (root / manifest).read_text(encoding="utf-8").splitlines():
            expected, relative = line.split("  ", 1)
            pure = PurePosixPath(relative)
            if (len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected) or
                    not relative or pure.is_absolute() or ".." in pure.parts or
                    "\\" in relative or ":" in relative or str(pure) != relative):
                raise ValueError("unsafe/invalid manifest entry")
            target = root / relative
            if (relative in items or target.is_symlink() or
                    not target.resolve(strict=True).is_relative_to(root) or not target.is_file()):
                raise ValueError("manifest path is not a unique in-bag file")
            if file_sha256(target) != expected:
                raise ValueError("bag hash mismatch: " + relative)
            items[relative] = expected
        checked[manifest] = items
    actual_payload = {p.relative_to(root).as_posix() for p in (root / "data").rglob("*") if p.is_file()}
    if set(checked["manifest-sha256.txt"]) != actual_payload:
        raise ValueError("unlisted or missing payload")
    if not {"bagit.txt", "bag-info.txt", "manifest-sha256.txt"}.issubset(checked["tagmanifest-sha256.txt"]):
        raise ValueError("missing tag hashes")
    return {"pass": True, "payload_files": len(actual_payload),
            "tag_files": len(checked["tagmanifest-sha256.txt"])}


def export_bag(archive: str | Path, destination: str | Path) -> dict:
    archive = Path(archive).resolve(strict=True)
    destination = Path(destination).resolve()
    # An existing export, including an interrupted export, is never overwritten.
    destination.mkdir(parents=True, exist_ok=False)
    sentinel = destination / "INCOMPLETE.txt"
    sentinel.write_text("Export not yet accepted. Preserve for diagnosis.\n", encoding="utf-8")
    canonical = destination / "data" / "canonical"
    interchange = destination / "data" / "interchange"
    provenance = destination / "data" / "provenance"
    for path in (canonical, interchange, provenance):
        path.mkdir(parents=True)
    copied = canonical / "wua.sqlite"
    with ArchiveStore(archive, readonly=True) as store:
        before = store.semantic_digest()
        with closing(sqlite3.connect(archive.as_uri() + "?mode=ro", uri=True)) as source:
            with closing(sqlite3.connect(copied)) as target:
                source.backup(target)
        if store.semantic_digest() != before:
            raise RuntimeError("archive changed during backup")
    with ArchiveStore(copied, readonly=True) as store:
        if store.semantic_digest() != before:
            raise RuntimeError("exported database semantic digest mismatch")
        integrity = store.integrity_check()
        if integrity != {"quick_check": ["ok"], "foreign_key_check": []}:
            raise ValueError("exported database integrity check failed")
        _json_file(provenance / "coverage.json", store.coverage())
        _json_file(provenance / "build.json", {"schema": "wua-bag-1", "semantic_digest": before,
            "integrity": integrity, "stats": store.stats(),
            "scope": "canonical observations only; original source packages stay separate",
            "media": "not_associated", "acquisition_completeness": "not_assessed"})
    with closing(sqlite3.connect(copied.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        db.row_factory = sqlite3.Row
        for table in TABLES:
            with (interchange / (table + ".jsonl")).open("x", encoding="utf-8", newline="\n") as handle:
                for row in db.execute("SELECT * FROM " + table + " ORDER BY 1,2"):
                    handle.write(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n")
        schema = db.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type,name").fetchall()
        with (interchange / "schema.sql").open("x", encoding="utf-8", newline="\n") as handle:
            handle.write("-- Documentation of the canonical database, including optional FTS.\n")
            for row in schema:
                handle.write(row[0] + ";\n")
    (destination / "bagit.txt").write_text("BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n",
                                             encoding="utf-8", newline="\n")
    payload = [p for p in (destination / "data").rglob("*") if p.is_file()]
    total = sum(p.stat().st_size for p in payload)
    (destination / "bag-info.txt").write_text(
        f"External-Description: WUA canonical observations; not a complete acquisition claim\nPayload-Oxum: {total}.{len(payload)}\n",
        encoding="utf-8", newline="\n")
    _manifest(destination, destination / "manifest-sha256.txt", payload)
    _manifest(destination, destination / "tagmanifest-sha256.txt",
              [destination / name for name in ("bagit.txt", "bag-info.txt", "manifest-sha256.txt")])
    result = verify_bag(destination)
    sentinel.unlink()
    return {**result, "semantic_digest": before, "payload_bytes": total,
            "media_association": "not_implemented"}
