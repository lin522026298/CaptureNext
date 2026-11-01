"""Explicit cold source copy with per-file source/copy SHA256 readback.

No process is stopped or launched. No links/reparse points are followed. A
failed attempt is retained as unaccepted, never silently reused or overwritten.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess

WECHAT_PROCESSES = ("Weixin.exe", "WeChat.exe", "WeixinAppEx.exe", "WeChatAppEx.exe")


def assert_stopped():
    if os.name != "nt":
        raise RuntimeError("cold process guard is implemented for Windows only")
    for name in WECHAT_PROCESSES:
        result = subprocess.run(["tasklist", "/FO", "CSV", "/NH", "/FI", "IMAGENAME eq " + name],
                                capture_output=True, text=True, errors="replace", check=True)
        for row in csv.reader(io.StringIO(result.stdout)):
            if row and row[0].casefold() == name.casefold():
                raise RuntimeError("WeChat process running; cold copy requires normal full exit")


def _safe_stat(path):
    info = path.lstat()
    if path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("links/reparse points are outside snapshot scope")
    return info


def inventory(roots):
    rows, directories = [], []
    for label, source in sorted(roots.items()):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", label):
            raise ValueError("root labels must be simple ASCII identifiers")
        source = Path(source)
        info = _safe_stat(source)
        if stat.S_ISREG(info.st_mode):
            rows.append((label, source.name, source, info.st_size, info.st_mtime_ns))
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("snapshot root must be a regular file/directory")
        stack = [source]
        while stack:
            directory = stack.pop()
            _safe_stat(directory)
            relative_dir = directory.relative_to(source).as_posix()
            directories.append((label, relative_dir))
            with os.scandir(directory) as entries:
                children = sorted(entries, key=lambda item: item.name)
            for entry in children:
                path = Path(entry.path)
                info = _safe_stat(path)
                if stat.S_ISDIR(info.st_mode):
                    stack.append(path)
                elif stat.S_ISREG(info.st_mode):
                    rows.append((label, path.relative_to(source).as_posix(), path,
                                 info.st_size, info.st_mtime_ns))
                else:
                    raise ValueError("non-regular source object")
    return sorted(rows), sorted(directories)


def _hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot(roots, destination: Path):
    roots = {label: Path(value) for label, value in roots.items()}
    for path in roots.values():
        _safe_stat(path)
    roots = {label: path.resolve(strict=True) for label, path in roots.items()}
    destination = Path(destination).resolve()
    if any(destination.is_relative_to(path) or path.is_relative_to(destination) for path in roots.values()):
        raise ValueError("source and destination trees must not overlap")
    assert_stopped()
    rows, directories = inventory(roots)
    destination.mkdir(parents=True, exist_ok=False)
    raw = destination / "10_RAW_SNAPSHOT"
    manifests = destination / "20_MANIFESTS"
    manifests.mkdir()
    raw.mkdir()
    report = {"schema": "weixin-cold-snapshot-1", "accepted": False,
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "roots": {label: str(path) for label, path in roots.items()},
              "file_count": len(rows), "source_bytes": sum(row[3] for row in rows),
              "process_guard": "Weixin/WeChat and AppEx absent before, during and after copy",
              "copy_readback_sha256": False, "source_post_copy_sha256": False}
    try:
        for label, relative in directories:
            (raw / label / relative).mkdir(parents=True, exist_ok=True)
        copied = []
        with (manifests / "files.jsonl").open("x", encoding="utf-8", newline="\n") as manifest:
            for index, (label, relative, source, size, mtime) in enumerate(rows, 1):
                if index == 1 or index % 1000 == 0:
                    assert_stopped()
                before = _safe_stat(source)
                if (before.st_size, before.st_mtime_ns) != (size, mtime):
                    raise RuntimeError("source metadata changed before copy")
                target = raw / label / relative
                if not target.resolve().is_relative_to(raw.resolve()):
                    raise ValueError("destination path escaped snapshot root")
                target.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                with source.open("rb") as original, target.open("xb") as output:
                    while chunk := original.read(4 * 1024 * 1024):
                        output.write(chunk)
                        digest.update(chunk)
                expected = digest.hexdigest()
                after = _safe_stat(source)
                if (after.st_size, after.st_mtime_ns) != (size, mtime) or _hash(target) != expected:
                    raise RuntimeError("copy readback or stable source metadata failed")
                row = {"root": label, "relative_path": relative, "bytes": size,
                       "mtime_ns": mtime, "sha256": expected}
                manifest.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                copied.append(row)
                if index % 5000 == 0:
                    print(json.dumps({"phase": "copy_readback", "files": index, "total": len(rows)}), flush=True)
        assert_stopped()
        after_rows, after_directories = inventory(roots)
        if rows != after_rows or directories != after_directories:
            raise RuntimeError("source inventory changed while copying")
        for index, ((_, _, source, _, _), expected) in enumerate(zip(rows, copied), 1):
            if _hash(source) != expected["sha256"]:
                raise RuntimeError("source post-copy hash mismatch")
            if index % 5000 == 0:
                assert_stopped()
                print(json.dumps({"phase": "source_post_hash", "files": index, "total": len(rows)}), flush=True)
        assert_stopped()
        if inventory(roots) != (rows, directories):
            raise RuntimeError("source inventory changed during final verification")
        report.update(accepted=True, copy_readback_sha256=True, source_post_copy_sha256=True,
                      file_manifest_sha256=_hash(manifests / "files.jsonl"))
    except Exception as exc:
        report.update(error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        with (destination / "SNAPSHOT_ACCEPTANCE.json").open("x", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", required=True, help="explicit label=path; repeatable")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    roots = {}
    for value in args.root:
        label, path = value.split("=", 1)
        if label in roots:
            parser.error("duplicate root label")
        roots[label] = path
    report = snapshot(roots, args.out)
    print(json.dumps({key: report[key] for key in ("accepted", "file_count", "source_bytes",
                                                  "copy_readback_sha256", "source_post_copy_sha256")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
