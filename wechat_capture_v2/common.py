"""Path boundaries, exact value encoding and crash-safe local writes."""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest_file(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def encoded(value):
    """Tagged recursive encoding, including TEXT that resembles a blob marker."""
    if value is None:
        return ["null"]
    if isinstance(value, bytes):
        return ["blob", base64.b64encode(value).decode("ascii")]
    if isinstance(value, str):
        return ["text", value]
    if type(value) is int:
        return ["integer", str(value)]
    if isinstance(value, float):
        return ["real", value.hex()]
    if isinstance(value, dict):
        return ["object", [[key, encoded(val)] for key, val in sorted(value.items())]]
    if isinstance(value, (list, tuple)):
        return ["array", [encoded(item) for item in value]]
    raise TypeError("unsupported SQLite/raw value type")


def decoded(value):
    tag = value[0]
    if tag == "null":
        return None
    if tag == "blob":
        return base64.b64decode(value[1], validate=True)
    if tag == "text":
        return value[1]
    if tag == "integer":
        return int(value[1])
    if tag == "real":
        return float.fromhex(value[1])
    if tag == "object":
        return {key: decoded(val) for key, val in value[1]}
    if tag == "array":
        return [decoded(item) for item in value[1]]
    raise ValueError("unknown exact-value encoding")


def safe_relative(value):
    value = str(value).replace("\\", "/")
    path = PurePosixPath(value)
    if not path.parts or path.is_absolute() or ":" in value or any(p in ("..", ".") for p in path.parts):
        raise ValueError("expected a contained relative path")
    return path.as_posix()


def regular(path):
    path = Path(path)
    info = path.lstat()
    if path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("links/reparse points are outside acquisition scope")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("expected regular source file")
    return info


def directory(path):
    path = Path(path)
    info = path.lstat()
    if path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400 or not stat.S_ISDIR(info.st_mode):
        raise ValueError("expected a non-linked directory")
    return path


def source_files(root):
    root = directory(root).resolve(strict=True)
    stack = [root]
    while stack:
        parent = directory(stack.pop())
        for child in sorted(parent.iterdir(), key=lambda item: item.name):
            info = child.lstat()
            if child.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("source tree contains a link/reparse point")
            if stat.S_ISDIR(info.st_mode):
                stack.append(child)
            elif stat.S_ISREG(info.st_mode):
                yield safe_relative(child.relative_to(root).as_posix()), child
            else:
                raise ValueError("source tree contains non-regular objects")


def stamp(path):
    info = regular(path)
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def readonly_database(path):
    db = sqlite3.connect(Path(path).resolve(strict=True).as_uri() + "?mode=ro&immutable=1", uri=True)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    db.execute("PRAGMA trusted_schema=OFF")
    return db


def write_json_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(canonical(value) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def writer_lock(state):
    """OS-released lock: a killed process cannot leave a stale logical lock."""
    state = Path(state)
    state.mkdir(parents=True, exist_ok=True)
    path = state / "writer.lock"
    stream = path.open("a+b")
    try:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        stream.close()
