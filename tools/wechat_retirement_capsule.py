"""Lossless, bounded-memory escrow helpers for one-off archive retirement.

This does not replace a product backup. The caller supplies authenticated,
guarded source readers and records source snapshot/filename identities.
"""
import base64
import hashlib
import json
import struct
import zipfile


def encode_value(value):
    if value is None:
        return ["null"]
    if type(value) is int:
        return ["integer", str(value)]
    if type(value) is float:
        return ["real", struct.pack(">d", value).hex()]
    if type(value) is str:
        return ["text", value]
    if isinstance(value, bytes):
        return ["blob", base64.b64encode(value).decode("ascii")]
    raise TypeError("unsupported SQLite value")


def decode_value(value):
    kind = value[0]
    if kind == "null" and len(value) == 1:
        return None
    if len(value) != 2:
        raise ValueError("invalid tagged SQLite value")
    if kind == "integer":
        return int(value[1])
    if kind == "real":
        return struct.unpack(">d", bytes.fromhex(value[1]))[0]
    if kind == "text":
        return value[1]
    if kind == "blob":
        return base64.b64decode(value[1], validate=True)
    raise ValueError("unknown SQLite storage class")


def json_line(value):
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")


def safe_name(name):
    parts = name.split("/")
    if not name or "\\" in name or "\0" in name or any(p in ("", ".", "..") for p in parts):
        raise ValueError("unsafe capsule member")
    if ":" in name or name.startswith("/"):
        raise ValueError("unsafe capsule member")
    return name


class Capsule:
    def __init__(self, path):
        self.zip = zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True)
        self.members = []

    def add(self, name, blocks, expected=None):
        safe_name(name)
        if name in self.zip.namelist():
            raise ValueError("duplicate capsule member")
        digest = hashlib.sha256()
        total = 0
        with self.zip.open(name, "w", force_zip64=True) as out:
            for raw in blocks:
                digest.update(raw)
                total += len(raw)
                out.write(raw)
        result = dict(name=name, bytes=total, sha256=digest.hexdigest())
        if expected is not None and (total != expected["bytes"] or result["sha256"] != expected["sha256"]):
            raise ValueError("capsule source digest mismatch")
        self.members.append(result)
        return result

    def finish(self, metadata):
        manifest = dict(format="wechat-retirement-capsule-v1", members=self.members.copy(), metadata=metadata)
        self.add("MANIFEST.private.json", [json_line(manifest)])
        self.zip.close()
        return manifest

    def close(self):
        self.zip.close()


def verify(path):
    """Fresh complete decompression and SHA of every member, not just ZIP CRC."""
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("duplicate member")
        for name in names:
            safe_name(name)
        manifest = json.loads(archive.read("MANIFEST.private.json"))
        if manifest["format"] != "wechat-retirement-capsule-v1":
            raise ValueError("unknown capsule format")
        declared = [member["name"] for member in manifest["members"]]
        if len(declared) != len(set(declared)) or "MANIFEST.private.json" in declared:
            raise ValueError("duplicate or reserved declared member")
        if set(names) != {"MANIFEST.private.json"} | {m["name"] for m in manifest["members"]}:
            raise ValueError("capsule member set differs")
        for member in manifest["members"]:
            digest = hashlib.sha256()
            total = 0
            with archive.open(member["name"]) as source:
                while raw := source.read(1024 * 1024):
                    total += len(raw)
                    digest.update(raw)
            if total != member["bytes"] or digest.hexdigest() != member["sha256"]:
                raise ValueError("capsule readback differs")
        return manifest


def table_lines(db, table):
    """Exact storage classes, raw text, blob and IEEE real bits; no DISTINCT."""
    quoted = '"' + table.replace('"', '""') + '"'
    shape = list(db.execute("PRAGMA table_info(" + quoted + ")"))
    schema = list(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE tbl_name=? ORDER BY type,name", (table,)))
    yield json_line(dict(table=table, shape=shape, sqlite_master=schema, encoding="tagged-sqlite-values-v1"))
    for row in db.execute("SELECT * FROM " + quoted):
        yield json_line([encode_value(value) for value in row])
