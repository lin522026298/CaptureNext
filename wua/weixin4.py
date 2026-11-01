"""Read a frozen, decrypted 4.x message shard without lossy row conversion.

This is an observed-schema adapter, not a universal Weixin parser. It never
opens a live process, decrypts a database, guesses direction, or strips a blob
to find plausible text. Original rows remain authoritative in ArchiveStore.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import sqlite3

ADAPTER_VERSION = "weixin4-msg-1"
MAX_TEXT_BYTES = 8 * 1024 * 1024
_MSG = re.compile(r"Msg_([0-9a-fA-F]{32})\Z")
_REQUIRED = {"local_id", "server_id", "local_type", "real_sender_id",
             "create_time", "message_content"}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def decode_text(value, compression_type=None) -> tuple[str | None, str]:
    if value is None:
        return None, "null"
    if isinstance(value, str):
        return value, "sqlite-text"
    if not isinstance(value, bytes):
        return None, "unsupported-value-type"
    if len(value) > MAX_TEXT_BYTES:
        return None, "input-size-limit"
    if compression_type not in (None, 0, 4):
        return None, "unsupported-wcdb-compression"
    if compression_type == 4 or value.startswith(b"\x28\xb5\x2f\xfd"):
        try:
            import zstandard
        except ImportError:
            return None, "zstandard-unavailable"
        try:
            size = zstandard.frame_content_size(value)
            if size >= 0 and size > MAX_TEXT_BYTES:
                return None, "decompressed-size-limit"
            data = zstandard.ZstdDecompressor().decompress(
                value, max_output_size=MAX_TEXT_BYTES, allow_extra_data=False)
            if len(data) > MAX_TEXT_BYTES:
                return None, "decompressed-size-limit"
            return data.decode("utf-8", errors="strict"), "zstd-utf8"
        except (ValueError, UnicodeDecodeError, zstandard.ZstdError):
            return None, "invalid-zstd-or-utf8"
    try:
        return value.decode("utf-8", errors="strict"), "blob-utf8"
    except UnicodeDecodeError:
        return None, "unparsed-binary"


class Weixin4Database:
    def __init__(self, path: str | Path, *, db_relative_path: str,
                 account_alias: str, self_username: str | None = None):
        self.path = Path(path).resolve(strict=True)
        if not self.path.is_file():
            raise ValueError("expected a regular frozen database file")
        with self.path.open("rb") as handle:
            if handle.read(16) != b"SQLite format 3\x00":
                raise ValueError("input is not a decrypted SQLite database")
        for suffix in ("-wal", "-journal"):
            sidecar = Path(str(self.path) + suffix)
            if sidecar.exists() and sidecar.stat().st_size:
                raise ValueError("nonempty SQLite sidecar: materialise a verified snapshot first")
        self.relative = db_relative_path
        self.account = account_alias
        self.self_username = self_username
        self.sha256 = file_sha256(self.path)
        self.db = sqlite3.connect(self.path.as_uri() + "?mode=ro&immutable=1", uri=True)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA query_only=ON")
        self.db.execute("PRAGMA trusted_schema=OFF")
        self.counts = Counter()
        self._consumed = False
        self.schemas = dict(self.db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"))
        self.names = {}
        if "Name2Id" in self.schemas:
            columns = {row[1] for row in self.db.execute('PRAGMA table_info("Name2Id")')}
            if "user_name" in columns:
                self.names = {row[0]: row[1] for row in self.db.execute(
                    'SELECT rowid,user_name FROM "Name2Id"')
                    if isinstance(row[1], str) and row[1]}
        candidates = {}
        for name in self.names.values():
            digest = hashlib.md5(name.encode("utf-8"), usedforsecurity=False).hexdigest()
            candidates.setdefault(digest, set()).add(name)
        self.conversations = {digest: next(iter(values)) for digest, values in candidates.items()
                              if len(values) == 1}
        self.profile = {"adapter": ADAPTER_VERSION, "database_sha256": self.sha256,
                        "db_relative_path": self.relative,
                        "schema_sha256": hashlib.sha256(repr(sorted(self.schemas.items())).encode()).hexdigest(),
                        "table_count": len(self.schemas), "name2id_rows": len(self.names)}

    def observations(self):
        if self._consumed:
            raise RuntimeError("make a new adapter instance for another import")
        self._consumed = True
        for table, sql in self.schemas.items():
            match = _MSG.fullmatch(table)
            if not match:
                continue
            quoted = '"' + table.replace('"', '""') + '"'
            columns = {row[1] for row in self.db.execute("PRAGMA table_info(" + quoted + ")")}
            if (not _REQUIRED.issubset(columns) or not sql or
                    "VIRTUAL TABLE" in sql.upper() or "__wua_rowid__" in columns):
                raise ValueError("unsupported message table schema: " + table)
            conversation = self.conversations.get(match[1].lower())
            self.counts["message_tables"] += 1
            for record in self.db.execute("SELECT rowid AS __wua_rowid__,* FROM " + quoted + " ORDER BY rowid"):
                raw = dict(record)
                rowid = raw.pop("__wua_rowid__")
                sender = self.names.get(raw["real_sender_id"])
                direction = ("outgoing" if sender == self.self_username else "incoming") if (
                    sender and self.self_username) else "unknown"
                text, status = decode_text(raw["message_content"], raw.get("WCDB_CT_message_content"))
                self.counts["rows"] += 1
                self.counts["text:" + status] += 1
                self.counts["unmapped_conversations"] += int(conversation is None)
                self.counts["unmapped_senders"] += int(sender is None)
                stamp = raw["create_time"]
                event = None
                if isinstance(stamp, int) and not isinstance(stamp, bool):
                    try:
                        event = datetime.fromtimestamp(stamp, timezone.utc).isoformat()
                    except (ValueError, OverflowError, OSError):
                        self.counts["invalid_times"] += 1
                else:
                    self.counts["invalid_times"] += 1
                yield {"account_alias": self.account,
                       "db_relative_path": self.relative, "table_name": table,
                       "native_locator": {"rowid": rowid, "local_id": raw["local_id"]},
                       "raw_record": raw,
                       "conversation_id": conversation,
                       "conversation_id_is_stable": conversation is not None,
                       "unresolved_conversation_table_hash": None if conversation else match[1].lower(),
                       "sender_id": sender, "direction": direction,
                       "server_id": raw["server_id"], "message_type": raw["local_type"],
                       "raw_time": stamp, "time_unit": "seconds", "event_time": event,
                       "time_precision": "second", "time_zone": "UTC",
                       "time_confidence": "observed-schema-not-device-clock-verified",
                       "body_text": text, "body_decode_status": status,
                       "input_database_sha256": self.sha256,
                       "input_schema_sha256": self.profile["schema_sha256"],
                       "adapter": ADAPTER_VERSION}
        if file_sha256(self.path) != self.sha256:
            raise RuntimeError("input changed while importing; transaction must roll back")

    def report(self):
        return {**self.profile, "counts": dict(sorted(self.counts.items())),
                "coverage": "observed_message_tables_only", "media_association": "not_implemented",
                "structured_xml_protobuf": "raw_preserved_not_interpreted"}

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
