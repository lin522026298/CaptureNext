"""Private, process-local reuse of an already authenticated paired readback.

This module does NOT acquire cold guards or authenticate repository blocks.
The sole writer must keep enforceable deny-write/delete guards on EVERY input
and repository file across input hashing, lookup, verify_files, and remember.
Input hashes must already equal the complete manifest file map. Repository
connections must be read-only, closed writers/journals must be gone, and the
same guarded cut must span successful verify_files and remember_verified.

Do not seed from publish: its verification precedes commit/reclaim/close. The
first guarded unchanged readback verifies normally, then seeds this memo.
There is deliberately no import/export of trusted proof or caller-supplied
repository hashes. This is not protection against malicious in-process code.
On platforms without enforceable cold guards, callers must not use the memo.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import threading
from typing import Any, Mapping

from wechat_capture_v2.common import canonical, digest_file
from . import backup as legacy

_HASH = re.compile(r'[0-9a-f]{64}\Z')
_REQUIRED = frozenset(('repository.sqlite', 'OWNER.private.json'))
_ALLOWED = _REQUIRED | {'repository.lock'}
JsonMap = Mapping[str, Any]
FileMap = Mapping[str, JsonMap]


def _json_bytes(value: Any) -> bytes:
    """Reject non-JSON values and non-string mapping keys, not lossy coercion."""
    def check(item: Any) -> None:
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise TypeError('readback binding requires string JSON keys')
            for child in item.values():
                check(child)
        elif type(item) is list:
            for child in item:
                check(child)
        elif item is not None and type(item) not in (str, int, float, bool):
            raise TypeError('readback binding requires ordinary JSON values')
    check(value)
    return canonical(value).encode('utf-8')


def _inventory(repository: Path) -> tuple[str, ...]:
    names = tuple(sorted(child.name for child in repository.iterdir()))
    if not _REQUIRED.issubset(names) or not set(names).issubset(_ALLOWED):
        raise ValueError('readback memo requires a closed complete repository')
    for name in names:
        legacy._file(repository / name)
    return names


class PairReadbackMemo:
    """One immutable cut/proof, usable only by its first actual worker Thread.

    lookup returns only a detached copy of verify_files' result, not a receipt
    claiming authentication ran now. A mismatch, invalid argument, I/O failure,
    or cross-thread attempt clears the proof. reset does not transfer ownership.
    """

    __slots__ = ('__thread', '__entry', '__gate')

    def __init__(self) -> None:
        self.__thread: threading.Thread | None = None
        self.__entry: tuple[bytes, bytes] | None = None
        self.__gate = threading.Lock()

    def __reduce_ex__(self, protocol: int) -> Any:
        raise TypeError('readback memo cannot be serialized or copied')

    def __getstate__(self) -> Any:
        raise TypeError('readback memo cannot be serialized or copied')

    def reset(self) -> None:
        with self.__gate:
            self.__entry = None

    def _worker(self) -> None:
        current = threading.current_thread()
        if self.__thread is None:
            self.__thread = current
        elif self.__thread is not current:
            raise RuntimeError('readback memo belongs to another worker thread')

    @staticmethod
    def _key(repository: Path, *, owner: JsonMap, snapshot_id: str,
             scope: JsonMap, profile: JsonMap, input_files: Mapping[str, Path],
             file_map: FileMap) -> bytes:
        if not isinstance(snapshot_id, str) or not _HASH.fullmatch(snapshot_id):
            raise ValueError('invalid readback snapshot identity')
        repository = legacy._parents(repository)
        files = dict(file_map)
        inputs = dict(input_files)
        if not files or set(files) != set(inputs):
            raise ValueError('readback input inventory differs from manifest')
        if any(type(name) is not str for name in files):
            raise TypeError('readback file names must be strings')
        if len({name.casefold() for name in files}) != len(files):
            raise ValueError('aliased readback file names')
        paths: dict[str, str] = {}
        for name, path in inputs.items():
            path = Path(path)
            path = legacy._parents(path.parent) / path.name
            legacy._file(path)
            paths[name] = str(path)
            entry = files[name]
            if (not isinstance(entry, Mapping) or type(entry.get('bytes')) is not int
                    or entry['bytes'] < 0 or not isinstance(entry.get('sha256'), str)
                    or not _HASH.fullmatch(entry['sha256'])):
                raise ValueError('invalid authenticated readback file map')
        if len(set(paths.values())) != len(paths):
            raise ValueError('aliased readback input paths')
        # Normalize before I/O so malformed bindings cannot seed a partial key.
        binding = dict(repository=str(repository), owner=dict(owner), snapshot_id=snapshot_id,
                       scope=dict(scope), profile=dict(profile), input_files=paths,
                       file_map={name: dict(entry) for name, entry in files.items()})
        _json_bytes(binding)
        names = _inventory(repository)
        if json.loads((repository / 'OWNER.private.json').read_text(encoding='utf-8')) != dict(owner):
            raise ValueError('readback repository owner differs')
        binding['repository_sha256'] = {
            name: digest_file(repository / name) for name in names}
        if _inventory(repository) != names:
            raise ValueError('readback repository inventory changed while hashing')
        return _json_bytes(binding)

    def lookup(self, repository: Path, *, owner: JsonMap, snapshot_id: str,
               scope: JsonMap, profile: JsonMap, input_files: Mapping[str, Path],
               file_map: FileMap) -> dict[str, Any] | None:
        with self.__gate:
            try:
                self._worker()
                if self.__entry is None:
                    return None
                key = self._key(repository, owner=owner, snapshot_id=snapshot_id,
                                scope=scope, profile=profile, input_files=input_files,
                                file_map=file_map)
                if key != self.__entry[0]:
                    self.__entry = None
                    return None
                return copy.deepcopy(json.loads(self.__entry[1]))
            except BaseException:
                self.__entry = None
                raise

    def remember_verified(self, repository: Path, *, owner: JsonMap, snapshot_id: str,
                          scope: JsonMap, profile: JsonMap, input_files: Mapping[str, Path],
                          file_map: FileMap, verification: JsonMap) -> None:
        """Call ONLY immediately after verify_files succeeds on this guarded cut."""
        with self.__gate:
            self.__entry = None
            try:
                self._worker()
                proof = dict(verification)
                if (set(proof) != {'files', 'bytes', 'verified'} or proof['verified'] is not True
                        or type(proof['files']) is not int or type(proof['bytes']) is not int
                        or proof['files'] != len(file_map)
                        or proof['bytes'] != sum(entry['bytes'] for entry in file_map.values())):
                    raise ValueError('successful complete verify_files result required')
                encoded = _json_bytes(proof)
                key = self._key(repository, owner=owner, snapshot_id=snapshot_id,
                                scope=scope, profile=profile, input_files=input_files,
                                file_map=file_map)
                self.__entry = (key, encoded)
            except BaseException:
                self.__entry = None
                raise
