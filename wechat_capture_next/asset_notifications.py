"""Loss-aware Windows attachment hints, not a substitute for file verification.

Consumer contract:
* poll() never consumes events. begin() takes an epoch ticket; complete() may
  acknowledge ONLY files/prefixes fully re-read and verified for that ticket.
* Every dirty name forces bytes even when (identity,size,mtime) is unchanged.
  Reconcile the complete inventory first; directory names invalidate all their
  descendants. Unresolved short-name aliases require require_full_bytes().
* Confirm absent names only after a complete inventory. Historical CAS objects
  are never deleted. full_bytes=True requires inventory_complete=True and a
  successful full byte sweep, not a metadata scan. Failed work is not acked.
* Start/restart, lost notifications, malformed data, bounded-set overflow, root
  replacement, and listener failure require a full byte sweep. Unavailable
  listeners never become cached idle, even after an attempted acknowledgement.
* Keep the separate periodic full-metadata fallback and manual byte verification.

The dedicated listener issues overlapped ReadDirectoryChangesW then blocks on
GetOverlappedResult. This preserves buffer lifetime through CancelIoEx and makes
the first 'ready' mean an actual request is queued, not merely a thread started.
Only native notification names and root metadata are read; no file content or
other account discovery occurs in this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ctypes
import os
from pathlib import Path, PureWindowsPath
import struct
import threading

from wechat_capture_v2.common import directory
from .paths import local_absolute

BUFFER_BYTES = 64 * 1024
MAX_DIRTY = 4096
MAX_DIRTY_BYTES = 2 * 1024 * 1024
ERROR_OPERATION_ABORTED = 995
ERROR_NOTIFY_ENUM_DIR = 1022
_ACTIONS = frozenset(range(1, 6))


def _relative(name):
    if not isinstance(name, str) or not name:
        raise ValueError('empty notification name')
    value = name.replace('\\', '/')
    windows = PureWindowsPath(name)
    parts = value.split('/')
    if (value.startswith('/') or windows.drive or any(part in ('', '.', '..') for part in parts)
            or any(ord(ch) < 32 or ch in '<>:"|?*' for ch in value)
            or any(part.endswith((' ', '.')) or PureWindowsPath(part).is_reserved() for part in parts)):
        raise ValueError('notification name is not an unambiguous contained relative path')
    return '/'.join(parts)


def parse_notifications(payload):
    """Strict FILE_NOTIFY_INFORMATION parsing; no partial result on failure."""
    if not isinstance(payload, bytes) or not 12 <= len(payload) <= BUFFER_BYTES:
        raise ValueError('empty/oversized/truncated notification buffer')
    records = []
    offset = 0
    while True:
        if offset % 4 or len(payload)-offset < 12:
            raise ValueError('notification record alignment/header invalid')
        following, action, length = struct.unpack_from('<III', payload, offset)
        end = offset+12+length
        if action not in _ACTIONS or not length or length % 2 or end > len(payload):
            raise ValueError('notification action/name bounds invalid')
        name = payload[offset+12:end].decode('utf-16-le', errors='strict')
        records.append((action, _relative(name)))
        if following == 0:
            padding = payload[end:]
            if len(padding) > 3:
                raise ValueError('unexpected trailing notification bytes')
            return tuple(records)
        if following % 4 or following < 12+length or offset+following+12 > len(payload):
            raise ValueError('notification next-record bounds invalid')
        if following-(12+length) > 3:
            raise ValueError('excess notification alignment padding')
        offset += following


@dataclass(frozen=True)
class Ticket:
    generation: int
    dirty_paths: frozenset[str]
    full_required: bool
    inventory_required: bool
    available: bool
    _owner: object = field(repr=False, compare=False)


class NotificationLedger:
    """Thread-safe bounded epoch ledger; independently testable without Win32."""
    def __init__(self, *, max_dirty=MAX_DIRTY, max_dirty_bytes=MAX_DIRTY_BYTES, available=True):
        if not isinstance(max_dirty, int) or not 1 <= max_dirty <= 65536:
            raise ValueError('invalid dirty-name bound')
        if not isinstance(max_dirty_bytes, int) or not 1 <= max_dirty_bytes <= 16*1024*1024:
            raise ValueError('invalid dirty-name byte bound')
        self.max_dirty = max_dirty
        self.max_dirty_bytes = max_dirty_bytes
        self._lock = threading.Lock()
        self._owner = object()
        self._generation = self._full_epoch = self._inventory_epoch = 1
        self._dirty = {}
        self._dirty_bytes = 0
        self._available = available
        self._reason = 'startup_continuity_unproven'

    def set_available(self):
        with self._lock:
            self._available = True

    def listener_exited(self):
        with self._lock:
            if self._available:
                self._generation += 1
                self._full_epoch = self._inventory_epoch = self._generation
                self._reason = 'listener_exited'
            self._available = False

    def invalidate(self, reason, *, unavailable=False):
        with self._lock:
            self._generation += 1
            self._full_epoch = self._inventory_epoch = self._generation
            self._reason = str(reason)[:160]
            if unavailable:
                self._available = False

    def ingest(self, payload):
        try:
            records = parse_notifications(payload)
        except (ValueError, UnicodeError, struct.error):
            self.invalidate('empty_overflow_or_malformed_notification')
            return
        with self._lock:
            self._generation += 1
            epoch = self._generation
            self._inventory_epoch = epoch
            for _, name in records:
                name_bytes = len(name.encode('utf-8'))
                if name not in self._dirty and (len(self._dirty) >= self.max_dirty
                        or self._dirty_bytes+name_bytes > self.max_dirty_bytes):
                    # Not a silent truncation: all unknown paths are now covered
                    # only by a mandatory full byte sweep of the complete tree.
                    self._dirty.clear()
                    self._dirty_bytes = 0
                    self._full_epoch = epoch
                    self._reason = 'dirty_name_capacity_exceeded'
                    break
                if name not in self._dirty:
                    self._dirty_bytes += name_bytes
                self._dirty[name] = epoch

    def begin(self):
        with self._lock:
            return Ticket(self._generation, frozenset(self._dirty),
                bool(self._full_epoch) or not self._available,
                bool(self._inventory_epoch), self._available, self._owner)

    def poll(self):
        with self._lock:
            return dict(dirty_paths=tuple(sorted(self._dirty)), generation=self._generation,
                dirty_name_bytes=self._dirty_bytes,
                full_required=bool(self._full_epoch) or not self._available,
                needs_full_bytes=bool(self._full_epoch) or not self._available,
                inventory_required=bool(self._inventory_epoch), available=self._available,
                reason=self._reason)

    def complete(self, ticket, *, verified_paths=(), absent_paths=(),
                 inventory_complete=False, full_bytes=False):
        if not isinstance(ticket, Ticket) or ticket._owner is not self._owner:
            raise ValueError('ticket belongs to another listener')
        verified = {_relative(path) for path in verified_paths}
        absent = {_relative(path) for path in absent_paths}
        if (full_bytes or absent) and not inventory_complete:
            raise ValueError('full-byte/absence acknowledgement needs a complete inventory')
        if not verified.union(absent).issubset(ticket.dirty_paths):
            raise ValueError('cannot acknowledge a name outside the starting ticket')
        with self._lock:
            if not self._available:
                return False  # no continuous listener: never cache idle
            for name, epoch in tuple(self._dirty.items()):
                if epoch <= ticket.generation and (full_bytes or name in verified or name in absent):
                    self._dirty_bytes -= len(name.encode('utf-8'))
                    del self._dirty[name]
            if full_bytes and self._full_epoch <= ticket.generation:
                self._full_epoch = 0
            if inventory_complete and self._inventory_epoch <= ticket.generation:
                self._inventory_epoch = 0
            if not self._dirty and not self._full_epoch and not self._inventory_epoch:
                self._reason = 'continuous_watch_no_unacknowledged_changes'
            return True


class _WindowsBackend:
    """One owned handle/event/buffer/OVERLAPPED; free only after I/O completes."""
    def __init__(self, root):
        from ctypes import wintypes as w
        class Overlapped(ctypes.Structure):
            _fields_ = [('Internal', ctypes.c_size_t), ('InternalHigh', ctypes.c_size_t),
                        ('Offset', w.DWORD), ('OffsetHigh', w.DWORD), ('hEvent', w.HANDLE)]
        self._w = w
        self._api = api = ctypes.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'CreateFileW': ([w.LPCWSTR,w.DWORD,w.DWORD,ctypes.c_void_p,w.DWORD,w.DWORD,w.HANDLE], w.HANDLE),
            'CreateEventW': ([ctypes.c_void_p,w.BOOL,w.BOOL,w.LPCWSTR], w.HANDLE),
            'ReadDirectoryChangesW': ([w.HANDLE,ctypes.c_void_p,w.DWORD,w.BOOL,w.DWORD,
                                      ctypes.POINTER(w.DWORD),ctypes.c_void_p,ctypes.c_void_p], w.BOOL),
            'GetOverlappedResult': ([w.HANDLE,ctypes.c_void_p,ctypes.POINTER(w.DWORD),w.BOOL], w.BOOL),
            'ResetEvent': ([w.HANDLE], w.BOOL),
            'CancelIoEx': ([w.HANDLE,ctypes.c_void_p], w.BOOL),
            'CloseHandle': ([w.HANDLE], w.BOOL),
        }
        for name, (args, result) in signatures.items():
            getattr(api, name).argtypes = args
            getattr(api, name).restype = result
        self.handle = self.event = None
        self.buffer = ctypes.create_string_buffer(BUFFER_BYTES)
        self.overlapped = Overlapped()
        self.pending = False
        self.handle = api.CreateFileW(str(root), 0x0001, 0x0001|0x0002|0x0004,
                                     None, 3, 0x02000000|0x40000000, None)
        if self.handle == ctypes.c_void_p(-1).value or self.handle is None:
            self.handle = None
            raise ctypes.WinError(ctypes.get_last_error())
        self.event = api.CreateEventW(None, True, False, None)
        if not self.event:
            error = ctypes.get_last_error()
            api.CloseHandle(self.handle)
            self.handle = None
            raise ctypes.WinError(error)
        self.overlapped.hEvent = self.event

    def begin(self):
        if not self._api.ResetEvent(self.event):
            raise ctypes.WinError(ctypes.get_last_error())
        self.overlapped.Internal = self.overlapped.InternalHigh = 0
        self.overlapped.Offset = self.overlapped.OffsetHigh = 0
        # No LAST_ACCESS: reading source bytes must not dirty its own watch.
        flags = 0x0001|0x0002|0x0004|0x0008|0x0010|0x0040|0x0100
        queued = self._api.ReadDirectoryChangesW(self.handle, self.buffer, BUFFER_BYTES,
            True, flags, None, ctypes.byref(self.overlapped), None)
        if not queued and ctypes.get_last_error() != 997:  # ERROR_IO_PENDING
            raise ctypes.WinError(ctypes.get_last_error())
        self.pending = True

    def wait(self):
        count = self._w.DWORD()
        result = self._api.GetOverlappedResult(self.handle, ctypes.byref(self.overlapped),
                                              ctypes.byref(count), True)
        self.pending = False  # even aborted/error completion owns no active I/O
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())
        if count.value > BUFFER_BYTES:
            raise ValueError('native notification count exceeds allocated buffer')
        return self.buffer.raw[:count.value]

    def cancel(self):
        if self.handle is not None and self.pending:
            # Failure ERROR_NOT_FOUND can mean normal completion already won.
            self._api.CancelIoEx(self.handle, ctypes.byref(self.overlapped))

    def close(self):
        if self.pending:
            raise RuntimeError('cannot release a buffer with pending native I/O')
        for name in ('event', 'handle'):
            value = getattr(self, name)
            if value is not None:
                self._api.CloseHandle(value)
                setattr(self, name, None)


def _identity(root):
    # O(path depth), not O(media count). A held root handle prevents a deleted
    # identity from being reused unnoticed while this watcher is alive.
    for part in reversed((root, *root.parents)):
        directory(part)
    info = root.lstat()
    if not info.st_ino:
        raise ValueError('root has no dependable local file identity')
    return info.st_dev, info.st_ino


class AssetNotifications:
    def __init__(self, root, *, max_dirty=MAX_DIRTY, max_dirty_bytes=MAX_DIRTY_BYTES, startup_timeout=3,
                 _backend_factory=None, _identity_probe=None):
        self.root = local_absolute(root)
        self._probe = _identity_probe or _identity
        self._ledger = NotificationLedger(max_dirty=max_dirty, max_dirty_bytes=max_dirty_bytes, available=False)
        self._backend_lock = threading.Lock()
        self._backend = None
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread = None
        self._closed = False
        try:
            self._root_identity = self._probe(self.root)
        except (OSError, ValueError):
            self._root_identity = None
            self._ledger.invalidate('root_unavailable', unavailable=True)
            return
        factory = _backend_factory or (_WindowsBackend if os.name == 'nt' else None)
        if factory is None:
            self._ledger.invalidate('platform_notification_unavailable', unavailable=True)
            return
        self._factory = factory
        self._thread = threading.Thread(target=self._run, name='next-asset-notifications', daemon=True)
        self._thread.start()
        self._ready.wait(startup_timeout)

    def _fail(self, reason):
        self._stop.set()
        with self._backend_lock:
            # Serialize with begin()+set_available(). Otherwise an in-flight
            # registration could overwrite unavailable after a root failure.
            self._ledger.invalidate(reason, unavailable=True)
            if self._backend is not None:
                self._backend.cancel()

    def _run(self):
        try:
            backend = self._factory(self.root)
            with self._backend_lock:
                self._backend = backend
            if self._probe(self.root) != self._root_identity:
                self._fail('root_replaced_during_registration')
                return
            while not self._stop.is_set():
                try:
                    with self._backend_lock:
                        if self._stop.is_set():
                            break
                        backend.begin()
                        self._ledger.set_available()
                        self._ready.set()
                    payload = backend.wait()
                    if not self._stop.is_set():
                        self._ledger.ingest(payload)
                except OSError as exc:
                    code = getattr(exc, 'winerror', None) or getattr(exc, 'errno', None)
                    if code == ERROR_OPERATION_ABORTED and self._stop.is_set():
                        break
                    if code == ERROR_NOTIFY_ENUM_DIR:
                        self._ledger.invalidate('native_notification_overflow')
                        continue
                    self._fail('native_notification_error:'+str(code))
                    break
        except Exception as exc:
            self._fail('listener_error:'+type(exc).__name__)
        finally:
            with self._backend_lock:
                if self._backend is not None:
                    self._backend.close()
                    self._backend = None
            self._ledger.listener_exited()
            self._ready.set()

    def _check(self):
        if self._closed or self._root_identity is None:
            return
        try:
            current = self._probe(self.root)
        except (OSError, ValueError):
            current = None
        if current != self._root_identity and not self._stop.is_set():
            self._fail('root_replaced_or_unavailable')
        if self._thread is not None and not self._thread.is_alive() and not self._stop.is_set():
            self._fail('listener_exited_unexpectedly')

    def poll(self):
        self._check()
        return self._ledger.poll()

    def begin(self):
        self._check()
        return self._ledger.begin()

    def complete(self, ticket, **kwargs):
        self._check()
        return self._ledger.complete(ticket, **kwargs)

    def require_full_bytes(self, reason='consumer_could_not_resolve_notification'):
        self._ledger.invalidate(reason)

    def close(self, *, timeout=3):
        if not self._closed:
            self._closed = True
            self._fail('closed')
        if self._thread is not None:
            self._thread.join(timeout)
            if self._thread.is_alive():
                # Do not free the OVERLAPPED/buffer early and corrupt memory.
                raise TimeoutError('native cancellation did not complete; listener remains untrusted')

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
