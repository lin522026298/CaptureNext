"""Notification parser/epoch tests and isolated Windows temporary-directory I/O."""
from contextlib import closing
import ctypes
import os
from pathlib import Path
import queue
import struct
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wechat_capture_next import asset_notifications as notifications


def packet(*records):
    pieces = []
    for index, (action, name) in enumerate(records):
        encoded = name.encode('utf-16-le')
        size = 12+len(encoded)
        padding = (-size) % 4
        following = size+padding if index+1 < len(records) else 0
        pieces.append(struct.pack('<III', following, action, len(encoded))+encoded+b'\0'*padding)
    return b''.join(pieces)


def wait_until(test, predicate, timeout=3):
    deadline = time.perf_counter()+timeout
    while time.perf_counter() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.005)
    test.fail('synthetic listener condition did not become true before timeout')


class ParserTests(unittest.TestCase):
    def test_unicode_multiple_actions_and_nonzero_alignment_padding(self):
        data = packet((1, '目录\\新附件.dat'), (4, 'old.dat'), (5, 'new.dat'))
        self.assertEqual(notifications.parse_notifications(data),
                         ((1, '目录/新附件.dat'), (4, 'old.dat'), (5, 'new.dat')))
        single = bytearray(packet((3, 'a')))
        single[-2:] = b'XY'  # OS padding bytes are not promised to be zero.
        self.assertEqual(notifications.parse_notifications(bytes(single)), ((3, 'a'),))

    def test_names_are_strict_relative_windows_paths(self):
        names = ('', '..', '../other', 'a/../b', '/root', '\\root', 'C:relative', 'C:\\root',
                 'a:stream', 'a//b', 'a\\\\b', '.', 'a/.', 'nul', 'x.', 'x ', 'bad\0name')
        for name in names:
            with self.subTest(name=name), self.assertRaises(ValueError):
                notifications.parse_notifications(packet((3, name)))

    def test_bounds_alignment_actions_and_utf16_fail_without_partial_result(self):
        malformed = [b'', b'\0'*11, b'x'*(notifications.BUFFER_BYTES+1),
            struct.pack('<III', 0, 0, 2)+b'a\0',
            struct.pack('<III', 0, 3, 3)+b'abc',
            struct.pack('<III', 0, 3, 20)+b'a\0',
            struct.pack('<III', 15, 3, 2)+b'a\0'+b'\0'*20,
            struct.pack('<III', 12, 3, 2)+b'a\0'+b'\0'*20,
            struct.pack('<III', 100, 3, 2)+b'a\0',
            struct.pack('<III', 0, 3, 2)+b'\x00\xd8',
            packet((3, 'ok'))+b'\0'*4]
        for data in malformed:
            with self.subTest(data=data[:24]), self.assertRaises((ValueError, UnicodeError)):
                notifications.parse_notifications(data)


class LedgerTests(unittest.TestCase):
    def clean(self, ledger):
        ticket = ledger.begin()
        self.assertTrue(ledger.complete(ticket, inventory_complete=True, full_bytes=True))
        self.assertFalse(ledger.poll()['full_required'])

    def test_start_requires_bytes_not_metadata_and_poll_does_not_consume(self):
        ledger = notifications.NotificationLedger()
        first = ledger.begin()
        self.assertTrue(first.full_required)
        ledger.complete(first, inventory_complete=True)
        self.assertTrue(ledger.poll()['full_required'])
        self.clean(ledger)
        ledger.ingest(packet((3, 'a.dat')))
        one = ledger.poll()
        self.assertEqual(one, ledger.poll())
        self.assertEqual(one['dirty_paths'], ('a.dat',))
        self.assertTrue(one['inventory_required'])

    def test_ack_old_ticket_retains_new_same_name_and_other_events(self):
        ledger = notifications.NotificationLedger()
        self.clean(ledger)
        ledger.ingest(packet((3, 'a.dat')))
        ticket = ledger.begin()
        ledger.ingest(packet((3, 'a.dat'), (1, 'b.dat')))
        ledger.complete(ticket, verified_paths=('a.dat',), inventory_complete=True)
        self.assertEqual(ledger.poll()['dirty_paths'], ('a.dat', 'b.dat'))
        self.assertTrue(ledger.poll()['inventory_required'])
        later = ledger.begin()
        ledger.complete(later, verified_paths=later.dirty_paths, inventory_complete=True)
        self.assertEqual(ledger.poll()['dirty_paths'], ())

    def test_full_ack_never_erases_overflow_after_ticket(self):
        ledger = notifications.NotificationLedger(max_dirty=1)
        ticket = ledger.begin()
        ledger.ingest(packet((1, 'one'), (1, 'two')))
        self.assertTrue(ledger.poll()['full_required'])
        self.assertLessEqual(len(ledger.poll()['dirty_paths']), 1)
        ledger.complete(ticket, full_bytes=True, inventory_complete=True)
        self.assertTrue(ledger.poll()['full_required'])
        self.clean(ledger)

    def test_utf8_name_budget_is_bounded_and_never_silently_truncated(self):
        ledger = notifications.NotificationLedger(max_dirty_bytes=8)
        self.clean(ledger)
        ledger.ingest(packet((3, 'one'), (3, 'two')))
        self.assertEqual(ledger.poll()['dirty_name_bytes'], 6)
        ticket = ledger.begin()
        ledger.complete(ticket, verified_paths=('one',), inventory_complete=True)
        self.assertEqual(ledger.poll()['dirty_name_bytes'], 3)
        ledger.ingest(packet((3, '新名字')))
        self.assertTrue(ledger.poll()['full_required'])
        self.assertEqual(ledger.poll()['dirty_name_bytes'], 0)
        self.assertEqual(ledger.poll()['dirty_paths'], ())

    def test_zero_bytes_and_malformed_force_bytes_not_a_truncated_dirty_set(self):
        ledger = notifications.NotificationLedger()
        for data in (b'', b'bad'):
            self.clean(ledger)
            ledger.ingest(data)
            self.assertTrue(ledger.poll()['needs_full_bytes'])

    def test_rename_and_delete_need_inventory_absence_ack(self):
        ledger = notifications.NotificationLedger()
        self.clean(ledger)
        ledger.ingest(packet((4, 'old'), (5, 'new'), (2, 'deleted')))
        ticket = ledger.begin()
        with self.assertRaises(ValueError):
            ledger.complete(ticket, absent_paths=('old', 'deleted'))
        ledger.complete(ticket, verified_paths=('new',), absent_paths=('old', 'deleted'),
                        inventory_complete=True)
        self.assertEqual(ledger.poll()['dirty_paths'], ())

    def test_foreign_ticket_names_and_unavailable_listener_cannot_ack_clean(self):
        first = notifications.NotificationLedger()
        second = notifications.NotificationLedger()
        with self.assertRaises(ValueError):
            second.complete(first.begin(), full_bytes=True, inventory_complete=True)
        ticket = first.begin()
        with self.assertRaises(ValueError):
            first.complete(ticket, verified_paths=('not-in-ticket',))
        first.invalidate('test platform unavailable', unavailable=True)
        self.assertFalse(first.complete(first.begin(), full_bytes=True, inventory_complete=True))
        self.assertTrue(first.poll()['full_required'])
        self.assertFalse(first.poll()['available'])


class FakeBackend:
    def __init__(self):
        self.items = queue.Queue()
        self.closed = False
        self.cancelled = False
        self.begins = 0

    def begin(self):
        self.begins += 1

    def wait(self):
        item = self.items.get(timeout=5)
        if isinstance(item, Exception):
            raise item
        return item

    def cancel(self):
        self.cancelled = True
        self.items.put(OSError(notifications.ERROR_OPERATION_ABORTED, 'cancelled synthetic read'))

    def close(self):
        self.closed = True


class ListenerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='next-notifications-synthetic-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_fake_root_identity_change_cancels_and_never_becomes_cached_idle(self):
        backend = FakeBackend()
        identity = [(1, 10)]
        with notifications.AssetNotifications(self.root, _backend_factory=lambda root: backend,
                _identity_probe=lambda root: identity[0]) as watcher:
            self.assertTrue(watcher.poll()['available'])
            ticket = watcher.begin()
            watcher.complete(ticket, full_bytes=True, inventory_complete=True)
            self.assertFalse(watcher.poll()['full_required'])
            identity[0] = (1, 11)
            self.assertTrue(watcher.poll()['full_required'])
            self.assertFalse(watcher.poll()['available'])
            self.assertFalse(watcher.complete(watcher.begin(), full_bytes=True, inventory_complete=True))
        self.assertTrue(backend.cancelled)
        self.assertTrue(backend.closed)
        self.assertFalse(watcher._thread.is_alive())

    def test_native_overflow_and_fatal_error_are_distinct_but_both_require_bytes(self):
        backend = FakeBackend()
        with notifications.AssetNotifications(self.root, _backend_factory=lambda root: backend) as watcher:
            ticket = watcher.begin()
            watcher.complete(ticket, full_bytes=True, inventory_complete=True)
            backend.items.put(OSError(notifications.ERROR_NOTIFY_ENUM_DIR, 'overflow'))
            wait_until(self, lambda: watcher.poll()['full_required'])
            self.assertTrue(watcher.poll()['available'])
            ticket = watcher.begin()
            watcher.complete(ticket, full_bytes=True, inventory_complete=True)
            backend.items.put(OSError(5, 'synthetic access denied'))
            wait_until(self, lambda: not watcher.poll()['available'])
            self.assertTrue(watcher.poll()['full_required'])
            self.assertEqual(watcher.poll()['reason'], 'native_notification_error:5')

    def test_poll_retains_events_until_epoch_ack_while_thread_keeps_reading(self):
        backend = FakeBackend()
        with notifications.AssetNotifications(self.root, _backend_factory=lambda root: backend) as watcher:
            watcher.complete(watcher.begin(), full_bytes=True, inventory_complete=True)
            backend.items.put(packet((3, 'one')))
            wait_until(self, lambda: 'one' in watcher.poll()['dirty_paths'])
            ticket = watcher.begin()
            backend.items.put(packet((3, 'one')))
            wait_until(self, lambda: watcher.poll()['generation'] > ticket.generation)
            watcher.complete(ticket, verified_paths=('one',), inventory_complete=True)
            self.assertEqual(watcher.poll()['dirty_paths'], ('one',))
            watcher.complete(watcher.begin(), verified_paths=('one',), inventory_complete=True)
            self.assertEqual(watcher.poll()['dirty_paths'], ())

    def test_non_windows_notification_unavailable_always_requests_full_bytes(self):
        with patch.object(notifications, 'os', SimpleNamespace(name='posix')):
            with notifications.AssetNotifications(self.root) as watcher:
                self.assertFalse(watcher.poll()['available'])
                self.assertTrue(watcher.poll()['full_required'])
                self.assertFalse(watcher.complete(watcher.begin(), full_bytes=True, inventory_complete=True))
                self.assertTrue(watcher.poll()['full_required'])


@unittest.skipUnless(os.name == 'nt', 'native notification acceptance requires Windows')
class NativeWindowsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='next-notifications-native-synthetic-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def clean(self, watcher):
        self.assertTrue(watcher.poll()['available'], watcher.poll())
        watcher.complete(watcher.begin(), full_bytes=True, inventory_complete=True)

    def test_create_write_rename_and_same_size_restored_mtime_stay_dirty(self):
        with notifications.AssetNotifications(self.root) as watcher:
            self.clean(watcher)
            path = self.root/'synthetic.dat'
            path.write_bytes(b'old!')
            wait_until(self, lambda: 'synthetic.dat' in watcher.poll()['dirty_paths'])
            # Drain the completed create before a distinct same-stamp rewrite.
            time.sleep(0.05)
            ticket = watcher.begin()
            self.assertEqual(path.read_bytes(), b'old!')
            watcher.complete(ticket, verified_paths=('synthetic.dat',), inventory_complete=True)
            old = path.stat()
            path.write_bytes(b'new!')
            os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns))
            self.assertEqual((path.stat().st_size, path.stat().st_mtime_ns),
                             (old.st_size, old.st_mtime_ns))
            wait_until(self, lambda: 'synthetic.dat' in watcher.poll()['dirty_paths'])
            ticket = watcher.begin()
            self.assertEqual(path.read_bytes(), b'new!')
            watcher.complete(ticket, verified_paths=('synthetic.dat',), inventory_complete=True)
            renamed = path.rename(self.root/'renamed.dat')
            wait_until(self, lambda: {'synthetic.dat', 'renamed.dat'}.issubset(watcher.poll()['dirty_paths']))
            self.assertTrue(watcher.poll()['inventory_required'])
            ticket = watcher.begin()
            watcher.complete(ticket, verified_paths=('renamed.dat',), absent_paths=('synthetic.dat',),
                             inventory_complete=True)
            renamed.unlink()
            wait_until(self, lambda: 'renamed.dat' in watcher.poll()['dirty_paths'])

    def test_real_root_replacement_is_detected_and_old_handle_does_not_block_rename(self):
        original = self.root/'watched'
        original.mkdir()
        watcher = notifications.AssetNotifications(original)
        try:
            self.clean(watcher)
            original.rename(self.root/'moved')  # requires FILE_SHARE_DELETE
            original.mkdir()
            self.assertTrue(watcher.poll()['full_required'])
            self.assertFalse(watcher.poll()['available'])
        finally:
            watcher.close()

    def test_pending_native_io_cancels_and_closes_all_owned_handles_promptly(self):
        for _ in range(5):
            watcher = notifications.AssetNotifications(self.root)
            self.assertTrue(watcher.poll()['available'], watcher.poll())
            with watcher._backend_lock:
                backend = watcher._backend
            began = time.perf_counter()
            watcher.close(timeout=2)
            self.assertLess(time.perf_counter()-began, 2)
            self.assertFalse(watcher._thread.is_alive())
            self.assertIsNone(backend.handle)
            self.assertIsNone(backend.event)
            self.assertFalse(backend.pending)
            watcher.close()  # idempotent


if __name__ == '__main__':
    unittest.main()
