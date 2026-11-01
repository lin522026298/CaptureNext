"""Loss-aware source byte proofs, including hardlink aliases and restored mtime."""
import ctypes
import os
from itertools import count
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

from wechat_capture_next import assets
from wechat_capture_next.asset_notifications import NotificationLedger
from wechat_capture_next.tests.test_asset_notifications import packet
from wechat_capture_next.tests import test_assets as fixtures
from wechat_capture_v2.common import digest_file


class AssetEventTests(unittest.TestCase):
    setUp = fixtures.AssetTests.setUp
    tearDown = fixtures.AssetTests.tearDown
    add_media = fixtures.AssetTests.add_media
    capture = fixtures.AssetTests.capture

    def arm(self):
        ledger = self.ledger = NotificationLedger()
        self.service._asset_notifications = SimpleNamespace(root=self.media,
            poll=ledger.poll, begin=ledger.begin, complete=ledger.complete,
            require_full_bytes=ledger.invalidate, close=lambda:None)

    def hidden_edit(self, path, data):
        before = path.stat()
        path.write_bytes(data)
        os.utime(path, ns=(before.st_atime_ns,before.st_mtime_ns))

    def current(self):
        return dict(self.service.catalog.db.execute('SELECT relative_path,file_sha FROM asset'))

    def test_named_same_stamp_edit_propagates_all_hardlink_aliases(self):
        first = self.add_media('a.dat',b'before')
        second = self.media/'b.dat'
        os.link(first,second)
        self.arm()
        self.capture()
        self.hidden_edit(first,b'edited')
        self.ledger.ingest(packet((3,'a.dat')))
        result = self.capture()
        self.assertEqual(result['new_versions'],2)
        self.assertEqual(self.current(),{'a.dat':digest_file(first),'b.dat':digest_file(first)})
        self.assertFalse(assets.assets_need_scan(self.service))
        with patch.object(assets,'_walk',side_effect=AssertionError('idle must not scan inventory')):
            for _ in range(20):
                self.assertFalse(assets.assets_need_scan(self.service))

    def test_incoming_directory_invalidates_earlier_alias_outside_dirty_prefix(self):
        first = self.add_media('a-alias.dat',b'before')
        incoming = self.account/'incoming'
        incoming.mkdir()
        os.link(first,incoming/'copy.dat')
        self.arm()
        self.capture()
        self.hidden_edit(first,b'edited')
        incoming.rename(self.media/'z-dir')
        self.ledger.ingest(packet((1,'z-dir')))
        result = self.capture()
        self.assertEqual(result['new_versions'],2)
        self.assertEqual(set(self.current().values()),{digest_file(first)})

    def test_external_hardlink_write_is_byte_checked_by_periodic_shared_audit(self):
        first = self.add_media(data=b'before')
        outside = self.account/'outside.dat'
        os.link(first,outside)
        self.arm()
        self.capture()
        self.hidden_edit(outside,b'edited')
        self.assertFalse(assets.assets_need_scan(self.service))
        result = self.capture(verify_shared=True)
        self.assertEqual(result['new_versions'],1)
        self.assertEqual(self.current()['a.dat'],digest_file(first))

    @unittest.skipUnless(os.name == 'nt', 'native timestamp suppression requires Windows')
    def test_native_quiet_same_stamp_write_is_caught_by_periodic_full_bytes(self):
        from ctypes import wintypes as w
        first = self.add_media(data=b'old!')
        self.assertEqual(first.stat().st_nlink,1)
        self.capture()  # Arm the real listener and establish the accepted bytes.
        watcher = self.service._asset_notifications
        self.assertTrue(watcher.poll()['available'],watcher.poll())
        self.assertFalse(assets.assets_need_scan(self.service))
        before = first.stat()
        old_sha = self.current()['a.dat']

        api = ctypes.WinDLL('kernel32',use_last_error=True)
        api.CreateFileW.argtypes = [w.LPCWSTR,w.DWORD,w.DWORD,ctypes.c_void_p,w.DWORD,w.DWORD,w.HANDLE]
        api.CreateFileW.restype = w.HANDLE
        api.SetFileTime.argtypes = [w.HANDLE,ctypes.POINTER(w.FILETIME),ctypes.POINTER(w.FILETIME),ctypes.POINTER(w.FILETIME)]
        api.SetFileTime.restype = w.BOOL
        api.WriteFile.argtypes = [w.HANDLE,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD),ctypes.c_void_p]
        api.WriteFile.restype = w.BOOL
        api.FlushFileBuffers.argtypes = [w.HANDLE]
        api.FlushFileBuffers.restype = w.BOOL
        api.CloseHandle.argtypes = [w.HANDLE]
        api.CloseHandle.restype = w.BOOL
        handle = api.CreateFileW(str(first),0x40000000,7,None,3,0,None)
        self.assertNotIn(handle,(None,ctypes.c_void_p(-1).value))
        try:
            # Documented Win32 behavior: suppress this handle's last-write time
            # updates, rather than restoring mtime afterward (which emits an event).
            suppressed = w.FILETIME(0xffffffff,0xffffffff)
            self.assertTrue(api.SetFileTime(handle,None,None,ctypes.byref(suppressed)))
            data = ctypes.create_string_buffer(b'new!')
            written = w.DWORD()
            self.assertTrue(api.WriteFile(handle,data,4,ctypes.byref(written),None))
            self.assertEqual(written.value,4)
            self.assertTrue(api.FlushFileBuffers(handle))
        finally:
            self.assertTrue(api.CloseHandle(handle))
        after = first.stat()
        self.assertEqual((after.st_ino,after.st_size,after.st_mtime_ns),
                         (before.st_ino,before.st_size,before.st_mtime_ns))
        self.assertEqual(first.read_bytes(),b'new!')
        # Allow asynchronous delivery: this valid single-link rewrite must stay
        # quiet, demonstrating why named events are not a complete byte proof.
        until = time.monotonic()+.3
        while time.monotonic() < until:
            snapshot = watcher.poll()
            self.assertTrue(snapshot['available'],snapshot)
            self.assertFalse(snapshot['dirty_paths'],snapshot)
            self.assertFalse(snapshot['full_required'],snapshot)
            self.assertFalse(snapshot['inventory_required'],snapshot)
            time.sleep(.01)
        self.assertFalse(assets.assets_need_scan(self.service))
        self.assertEqual(self.current()['a.dat'],old_sha)

        result = self.capture(force=True)  # Both watch entries retain this periodic policy.
        self.assertEqual(result['byte_verification'],'full_sweep')
        self.assertTrue(result['complete'])
        self.assertFalse(result['errors'])
        self.assertEqual(result['new_versions'],1)
        self.assertEqual(self.current()['a.dat'],digest_file(first))
        self.assertNotEqual(self.current()['a.dat'],old_sha)

    def test_periodic_shared_audit_upgrades_active_pass_and_revisits_prefix(self):
        first = self.add_media('a-prefix.dat',b'before')
        self.add_media('z-tail.dat',b'known')
        outside = self.account/'outside.dat'
        os.link(first,outside)
        self.arm()
        self.capture()
        self.hidden_edit(outside,b'edited')
        with patch.object(assets.time,'monotonic',side_effect=count().__next__):
            self.assertFalse(self.capture(budget_seconds=.5)['complete'])
        self.assertFalse(self.service._asset_force)
        self.assertFalse(self.service._asset_verify_shared)
        result = self.capture(verify_shared=True)
        self.assertTrue(result['complete'])
        self.assertEqual(result['new_versions'],1)
        self.assertTrue(result['shared_inode_periodic_bytes'])
        self.assertEqual(self.current()['a-prefix.dat'],digest_file(first))

    def test_unknown_deleted_name_or_short_alias_forces_all_source_bytes(self):
        self.add_media(data=b'known')
        self.arm()
        self.capture()
        for name in ('new-but-already-deleted.tmp','LONGNA~1.DAT'):
            self.ledger.ingest(packet((2,name)))
            result = self.capture()
            self.assertEqual(result['byte_verification'],'full_sweep')
            self.assertEqual(result['verified_unchanged_files'],1)
            self.assertFalse(assets.assets_need_scan(self.service))

    def test_late_event_survives_successful_full_pass_acknowledgement(self):
        self.add_media(data=b'known')
        self.arm()
        self.capture()
        self.ledger.ingest(packet((3,'a.dat')))
        actual = assets._KnownSourceCheck.advance
        def raced(pending, deadline):
            value = actual(pending,deadline)
            if value:
                self.ledger.ingest(packet((3,'a.dat')))
            return value
        with patch.object(assets._KnownSourceCheck,'advance',raced):
            self.assertTrue(self.capture()['complete'])
        self.assertTrue(assets.assets_need_scan(self.service))
        self.capture()
        self.assertFalse(assets.assets_need_scan(self.service))

    def test_known_hash_reuse_has_no_object_or_asset_writes(self):
        self.add_media(data=b'known'*1000)
        self.arm()
        self.capture()
        before = self.service.objects.db.total_changes, self.service.catalog.db.total_changes
        result = self.capture(force=True)
        self.assertEqual(result['verified_unchanged_files'],1)
        self.assertEqual(result['verified_unchanged_bytes'],5000)
        self.assertEqual(before,(self.service.objects.db.total_changes,self.service.catalog.db.total_changes))
