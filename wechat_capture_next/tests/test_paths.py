from pathlib import Path
import os
import tempfile
import unittest

from wechat_capture_next.paths import local_absolute, safe_name


class PathTests(unittest.TestCase):
    def test_windows_namespace_aliases_rejected_before_filesystem_access(self):
        for value in (r'\\?\E:\source\new', r'\\.\E:\source\new', '//?/E:/source/new',
                      r'\\server\share\source\new', r'\??\E:\source\new', '/Device/HarddiskVolume1/new'):
            with self.assertRaises(ValueError, msg=value):
                local_absolute(value)
        self.assertEqual(local_absolute(Path.cwd()), Path.cwd())

    def test_windows_reserved_and_control_names(self):
        for value in ('COM¹.json','COM².json','LPT³.json','CON .json','NUL','x\x00y','x:y','x?y','..','a/b','a\\b','bad.'):
            with self.assertRaises(ValueError,msg=value):
                safe_name(value)
        self.assertEqual(safe_name('归档-2026.10'), '归档-2026.10')

    @unittest.skipUnless(os.name=='nt','DOS aliases are Windows-specific')
    def test_existing_dos_short_ancestor_is_canonicalized_before_boundary_check(self):
        import ctypes
        with tempfile.TemporaryDirectory() as work:
            state=Path(work)/'long archive state directory'
            state.mkdir()
            api=ctypes.windll.kernel32.GetShortPathNameW
            buffer=ctypes.create_unicode_buffer(32768)
            size=api(str(state),buffer,len(buffer))
            if not size or Path(buffer.value)==state:
                self.skipTest('filesystem did not create a distinct DOS short alias')
            alias=Path(buffer.value)
            self.assertTrue(alias.samefile(state))
            self.assertTrue(local_absolute(alias/'new-output').is_relative_to(state))
            self.assertEqual(local_absolute(alias),local_absolute(state))
