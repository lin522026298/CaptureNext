"""Compile only the real runtime-directory helper; no shell/UI/backend/build."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class DesktopRuntimeDirectoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler=Path(os.environ.get('WINDIR','C:/Windows'))/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        if not compiler.is_file():
            raise unittest.SkipTest('Windows .NET compiler unavailable')
        parent=Path(__file__).resolve().parents[2]/'working/wechat_product_20261022/runtime-directory-selftests'
        parent.mkdir(parents=True,exist_ok=True)
        cls.temporary=tempfile.TemporaryDirectory(prefix='helper-',dir=parent)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.test_root=Path(cls.temporary.name)
        cls.source=(Path(__file__).parents[1]/'desktop/CaptureNext.cs').read_text(encoding='utf-8')
        helper=cls.source[cls.source.index('    static class ShellRuntimeDirectory {'):cls.source.index('    // Pure status projection:')]
        harness='''
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;
namespace CaptureNext {
HELPER
class Test {
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern SafeFileHandle Probe(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    static void Main() {
        Console.InputEncoding=new UTF8Encoding(false); Console.OutputEncoding=new UTF8Encoding(false);
        var json=new JavaScriptSerializer(); string line;
        while((line=Console.ReadLine())!=null) {
            try {
                var value=json.Deserialize<Dictionary<string,object>>(line);
                if((string)value["operation"]=="probe") {
                    // Access test only: no disposition/delete operation.
                    using(var handle=Probe((string)value["path"],0x10000,0,IntPtr.Zero,3,
                            (bool)value["directory"]?0x00200000u|0x02000000u:0x00200000u,IntPtr.Zero)) {
                        if(handle.IsInvalid) throw new IOException("guard not released");
                    }
                } else ShellRuntimeDirectory.Write((string)value["root"],(string)value["runtime"],(string)value["contents"]);
                Console.WriteLine(json.Serialize(new { ok=true }));
            } catch(Exception error) { Console.WriteLine(json.Serialize(new { ok=false,error_type=error.GetType().Name })); }
        }
    }
}}
'''.replace('HELPER',helper)
        source=cls.test_root/'RuntimeDirectoryTest.cs';source.write_text(harness,encoding='utf-8')
        cls.executable=cls.test_root/'RuntimeDirectoryTest.exe'
        result=subprocess.run([str(compiler),'/nologo','/target:exe','/platform:x64','/codepage:65001',
            '/r:System.Web.Extensions.dll','/out:'+str(cls.executable),str(source)],capture_output=True,text=True,
            creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:
            raise AssertionError(result.stdout+result.stderr)

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='case-',dir=self.test_root)
        self.addCleanup(self.temp.cleanup)
        self.case=Path(self.temp.name);self.root=self.case/'workspace';self.root.mkdir()

    def runtime(self,recovery=False):
        return self.root/'archives/wechat-next'/('product-recovery' if recovery else 'product')

    def request(self,runtime=None,contents='{"phase":"tray"}',root=None):
        return dict(operation='write',root=str(root or self.root),runtime=str(runtime or self.runtime()),contents=contents)

    def run_requests(self,*requests):
        result=subprocess.run([str(self.executable)],input=''.join(json.dumps(r)+'\n' for r in requests),
            capture_output=True,text=True,encoding='utf-8',creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode,0,result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines()]

    def junction(self,link,target):
        self.assertTrue(link.is_relative_to(self.case));self.assertTrue(target.is_relative_to(self.case))
        result=subprocess.run(['cmd','/d','/c','mklink','/J',str(link),str(target)],
            capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode,0)

    def test_missing_normal_runtime_gets_marker_without_window_or_session_output(self):
        text='{"phase":"tray","synthetic":"中文"}'
        self.assertTrue(self.run_requests(self.request(contents=text))[0]['ok'])
        self.assertEqual((self.runtime()/'shell.private.json').read_bytes(),text.encode())
        self.assertFalse((self.root/'archives/wechat-next/product-sessions').exists())
        self.assertFalse((self.runtime()/'webview-cache').exists())

    def test_recovery_runtime_stays_separate_from_normal(self):
        self.assertTrue(self.run_requests(self.request(self.runtime(True)))[0]['ok'])
        self.assertTrue((self.runtime(True)/'shell.private.json').is_file())
        self.assertFalse(self.runtime().exists())

    def test_existing_session_output_owner_settings_and_data_unchanged(self):
        base=self.root/'archives/wechat-next';session=base/'product-sessions'/('a'*32)
        session.mkdir(parents=True)
        preserved={session/'OWNER.private.json':b'{"synthetic_owner":1}',session/'operations.private.json':b'synthetic ledger',
            base/'active-binding.private.json':b'{"synthetic_binding":1}'}
        self.runtime().mkdir()
        preserved[self.runtime()/'settings.private.json']=b'{"synthetic_settings":1}'
        for path,data in preserved.items():path.write_bytes(data)
        self.assertTrue(self.run_requests(self.request())[0]['ok'])
        for path,data in preserved.items():self.assertEqual(path.read_bytes(),data)
        self.assertFalse((session/'shell.private.json').exists())

    def test_repeated_marker_write_truncates_only_owned_regular_marker(self):
        values=self.run_requests(self.request(contents='x'*100),self.request(contents='short'))
        self.assertTrue(all(value['ok'] for value in values))
        self.assertEqual((self.runtime()/'shell.private.json').read_bytes(),b'short')

    def test_window_preflight_creates_runtime_but_never_writes_marker(self):
        self.assertTrue(self.run_requests(self.request(contents=None))[0]['ok'])
        self.assertTrue(self.runtime().is_dir());self.assertFalse((self.runtime()/'shell.private.json').exists())

    def test_outside_fixed_runtime_and_other_workspace_rejected_before_creation(self):
        other=self.case/'other';other.mkdir()
        values=self.run_requests(self.request(self.root/'archives/wechat-next/state'),
            self.request(other/'archives/wechat-next/product'))
        self.assertTrue(all(not value['ok'] for value in values))
        self.assertFalse((self.root/'archives').exists());self.assertFalse((other/'archives').exists())

    def test_workspace_must_be_existing_directory_not_file(self):
        file_root=self.case/'file-root';file_root.write_bytes(b'original data')
        missing=self.case/'missing-root'
        values=self.run_requests(self.request(file_root/'archives/wechat-next/product',root=file_root),
            self.request(missing/'archives/wechat-next/product',root=missing))
        self.assertTrue(all(not value['ok'] for value in values))
        self.assertEqual(file_root.read_bytes(),b'original data');self.assertFalse(missing.exists())

    def test_intermediate_file_and_runtime_file_are_not_replaced(self):
        for recovery in (False,True):
            runtime=self.runtime(recovery);runtime.parent.mkdir(parents=True,exist_ok=True)
            runtime.write_bytes(b'keep runtime file')
            self.assertFalse(self.run_requests(self.request(runtime))[0]['ok'])
            self.assertEqual(runtime.read_bytes(),b'keep runtime file')
        another=self.case/'another';another.mkdir();(another/'archives').write_bytes(b'keep ancestor file')
        value=self.run_requests(self.request(another/'archives/wechat-next/product',root=another))[0]
        self.assertFalse(value['ok']);self.assertEqual((another/'archives').read_bytes(),b'keep ancestor file')

    def test_workspace_junction_not_traversed(self):
        actual=self.case/'actual';actual.mkdir();linked=self.case/'linked';self.junction(linked,actual)
        value=self.run_requests(self.request(linked/'archives/wechat-next/product',root=linked))[0]
        self.assertFalse(value['ok']);self.assertFalse((actual/'archives').exists())

    def test_runtime_junction_not_traversed_or_target_changed(self):
        self.runtime().parent.mkdir(parents=True)
        actual=self.case/'outside-runtime';actual.mkdir();marker=actual/'shell.private.json';marker.write_bytes(b'keep outside data')
        self.junction(self.runtime(),actual)
        self.assertFalse(self.run_requests(self.request())[0]['ok'])
        self.assertEqual(marker.read_bytes(),b'keep outside data')

    def test_marker_directory_and_hardlink_never_truncated_and_guards_release(self):
        self.runtime().mkdir(parents=True);marker=self.runtime()/'shell.private.json';marker.mkdir()
        (marker/'important.txt').write_bytes(b'keep nested data')
        self.assertFalse(self.run_requests(self.request())[0]['ok'])
        self.assertEqual((marker/'important.txt').read_bytes(),b'keep nested data')
        (marker/'important.txt').unlink();marker.rmdir()
        original=self.case/'important-original';original.write_bytes(b'keep hardlink data');os.link(original,marker)
        requests=[self.request(),dict(operation='probe',path=str(self.runtime()),directory=True),
            dict(operation='probe',path=str(self.root),directory=True),dict(operation='probe',path=str(marker),directory=False)]
        values=self.run_requests(*requests)
        self.assertFalse(values[0]['ok']);self.assertTrue(all(value['ok'] for value in values[1:]))
        self.assertEqual(original.read_bytes(),b'keep hardlink data');self.assertEqual(marker.read_bytes(),b'keep hardlink data')

    def test_write_failure_keeps_original_catch_and_backend_safe_cleanup(self):
        state=self.source[self.source.index('        void WriteState()'):self.source.index('        void CleanBrowserMetrics()')]
        self.assertIn('ShellRuntimeDirectory.Write(workspace,runtime,json.Serialize',state)
        self.assertIn('Runtime evidence failure must not stop acquisition',state)
        window=self.source[self.source.index('        async Task OpenWindow('):self.source.index('        void RevealWindow(')]
        self.assertLess(window.index('ShellRuntimeDirectory.Write(workspace,runtime,null)'),window.index('CoreWebView2Environment.CreateAsync'))
        constructor=self.source[self.source.index('        public Shell('):self.source.index('        void WriteState()')]
        self.assertIn('if(recoveryMode) runtime=Path.Combine(root,"archives","wechat-next","product-recovery")',constructor)
        self.assertIn('if(!initialized)',constructor);self.assertIn('backend.StandardInput.Close()',constructor)
        self.assertIn('backend.Dispose()',constructor);self.assertNotIn('.Kill(',self.source)
        quit=self.source[self.source.index('        async Task Quit()'):self.source.index('    static class Program')]
        self.assertIn('backend.StandardInput.WriteLine("quit")',quit);self.assertIn('finally { phase="stopped"; WriteState()',quit)
        self.assertNotIn('File.Delete(',state)


if __name__=='__main__':unittest.main()
