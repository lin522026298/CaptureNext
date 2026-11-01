"""Actual C# backend-exit/event branches with non-UI synthetic substitutes."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class DesktopBackendExitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler=Path(os.environ.get('WINDIR','C:/Windows'))/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        if not compiler.is_file():raise unittest.SkipTest('Windows .NET compiler unavailable')
        source=(Path(__file__).parents[1]/'desktop/CaptureNext.cs').read_text(encoding='utf-8')
        poll=source[source.index('        async Task Poll()'):source.index('        void ApplyStartup(')]
        branch=re.search(r'if\(backend.HasExited\) \{[^\r\n]+ return; \}',poll).group()
        stop=re.search(r'if\(exitEvent.WaitOne\(0\)\) \{ await Quit\(\); return; \}',source).group()
        opening=re.search(r'if\(openEvent.WaitOne\(0\)\) await OpenWindow\("overview"\);',source).group()
        cls.temporary=tempfile.TemporaryDirectory(prefix='capture-exited-controls-');cls.addClassCleanup(cls.temporary.cleanup)
        directory=Path(cls.temporary.name);cls.executable=directory/'ControlTest.exe'
        code='''using System;using System.Threading;using System.Threading.Tasks;
class ControlTest {
 class Backend { public bool HasExited=true; }
 class Tray { public string Text; }
 class Notices { public bool Changed(string value,bool enabled){return false;} }
 class Timer { public bool Enabled=true;public void Stop(){Enabled=false;} }
 Backend backend=new Backend();Tray tray=new Tray();Notices notices=new Notices();Timer timer=new Timer();
 bool notifications=false,quitCalled=false,openCalled=false;
 EventWaitHandle exitEvent=new EventWaitHandle(false,EventResetMode.AutoReset);
 EventWaitHandle openEvent=new EventWaitHandle(false,EventResetMode.AutoReset);
 void Alert(string text,bool error){}
 Task Quit(){quitCalled=true;return Task.FromResult(0);}
 Task OpenWindow(string page){openCalled=true;return Task.FromResult(0);}
 async Task Poll(){BRANCH await Task.FromResult(0);}
 async Task Tick(){if(!timer.Enabled)return;STOP OPEN}
 static int Main(string[] args){var test=new ControlTest();test.Poll().GetAwaiter().GetResult();
  if(args[0]=="quit")test.exitEvent.Set();else test.openEvent.Set();
  test.Tick().GetAwaiter().GetResult();
  Console.WriteLine(test.timer.Enabled+","+test.quitCalled+","+test.openCalled);return 0;}
}'''.replace('BRANCH',branch).replace('STOP',stop).replace('OPEN',opening)
        path=directory/'ControlTest.cs';path.write_text(code,encoding='utf-8')
        result=subprocess.run([str(compiler),'/nologo','/target:exe','/out:'+str(cls.executable),str(path)],capture_output=True,text=True)
        if result.returncode:raise AssertionError(result.stdout+result.stderr)

    def test_backend_exit_still_consumes_safe_quit_signal(self):
        result=subprocess.run([str(self.executable),'quit'],capture_output=True,text=True,check=True)
        self.assertEqual(result.stdout.strip(),'True,True,False')

    def test_backend_exit_still_consumes_existing_instance_activation(self):
        result=subprocess.run([str(self.executable),'open'],capture_output=True,text=True,check=True)
        self.assertEqual(result.stdout.strip(),'True,False,True')


if __name__=='__main__':unittest.main()
