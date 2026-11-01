"""Exercise the portable launcher with mocks only, never user desktop input."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name=='nt','Windows PowerShell boundary tests')
class DistributionLauncherTests(unittest.TestCase):
    def test_modes_quote_boundaries_and_no_offline_fallback(self):
        project=Path(__file__).resolve().parents[2]
        launcher=project/'Start-CaptureNext.ps1'
        if not launcher.exists():launcher=project/'wechat_capture_next'/'distribution'/'Start-CaptureNext.ps1'
        powershell=Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'powershell.exe'
        with tempfile.TemporaryDirectory() as temporary:
            report=Path(temporary)/'report.json'
            result=subprocess.run([str(powershell),'-NoProfile','-ExecutionPolicy','Bypass',
                '-File',str(Path(__file__).with_name('start_product_mock.ps1')),
                '-ReportPath',str(report),'-PortableLauncherPath',str(launcher)],
                capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90,
                env={k:v for k,v in os.environ.items() if k.upper()!='PSMODULEPATH'},
                creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            self.assertEqual(result.returncode,0,result.stderr)
            value=json.loads(report.read_text(encoding='utf-8-sig'))
            self.assertGreaterEqual(value['case_count'],40)
            self.assertFalse(value['failed'])
            self.assertFalse(value['single_instance_failed'])
            self.assertFalse(value['real_start_process_called'])
