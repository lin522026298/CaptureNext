"""No-GUI launcher contracts, against both available PowerShell engines.

The PS harness AST-whitelists the entry's commands and shadows Start-Process
without ever delegating to a process launcher. Only these test PS interpreters
are launched. No product executable, archive, registry or real state is opened.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == "win32", "Windows PowerShell launcher contract")
class StartProductTests(unittest.TestCase):
    def test_entry_with_all_available_powershell_engines(self):
        project = Path(__file__).resolve().parents[2]
        harness = Path(__file__).with_name("start_product_mock.ps1")
        evidence = project / "working/wechat_product_20261022/launcher-qa"
        evidence.mkdir(parents=True, exist_ok=True)
        windows = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
            "System32/WindowsPowerShell/v1.0/powershell.exe"
        )
        self.assertTrue(windows.is_file(), "system PowerShell 5.1 is required")
        engines = [("windows51", str(windows))]
        pwsh = shutil.which("pwsh")
        if not pwsh:
            installed = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "PowerShell/7/pwsh.exe"
            if installed.is_file():
                pwsh = str(installed)
        if pwsh:
            engines.append(("pwsh", pwsh))
        for name, executable in engines:
            with self.subTest(engine=name):
                with tempfile.TemporaryDirectory(prefix="mock-", dir=evidence) as temp:
                    report = Path(temp) / "result.json"
                    result = subprocess.run(
                        [executable, "-NoLogo", "-NoProfile", "-NonInteractive",
                         "-File", str(harness), "-ReportPath", str(report)],
                        cwd=project, capture_output=True, timeout=45,
                        # A pwsh host's PSModulePath can hide Windows 5.1's
                        # own utility modules; let each child build its defaults.
                        env={k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"},
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                    data = json.loads(report.read_text(encoding="utf-8-sig"))
                    self.assertFalse(data["real_start_process_called"])
                    self.assertEqual(data["launcher_hash_before"], data["launcher_hash_after"])
                    self.assertGreaterEqual(data["case_count"], 57)
                    self.assertEqual(data["failed"], [])
                    self.assertEqual(data["single_instance_failed"], [])
                    self.assertEqual(len(data["single_instance"]), 10)
                    # Small synthetic receipt survives TemporaryDirectory cleanup.
                    (evidence / ("unittest-" + name + ".json")).write_text(
                        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
                    )


if __name__ == "__main__":
    unittest.main()
