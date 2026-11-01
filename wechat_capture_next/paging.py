"""Read-only Windows system paging counters, not process/physical-I/O attribution."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading


class PagingSampler:
    def __init__(self, output):
        self.process = None
        self.samples = 0
        self.maxima = {}
        self.error = None
        if os.name != 'nt':
            self.error = 'Windows counters unavailable on this OS'
            return
        shell = shutil.which('pwsh') or shutil.which('powershell')
        if not shell:
            self.error = 'PowerShell counter reader unavailable'
            return
        code = r"""$ErrorActionPreference='Stop'
Get-Counter -Counter @('\Memory\Pages Input/sec','\Memory\Pages Output/sec','\Paging File(_Total)\% Usage') -SampleInterval 1 -Continuous | ForEach-Object {
    $values=@{}
    foreach ($counterSample in $_.CounterSamples) {
        $values[$counterSample.Path.Substring($counterSample.Path.LastIndexOf('\')+1)]=$counterSample.CookedValue
    }
    @{unix_ms=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();values=$values} | ConvertTo-Json -Compress
}"""
        self.process = subprocess.Popen([shell, '-NoLogo', '-NoProfile', '-Command', code],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8',
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))

        def read():
            with Path(output).open('x', encoding='utf-8') as stream:
                for line in self.process.stdout:
                    try:
                        row = json.loads(line)
                        self.samples += 1
                        for key, value in row['values'].items():
                            self.maxima[key] = max(self.maxima.get(key, 0), value)
                        stream.write(json.dumps(row, separators=(',', ':'))+'\n')
                        stream.flush()
                    except (ValueError, KeyError) as exc:
                        self.error = type(exc).__name__

        self.thread = threading.Thread(target=read, daemon=True)
        self.thread.start()

    def finish(self):
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()  # Own counter helper only; never a user app.
            self.process.wait(timeout=10)
            self.thread.join(timeout=5)
            stderr = self.process.stderr.read()
            if stderr.strip():
                self.error = stderr
        return dict(samples=self.samples, error=self.error,
            pages_input_per_second_max=self.maxima.get('pages input/sec'),
            pages_output_per_second_max=self.maxima.get('pages output/sec'),
            pagefile_usage_percent_max=self.maxima.get('% usage'),
            scope='system-wide, includes mapped-file paging; not this process hard faults or physical writes')
