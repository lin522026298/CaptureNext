[CmdletBinding()]
param([string]$Python = 'python', [switch]$SkipInstall)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location -LiteralPath $root
$buildPython = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $buildPython)) {
    & $Python -c "import sys,struct; assert sys.version_info[:2] == (3,11) and struct.calcsize('P')==8, 'Use 64-bit Python 3.11'"
    if ($LASTEXITCODE) { throw '64-bit Python 3.11 is required.' }
    & $Python -m venv (Join-Path $root '.venv')
    if ($LASTEXITCODE) { throw 'Isolated environment creation failed.' }
}
if (-not $SkipInstall) {
    & $buildPython -m pip install --timeout 60 --retries 3 -r (Join-Path $root 'requirements-build.lock')
    if ($LASTEXITCODE) { throw 'Dependency installation failed.' }
}
$cache = Join-Path $root 'build\sdk'
New-Item -ItemType Directory -Path $cache -Force | Out-Null
$package = Join-Path $cache 'webview2.1.0.3719.77.nupkg'
if (-not (Test-Path -LiteralPath $package)) {
    Invoke-WebRequest 'https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/1.0.3719.77/microsoft.web.webview2.1.0.3719.77.nupkg' -OutFile $package
}
if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -ne '2F6BE3A10A1A8D6D1FDE986AF4131DAB344F8181FFFE75590824E0F4B037ED73') {
    throw 'WebView2 SDK checksum mismatch; no SDK files executed.'
}
$sdk = Join-Path $cache 'webview2.1.0.3719.77'
if (-not (Test-Path -LiteralPath $sdk)) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($package,$sdk)
}
$output = Join-Path $root 'app'
if (Test-Path -LiteralPath $output) { throw 'App output already exists; build in a fresh checkout instead of overwriting an installation.' }
& (Join-Path $root 'wechat_capture_next\desktop\build.ps1') -Sdk $sdk -Output $output -BuildPython $buildPython -BuildWork (Join-Path $root 'build\freeze')
if ($LASTEXITCODE) { throw 'Portable build failed.' }
Copy-Item -LiteralPath (Join-Path $sdk 'LICENSE.txt') -Destination (Join-Path $output 'WebView2-LICENSE.txt')
& $buildPython (Join-Path $root 'scripts\dependency-notices.py') --out (Join-Path $output 'dependency-notices')
if ($LASTEXITCODE) { throw 'Dependency notice generation failed.' }
Write-Host 'Build ready. Run Configure-CaptureNext.ps1 once, then Start-CaptureNext.ps1.'
