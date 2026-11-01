[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$core = Join-Path $PSScriptRoot 'app\backend-dist\CaptureNextCore\CaptureNextCore.exe'
if (-not (Test-Path -LiteralPath $core -PathType Leaf)) { throw 'Build or download the portable app first.' }
& $core --configure --root $PSScriptRoot
if ($LASTEXITCODE -ne 0) { throw 'Configuration was not accepted. Existing state was not replaced.' }
Write-Host 'Configured. Run Start-CaptureNext.ps1 to start the tray app.'
