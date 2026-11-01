[CmdletBinding(PositionalBinding=$false)]
param([switch]$Tray, [switch]$Stop, [switch]$Recovery, [string]$Offline)
$ErrorActionPreference = 'Stop'
$hasOffline = $PSBoundParameters.ContainsKey('Offline')
$root = $PSScriptRoot
$application = Join-Path $root 'app\CaptureNext.exe'
if (-not (Test-Path -LiteralPath $application -PathType Leaf)) {
    throw 'Portable app missing. Download the Windows release or run scripts\build-portable.ps1.'
}
if (@($Stop.IsPresent,$Recovery.IsPresent,$hasOffline).Where({$_}).Count -gt 1) { throw 'Choose only one operation.' }
$launch = @('--root', ('"'+$root+'"'))
if ($Stop) { $launch += '--quit' } else {
    if ($Tray) { $launch += '--tray' }
    if ($Recovery) { $launch += '--recovery' }
    if ($hasOffline) {
        $hasControl=$false
        foreach ($character in $Offline.ToCharArray()) {
            if ([char]::IsControl($character)) { $hasControl=$true; break }
        }
        if ($Offline -notmatch '^[A-Za-z]:[\\/]' -or $Offline.Contains('"') -or $hasControl) {
            throw 'Offline needs an explicit local absolute directory, without quotes or control characters.'
        }
        $target = [IO.Path]::GetFullPath($Offline)
        if ($target -eq [IO.Path]::GetPathRoot($target)) { throw 'A restored bundle directory is required.' }
        $target=$target.TrimEnd([char[]]'\/')
        $launch += @('--offline', ('"'+$target+'"'))
    }
}
Start-Process -FilePath $application -ArgumentList $launch -WorkingDirectory $root -WindowStyle Hidden
