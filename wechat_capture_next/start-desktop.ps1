param([switch]$Tray,[switch]$Stop)
$ErrorActionPreference='Stop'
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$application=Join-Path $projectRoot 'archives\wechat-next\app\CaptureNext.exe'
if(-not (Test-Path -LiteralPath $application -PathType Leaf)) {
  throw '便携桌面程序尚未构建，请参阅 wechat_capture_next/desktop/build.ps1。'
}
$arguments=@('--root',('"'+$projectRoot+'"'))
if($Stop) {$arguments+='--quit'} elseif($Tray) {$arguments+='--tray'}
Start-Process -FilePath $application -ArgumentList $arguments -WindowStyle Hidden
