# Versioned product entry; the previous start-desktop.ps1 and app stay intact.
[CmdletBinding(PositionalBinding=$false)]
param([switch]$Tray,[switch]$Stop,[switch]$Recovery,[string]$Offline)
$ErrorActionPreference='Stop'
$taskHasOffline=$PSBoundParameters.ContainsKey('Offline')
$taskProjectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskApplication=Join-Path $taskProjectRoot 'archives\wechat-next\app-20261022\CaptureNext.exe'
if(-not (Test-Path -LiteralPath $taskApplication -PathType Leaf)) {
  throw '本轮新版尚未完成发布；请查看产品交付记录，不会回退启动旧程序。'
}
if(@($Stop.IsPresent,$Recovery.IsPresent,$taskHasOffline).Where({$_}).Count -gt 1) {
  throw 'Stop、Recovery 与 Offline 只能选择一种模式。'
}
$taskArguments=@('--root',('"'+$taskProjectRoot+'"'))
if($Stop) {$taskArguments+='--quit'} else {
  if($Tray) {$taskArguments+='--tray'}
  if($Recovery) {$taskArguments+='--recovery'}
  if($taskHasOffline) {
    $taskHasControl=$false
    foreach($taskCharacter in $Offline.ToCharArray()) {
      if([char]::IsControl($taskCharacter)) {$taskHasControl=$true;break}
    }
    # IsPathRooted also accepts C:relative and \current-drive-relative. Match
    # the backend's local-only scope without requiring newer .NET path APIs.
    if($Offline -notmatch '^[A-Za-z]:[\\/]' -or $Offline.Contains('"') -or $taskHasControl) {
      throw 'Offline 需要具体的本地磁盘绝对路径，不接受 UNC、引号或控制字符。'
    }
    $taskOfflinePath=[IO.Path]::GetFullPath($Offline)
    if($taskOfflinePath -eq [IO.Path]::GetPathRoot($taskOfflinePath)) {
      throw '请选择具体恢复副本文件夹，不能选择整个磁盘根目录。'
    }
    $taskOfflinePath=$taskOfflinePath.TrimEnd([char[]]'\/')
    $taskArguments+=@('--offline',('"'+$taskOfflinePath+'"'))
  }
}
# The native shell owns single-instance activation and safe queue shutdown.
# Existing instances are focused, not silently switched to another mode.
Start-Process -FilePath $taskApplication -ArgumentList $taskArguments -WorkingDirectory $taskProjectRoot -WindowStyle Hidden
