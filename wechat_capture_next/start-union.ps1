<#
.SYNOPSIS
正式联合归档入口：统计、同步、成套备份、离线恢复；不启动采集或登录。
.DESCRIPTION
所有重任务显式执行。backup/restore 必须传全新 Out 目录且父目录已存在。
恢复会写出完整展开副本，验收后可按清单删除，不自动清理旧数据。
本入口不控制桌面，不创建后台服务；旧前端及当前采集工作台均不展示 compact 联合档案。
#>
param(
    [ValidateSet('stats', 'sync', 'backup', 'restore')][string]$Action = 'stats',
    [string]$StateRoot,
    [string]$UnionRoot,
    [string]$StateRepository,
    [string]$UnionRepository,
    [string]$Out,
    [string]$Snapshot,
    [switch]$Verify,
    [switch]$IncludeSecrets
)
$ErrorActionPreference = 'Stop'
$captureProject = Split-Path -Parent $PSScriptRoot
$capturePython = Join-Path $captureProject 'working/reverse_20261015/.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $capturePython -PathType Leaf)) { throw '项目 Python 运行环境不存在。' }
if (-not $StateRoot) { $StateRoot = Join-Path $captureProject 'archives/wechat-next/state' }
if (-not $UnionRoot) { $UnionRoot = Join-Path $captureProject 'archives/wechat-next/unified' }
if (-not $StateRepository) { $StateRepository = Join-Path $captureProject 'archives/wechat-next/backups/state' }
if (-not $UnionRepository) { $UnionRepository = Join-Path $captureProject 'archives/wechat-next/backups/unified' }
if ($Verify -and $Action -ne 'sync') { throw 'Verify 仅用于 sync；成套备份和恢复会执行自己的完整核验。' }
if ($IncludeSecrets -and $Action -ne 'backup') { throw 'IncludeSecrets 仅用于 backup。' }
if ($Action -in @('backup', 'restore')) {
    if (-not $Out -or -not [IO.Path]::IsPathFullyQualified($Out)) { throw '请显式提供全新 Out 绝对目录。' }
} elseif ($Out) { throw '只有 backup/restore 使用 Out。' }
if ($Action -eq 'restore' -and -not $Snapshot) { throw 'restore 必须指定联合快照 Snapshot。' }
if ($Action -ne 'restore' -and $Snapshot) { throw 'Snapshot 仅用于 restore。' }
$captureArguments = @('-m', 'wechat_capture_next.union_delivery', $Action)
if ($Action -ne 'restore') { $captureArguments += @('--state', $StateRoot, '--union', $UnionRoot) }
if ($Action -in @('backup', 'restore')) {
    $captureArguments += @('--state-repo', $StateRepository, '--union-repo', $UnionRepository, '--out', $Out)
}
if ($Verify) { $captureArguments += '--verify' }
if ($IncludeSecrets) { $captureArguments += '--include-secrets' }
if ($Snapshot) { $captureArguments += @('--snapshot', $Snapshot) }
Push-Location -LiteralPath $captureProject
try {
    & $capturePython @captureArguments
    if ($LASTEXITCODE -ne 0) { throw "联合归档操作失败，退出码：$LASTEXITCODE；失败输出不应视为已完成。" }
} finally { Pop-Location }
