<#
.SYNOPSIS
启动独立的新本机工作台，不启动采集、不改旧前端。
.DESCRIPTION
默认绑定正式新状态和新CAS仓库；兼容WUA仅在明确同步/比对时物化。
其他新状态可显式传入四个目录参数；不初始化、不收养旧目录、不更改系统设置。
#>
param(
    [string]$State,
    [string]$OutputRoot,
    [string]$RepositoryRoot,
    [string]$ManagedRoot,
    [int]$Port = 0
)
$ErrorActionPreference = 'Stop'
$captureProject = Split-Path -Parent $PSScriptRoot
$capturePython = Join-Path $captureProject 'working/reverse_20261015/.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $capturePython -PathType Leaf)) {
    throw '项目 Python 环境不存在，请按 README 配置。'
}
if (-not $State) { $State = Join-Path $captureProject 'archives/wechat-next/state' }
if (-not $OutputRoot) { $OutputRoot = Join-Path $captureProject 'archives/wechat-next/console-output' }
if (-not $RepositoryRoot) { $RepositoryRoot = Join-Path $captureProject 'archives/wechat-next/backups/state' }
if (-not $ManagedRoot) { $ManagedRoot = Join-Path $captureProject 'archives/wechat-next/compatibility-wua' }
if (-not (Test-Path -LiteralPath $State -PathType Container)) {
    throw '独立新状态不存在；请先按 README 显式初始化，脚本不会改动旧成果。'
}
$captureArguments = @('-m', 'wechat_capture_next', 'serve', '--state', $State,
    '--output-root', $OutputRoot, '--repository-root', $RepositoryRoot,
    '--managed-root', $ManagedRoot, '--port', [string]$Port)
Push-Location -LiteralPath $captureProject
try {
    & $capturePython @captureArguments
    if ($LASTEXITCODE -ne 0) { throw "新工作台退出码：$LASTEXITCODE" }
} finally {
    Pop-Location
}
