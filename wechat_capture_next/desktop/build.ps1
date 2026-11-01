param(
  [string]$Sdk = 'archives\wechat-next\app',
  [string]$Output = 'working\wechat-product-build\app',
  [string]$BuildPython = 'working\wechat-product-build\build-env\Scripts\python.exe',
  [string]$BuildWork = 'working\wechat-product-build\freeze-build',
  [switch]$ShellOnly
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Set-Location -LiteralPath $root
function Resolve-BuildPath([string]$Value) {
  if ([IO.Path]::IsPathRooted($Value)) { return [IO.Path]::GetFullPath($Value) }
  return [IO.Path]::GetFullPath((Join-Path $root $Value))
}
$sdkPath = Resolve-BuildPath $Sdk
$outputPath = Resolve-BuildPath $Output
$BuildPython = Resolve-BuildPath $BuildPython
$BuildWork = Resolve-BuildPath $BuildWork
$managedSdk = Join-Path $sdkPath 'lib\net462'
$nativeSdk = Join-Path $sdkPath 'runtimes\win-x64\native'
if (-not (Test-Path -LiteralPath (Join-Path $managedSdk 'Microsoft.Web.WebView2.Core.dll'))) {
  $managedSdk = $sdkPath
  $nativeSdk = $sdkPath
}
if ($outputPath -eq $sdkPath) { throw 'Build output must not overwrite retained SDK/application' }
New-Item -ItemType Directory -Path $outputPath -ErrorAction SilentlyContinue | Out-Null
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /target:winexe /platform:x64 ("/out:"+(Join-Path $outputPath 'CaptureNext.exe')) ("/win32manifest:"+(Join-Path $PSScriptRoot 'CaptureNext.manifest')) /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Net.Http.dll /r:System.Web.Extensions.dll ("/r:"+(Join-Path $managedSdk 'Microsoft.Web.WebView2.Core.dll')) ("/r:"+(Join-Path $managedSdk 'Microsoft.Web.WebView2.WinForms.dll')) (Join-Path $PSScriptRoot 'CaptureNext.cs')
if ($LASTEXITCODE) { throw 'Desktop compilation failed' }
foreach ($name in @('Microsoft.Web.WebView2.Core.dll','Microsoft.Web.WebView2.WinForms.dll')) {
  Copy-Item -LiteralPath (Join-Path $managedSdk $name) -Destination $outputPath
}
Copy-Item -LiteralPath (Join-Path $nativeSdk 'WebView2Loader.dll') -Destination $outputPath
if (-not $ShellOnly) {
  & $BuildPython -m PyInstaller --noconfirm --distpath (Join-Path $outputPath 'backend-dist') --workpath $BuildWork (Join-Path $PSScriptRoot 'product.spec')
  if ($LASTEXITCODE) { throw 'Backend freezing failed' }
  # Keep freezer's generated directory unchanged; the shell locates it here.
}
Write-Output $outputPath
