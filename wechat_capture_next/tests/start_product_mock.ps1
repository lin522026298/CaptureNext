param([Parameter(Mandatory=$true)][string]$ReportPath,[string]$PortableLauncherPath)
$ErrorActionPreference='Stop'
$qaRoot=$PSScriptRoot
$qaProject=[IO.Path]::GetFullPath((Join-Path $qaRoot '../..'))
$qaLauncher=Join-Path $qaProject 'wechat_capture_next/start-product.ps1'
$qaShell=Join-Path $qaProject 'wechat_capture_next/desktop/CaptureNext.cs'
$qaAppPattern='*\archives\wechat-next\app-20261022\CaptureNext.exe'
if($PortableLauncherPath) {
    $qaLauncher=[IO.Path]::GetFullPath($PortableLauncherPath)
    $qaProject=[IO.Path]::GetDirectoryName($qaLauncher)
    $qaAppPattern='*\app\CaptureNext.exe'
}
$qaHashBefore=(Get-FileHash -LiteralPath $qaLauncher -Algorithm SHA256).Hash
$qaSource=Get-Content -LiteralPath $qaLauncher -Raw
$qaTokens=$null;$qaParseErrors=$null
$qaAst=[Management.Automation.Language.Parser]::ParseFile($qaLauncher,[ref]$qaTokens,[ref]$qaParseErrors)
if($qaParseErrors.Count){throw 'Launcher failed PowerShell AST parse'}
$qaCommandNames=@($qaAst.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object {$_.GetCommandName()})
if(@($qaCommandNames|Where-Object {$_ -notin @('Join-Path','Test-Path','Start-Process','Where-Object')}).Count){throw 'Unexpected command surface: refusing to invoke launcher even with mocks'}
# Fail closed on future direct .NET launch/file/registry APIs as well as
# qualified, dynamic or otherwise unmocked PowerShell commands.
$qaMemberCalls=@($qaAst.FindAll({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst]},$true)|ForEach-Object {$_.Member.Value})
if(@($qaMemberCalls|Where-Object {$_ -notin @('GetFullPath','ContainsKey','Where','ToCharArray','IsControl','Contains','GetPathRoot','TrimEnd')}).Count){throw 'Unexpected member-call surface: fixture review required'}
if($qaAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -or $node -is [Management.Automation.Language.TypeDefinitionAst]},$true).Count){throw 'Source-defined command/type rejected by fixture'}
$qaCalls=[Collections.Generic.List[object]]::new();$qaLookups=[Collections.Generic.List[object]]::new();$qaAppAvailable=$true
function Invoke-LauncherMock {
    param($Parameters,[object[]]$ExtraArguments=@())
    function Test-Path {
        param([string]$LiteralPath,[string]$PathType)
        $qaLookups.Add([pscustomobject]@{path=$LiteralPath;type=$PathType})
        if($LiteralPath -notlike $qaAppPattern -or $PathType -ne 'Leaf'){throw 'Unexpected path probe blocked by fixture'}
        return $qaAppAvailable
    }
    function Start-Process {
        param([string]$FilePath,[string[]]$ArgumentList,[string]$WorkingDirectory,[string]$WindowStyle)
        $qaCalls.Add([pscustomobject]@{file=$FilePath;arguments=@($ArgumentList);working_directory=$WorkingDirectory;window_style=$WindowStyle})
    }
    & $qaLauncher @Parameters @ExtraArguments
}
# The source's actual two early single-instance branches are executed with
# in-memory signals/mutex, never Windows UI or real named synchronization.
$qaCs=Get-Content -LiteralPath $qaShell -Raw
$qaBranch=[regex]::Match($qaCs,'if\(!created\) \{ if\(quit\) exitSignal.Set\(\); else signal.Set\(\); return 0; \}\s*if\(quit\) \{ mutex.ReleaseMutex\(\); return 0; \}').Value
if(-not $qaBranch){throw 'Native single-instance branch changed; refusing a guessed model'}
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace LauncherQa {
 public static class NativeArgs {
  [DllImport("shell32.dll", SetLastError=true)] static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)]string command,out int count);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
  public static string[] Parse(string command) { int count;var value=CommandLineToArgvW(command,out count);if(value==IntPtr.Zero)throw new Exception("parse failed");try{var result=new string[count];for(int i=0;i<count;i++)result[i]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(value,i*IntPtr.Size));return result;}finally{LocalFree(value);} }
 }
 public class Decision { public string Signal="none";public bool Released;public bool NewShell;public string Mode; }
 class Signal { Decision result;string name;public Signal(Decision result,string name){this.result=result;this.name=name;}public void Set(){result.Signal=name;} }
 class Mutex { Decision result;public Mutex(Decision result){this.result=result;}public void ReleaseMutex(){result.Released=true;} }
 public static class SingleInstance {
  static int Branch(bool created,bool quit,Decision result){var signal=new Signal(result,"open");var exitSignal=new Signal(result,"exit");var mutex=new Mutex(result);
   $qaBranch
   return 1;
  }
  public static Decision Run(bool created,bool quit,string mode){var result=new Decision();result.NewShell=Branch(created,quit,result)==1;result.Mode=result.NewShell?mode:null;return result;}
 }
}
"@
$qaCases=[Collections.Generic.List[object]]::new()
function Add-Case($name,$parameters,[bool]$reject,[bool]$available=$true,[object[]]$extra=@()){$qaCases.Add([pscustomobject]@{name=$name;parameters=$parameters;reject=$reject;available=$available;extra=$extra})}
Add-Case 'default-visible-mode' @{} $false
Add-Case 'tray' @{Tray=$true} $false
Add-Case 'stop' @{Stop=$true} $false
Add-Case 'stop-with-tray-ignored' @{Stop=$true;Tray=$true} $false
Add-Case 'recovery' @{Recovery=$true} $false
Add-Case 'recovery-tray' @{Recovery=$true;Tray=$true} $false
Add-Case 'offline-spaces' @{Offline='C:\SYNTHETIC Copy\bundle'} $false
Add-Case 'offline-tray' @{Offline='C:\SYNTHETIC Copy\bundle';Tray=$true} $false
Add-Case 'offline-single-quote' @{Offline="C:\SYNTHETIC O'Reilly\bundle"} $false
Add-Case 'offline-metacharacters-are-data' @{Offline='C:\SYNTHETIC & semi; dollar$(noop) ` tick\bundle'} $false
Add-Case 'offline-trailing-backslash' @{Offline='C:\SYNTHETIC Copy\bundle\'} $false
Add-Case 'offline-trailing-forwardslash' @{Offline='C:\SYNTHETIC Copy\bundle/'} $false
Add-Case 'offline-double-trailing-backslash' @{Offline='C:\SYNTHETIC Copy\bundle\\'} $false
Add-Case 'offline-empty-explicit' @{Offline=''} $true
Add-Case 'offline-null-explicit' @{Offline=$null} $true
Add-Case 'offline-whitespace' @{Offline=' '} $true
Add-Case 'offline-relative' @{Offline='synthetic\bundle'} $true
Add-Case 'offline-drive-relative' @{Offline='C:synthetic-bundle'} $true
Add-Case 'offline-drive-only' @{Offline='C:'} $true
Add-Case 'offline-project-drive-only' @{Offline=([IO.Path]::GetPathRoot($qaProject).TrimEnd([char[]]'\/'))} $true
Add-Case 'offline-current-drive-rooted' @{Offline='\synthetic-bundle'} $true
Add-Case 'offline-current-drive-rooted-forwardslash' @{Offline='/synthetic-bundle'} $true
Add-Case 'offline-root' @{Offline='C:\'} $true
Add-Case 'offline-root-forwardslash' @{Offline='C:/'} $true
Add-Case 'offline-root-duplicate-separator' @{Offline='C:\\'} $true
Add-Case 'offline-root-after-dot-normalization' @{Offline='C:\SYNTHETIC\..'} $true
Add-Case 'offline-unc-share-root' @{Offline='\\SYNTHETIC\SHARE'} $true
Add-Case 'offline-unc-share-root-trailing' @{Offline='\\SYNTHETIC\SHARE\'} $true
Add-Case 'offline-unc-child' @{Offline='\\SYNTHETIC\SHARE\bundle'} $true
Add-Case 'offline-device-question' @{Offline='\\?\C:\SYNTHETIC\bundle'} $true
Add-Case 'offline-device-dot' @{Offline='\\.\C:\SYNTHETIC\bundle'} $true
Add-Case 'offline-quoted' @{Offline='C:\SYNTHETIC " --quit'} $true
foreach($control in @(0,9,10,13,27,31,127,133,159)){Add-Case ('offline-control-'+$control) @{Offline=('C:\SYNTHETIC'+[char]$control+'bundle')} $true}
Add-Case 'stop-recovery-mutually-exclusive' @{Stop=$true;Recovery=$true} $true
Add-Case 'stop-offline-mutually-exclusive' @{Stop=$true;Offline='C:\SYNTHETIC'} $true
Add-Case 'recovery-offline-mutually-exclusive' @{Recovery=$true;Offline='C:\SYNTHETIC'} $true
Add-Case 'all-modes-mutually-exclusive' @{Stop=$true;Recovery=$true;Offline='C:\SYNTHETIC';Tray=$true} $true
Add-Case 'stop-empty-offline-still-conflict' @{Stop=$true;Offline=''} $true
Add-Case 'recovery-empty-offline-still-conflict' @{Recovery=$true;Offline=''} $true
Add-Case 'explicit-false-switch-not-a-mode' @{Stop=$false;Recovery=$false;Tray=$false;Offline='C:\SYNTHETIC'} $false
Add-Case 'missing-target-no-fallback-default' @{} $true $false
Add-Case 'missing-target-no-fallback-offline' @{Offline='C:\SYNTHETIC'} $true $false
Add-Case 'missing-target-no-fallback-stop' @{Stop=$true} $true $false
Add-Case 'unknown-switch-rejected' @{Bogus=$true} $true
Add-Case 'misspelled-offline-rejected' @{Offilne='C:\SYNTHETIC'} $true
Add-Case 'double-dash-offline-preserves-offline-binding' @{'-offline'='C:\SYNTHETIC'} $false
Add-Case 'unexpected-positional' @{} $true $true @('C:\SYNTHETIC')
Add-Case 'offline-extra-positional' @{Offline='C:\SYNTHETIC'} $true $true @('extra')
Add-Case 'tray-extra-positional' @{Tray=$true} $true $true @('extra')
$qaResults=[Collections.Generic.List[object]]::new()
foreach($case in $qaCases){
    $qaCalls.Clear();$qaLookups.Clear();$qaAppAvailable=$case.available;$errorText=$null
    try { Invoke-LauncherMock -Parameters $case.parameters -ExtraArguments $case.extra } catch {$errorText=$_.Exception.Message}
    $parsed=$null;$argumentsSafe=$true
    if($qaCalls.Count){
        $parsed=@([LauncherQa.NativeArgs]::Parse('qa.exe '+($qaCalls[0].arguments -join ' '))|Select-Object -Skip 1)
        $argumentsSafe=$qaCalls.Count -eq 1 -and $parsed[0] -eq '--root' -and $parsed[1] -eq $qaProject
        if($case.parameters.ContainsKey('Offline') -and -not $case.parameters.Stop){
            $expected=[IO.Path]::GetFullPath([string]$case.parameters.Offline).TrimEnd([char[]]'\/')
            $position=[array]::IndexOf($parsed,'--offline')
            $argumentsSafe=$argumentsSafe -and $position -ge 0 -and $parsed[$position+1] -ceq $expected
        }
        $argumentsSafe=$argumentsSafe -and $qaCalls[0].window_style -eq 'Hidden' -and $qaCalls[0].working_directory -eq $qaProject
        if($case.parameters.Stop){$argumentsSafe=$argumentsSafe -and ($parsed -contains '--quit') -and ($parsed -notcontains '--tray')}
        elseif($case.parameters.Tray){$argumentsSafe=$argumentsSafe -and ($parsed -contains '--tray')}
        if($case.parameters.Recovery){$argumentsSafe=$argumentsSafe -and ($parsed -contains '--recovery')}
        $expectedArgs=@('--root',$qaProject)
        if($case.parameters.Stop){$expectedArgs+='--quit'}else{
            if($case.parameters.Tray){$expectedArgs+='--tray'}
            if($case.parameters.Recovery){$expectedArgs+='--recovery'}
            $offlineKey=if($case.parameters.ContainsKey('Offline')){'Offline'}elseif($case.parameters.ContainsKey('-offline')){'-offline'}else{$null}
            if($offlineKey){$expectedArgs+=@('--offline',[IO.Path]::GetFullPath([string]$case.parameters[$offlineKey]).TrimEnd([char[]]'\/'))}
        }
        $argumentsSafe=$argumentsSafe -and $parsed.Count -eq $expectedArgs.Count
        for($index=0;$index -lt $expectedArgs.Count;$index++){$argumentsSafe=$argumentsSafe -and $parsed[$index] -ceq $expectedArgs[$index]}
    }
    $passed=if($case.reject){$null -ne $errorText -and $qaCalls.Count -eq 0}else{$null -eq $errorText -and $argumentsSafe -and $qaCalls.Count -eq 1}
    $qaResults.Add([pscustomobject]@{name=$case.name;expected_rejection=$case.reject;passed=$passed;error=$errorText;start_count=$qaCalls.Count;path_probes=$qaLookups.ToArray();calls=$qaCalls.ToArray();parsed_arguments=$parsed})
}
$qaInstanceResults=@()
foreach($mode in @('normal','tray','recovery','offline')){
    $decision=[LauncherQa.SingleInstance]::Run($false,$false,$mode)
    $qaInstanceResults+=[pscustomobject]@{name='existing-instance-'+$mode;passed=($decision.Signal -eq 'open' -and -not $decision.NewShell -and $null -eq $decision.Mode);decision=$decision}
}
foreach($created in @($false,$true)){
    $decision=[LauncherQa.SingleInstance]::Run($created,$true,'stop')
    $qaInstanceResults+=[pscustomobject]@{name='stop-created-'+$created;passed=(-not $decision.NewShell -and $(if($created){$decision.Released -and $decision.Signal -eq 'none'}else{$decision.Signal -eq 'exit'}));decision=$decision}
}
foreach($mode in @('normal','tray','recovery','offline')){
    $decision=[LauncherQa.SingleInstance]::Run($true,$false,$mode)
    $qaInstanceResults+=[pscustomobject]@{name='new-instance-'+$mode;passed=($decision.NewShell -and $decision.Mode -eq $mode);decision=$decision}
}
$qaHashAfter=(Get-FileHash -LiteralPath $qaLauncher -Algorithm SHA256).Hash
$qaReport=[pscustomobject]@{scope='mock-only launcher plus actual extracted native single-instance branches; never starts a process or UI';powershell=$PSVersionTable.PSVersion.ToString();launcher_hash_before=$qaHashBefore;launcher_hash_after=$qaHashAfter;static_commands=$qaCommandNames;real_start_process_called=$false;cases=$qaResults.ToArray();single_instance=@($qaInstanceResults);case_count=$qaResults.Count;failed=@($qaResults|Where-Object {-not $_.passed});single_instance_failed=@($qaInstanceResults|Where-Object {-not $_.passed})}
$qaReport|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $ReportPath -Encoding utf8
[pscustomobject]@{mock_cases=$qaResults.Count;failed=@($qaReport.failed).Count;single_instance_cases=$qaInstanceResults.Count;single_instance_failed=@($qaReport.single_instance_failed).Count;source_unchanged=($qaHashBefore -eq $qaHashAfter)}|ConvertTo-Json
