# Native profile-isolation feasibility only. Uses only owned disposable fixtures and vendor bytes.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:INSIGHT_NATIVE_DISPOSABLE -ne '1'){throw 'Disposable native scope must be explicit'}
if(Get-Process -Name 'Procmon*' -ErrorAction SilentlyContinue){throw 'Foreign Process Monitor already exists'}
$root=Join-Path $env:RUNNER_TEMP 'insight-procmon-isolated spaces-Ω';New-Item -ItemType Directory -Force $root | Out-Null
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path;$bootstrap=Join-Path $repo 'skills/ghidra-coordinator/runtime/native/windows-job/windows-job.ps1';$shim=$env:INSIGHT_REGISTRY_SHIM;$shimHash=(Get-FileHash $shim -Algorithm SHA256).Hash.ToLowerInvariant()
$zip=Join-Path $root 'ProcessMonitor.zip';Invoke-WebRequest 'https://download.sysinternals.com/files/ProcessMonitor.zip' -OutFile $zip
if((Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne '477754bf299c9e5b311c5666f7a4a48dfdb21265eaa8f0cca70ef9d9552e3a10'){throw 'Vendor archive differs'}
[IO.Compression.ZipFile]::ExtractToDirectory($zip,(Join-Path $root 'tool'));$procmon=Join-Path $root 'tool/Procmon64.exe'
function Snapshot {
 $key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Sysinternals\Process Monitor');$values=@{}
 if($key){try{foreach($name in $key.GetValueNames()){$value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);$bytes=if($value -is [byte[]]){$value}else{[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Compress))};$values[$name]=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))}}finally{$key.Dispose()}}
 return $values
}
function StartOwned([string[]]$arguments,[string]$mutex=$null){
 $directory=Join-Path $root ([Guid]::NewGuid().ToString());New-Item -ItemType Directory $directory|Out-Null
 $spec=@{schema=1;nonce=[Guid]::NewGuid().ToString();ownerPid=$PID;ownerBirthTicks=[string]([Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().Ticks);executable=$procmon;arguments=$arguments;cwd=$directory;timeoutMs=30000;registryShim=$shim;registryShimSha256=$shimHash}
 if($mutex){$spec.nativeMutex=$mutex}
 $file=Join-Path $directory 'job-specification.json';[IO.File]::WriteAllText($file,($spec|ConvertTo-Json -Depth 5 -Compress))
 $info=[Diagnostics.ProcessStartInfo]::new((Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'));$info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 foreach($a in @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$bootstrap,'-Specification',$file)){$info.ArgumentList.Add($a)}
 $p=[Diagnostics.Process]::new();$p.StartInfo=$info;[void]$p.Start();return @{process=$p;directory=$directory;stdout=$p.StandardOutput.ReadToEndAsync();stderr=$p.StandardError.ReadToEndAsync()}
}
function FinishOwned($execution){
 if(!$execution.process.WaitForExit(35000)){$execution.process.Kill($true);throw 'Owned isolated controller timed out'}
 $text=$execution.stdout.GetAwaiter().GetResult();$errorText=$execution.stderr.GetAwaiter().GetResult()
 if($execution.process.ExitCode -ne 0){throw ('Owned isolated controller failed: '+$errorText+$text)}
 $receipt=Get-Content (Join-Path $execution.directory 'job-result.json') -Raw|ConvertFrom-Json
 if($receipt.phase -ne 'completed'){throw ('Owned isolated controller outcome: '+$receipt.phase)}
 return $receipt
}
# Verifier-only compilation: the shipped runtime uses the prebuilt native/managed helpers.
Add-Type @'
using System;using System.Runtime.InteropServices;
public static class InsightHiveOracle {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)]static extern int RegLoadAppKey(string file,out IntPtr key,uint rights,uint options,uint reserved);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)]static extern int RegOpenKeyEx(IntPtr root,string subkey,int options,uint rights,out IntPtr key);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)]static extern int RegQueryValueEx(IntPtr key,string name,IntPtr reserved,out uint type,IntPtr bytes,ref uint size);
 [DllImport("advapi32.dll")]static extern int RegCloseKey(IntPtr key);
 public static bool HasCapturedSettings(string file){IntPtr root=IntPtr.Zero,key=IntPtr.Zero;try{if(RegLoadAppKey(file,out root,0x20019,0,0)!=0)return false;if(RegOpenKeyEx(root,@"user\Software\Sysinternals\Process Monitor",0,0x20019,out key)!=0)return false;uint type,size=0;return RegQueryValueEx(key,"FilterRules",IntPtr.Zero,out type,IntPtr.Zero,ref size)==0&&size>5;}finally{if(key!=IntPtr.Zero)RegCloseKey(key);if(root!=IntPtr.Zero)RegCloseKey(root);}}
}
'@
$before=Snapshot;$all=@();$complete=$false
try{
 $config=Join-Path $root 'owned-settings.txt';[IO.File]::WriteAllText($config,'owned-private-registry');$pmc=Join-Path $root 'scope.pmc';$pml=Join-Path $root 'owned.pml';$csv=Join-Path $root 'owned.csv'
 & node --input-type=module -e "import {procmonConfiguration} from './skills/ghidra-coordinator/dist/src/procmon-config.js';import {writeFileSync} from 'node:fs';writeFileSync(process.argv[1],procmonConfiguration(Number(process.argv[2]),process.argv[3]));" $pmc $PID $config
 if($LASTEXITCODE){throw 'Scoped PMC creation failed'}
 $probe=StartOwned @('/AcceptEula','/Quiet','/Minimized','/LoadConfig',$pmc,'/BackingFile',$pml,'/Runtime','3') 'Local\insight-cli-procmon-capture';$all+=$probe
 $clock=[Diagnostics.Stopwatch]::StartNew();while(!$probe.process.HasExited -and $clock.ElapsedMilliseconds -lt 20000){[void][IO.File]::ReadAllText($config);Start-Sleep -Milliseconds 100}
 $result=FinishOwned $probe
 if($result.childExitCode -ne 0){throw 'Isolated ProcMon capture failed'}
 $export=StartOwned @('/AcceptEula','/Quiet','/NoConnect','/NoFilter','/OpenLog',$pml,'/SaveAs',$csv);$all+=$export;$exported=FinishOwned $export
 if($exported.childExitCode -ne 0){throw 'Isolated ProcMon export failed'}
 $rows=@(Import-Csv $csv);$matching=@($rows|Where-Object {$_.PID -eq [string]$PID -and $_.Path -eq $config -and $_.Operation -eq 'ReadFile' -and $_.Result -eq 'SUCCESS'})
 $foreign=@($rows|Where-Object {$_.PID -ne [string]$PID -or $_.Path -ne $config})
 $after=Snapshot;$changed=@(@($before.Keys)+@($after.Keys)|Select-Object -Unique|Where-Object {$before[$_] -ne $after[$_]})
 $hives=@(Get-ChildItem $root -Recurse -Filter 'user-settings.hive');$acks=@(Get-ChildItem $root -Recurse -Filter 'registry-isolated.bin')
 $privateSettings=[InsightHiveOracle]::HasCapturedSettings((Join-Path $probe.directory 'user-settings.hive'))
 $passed=$privateSettings -and $changed.Count -eq 0 -and $hives.Count -eq 2 -and $acks.Count -eq 2 -and $matching.Count -gt 0 -and $foreign.Count -eq 0
 @{schema=1;scope='Owned ProcMon private HKCU feasibility; public adapter/agent gates pending';passed=$passed;privateCapturedSettingsPresent=$privateSettings;globalPreferencesUnchanged=$changed.Count -eq 0;actualOwnedReadObserved=$matching.Count -gt 0;matchingReads=$matching.Count;onlyOwnedPidAndPath=$foreign.Count -eq 0;runtimeAutoExit=$true;changedGlobalNames=$changed;privateHiveFiles=$hives.Count;verifiedConstructorReceipts=$acks.Count;nativeChildExit=$result.childExitCode;shimSha256=$shimHash;nativeControllerExited=$probe.process.HasExited} | ConvertTo-Json | Set-Content -Encoding utf8 'toolbox-procmon-isolated.json'
 if(!$passed){throw 'ProcMon private registry isolation was not established'};$complete=$true
}finally{foreach($execution in $all){if(!$execution.process.HasExited){$execution.process.Kill($true)}};Remove-Item (Join-Path $root 'owned.pml'),(Join-Path $root 'owned.csv') -Force -ErrorAction SilentlyContinue}
