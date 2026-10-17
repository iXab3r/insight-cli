# Only owned native inputs and Microsoft bytes on a disposable Windows runner.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$root=Join-Path $env:RUNNER_TEMP 'insight-windbg-native';New-Item -ItemType Directory -Force $root | Out-Null
$bundle=Join-Path $root 'windbg.msixbundle'
Invoke-WebRequest 'https://windbg.download.prss.microsoft.com/dbazure/prod/1-2610-1001-0/windbg.msixbundle' -OutFile $bundle
if((Get-FileHash $bundle -Algorithm SHA256).Hash.ToLowerInvariant() -ne '4662ae17bc0dc77db987b89cccea32c30058baa06268f861d09e0ab4e4f45c20'){throw 'WinDbg archive differs'}
[IO.Compression.ZipFile]::ExtractToDirectory($bundle,(Join-Path $root 'bundle'))
[IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $root 'bundle/windbg_win-x64.msix'),(Join-Path $root 'debugger'))
$installation=& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
Import-Module (Join-Path $installation 'Common7/Tools/Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $installation -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
@'
#include <windows.h>
extern "C" __declspec(dllexport) volatile int observed_count=11;
extern "C" __declspec(dllexport) volatile int observed_total=109;
extern "C" __declspec(dllexport) __declspec(noinline) void quote_total(){DebugBreak();observed_total+=observed_count;}
int main(){quote_total();return 0;}
'@ | Set-Content -Encoding utf8 (Join-Path $root 'probe.cpp')
Push-Location $root
try{& cl.exe /nologo /Zi /Od /EHsc probe.cpp /Fe:InsightOwnedNative.exe /link /DEBUG /PDB:InsightOwnedNative.pdb;if($LASTEXITCODE){throw 'Native fixture build failed'}}finally{Pop-Location}
$cdb=Join-Path $root 'debugger/amd64/cdb.exe';$dump=Join-Path $root 'native.dmp';$exe=Join-Path $root 'InsightOwnedNative.exe'
$info=[Diagnostics.ProcessStartInfo]::new($cdb);$info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
foreach($a in @('-sins','-noshell','-netsyms:no','-y',$root,'-c',('g; .printf "INSIGHT_ADDRESS=%p\n", &InsightOwnedNative!observed_total; .dump /ma "'+$dump+'"; q'),$exe)){$info.ArgumentList.Add($a)}
$p=[Diagnostics.Process]::new();$p.StartInfo=$info;[void]$p.Start();$stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
if(!$p.WaitForExit(30000)){$p.Kill($true);throw 'Owned fixture dump creation timed out'}
$text=$stdout.GetAwaiter().GetResult();$err=$stderr.GetAwaiter().GetResult()
if($p.ExitCode -ne 0 -or !(Test-Path $dump) -or $text -notmatch 'INSIGHT_ADDRESS=([0-9a-fA-F`]+)'){throw ('Owned native dump creation failed: '+$text+$err)}
$address='0x'+$Matches[1].Replace('`','')
@{root=$root;bundle=$bundle;dump=$dump;symbols=(Join-Path $root 'InsightOwnedNative.pdb');cdb=$cdb;address=$address} | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $root 'fixture.json')
"INSIGHT_WINDBG_FIXTURE=$(Join-Path $root 'fixture.json')" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
