# Owned disposable pre-capture scope feasibility; does not establish a public adapter.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:INSIGHT_NATIVE_DISPOSABLE -ne '1'){throw 'Disposable native scope must be explicit'}
if(Get-Process -Name 'Procmon*' -ErrorAction SilentlyContinue){throw 'Foreign Process Monitor already exists'}
$root=Join-Path $env:RUNNER_TEMP 'insight-procmon-scoped';New-Item -ItemType Directory -Force $root | Out-Null
$zip=Join-Path $root 'ProcessMonitor.zip';Invoke-WebRequest 'https://download.sysinternals.com/files/ProcessMonitor.zip' -OutFile $zip
if((Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne '477754bf299c9e5b311c5666f7a4a48dfdb21265eaa8f0cca70ef9d9552e3a10'){throw 'Vendor archive differs'}
[IO.Compression.ZipFile]::ExtractToDirectory($zip,(Join-Path $root 'tool'));$procmon=Join-Path $root 'tool/Procmon64.exe'
$fixture=Join-Path $root 'fixture';New-Item -ItemType Directory $fixture | Out-Null
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>' | Set-Content (Join-Path $fixture 'Probe.csproj')
'File.WriteAllText(args[2],Environment.ProcessId.ToString());while(!File.Exists(args[1]))Thread.Sleep(20);Console.WriteLine(File.ReadAllText(args[0]));' | Set-Content (Join-Path $fixture 'Program.cs')
& dotnet build (Join-Path $fixture 'Probe.csproj') -c Release -o (Join-Path $fixture 'out') --nologo
if($LASTEXITCODE){throw 'Owned fixture build failed'}
function Launch($executable,[string[]]$arguments){$info=[Diagnostics.ProcessStartInfo]::new($executable);$info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;foreach($a in $arguments){$info.ArgumentList.Add($a)};$p=[Diagnostics.Process]::new();$p.StartInfo=$info;[void]$p.Start();return @{process=$p;stdout=$p.StandardOutput.ReadToEndAsync();stderr=$p.StandardError.ReadToEndAsync()}}
function Finish($execution,$milliseconds=20000){if(!$execution.process.WaitForExit($milliseconds)){$execution.process.Kill($true);throw 'Owned probe timed out'};return @{code=$execution.process.ExitCode;stdout=$execution.stdout.GetAwaiter().GetResult();stderr=$execution.stderr.GetAwaiter().GetResult()}}
$exe=Join-Path $fixture 'out/Probe.exe';$config=Join-Path $root 'owned-settings.txt';'owned-report Pending37' | Set-Content $config
$go=Join-Path $root 'go';$subject=Launch $exe @($config,$go,(Join-Path $root 'ready-subject'));$noise=Launch $exe @($config,$go,(Join-Path $root 'ready-noise'));$capture=$null
try{
 $pmc=Join-Path $root 'scoped.pmc'
 & node --input-type=module -e "import {procmonConfiguration} from './skills/ghidra-coordinator/dist/src/procmon-config.js';import {writeFileSync} from 'node:fs';writeFileSync(process.argv[1],procmonConfiguration(Number(process.argv[2]),process.argv[3]));" $pmc $subject.process.Id $config
 if($LASTEXITCODE){throw 'Scoped PMC creation failed'}
 $pml=Join-Path $root 'owned.pml';$csv=Join-Path $root 'owned.csv'
 $capture=Launch $procmon @('/AcceptEula','/Quiet','/Minimized','/LoadConfig',$pmc,'/BackingFile',$pml,'/Runtime','20')
 $idle=$null;for($n=0;$n -lt 20;$n++){$idle=Finish (Launch $procmon @('/AcceptEula','/Quiet','/WaitForIdle')) 5000;if($idle.code -eq 0){break};Start-Sleep -Milliseconds 250}
 if($idle.code -ne 0){throw 'Filtered capture did not become ready'}
 [IO.File]::WriteAllText($go,'go');$ran=Finish $subject;$noiseRan=Finish $noise;Start-Sleep -Seconds 2
 $stopped=Finish (Launch $procmon @('/Terminate'));if(!$capture.process.WaitForExit(20000)){throw 'Owned capture did not exit'}
 # Export with filtering disabled: this must expose only events retained by the pre-capture destructive filter.
 $export=Finish (Launch $procmon @('/AcceptEula','/Quiet','/NoFilter','/OpenLog',$pml,'/SaveAs',$csv))
 $rows=@(Import-Csv $csv);$matching=@($rows|Where-Object {$_.PID -eq [string]$subject.process.Id -and $_.Path -eq $config -and $_.Operation -eq 'ReadFile' -and $_.Result -eq 'SUCCESS'})
 $foreign=@($rows|Where-Object {$_.PID -ne [string]$subject.process.Id -or $_.Path -ne $config})
 $passed=$ran.code -eq 0 -and $noiseRan.code -eq 0 -and $matching.Count -gt 0 -and $foreign.Count -eq 0 -and $rows.Count -gt 0 -and $export.code -eq 0
 @{schema=1;scope='Native pre-capture filter feasibility; public adapter and agent gates pending';version='4.12';passed=$passed;subjectReadObserved=$matching.Count -gt 0;allExportedRowsMatchOwnedPidAndPath=$foreign.Count -eq 0;noiseProcessReadSameFile=$noiseRan.stdout.Contains('owned-report Pending37');totalEvents=$rows.Count;matchingReads=$matching.Count;captureExited=$capture.process.HasExited;exportWithNoFilter=$true;configurationSha256=(Get-FileHash $pmc -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json | Set-Content -Encoding utf8 'toolbox-procmon-scoped.json'
 if(!$passed){throw 'Destructive pre-capture PID/path scope was not established'}
}finally{foreach($execution in @($subject,$noise,$capture)){if($execution -and !$execution.process.HasExited){$execution.process.Kill($true)}};Remove-Item (Join-Path $root 'owned.pml'),(Join-Path $root 'owned.csv') -Force -ErrorAction SilentlyContinue}
