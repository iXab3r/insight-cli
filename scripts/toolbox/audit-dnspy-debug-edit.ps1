# Native API feasibility; public adapter and independent model acceptance are separate gates.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:INSIGHT_NATIVE_DISPOSABLE -ne '1'){throw 'Disposable native scope must be explicit'}
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path;$root=Join-Path $env:RUNNER_TEMP 'insight-dnspy-debug spaces-Ω';New-Item -ItemType Directory -Force $root|Out-Null
$zip=Join-Path $root 'dnSpy.zip';Invoke-WebRequest 'https://github.com/dnSpyEx/dnSpy/releases/download/v6.6.0/dnSpy-net-win64.zip' -OutFile $zip
if((Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne '8ed48f165dc355e869f3a0037ad4f9216147f995a5ae0258b296eeef1f73aab0'){throw 'Pinned dnSpyEx distribution differs'}
$tool=Join-Path $root 'tool';[IO.Compression.ZipFile]::ExtractToDirectory($zip,$tool);$extension=Join-Path $root 'extension';New-Item -ItemType Directory $extension|Out-Null
$source=Join-Path $repo 'skills/ghidra-coordinator/runtime/native/dnspy-extension';$build=Join-Path $root 'build';Copy-Item $source $build -Recurse
& dotnet build (Join-Path $build 'Insight.DnSpy.csproj') --configuration Release -p:RestoreLockedMode=true "-p:DnSpyRuntime=$tool/bin" "-p:PathMap=$build=/_/dnspy-extension" --nologo
if($LASTEXITCODE){throw 'Typed dnSpy extension build failed'}
Copy-Item (Join-Path $build 'bin/Release/net10.0-windows/Insight.DnSpy.x.dll') $extension
@'
using System;using System.Runtime.CompilerServices;
public class OwnedResearch {
 [MethodImpl(MethodImplOptions.NoInlining)] public static int QuoteTotal(int count){return count*9+10;}
 [MethodImpl(MethodImplOptions.NoInlining)] public static int Settings(){return 7;}
 public static void Main(){Console.WriteLine("quote="+QuoteTotal(11)+";setting="+Settings());}
}
'@|Set-Content -Encoding utf8 (Join-Path $root 'OwnedResearch.cs')
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET/Framework64/v4.0.30319/csc.exe';$researchInput=Join-Path $root 'OwnedResearch.exe'
& $compiler /nologo /optimize+ /debug:pdbonly "/out:$researchInput" (Join-Path $root 'OwnedResearch.cs');if($LASTEXITCODE){throw 'Owned Framework fixture build failed'}
$assembly=[Reflection.Assembly]::LoadFile($researchInput);$type=$assembly.GetType('OwnedResearch');$method=$type.GetMethod('QuoteTotal');$settings=$type.GetMethod('Settings');$code=$settings.GetMethodBody().GetILAsByteArray();if($code[0] -ne 0x1d){throw 'Owned Settings fixture did not start with ldc.i4.7'}
$before=(Get-FileHash $researchInput -Algorithm SHA256).Hash.ToLowerInvariant()
function InvokePlan([hashtable]$values){
 $directory=Join-Path $root ([Guid]::NewGuid().ToString());New-Item -ItemType Directory $directory|Out-Null;$plan=Join-Path $directory 'plan.json';$result=Join-Path $directory 'result.json';$nonce=[Guid]::NewGuid().ToString();$values.Schema=1;$values.Nonce=$nonce;if(!$values.ContainsKey('Input')){$values.Input=$researchInput};$values.Result=$result
 [IO.File]::WriteAllText($plan,($values|ConvertTo-Json -Depth 5 -Compress));$ownerBirth=[string]([Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().Ticks)
 $arguments=@('--multiple','--no-activate','--settings-file',(Join-Path $directory 'settings.xml'),'--extension-directory',$extension,('--insight-plan:'+$plan))
 $spec=@{schema=1;nonce=$nonce;ownerPid=$PID;ownerBirthTicks=$ownerBirth;executable=(Join-Path $tool 'dnSpy.exe');arguments=$arguments;cwd=$directory;timeoutMs=60000};$specFile=Join-Path $directory 'job-specification.json';[IO.File]::WriteAllText($specFile,($spec|ConvertTo-Json -Depth 5 -Compress))
 $info=[Diagnostics.ProcessStartInfo]::new((Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'));$info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 foreach($a in @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $repo 'skills/ghidra-coordinator/runtime/native/windows-job/windows-job.ps1'),'-Specification',$specFile)){$info.ArgumentList.Add($a)}
 $process=[Diagnostics.Process]::new();$process.StartInfo=$info;[void]$process.Start();$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
 try{if(!$process.WaitForExit(65000)){$process.Kill($true);throw 'Owned dnSpy operation exceeded its deadline'};$errorText=$stderr.GetAwaiter().GetResult();$outputText=$stdout.GetAwaiter().GetResult();if(!(Test-Path $result)){foreach($file in @(Get-ChildItem $root -Recurse -Filter '*.bridge-error.txt')){Write-Host ([IO.File]::ReadAllText($file.FullName))};foreach($name in @('job-started.json','job-result.json')){$file=Join-Path $directory $name;if(Test-Path $file){Write-Host ([IO.File]::ReadAllText($file))}};foreach($event in @(Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000,1026;StartTime=(Get-Date).AddMinutes(-2)} -ErrorAction SilentlyContinue)){if($event.Message.Contains($root)){Write-Host $event.Message}};throw ('dnSpy did not produce a typed result: '+$errorText+$outputText)};$receipt=Get-Content $result -Raw|ConvertFrom-Json;if($receipt.nonce -ne $nonce -or $receipt.data.state -ne 'completed'){throw ('dnSpy typed operation failed: '+($receipt|ConvertTo-Json -Depth 8 -Compress))};$job=Get-Content (Join-Path $directory 'job-result.json') -Raw|ConvertFrom-Json;if($job.phase -ne 'completed' -or $job.childExitCode -ne 0){throw 'Owned debugger did not exit normally'};return $receipt.data}finally{if(!$process.HasExited){$process.Kill($true)}}
}
$debug=InvokePlan @{Mode='debug';Runtime='framework';Token=$method.MetadataToken;Offset=0;Parameters=@(0);Arguments=@()}
if($debug.parameters.Count -ne 1 -or $debug.parameters[0].value -ne '11' -or $debug.frames.Count -lt 1){throw 'Actual managed parameter and stack were not observed'}
$core=Join-Path $root 'core';New-Item -ItemType Directory $core|Out-Null
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Exe</OutputType><AssemblyName>OwnedCoreProbe</AssemblyName></PropertyGroup></Project>'|Set-Content -Encoding utf8 (Join-Path $core 'Core.csproj')
Copy-Item (Join-Path $root 'OwnedResearch.cs') (Join-Path $core 'Program.cs')
& dotnet build (Join-Path $core 'Core.csproj') --configuration Release --output (Join-Path $core 'out') --nologo
if($LASTEXITCODE){throw 'Owned Core fixture build failed'}
$coreModule=Join-Path $core 'out/OwnedCoreProbe.dll';$coreAssembly=[Reflection.Assembly]::LoadFile($coreModule);$coreMethod=$coreAssembly.GetType('OwnedResearch').GetMethod('QuoteTotal')
$coreDebug=InvokePlan @{Mode='debug';Runtime='core';Input=(Join-Path $core 'out/OwnedCoreProbe.exe');Module=$coreModule;Token=$coreMethod.MetadataToken;Offset=0;Parameters=@(0);Arguments=@()}
if($coreDebug.parameters.Count -ne 1 -or $coreDebug.parameters[0].value -ne '11'){throw 'Core managed parameter was not observed'}
$patched=Join-Path $root 'OwnedResearch-patched.exe';$edit=InvokePlan @{Mode='edit-constant';Token=$settings.MetadataToken;Offset=0;ExpectedConstant=7;ReplacementConstant=37;Output=$patched}
$output=& $patched;if($LASTEXITCODE -ne 0 -or $output -ne 'quote=109;setting=37'){throw 'Patched managed behavior was not verified'}
if((Get-FileHash $researchInput -Algorithm SHA256).Hash.ToLowerInvariant() -ne $before){throw 'Original fixture changed'}
@{schema=1;passed=$true;scope='Actual dnSpyEx debugger and editor document API feasibility; public adapter/model gates pending';version='6.6.0';managedBreakpointHit=$true;observedArgument11=$true;coreManagedArgument11=$true;managedStackPresent=$true;editorDocumentLoaded=$edit.editorDocumentLoaded;actualPatchedBehavior=$true;originalPreserved=$true;ownedDebuggerExited=$true;originalSha256=$before;patchedSha256=(Get-FileHash $patched -Algorithm SHA256).Hash.ToLowerInvariant();extensionSha256=(Get-FileHash (Join-Path $extension 'Insight.DnSpy.x.dll') -Algorithm SHA256).Hash.ToLowerInvariant()}|ConvertTo-Json|Set-Content -Encoding utf8 'toolbox-dnspy-debug-edit.json'
