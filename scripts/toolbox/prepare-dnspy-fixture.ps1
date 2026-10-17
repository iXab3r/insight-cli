# Only explicitly owned managed research inputs and unmodified upstream bytes.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:INSIGHT_NATIVE_DISPOSABLE -ne '1'){throw 'Disposable scope must be explicit'}
$root=Join-Path $env:RUNNER_TEMP 'insight-dnspy-cli spaces-Ω';New-Item -ItemType Directory -Force $root|Out-Null
$archive=Join-Path $root 'dnSpy.zip';Invoke-WebRequest 'https://github.com/dnSpyEx/dnSpy/releases/download/v6.6.0/dnSpy-net-win64.zip' -OutFile $archive
if((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne '8ed48f165dc355e869f3a0037ad4f9216147f995a5ae0258b296eeef1f73aab0'){throw 'Upstream dnSpyEx archive differs'}
[IO.Compression.ZipFile]::ExtractToDirectory($archive,(Join-Path $root 'external'))
@'
using System;using System.IO;using System.Threading;using System.Runtime.CompilerServices;
public class OwnedResearch {
 [MethodImpl(MethodImplOptions.NoInlining)] public static int QuoteTotal(int count){return count*9+10;}
 [MethodImpl(MethodImplOptions.NoInlining)] public static int Settings(){return 7;}
 public static void Main(string[] args){if(args.Length==2&&args[0]=="wait"){File.WriteAllText(args[1],System.Diagnostics.Process.GetCurrentProcess().Id.ToString());Thread.Sleep(70000);return;}Console.WriteLine("quote="+QuoteTotal(11)+";setting="+Settings());}
}
'@|Set-Content -Encoding utf8 (Join-Path $root 'OwnedResearch.cs')
$researchInput=Join-Path $root 'OwnedResearch.exe';$compiler=Join-Path $env:SystemRoot 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
& $compiler /nologo /optimize+ /debug:pdbonly "/out:$researchInput" (Join-Path $root 'OwnedResearch.cs');if($LASTEXITCODE){throw 'Owned fixture compile failed'}
$type=([Reflection.Assembly]::LoadFile($researchInput)).GetType('OwnedResearch');$method='0x'+$type.GetMethod('QuoteTotal').MetadataToken.ToString('x8');$settings='0x'+$type.GetMethod('Settings').MetadataToken.ToString('x8');if($type.GetMethod('Settings').GetMethodBody().GetILAsByteArray()[0] -ne 0x1d){throw 'Settings did not start with ldc.i4.7'}
$core=Join-Path $root 'core';New-Item -ItemType Directory $core|Out-Null
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Exe</OutputType><AssemblyName>OwnedCoreProbe</AssemblyName></PropertyGroup></Project>'|Set-Content -Encoding utf8 (Join-Path $core 'Core.csproj');Copy-Item (Join-Path $root 'OwnedResearch.cs') (Join-Path $core 'Program.cs')
& dotnet build (Join-Path $core 'Core.csproj') --configuration Release --output (Join-Path $core 'out') --nologo;if($LASTEXITCODE){throw 'Owned Core fixture compile failed'}
$coreModule=Join-Path $core 'out/OwnedCoreProbe.dll';$coreMethod='0x'+([Reflection.Assembly]::LoadFile($coreModule)).GetType('OwnedResearch').GetMethod('QuoteTotal').MetadataToken.ToString('x8')
@{root=$root;archive=$archive;executable=(Join-Path $root 'external/dnSpy.exe');researchInput=$researchInput;method=$method;settingsMethod=$settings;coreExe=(Join-Path $core 'out/OwnedCoreProbe.exe');coreModule=$coreModule;coreMethod=$coreMethod;coreRuntimeConfig=(Join-Path $core 'out/OwnedCoreProbe.runtimeconfig.json');coreDeps=(Join-Path $core 'out/OwnedCoreProbe.deps.json')}|ConvertTo-Json|Set-Content -Encoding utf8 (Join-Path $root 'fixture.json')
"INSIGHT_DNSPY_FIXTURE=$(Join-Path $root 'fixture.json')"|Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
