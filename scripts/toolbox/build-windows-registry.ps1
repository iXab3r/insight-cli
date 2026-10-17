# Maintainer-only native build; consumers never need Visual Studio or a compiler.
param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$installation=& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
Import-Module (Join-Path $installation 'Common7/Tools/Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $installation -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
New-Item -ItemType Directory -Force $Output | Out-Null
$source=Join-Path $repo 'skills/ghidra-coordinator/runtime/native/windows-registry.c';$built=@()
$archive=Join-Path $repo 'skills/ghidra-coordinator/runtime/native/sources/detours-e4bfd6b.tar.gz'
if((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'd24f5dd1f977c33301ebd9f3be064e938a7908954df15b31235c9ca6691cb356'){throw 'Pinned Detours source differs'}
$detours=Join-Path $Output 'detours';New-Item -ItemType Directory -Force $detours|Out-Null
& tar -xzf $archive -C $detours
if($LASTEXITCODE){throw 'Detours source extraction failed'}
$detoursSource=Join-Path $detours 'Detours-e4bfd6b03e50de46b47abfbd1e46b384f0c5f833/src'
$names=@('detours','modules','disasm','image','creatwth','disolx86','disolx64','disolia64','disolarm','disolarm64')
foreach($name in @('first','second')){
 $directory=Join-Path $Output $name;New-Item -ItemType Directory -Force $directory | Out-Null
 Push-Location $directory
 try{
  $sources=@($names|ForEach-Object {Join-Path $detoursSource ($_.ToString()+'.cpp')})
  & cl.exe /nologo /c /O2 /MT /DNDEBUG /Zl /Gy /Brepro "/I$detoursSource" @sources
  if($LASTEXITCODE){throw 'Pinned Detours source build failed'}
  $objects=@($names|ForEach-Object {$_.ToString()+'.obj'})
  & lib.exe /nologo /Brepro /OUT:detours.lib @objects
  if($LASTEXITCODE){throw 'Pinned Detours library build failed'}
  & cl.exe /nologo /LD /TP /O2 /MT /DNDEBUG /Brepro "/I$detoursSource" $source /Fe:insight-registry-win-x64.dll /link /DYNAMICBASE /NXCOMPAT /OPT:REF /OPT:ICF /Brepro detours.lib advapi32.lib ("/DEF:"+(Join-Path $repo 'skills/ghidra-coordinator/runtime/native/windows-registry.def'))
  if($LASTEXITCODE){throw 'Native registry shim build failed'}
 }finally{Pop-Location}
 $built+=Join-Path $directory 'insight-registry-win-x64.dll'
}
$hash=(Get-FileHash $built[0] -Algorithm SHA256).Hash.ToLowerInvariant()
if((Get-FileHash $built[1] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash){throw 'Independent registry shim builds differ'}
Copy-Item $built[0] (Join-Path $Output 'insight-registry-win-x64.dll')
$version=@(& cl.exe /? 2>&1 | ForEach-Object {$_.ToString()})[0]
@{schema=1;sourceSha256=(Get-FileHash $source -Algorithm SHA256).Hash.ToLowerInvariant();sha256=$hash;size=(Get-Item $built[0]).Length;compiler=$version;flags='/LD /TP /O2 /MT /DNDEBUG /DYNAMICBASE /NXCOMPAT /OPT:REF /OPT:ICF /Brepro';detoursCommit='e4bfd6b03e50de46b47abfbd1e46b384f0c5f833';detoursSha256='d24f5dd1f977c33301ebd9f3be064e938a7908954df15b31235c9ca6691cb356';reproducible=$true} | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $Output 'registry-provenance.json')
"INSIGHT_REGISTRY_SHIM=$(Join-Path $Output 'insight-registry-win-x64.dll')" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
