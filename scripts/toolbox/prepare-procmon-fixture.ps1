# Only disposable owned inputs and the approved vendor distribution.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:INSIGHT_NATIVE_DISPOSABLE -ne '1'){throw 'Disposable native scope must be explicit'}
$root=Join-Path $env:RUNNER_TEMP 'insight-procmon-cli spaces-Ω';New-Item -ItemType Directory -Force $root|Out-Null
$archive=Join-Path $root 'ProcessMonitor.zip';Invoke-WebRequest 'https://download.sysinternals.com/files/ProcessMonitor.zip' -OutFile $archive
if((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne '477754bf299c9e5b311c5666f7a4a48dfdb21265eaa8f0cca70ef9d9552e3a10'){throw 'Vendor archive differs'}
[IO.Compression.ZipFile]::ExtractToDirectory($archive,(Join-Path $root 'external'))
@{root=$root;archive=$archive;executable=(Join-Path $root 'external/Procmon64.exe')}|ConvertTo-Json|Set-Content -Encoding utf8 (Join-Path $root 'fixture.json')
"INSIGHT_PROCMON_FIXTURE=$(Join-Path $root 'fixture.json')"|Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
