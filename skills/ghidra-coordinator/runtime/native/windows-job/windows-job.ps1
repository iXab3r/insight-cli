param([Parameter(Mandatory=$true)][string]$Specification)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function Phase([string]$value){[IO.File]::WriteAllText([IO.Path]::Combine([IO.Path]::GetDirectoryName($Specification),'job-launcher-phase.txt'),$value)}
Phase 'script_started'
try {
    $spec=Get-Content -LiteralPath $Specification -Raw -Encoding UTF8 | ConvertFrom-Json
    if($spec.schema -ne 1 -or !$spec.nonce -or $spec.timeoutMs -lt 1000 -or $spec.timeoutMs -gt 600000) { throw 'Invalid owned job specification' }
    Phase 'specification_read'
    $root=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Specification))
    $env:TEMP=$root;$env:TMP=$root
    [void][Reflection.Assembly]::LoadFrom((Join-Path $PSScriptRoot 'Insight.WindowsJob.dll'))
    Phase 'assembly_loaded'
    $callback=[Action[Insight.WindowsJob.Started]] {
        param($origin)
        $value=[ordered]@{schema=1;nonce=$spec.nonce;launcherPid=$origin.LauncherPid;childPid=$origin.ChildPid;childBirthTicks=[string]$origin.ChildBirthTicks;phase='assigned_suspended'}
        $bytes=[Text.Encoding]::UTF8.GetBytes(($value | ConvertTo-Json -Compress))
        $file=[IO.File]::Open((Join-Path $root 'job-started.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try {$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
    }
    Phase 'calling_native_job'
    $result=[Insight.WindowsJob.OwnedJob]::Run([string]$spec.executable,[string[]]@($spec.arguments),[string]$spec.cwd,[int]$spec.ownerPid,[long]$spec.ownerBirthTicks,[int]$spec.timeoutMs,$callback)
    $value=[ordered]@{schema=1;nonce=$spec.nonce;launcherPid=$PID;phase=$result.Kind;childExitCode=$result.ExitCode;childPid=$result.Started.ChildPid;childBirthTicks=[string]$result.Started.ChildBirthTicks}
    $bytes=[Text.Encoding]::UTF8.GetBytes(($value | ConvertTo-Json -Compress))
    $file=[IO.File]::Open((Join-Path $root 'job-result.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try {$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
    exit 0
} catch {[Console]::Error.WriteLine('Owned Windows job failed: '+$_.Exception.Message);exit 70}
