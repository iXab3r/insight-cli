param([Parameter(Mandatory=$true)][string]$Specification)
$ErrorActionPreference='Stop'
try {
    # No module autoload, profiles, JSON cmdlets or compiler in this minimal host.
    [void][Reflection.Assembly]::LoadFrom([IO.Path]::Combine($PSScriptRoot,'Insight.WindowsJob.dll'))
    [Insight.WindowsJob.OwnedJob]::RunSpecification($Specification)
    exit 0
} catch {[Console]::Error.WriteLine('Owned Windows job failed: '+$_.Exception.Message);exit 70}
