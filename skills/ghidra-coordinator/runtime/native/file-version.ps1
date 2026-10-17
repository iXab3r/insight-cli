param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference='Stop'
try {[Console]::Out.Write([Diagnostics.FileVersionInfo]::GetVersionInfo($Executable).FileVersion);exit 0}
catch {[Console]::Error.WriteLine('Native file version is unavailable: '+$_.Exception.Message);exit 70}
