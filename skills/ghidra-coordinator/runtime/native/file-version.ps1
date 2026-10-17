param([string]$Executable,[switch]$Administrator)
$ErrorActionPreference='Stop'
try {
 if($Administrator){$identity=[Security.Principal.WindowsIdentity]::GetCurrent();try{$principal=[Security.Principal.WindowsPrincipal]::new($identity);[Console]::Out.Write($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator).ToString().ToLowerInvariant())}finally{$identity.Dispose()}}
 else {if(!$Executable){throw 'Executable path is required'};[Console]::Out.Write([Diagnostics.FileVersionInfo]::GetVersionInfo($Executable).FileVersion)}
 exit 0
}catch {[Console]::Error.WriteLine('Native metadata is unavailable: '+$_.Exception.Message);exit 70}
