# Native feasibility only: these probes do not establish adapter or agent acceptance.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = Join-Path $env:RUNNER_TEMP 'insight-toolbox-audit'
New-Item -ItemType Directory -Force $root | Out-Null
$result = [ordered]@{schema=1;scope='Windows host feasibility, not toolbox acceptance';tools=[ordered]@{} }
$owned = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
function Acquire($name,$url,$sha) {
    $path=Join-Path $root $name
    Invoke-WebRequest $url -OutFile $path
    if ((Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sha) { throw "Pinned hash differs: $name" }
    return $path
}
function Expand-Checked($archive,$destination) {
    $zip=[System.IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $prefix=[System.IO.Path]::GetFullPath($destination)+[System.IO.Path]::DirectorySeparatorChar
        foreach($entry in $zip.Entries) {
            $target=[System.IO.Path]::GetFullPath((Join-Path $destination $entry.FullName))
            if (!$target.StartsWith($prefix,[System.StringComparison]::OrdinalIgnoreCase)) { throw 'Archive entry escapes destination' }
        }
    } finally { $zip.Dispose() }
    [System.IO.Compression.ZipFile]::ExtractToDirectory($archive,$destination)
}
function Launch($executable,[string[]]$arguments) {
    $info=[System.Diagnostics.ProcessStartInfo]::new($executable)
    $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    foreach($argument in $arguments) { $info.ArgumentList.Add($argument) }
    $process=[System.Diagnostics.Process]::new();$process.StartInfo=$info
    [void]$process.Start();$owned.Add($process)
    return @{process=$process;stdout=$process.StandardOutput.ReadToEndAsync();stderr=$process.StandardError.ReadToEndAsync()}
}
function Finish($execution,$milliseconds=30000) {
    if(!$execution.process.WaitForExit($milliseconds)) { $execution.process.Kill($true);throw 'Owned probe exceeded its deadline' }
    return @{code=$execution.process.ExitCode;stdout=$execution.stdout.GetAwaiter().GetResult();stderr=$execution.stderr.GetAwaiter().GetResult()}
}
try {
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    $result.administrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $fixture=Join-Path $root 'fixture';New-Item -ItemType Directory $fixture | Out-Null
    @'
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><AssemblyName>InsightOwnedProbe</AssemblyName><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>
'@ | Set-Content (Join-Path $fixture 'Probe.csproj')
    @'
string path=args[0];
Console.WriteLine("OWNED_CONFIG="+File.ReadAllText(path).Trim());
if(args.Length>1) for(int i=0;i<600;i++) Thread.Sleep(100);
'@ | Set-Content (Join-Path $fixture 'Program.cs')
    & dotnet build (Join-Path $fixture 'Probe.csproj') --configuration Release --output (Join-Path $fixture 'out') --nologo
    if($LASTEXITCODE) { throw 'Owned fixture build failed' }
    $exe=Join-Path $fixture 'out/InsightOwnedProbe.exe'
    $dll=Join-Path $fixture 'out/InsightOwnedProbe.dll'
    $config=Join-Path $fixture 'owned-settings.txt';'fixture-value' | Set-Content $config
    $result.fixtureSha256=(Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    try {
        $bundle=Acquire 'windbg.msixbundle' 'https://windbg.download.prss.microsoft.com/dbazure/prod/1-2610-1001-0/windbg.msixbundle' '4662ae17bc0dc77db987b89cccea32c30058baa06268f861d09e0ab4e4f45c20'
        $unpacked=Join-Path $root 'windbg-bundle';Expand-Checked $bundle $unpacked
        $debugger=Join-Path $root 'windbg';Expand-Checked (Join-Path $unpacked 'windbg_win-x64.msix') $debugger
        $cdb=Join-Path $debugger 'amd64/cdb.exe'
        $r=Finish (Launch $cdb @('-c','.echo INSIGHT_DEBUGGER_PROBE; r; k; lm; q',$exe,$config))
        $result.tools.windbg=@{version='1.2610.1001.0';consoleAutomation=($r.code -eq 0 -and $r.stdout.Contains('INSIGHT_DEBUGGER_PROBE') -and $r.stdout.Contains('rip='));adapterAccepted=$false}
    } catch { $result.tools.windbg=@{feasible=$false;errorType=$_.Exception.GetType().Name;adapterAccepted=$false} }
    try {
        if(Get-Process -Name 'Procmon*' -ErrorAction SilentlyContinue) { throw 'Unowned Process Monitor already exists' }
        $zip=Acquire 'ProcessMonitor.zip' 'https://download.sysinternals.com/files/ProcessMonitor.zip' '477754bf299c9e5b311c5666f7a4a48dfdb21265eaa8f0cca70ef9d9552e3a10'
        $procmon=Join-Path $root 'procmon';Expand-Checked $zip $procmon
        $launcher=Join-Path $procmon 'Procmon64.exe';$pml=Join-Path $root 'owned.pml';$csv=Join-Path $root 'owned.csv'
        $capture=Launch $launcher @('/AcceptEula','/Quiet','/Minimized','/BackingFile',$pml)
        # /WaitForIdle can return 1 before the first instance has registered its endpoint.
        # A fixed sleep cannot establish readiness before the short fixture starts.
        $readinessStarted=[System.Diagnostics.Stopwatch]::StartNew();$idle=$null;$readinessAttempts=0
        do {
            if($capture.process.HasExited) { throw 'Owned Process Monitor exited before readiness' }
            $readinessAttempts++
            $idle=Finish (Launch $launcher @('/AcceptEula','/Quiet','/WaitForIdle')) 10000
            if($idle.code -eq 0) { break }
            Start-Sleep -Milliseconds 500
        } while($readinessStarted.ElapsedMilliseconds -lt 30000)
        if($idle.code -ne 0) { throw 'Owned Process Monitor did not report capture readiness' }
        $readinessMs=$readinessStarted.ElapsedMilliseconds
        $driverRunning=@(Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -like 'PROCMON*' -and $_.State -eq 'Running' }).Count -gt 0
        $ran=Finish (Launch $exe @($config))
        $stop=Finish (Launch $launcher @('/Terminate'))
        if(!$capture.process.WaitForExit(20000)) { throw 'Owned capture did not stop' }
        $export=Finish (Launch $launcher @('/AcceptEula','/Quiet','/OpenLog',$pml,'/SaveAs',$csv))
        $rows=@();if(Test-Path $csv){$rows=@(Import-Csv $csv)}
        $ownedRows=@($rows | Where-Object { $_.'Process Name' -eq 'InsightOwnedProbe.exe' })
        $configPath=[System.IO.Path]::GetFullPath($config)
        $configRows=@($ownedRows | Where-Object { $_.Path.Replace('/','\') -eq $configPath })
        $matches=@($configRows | Where-Object { $_.Operation -eq 'ReadFile' -and $_.Result -eq 'SUCCESS' }).Count
        $configOperations=@($configRows | Group-Object Operation,Result | ForEach-Object { @{operation=$_.Group[0].Operation;result=$_.Group[0].Result;count=$_.Count} })
        $result.tools.procmon=@{version='4.12';ownedConfigReadObserved=($ran.code -eq 0 -and $matches -gt 0);matchingEvents=$matches;configOperations=$configOperations;configSuffixEvents=@($ownedRows | Where-Object { $_.Path.EndsWith("owned-settings.txt") }).Count;totalEvents=$rows.Count;ownedEvents=$ownedRows.Count;columns=@(if($rows.Count){$rows[0].PSObject.Properties.Name});captureExited=$capture.process.HasExited;idleExit=$idle.code;readinessAttempts=$readinessAttempts;readinessMs=$readinessMs;fixtureExit=$ran.code;stopExit=$stop.code;exportExit=$export.code;driverRunning=$driverRunning;fixtureOutputValid=$ran.stdout.Contains('OWNED_CONFIG=fixture-value');captureScope='disposable runner feasibility only; product-side prefilter still required';adapterAccepted=$false}
        # Raw process captures can include unrelated runner data: never upload them.
        Remove-Item $pml,$csv -Force -ErrorAction SilentlyContinue
    } catch { $result.tools.procmon=@{feasible=$false;errorType=$_.Exception.GetType().Name;adapterAccepted=$false} }
    try {
        $zip=Acquire 'dnSpy-net-win64.zip' 'https://github.com/dnSpyEx/dnSpy/releases/download/v6.6.0/dnSpy-net-win64.zip' '8ed48f165dc355e869f3a0037ad4f9216147f995a5ae0258b296eeef1f73aab0'
        $dnspy=Join-Path $root 'dnspy';Expand-Checked $zip $dnspy
        $launcher=Join-Path $dnspy 'dnSpy.exe'
        $target=Launch $exe @($config,'wait')
        $gui=Launch $launcher @('--multiple','--settings-file',(Join-Path $root 'dnspy-settings.xml'),'--pid',[string]$target.process.Id,$dll)
        Start-Sleep -Seconds 10;$gui.process.Refresh()
        $result.tools.dnspy=@{version='6.6.0';launchAlive=(!$gui.process.HasExited);windowHandlePresent=($gui.process.MainWindowHandle -ne 0);extensionContractsPresent=(@(Get-ChildItem $dnspy -Recurse -Filter '*Contracts*Debugger*.dll').Count -gt 0);debugEditAutomationProven=$false;adapterAccepted=$false}
        if(!$gui.process.HasExited) { [void]$gui.process.CloseMainWindow();[void]$gui.process.WaitForExit(5000) }
    } catch { $result.tools.dnspy=@{feasible=$false;errorType=$_.Exception.GetType().Name;adapterAccepted=$false} }
} finally {
    foreach($process in $owned) { try { if(!$process.HasExited){$process.Kill($true);$process.WaitForExit()} } catch {} }
    # Only the sanitized receipt is retained; downloaded payloads and raw captures stay private.
    $output=Join-Path $env:GITHUB_WORKSPACE 'toolbox-audit-windows.json'
    $result | ConvertTo-Json -Depth 10 | Set-Content $output
    $result | ConvertTo-Json -Depth 10 | Write-Output
}
if($result.tools.windbg.consoleAutomation -ne $true -or $result.tools.procmon.ownedConfigReadObserved -ne $true -or $result.tools.dnspy.launchAlive -ne $true -or $result.tools.dnspy.windowHandlePresent -ne $true) {
    throw 'One or more required host feasibility probes failed; inspect the sanitized receipt'
}
