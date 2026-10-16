using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using CliWrap;
using EyeAuras.Automation;
using NUnit.Framework;
using Reqnroll;

namespace Insight.Acceptance;

[Binding]
public sealed class IntegrationSteps(ScenarioContext context)
{
    private AutomationScenario scenario = null!;
    private AutomationCommandResult result = null!;
    private readonly Stopwatch elapsed = new();
    private string commandName = "not-started";
    private static string Root => Required("INSIGHT_REPOSITORY_ROOT");
    private static string Node => Required("INSIGHT_NODE");

    [BeforeScenario("technical")]
    public async Task Start()
    {
        scenario = (await AutomationRun.ConnectAsync()).CreateScenario();
        elapsed.Start();
    }

    [Given("the current insight-cli distribution has been built")]
    public void DistributionExists()
    {
        Assert.That(File.Exists(Path.Combine(Root, "skills/ghidra-coordinator/dist/src/bin.js")),
            Is.True, "Run npm run build before acceptance.");
    }

    [Given("disposable native acceptance is explicitly enabled")]
    public void NativeEnabled()
    {
        Assert.That(Environment.GetEnvironmentVariable("INSIGHT_NATIVE_DISPOSABLE"), Is.EqualTo("1"),
            "Set INSIGHT_NATIVE_DISPOSABLE=1 to authorize only owned disposable native fixtures.");
        Assert.That(OperatingSystem.IsMacOS(), Is.True, "The complete native GUI/keyring gate targets macOS.");
    }

    [When("the isolated package integration check runs")]
    public Task Package() => Execute("package", ["scripts/test-package.mjs"], TimeSpan.FromMinutes(5));

    [When("the offline CLI integration checks run")]
    public Task CliIntegration() => Execute("offline-cli",
        ["--test", "--test-reporter=tap", "skills/ghidra-coordinator/dist/tests/research-cli.test.js"], TimeSpan.FromMinutes(5));

    [When("the installed multi-agent native acceptance runs")]
    public Task NativeFacade() => Execute("native-facade",
        ["scripts/acceptance-facade.mjs", .. NativeArguments()], TimeSpan.FromMinutes(30));

    [When("the complete native acceptance runs")]
    public Task NativeFull() => Execute("native-full",
        ["scripts/acceptance-full.mjs", .. NativeArguments()], TimeSpan.FromHours(4));

    [Then("the package interface check succeeds")]
    public void PackagePassed()
    {
        Passed();
        Assert.That(result.StandardOutput, Does.Contain("Packed isolated install:").And.Contain("PASS"));
    }

    [Then("all selected CLI integration checks pass")]
    public void CliPassed()
    {
        Passed();
        var match = Regex.Match(result.StandardOutput, @"^# pass (\d+)\s*$", RegexOptions.Multiline);
        Assert.That(match.Success && int.Parse(match.Groups[1].Value) > 0, Is.True,
            "A successful exit without executed integration tests is not acceptance.");
        Assert.That(result.StandardOutput, Does.Match(@"(?m)^# fail 0\s*$"));
    }

    [Then("the native acceptance reports success")]
    public void NativePassed()
    {
        Passed();
        var line = result.StandardOutput.Split('\n').Last(x => x.TrimStart().StartsWith('{'));
        using var receipt = JsonDocument.Parse(line);
        Assert.That(receipt.RootElement.GetProperty("scope").GetString(), Is.EqualTo("installed native Factory facade IPC/OS secrets"));
        Assert.That(receipt.RootElement.GetProperty("sessions").GetInt32(), Is.EqualTo(2));
        Assert.That(receipt.RootElement.GetProperty("targets").GetInt32(), Is.EqualTo(2));
        Assert.That(receipt.RootElement.GetProperty("contexts").GetInt32(), Is.EqualTo(4));
        foreach (var check in new[] { "parallelCliProcesses", "independentPrivateViews", "explicitMergeRefresh",
                     "conflictRetainedAfterOwnerRestart", "managedServerRestartRetainsWork" })
            Assert.That(receipt.RootElement.GetProperty(check).GetBoolean(), Is.True, check);
    }

    [When("global CLI runtime delivery acceptance runs")]
    public Task ManagedRuntime() => Execute("managed-runtime",
        ["scripts/proof-managed-runtime.mjs", Required("INSIGHT_GLOBAL_CLI"),
         Required("INSIGHT_RUNTIME_EXE"), Path.Combine(scenario.ArtifactDirectory, "runtime-result.json"),
         Required("INSIGHT_EXTERNAL_GHIDRA"), Required("INSIGHT_GHIDRA_ARCHIVE")], TimeSpan.FromMinutes(30));

    [Then("managed and external runtime acceptance succeeds")]
    public void ManagedRuntimePassed()
    {
        Passed();
        var line = result.StandardOutput.Split('\n').Last(x => x.TrimStart().StartsWith('{'));
        using var receipt = JsonDocument.Parse(line);
        Assert.That(receipt.RootElement.GetProperty("state").GetString(), Is.EqualTo("passed"));
        foreach (var check in new[] { "freshProfileWithoutRuntimePaths", "pinnedDownloadsAndOfflineCache",
                     "nativeInstallAndDoctor", "explicitOwnedServerLifecycle", "multiClientRealExeResearchMergeRefresh",
                     "busyRuntimeAndServerProtected", "uninstallPreservesResearchAndArtifacts",
                     "localArchivesAndResearchContinuation", "officialZipWithManagedMacNatives", "managedGuiAndLiveDebugger", "managedBaseAndIsolatedExtension", "externalLauncherRealExeMergeAndSafeUninstall", "unchangedInput" })
            Assert.That(receipt.RootElement.GetProperty("checks").GetProperty(check).GetBoolean(), Is.True, check);
    }

    [Then("the complete native gate succeeds")]
    public void FullPassed()
    {
        Passed();
        Assert.That(result.StandardOutput, Does.Contain("Full acceptance passed; report:"));
    }

    private void Passed() => Assert.That(result.ExitCode, Is.Zero,
        $"{commandName} failed. See {result.StandardOutputPath} and {result.StandardErrorPath}.");

    private async Task Execute(string name, string[] arguments, TimeSpan timeout)
    {
        commandName = name;
        var clock = Stopwatch.StartNew();
        result = await scenario.ExecuteAsync(Cli.Wrap(Node).WithArguments(arguments).WithWorkingDirectory(Root), timeout);
        await File.WriteAllTextAsync(Path.Combine(scenario.ArtifactDirectory, "command-timing.json"),
            JsonSerializer.Serialize(new { name, elapsedSeconds = clock.Elapsed.TotalSeconds, result.ExitCode }));
    }

    private static string[] NativeArguments() =>
    [
        "--ack-disposable", "--java", Required("INSIGHT_JAVA"),
        "--ghidra-home", Required("INSIGHT_GHIDRA_HOME"),
        "--mcp-jar", Path.Combine(Root, "skills/ghidra-coordinator/runtime/GhidraMCP-7.0.0.jar"),
        "--clang", Required("INSIGHT_CLANG"), "--lld", Required("INSIGHT_LLD")
    ];

    private static string Required(string name) => Environment.GetEnvironmentVariable(name)
        is { Length: > 0 } value ? value : throw new InvalidOperationException($"Missing {name}.");

    [AfterScenario("technical")]
    public async Task Finish()
    {
        if (scenario is null) return;
        try { await scenario.FinishAsync(context.TestError); }
        finally
        {
            await File.WriteAllTextAsync(Path.Combine(scenario.ArtifactDirectory, "timing.json"),
                JsonSerializer.Serialize(new
                {
                    scenario = context.ScenarioInfo.Title,
                    elapsedSeconds = elapsed.Elapsed.TotalSeconds,
                    failed = context.TestError is not null,
                    measurement = "scenario wall time including cleanup; not a parallel-speedup benchmark"
                }));
        }
    }
}
