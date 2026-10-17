using System.Text.Json;
using CliWrap;
using EyeAuras.Automation;
using NUnit.Framework;
using Reqnroll;

namespace Insight.Acceptance;

[Binding, Scope(Tag = "toolbox")]
public sealed class ToolboxSteps(ScenarioContext context)
{
    private AutomationScenario scenario = null!;
    private JsonDocument? manifest;
    private JsonDocument? receipt;
    private static string Required(string name) => Environment.GetEnvironmentVariable(name)
        is { Length: > 0 } value ? value : throw new InvalidOperationException($"Missing {name}.");

    [BeforeScenario("toolbox")]
    public async Task Start() => scenario = (await AutomationRun.ConnectAsync()).CreateScenario();

    [Given("an isolated globally installed toolbox candidate is selected")]
    public void Ready()
    {
        Assert.That(Environment.GetEnvironmentVariable("INSIGHT_NATIVE_DISPOSABLE"), Is.EqualTo("1"));
        manifest = JsonDocument.Parse(File.ReadAllText(Required("INSIGHT_TOOLBOX_MANIFEST")));
        Assert.That(File.Exists(Path.Combine(Value("packageRoot"), "package.json")), Is.True);
    }

    private string Value(string name) => manifest!.RootElement.GetProperty(name).GetString()!;
    private async Task Execute(string script, params string[] inputs)
    {
        var result = await scenario.ExecuteAsync(Cli.Wrap(Required("INSIGHT_NODE"))
            .WithWorkingDirectory(Required("INSIGHT_REPOSITORY_ROOT"))
            .WithArguments(new[] { script, Value("packageRoot"), scenario.ArtifactDirectory }.Concat(inputs)),
            TimeSpan.FromMinutes(10));
        Assert.That(result.ExitCode, Is.Zero, $"Inspect {result.StandardOutputPath} and {result.StandardErrorPath}");
        receipt = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(scenario.ArtifactDirectory, "result.json")));
    }

    [When("Codex connects and disconnects the packaged skill bundle")]
    public Task Discover() => Execute("scripts/toolbox/host-discovery.mjs");

    [When("the public CLI recovers the owned container and retains its materials")]
    public Task Recover() => Execute("scripts/toolbox/native-sevenzip.mjs", Value("sevenzipArchive"), Value("container"), Value("sevenzipExecutable"));

    [When("the public CLI inspects native images and their debug records")]
    public Task InspectNative() => Execute("scripts/toolbox/native-llvm.mjs", Value("llvmArchive"), Value("nativeSubjects"));

    [When("the public CLI investigates the owned managed worker")]
    public Task InspectManaged() => Execute("scripts/toolbox/native-diagnostics.mjs", Value("diagnosticsArchives"), Value("dotnetArchive"), Value("managedWorker"));

    [When("the public CLI classifies owned native and managed inputs")]
    public Task Classify() => Execute("scripts/toolbox/native-die.mjs", Value("dieArchive"), Value("nativeSubjects"), Value("managedWorker"));

    [When("the public CLI observes owned native breakpoint snapshots")]
    public Task ObserveNative() => Execute("scripts/toolbox/native-lldb.mjs", Value("lldbArchive"), Value("nativeWorker"));

    [When("the installed debugger runner suffers controlled lifetime faults")]
    public Task DebuggerFaults() => Execute("scripts/toolbox/fault-lldb.mjs", Value("lldbArchive"), Value("nativeWorker"));

    [When("the public CLI traces the owned Linux worker")]
    public Task TraceLinux() => Execute("scripts/toolbox/native-strace.mjs", Value("straceArchive"), Value("nativeLinuxWorker"), Value("nativeLinuxSettings"));

    [When("the public CLI observes calls in the owned instrumented worker")]
    public Task InstrumentNative() => Execute("scripts/toolbox/native-frida.mjs", Value("fridaArchive"), Value("instrumentedWorker"), Value("nativeWorker"));

    [When("the public instrumentation collector suffers controlled lifetime faults")]
    public Task InstrumentationFaults() => Execute("scripts/toolbox/fault-frida.mjs", Value("fridaArchive"), Value("instrumentedWorker"));

    [Then("syscall evidence and checkpoints survive tracer removal")]
    [Then("hook evidence and checkpoints retain source identity and cleanup")]
    [Then("the original target remains alive with its ordinary behavior restored")]
    [Then("runtime evidence and checkpoints survive debugger removal")]
    [Then("owned debugger processes exit and uncertain results are not replayed")]
    [Then("header and signature evidence retains scan uncertainty")]
    [Then("the waiting stack and heap state have retained diagnostic evidence")]
    [Then("native linkage and focused debug evidence survive tool removal")]
    [Then("all shipped skills are visible and unrelated project skills survive")]
    [Then("exact recovered bytes and configuration survive tool removal")]
    public void Passed()
    {
        Assert.That(receipt, Is.Not.Null);
        Assert.That(receipt!.RootElement.GetProperty("state").GetString(), Is.EqualTo("passed"));
        Assert.That(receipt.RootElement.GetProperty("cleanupComplete").GetBoolean(), Is.True);
        var checks = receipt.RootElement.GetProperty("checks").EnumerateObject().ToArray();
        Assert.That(checks.Length, Is.GreaterThan(0));
        foreach (var check in checks) Assert.That(check.Value.GetBoolean(), Is.True, check.Name);
    }

    [AfterScenario("toolbox")]
    public async Task Finish()
    {
        try { if (scenario is not null) await scenario.FinishAsync(context.TestError); }
        finally { manifest?.Dispose(); receipt?.Dispose(); }
    }
}
