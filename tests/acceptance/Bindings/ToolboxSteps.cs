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
    public async Task Start()
    {
        var tags = context.ScenarioInfo.Tags;
        if (tags.Contains("linux") && !OperatingSystem.IsLinux()) Assert.Ignore("Native Linux profile is evaluated in its own CI gate.");
        if (tags.Contains("windows") && !OperatingSystem.IsWindows()) Assert.Ignore("Native Windows profile is evaluated in its own CI gate.");
        if (tags.Contains("macos") && !OperatingSystem.IsMacOS()) Assert.Ignore("Native macOS profile is evaluated in its own gate.");
        scenario = (await AutomationRun.ConnectAsync()).CreateScenario();
    }

    [Given("an isolated globally installed toolbox candidate is selected")]
    public void Ready()
    {
        Assert.That(Environment.GetEnvironmentVariable("INSIGHT_NATIVE_DISPOSABLE"), Is.EqualTo("1"));
        manifest = JsonDocument.Parse(File.ReadAllText(Required("INSIGHT_TOOLBOX_MANIFEST")));
        Assert.That(File.Exists(Path.Combine(Value("packageRoot"), "package.json")), Is.True);
    }

    [Given("an owned Windows native dump fixture is prepared")]
    public void WindowsReady()
    {
        Assert.That(OperatingSystem.IsWindows(), Is.True);
        Assert.That(Environment.GetEnvironmentVariable("INSIGHT_NATIVE_DISPOSABLE"), Is.EqualTo("1"));
        Assert.That(File.Exists(Required("INSIGHT_WINDBG_FIXTURE")), Is.True);
    }

    [When("the public CLI investigates the native Windows dump")]
    public async Task InspectWindowsDump()
    {
        var root = Required("INSIGHT_REPOSITORY_ROOT");
        var result = await scenario.ExecuteAsync(Cli.Wrap(Required("INSIGHT_NODE"))
            .WithWorkingDirectory(root).WithArguments(new[] { "scripts/toolbox/native-windbg.mjs" }), TimeSpan.FromMinutes(10));
        if (result.ExitCode != 0)
        {
            await NativeFailure(result.StandardOutputPath, result.StandardErrorPath);
        }
        Assert.That(result.ExitCode, Is.Zero, $"Inspect {result.StandardOutputPath} and {result.StandardErrorPath}");
        receipt = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "toolbox-windbg.json")));
    }

    [Given("an owned Windows file-observation fixture is prepared")]
    public void ProcmonReady()
    {
        Assert.That(OperatingSystem.IsWindows(), Is.True);
        Assert.That(Environment.GetEnvironmentVariable("INSIGHT_NATIVE_DISPOSABLE"), Is.EqualTo("1"));
        Assert.That(File.Exists(Required("INSIGHT_PROCMON_FIXTURE")), Is.True);
    }

    [When("the public CLI observes and reopens the Windows file capture")]
    public async Task ObserveWindowsFiles()
    {
        var root = Required("INSIGHT_REPOSITORY_ROOT");
        var result = await scenario.ExecuteAsync(Cli.Wrap(Required("INSIGHT_NODE"))
            .WithWorkingDirectory(root).WithArguments(new[] { "scripts/toolbox/native-procmon.mjs" }), TimeSpan.FromMinutes(10));
        if (result.ExitCode != 0)
        {
            await NativeFailure(result.StandardOutputPath, result.StandardErrorPath);
        }
        Assert.That(result.ExitCode, Is.Zero, $"Inspect {result.StandardOutputPath} and {result.StandardErrorPath}");
        receipt = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "toolbox-procmon.json")));
    }

    [Given("an owned Windows managed-research fixture is prepared")]
    public void DnspyReady()
    {
        Assert.That(OperatingSystem.IsWindows(), Is.True);
        Assert.That(Environment.GetEnvironmentVariable("INSIGHT_NATIVE_DISPOSABLE"), Is.EqualTo("1"));
        Assert.That(File.Exists(Required("INSIGHT_DNSPY_FIXTURE")), Is.True);
    }

    [When("the public CLI debugs and edits the managed Windows inputs")]
    public async Task DebugManagedWindows()
    {
        var root = Required("INSIGHT_REPOSITORY_ROOT");
        var result = await scenario.ExecuteAsync(Cli.Wrap(Required("INSIGHT_NODE"))
            .WithWorkingDirectory(root).WithArguments(new[] { "scripts/toolbox/native-dnspy.mjs" }), TimeSpan.FromMinutes(10));
        if (result.ExitCode != 0)
        {
            await NativeFailure(result.StandardOutputPath, result.StandardErrorPath);
        }
        Assert.That(result.ExitCode, Is.Zero, $"Inspect {result.StandardOutputPath} and {result.StandardErrorPath}");
        receipt = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "toolbox-dnspy.json")));
    }

    private static async Task NativeFailure(string output, string error)
    {
        foreach (var path in new[] { output, error })
        {
            if (!File.Exists(path)) continue;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            var buffer = new char[4096];
            var length = await reader.ReadBlockAsync(buffer, 0, buffer.Length);
            TestContext.Out.WriteLine(new string(buffer, 0, length));
        }
    }

    private string Value(string name) => manifest!.RootElement.GetProperty(name).GetString()!;
    private async Task Execute(string script, params string[] inputs)
    {
        var result = await scenario.ExecuteAsync(Cli.Wrap(Required("INSIGHT_NODE"))
            .WithWorkingDirectory(Required("INSIGHT_REPOSITORY_ROOT"))
            .WithArguments(new[] { script, Value("packageRoot"), scenario.ArtifactDirectory }.Concat(inputs)),
            TimeSpan.FromMinutes(10));
        if (result.ExitCode != 0)
        {
            await NativeFailure(result.StandardOutputPath, result.StandardErrorPath);
        }
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

    [When("the public CLI investigates the offline HTTP capture")]
    public Task InspectCapture() => Execute("scripts/toolbox/native-tshark.mjs", Value("tsharkArchive"), Value("packetCapture"));

    [When("the public CLI records and compares the owned HTTP exchanges")]
    public Task ObserveHttp() => Execute("scripts/toolbox/native-mitmproxy.mjs", Value("mitmproxyArchive"));

    [When("the public CLI compares managed metadata without executing targets")]
    public Task QueryMetadata() => Execute("scripts/toolbox/native-managed-metadata.mjs", Value("managedMetadataFixture"));

    [When("the public CLI queries the captured managed heap and stacks")]
    public Task QueryHeap() => Execute("scripts/toolbox/native-managed-heap.mjs", Value("managedWorker"), Value("mismatchedDac"));

    [When("the public CLI traces the owned Linux worker")]
    public Task TraceLinux() => Execute("scripts/toolbox/native-strace.mjs", Value("straceArchive"), Value("nativeLinuxWorker"), Value("nativeLinuxSettings"));

    [When("the public CLI observes calls in the owned instrumented worker")]
    public Task InstrumentNative() => Execute("scripts/toolbox/native-frida.mjs", Value("fridaArchive"), Value("instrumentedWorker"), Value("nativeWorker"));

    [When("the public instrumentation collector suffers controlled lifetime faults")]
    public Task InstrumentationFaults() => Execute("scripts/toolbox/fault-frida.mjs", Value("fridaArchive"), Value("instrumentedWorker"));

    [Then("object field and waiting stack evidence preserve dump identity and runtime limits")]
    [Then("managed metadata and normalized IL retain immutable input identity")]
    [Then("HTTP evidence and explicit TLS failures survive interruption and removal")]
    [Then("packet and stream evidence preserves input identity and bounded coverage")]
    [Then("managed runtime findings and copied edits preserve original inputs")]
    [Then("actual file evidence survives collector interruption and removal")]
    [Then("dump findings and checkpoints survive debugger removal")]
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
