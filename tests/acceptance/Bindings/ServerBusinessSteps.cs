using System.Text.Json;
using CliWrap;
using EyeAuras.Automation;
using NUnit.Framework;
using Reqnroll;

namespace Insight.Acceptance;

[Binding, Scope(Tag = "server-business")]
public sealed class ServerBusinessSteps(ScenarioContext context)
{
    private AutomationScenario scenario = null!;
    private JsonDocument? result;
    private static string Required(string name) => Environment.GetEnvironmentVariable(name)
        is { Length: > 0 } value ? value : throw new InvalidOperationException($"Missing {name}.");

    [BeforeScenario("server-business")]
    public async Task Start() => scenario = (await AutomationRun.ConnectAsync()).CreateScenario();

    [Given("an isolated installed CLI and a disposable Ghidra repository are ready")]
    public void Ready()
    {
        Assert.That(Environment.GetEnvironmentVariable("INSIGHT_NATIVE_DISPOSABLE"), Is.EqualTo("1"));
        Assert.That(File.Exists(Required("INSIGHT_SERVER_BUSINESS_MANIFEST")), Is.True);
    }

    [When("agents perform collaboration workflow {string}")]
    public async Task Run(string id)
    {
        var execution = await scenario.ExecuteAsync(Cli.Wrap(Required("INSIGHT_NODE"))
            .WithWorkingDirectory(Required("INSIGHT_REPOSITORY_ROOT"))
            .WithArguments(new[] { "scripts/server-business/driver.mjs", "--case", id,
                "--manifest", Required("INSIGHT_SERVER_BUSINESS_MANIFEST"),
                "--output", scenario.ArtifactDirectory }), TimeSpan.FromMinutes(25));
        Assert.That(execution.ExitCode, Is.Zero,
            $"{id}: {execution.StandardOutputPath}; {execution.StandardErrorPath}");
        result = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(scenario.ArtifactDirectory, "result.json")));
        Assert.That(result.RootElement.GetProperty("id").GetString(), Is.EqualTo(id));
    }

    [Then("the collaboration outcome is {string}")]
    public void Outcome(string expected)
    {
        Assert.That(result, Is.Not.Null);
        var value = result!.RootElement;
        Assert.That(value.GetProperty("outcome").GetString(), Is.EqualTo(expected));
        Assert.That(value.GetProperty("state").GetString(), Is.EqualTo("passed"));
        Assert.That(value.GetProperty("publicCliOnly").GetBoolean(), Is.True);
        Assert.That(value.GetProperty("cleanupComplete").GetBoolean(), Is.True);
        Assert.That(value.GetProperty("serviceCleanupComplete").GetBoolean(), Is.True);
        var checks = value.GetProperty("checks").EnumerateArray().ToArray();
        Assert.That(checks.Length, Is.GreaterThan(0));
        foreach (var check in checks) Assert.That(check.GetProperty("passed").GetBoolean(), Is.True);
    }

    [AfterScenario("server-business")]
    public async Task Finish()
    {
        try { if (scenario is not null) await scenario.FinishAsync(context.TestError); }
        finally { result?.Dispose(); }
    }
}
