using System.Text.Json;
using CliWrap;
using EyeAuras.Automation;
using NUnit.Framework;
using Reqnroll;

[assembly: LevelOfParallelism(1)]

namespace Insight.Acceptance;

[Binding, Scope(Tag = "business")]
public sealed class BusinessSteps(ScenarioContext context)
{
    private AutomationScenario scenario = null!;
    private JsonDocument? result;
    private string selectedId = "";
    private string expectedOutcome = "";
    private static string Required(string name) => Environment.GetEnvironmentVariable(name)
        is { Length: > 0 } value ? value : throw new InvalidOperationException($"Missing {name}.");

    [BeforeScenario("business")]
    public async Task Start() => scenario = (await AutomationRun.ConnectAsync()).CreateScenario();

    [Given("the installed public CLI and versioned EXE oracle are ready")]
    public void Ready()
    {
        Assert.That(Environment.GetEnvironmentVariable("INSIGHT_NATIVE_DISPOSABLE"), Is.EqualTo("1"));
        Assert.That(File.Exists(Required("INSIGHT_BUSINESS_MANIFEST")), Is.True);
    }

    [When(@"I (.*)")]
    public async Task Investigate(string action)
    {
        var root = Required("INSIGHT_REPOSITORY_ROOT");
        using var actions = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root,
            "tests/acceptance/fixtures/business-actions.json")));
        var selection = actions.RootElement.GetProperty(action);
        selectedId = selection.GetProperty("id").GetString()!;
        expectedOutcome = selection.GetProperty("outcome").GetString()!;
        var execution = await scenario.ExecuteAsync(Cli.Wrap(Required("INSIGHT_NODE"))
            .WithWorkingDirectory(root).WithArguments(new[]
            {
                "scripts/business/driver.mjs", "--case", selectedId,
                "--manifest", Required("INSIGHT_BUSINESS_MANIFEST"), "--output", scenario.ArtifactDirectory
            }), TimeSpan.FromHours(8));
        Assert.That(execution.ExitCode, Is.Zero,
            $"{selectedId}: see {execution.StandardOutputPath} and {execution.StandardErrorPath}");
        result = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(scenario.ArtifactDirectory, "result.json")));
    }

    [Then(@"(.*)")]
    public void Outcome(string outcome)
    {
        Assert.That(outcome, Is.EqualTo(expectedOutcome));
        Assert.That(result, Is.Not.Null);
        var value = result!.RootElement;
        Assert.That(value.GetProperty("id").GetString(), Is.EqualTo(selectedId));
        Assert.That(value.GetProperty("state").GetString(), Is.EqualTo("passed"));
        Assert.That(value.GetProperty("publicCliOnly").GetBoolean(), Is.True);
        Assert.That(value.GetProperty("cleanupComplete").GetBoolean(), Is.True);
        var checks = value.GetProperty("checks").EnumerateObject().ToArray();
        Assert.That(checks.Length, Is.GreaterThan(0));
        foreach (var check in checks) Assert.That(check.Value.GetBoolean(), Is.True, check.Name);
    }

    [AfterScenario("business")]
    public async Task Finish()
    {
        try { if (scenario is not null) await scenario.FinishAsync(context.TestError); }
        finally { result?.Dispose(); }
    }
}
