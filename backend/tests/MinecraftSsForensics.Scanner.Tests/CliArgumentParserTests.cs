using MinecraftSsForensics.Scanner.Cli;

namespace MinecraftSsForensics.Scanner.Tests;

public class CliArgumentParserTests
{
    [Fact]
    public void Parse_RejectsScanWithoutExplicitConsent()
    {
        var result = ScanCliOptions.Parse(new[] { "scan" });

        Assert.False(result.Success);
        Assert.Contains("--consent", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_AcceptsExplicitConsentAndFormats()
    {
        var result = ScanCliOptions.Parse(new[] { "scan", "--consent", "--output", "reports", "--format", "json,html" });

        Assert.True(result.Success);
        Assert.NotNull(result.Options);
        Assert.Equal(new[] { "json", "html" }, result.Options.Formats);
        Assert.Equal("reports", result.Options.OutputDirectory);
    }

    [Fact]
    public void Parse_RejectsInvalidOrIncompleteOptions()
    {
        string[][] invalidArguments =
        [
            ["scan", "--consent", "--format", "exe"],
            ["scan", "--consent", "--mode", "FAST"],
            ["scan", "--consent", "--output"],
            ["scan", "--consent", "--unknown"]
        ];

        foreach (string[] args in invalidArguments)
        {
            var result = ScanCliOptions.Parse(args);
            Assert.False(result.Success);
            Assert.NotEmpty(result.ErrorMessage);
        }
    }
}
