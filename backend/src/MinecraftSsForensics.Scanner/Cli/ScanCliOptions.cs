using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MinecraftSsForensics.Scanner.Policy;

namespace MinecraftSsForensics.Scanner.Cli;

public sealed record ScanCliOptions(
    string OutputDirectory,
    string ScanMode,
    string Gamemode,
    string? CustomDirectory,
    IReadOnlyList<string> Formats,
    bool IncludeBrowserHistory)
{
    private static readonly HashSet<string> AllowedFormats = new(StringComparer.OrdinalIgnoreCase)
    {
        "json", "html", "csv", "markdown"
    };

    public static (bool Success, ScanCliOptions? Options, string ErrorMessage) Parse(string[] args)
    {
        if (args.Length == 0 || !args[0].Equals("scan", StringComparison.OrdinalIgnoreCase))
            return (false, null, "A 'scan' command is required.");

        string output = Path.Combine(Environment.CurrentDirectory, "reports");
        string mode = "FULL";
        string gamemode = "Crystal PvP";
        string? directory = null;
        string format = "all";
        bool consent = false;
        bool browser = false;

        for (int i = 1; i < args.Length; i++)
        {
            string option = args[i];
            if (option.Equals("--consent", StringComparison.OrdinalIgnoreCase))
            {
                consent = true;
                continue;
            }
            if (option.Equals("--browser", StringComparison.OrdinalIgnoreCase))
            {
                browser = true;
                continue;
            }

            bool takesValue = option is "-o" or "--output" or "-m" or "--mode" or "-g" or "--gamemode" or "-d" or "--dir" or "-f" or "--format";
            if (!takesValue)
                return (false, null, $"Unknown scan option '{option}'.");
            if (i + 1 >= args.Length || args[i + 1].StartsWith("-", StringComparison.Ordinal))
                return (false, null, $"Option '{option}' requires a value.");

            string value = args[++i];
            switch (option.ToLowerInvariant())
            {
                case "-o":
                case "--output":
                    output = value;
                    break;
                case "-m":
                case "--mode":
                    mode = value.ToUpperInvariant();
                    if (mode is not ("QUICK" or "FULL"))
                        return (false, null, "Scan mode must be QUICK or FULL.");
                    break;
                case "-g":
                case "--gamemode":
                    if (!IsKnownGamemode(value))
                        return (false, null, $"Unknown gamemode '{value}'. Choose a registered policy name.");
                    gamemode = value;
                    break;
                case "-d":
                case "--dir":
                    directory = value;
                    break;
                case "-f":
                case "--format":
                    format = value;
                    break;
            }
        }

        if (!consent)
            return (false, null, "Scanning requires explicit consent. Include --consent after reviewing the collection scope.");

        string[] formats = format.Equals("all", StringComparison.OrdinalIgnoreCase)
            ? new[] { "json", "html", "csv", "markdown" }
            : format.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(x => x.Equals("md", StringComparison.OrdinalIgnoreCase) ? "markdown" : x.ToLowerInvariant())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

        if (formats.Length == 0 || formats.Any(x => !AllowedFormats.Contains(x)))
            return (false, null, "Report formats must be json, html, csv, markdown, or all (comma-separated). ");
        if (directory != null && !Directory.Exists(directory))
            return (false, null, $"Custom Minecraft directory does not exist: {directory}");

        return (true, new ScanCliOptions(output, mode, gamemode, directory, formats, browser), string.Empty);
    }

    private static bool IsKnownGamemode(string requested)
    {
        var registry = new ModPolicyRegistry();
        return registry.GetAllPolicies().Any(p =>
            p.Gamemode.Equals(requested, StringComparison.OrdinalIgnoreCase) ||
            p.PolicyName.Equals(requested, StringComparison.OrdinalIgnoreCase) ||
            p.PolicyId.Equals(requested, StringComparison.OrdinalIgnoreCase) ||
            (p.Gamemode.EndsWith(" PvP", StringComparison.OrdinalIgnoreCase) &&
             p.Gamemode[..^4].Equals(requested, StringComparison.OrdinalIgnoreCase)));
    }
}
