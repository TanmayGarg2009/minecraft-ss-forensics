using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace MinecraftSsForensics.Scanner.Process;

/// <summary>Extracts supported Minecraft launch directory and version arguments without executing them.</summary>
public static class MinecraftLaunchArguments
{
    public static string? GetGameDirectory(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
            return null;

        IReadOnlyList<string> tokens = Tokenize(commandLine);
        for (int i = 0; i < tokens.Count; i++)
        {
            string token = tokens[i];
            if (token.Equals("--gameDir", StringComparison.OrdinalIgnoreCase) || token.Equals("--gameDirectory", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < tokens.Count)
                    return NormalizePath(tokens[i + 1]);
            }

            const string gameDirPrefix = "--gameDir=";
            const string gameDirectoryPrefix = "--gameDirectory=";
            if (token.StartsWith(gameDirPrefix, StringComparison.OrdinalIgnoreCase))
                return NormalizePath(token[gameDirPrefix.Length..]);
            if (token.StartsWith(gameDirectoryPrefix, StringComparison.OrdinalIgnoreCase))
                return NormalizePath(token[gameDirectoryPrefix.Length..]);
        }
        return null;
    }

    public static string? GetVersion(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        IReadOnlyList<string> tokens = Tokenize(commandLine);
        for (int i = 0; i < tokens.Count; i++)
        {
            if ((tokens[i].Equals("--version", StringComparison.OrdinalIgnoreCase) || tokens[i].Equals("--fml.mcVersion", StringComparison.OrdinalIgnoreCase)) && i + 1 < tokens.Count)
                return tokens[i + 1];
            if (tokens[i].StartsWith("--version=", StringComparison.OrdinalIgnoreCase))
                return tokens[i][10..];
        }
        return null;
    }

    private static string? NormalizePath(string path)
    {
        path = path.Trim().Trim('"');
        if (path.Length == 0 || path.Contains("[REDACTED", StringComparison.OrdinalIgnoreCase))
            return null;
        try { return Path.GetFullPath(Environment.ExpandEnvironmentVariables(path)); }
        catch (ArgumentException) { return path; }
        catch (NotSupportedException) { return path; }
    }

    private static IReadOnlyList<string> Tokenize(string commandLine)
    {
        var tokens = new List<string>();
        var current = new System.Text.StringBuilder();
        bool quoted = false;
        foreach (char c in commandLine)
        {
            if (c == '"') { quoted = !quoted; continue; }
            if (char.IsWhiteSpace(c) && !quoted)
            {
                if (current.Length > 0) { tokens.Add(current.ToString()); current.Clear(); }
                continue;
            }
            current.Append(c);
        }
        if (current.Length > 0) tokens.Add(current.ToString());
        return tokens;
    }
}
