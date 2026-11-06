using System;

namespace MinecraftSsForensics.Scanner.Process;

/// <summary>
/// Redacts sensitive authentication tokens and personal file system paths from Minecraft command lines and reports.
/// Backwards-compatible wrapper delegating to PrivacyBoundary.
/// </summary>
public static class CommandLineRedactor
{
    public static string Redact(string commandLine) => PrivacyBoundary.RedactCommandLine(commandLine);

    public static string RedactPath(string? filePath) => PrivacyBoundary.RedactPath(filePath);
}
