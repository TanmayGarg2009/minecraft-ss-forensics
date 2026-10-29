using System.Text.RegularExpressions;

namespace MinecraftSsForensics.Scanner.Process;

public static class CommandLineRedactor
{
    private static readonly Regex AccessTokenRegex = new(
        @"(--accessToken\s+)(\S+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UuidRegex = new(
        @"(--uuid\s+)([0-9a-fA-F\-]{32,36})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SessionRegex = new(
        @"(--session\s+)(\S+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UserPropertiesRegex = new(
        @"(--userProperties\s+)({[^}]+}|\[[^\]]+\]|\S+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PasswordRegex = new(
        @"(--password\s+)(\S+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex JvmPropertySecretRegex = new(
        @"(-D(?:auth|token|secret|password|key)[^\s=]*=)(\S+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static string Redact(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
            return string.Empty;

        string redacted = commandLine;

        redacted = AccessTokenRegex.Replace(redacted, "$1[REDACTED_ACCESS_TOKEN]");
        redacted = UuidRegex.Replace(redacted, "$1[REDACTED_UUID]");
        redacted = SessionRegex.Replace(redacted, "$1[REDACTED_SESSION]");
        redacted = UserPropertiesRegex.Replace(redacted, "$1[REDACTED_USER_PROPERTIES]");
        redacted = PasswordRegex.Replace(redacted, "$1[REDACTED_PASSWORD]");
        redacted = JvmPropertySecretRegex.Replace(redacted, "$1[REDACTED_SECRET]");

        return redacted;
    }
}
