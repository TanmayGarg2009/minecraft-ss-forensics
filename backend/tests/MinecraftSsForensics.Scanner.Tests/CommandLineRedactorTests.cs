using MinecraftSsForensics.Scanner.Process;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class CommandLineRedactorTests
{
    [Fact]
    public void Redact_RedactsAccessTokenAndUuidAndSession()
    {
        string raw = "javaw.exe -Xmx4G -Djava.library.path=bin --username Steve --accessToken eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token123 --uuid 12345678-1234-1234-1234-123456789abc --session token_secret_999 --version 1.20.4";

        string redacted = CommandLineRedactor.Redact(raw);

        Assert.DoesNotContain("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token123", redacted);
        Assert.DoesNotContain("12345678-1234-1234-1234-123456789abc", redacted);
        Assert.DoesNotContain("token_secret_999", redacted);

        Assert.Contains("--accessToken [REDACTED_ACCESS_TOKEN]", redacted);
        Assert.Contains("--uuid [REDACTED_UUID]", redacted);
        Assert.Contains("--session [REDACTED_SESSION]", redacted);

        // Safe arguments preserved
        Assert.Contains("--username Steve", redacted);
        Assert.Contains("-Xmx4G", redacted);
        Assert.Contains("--version 1.20.4", redacted);
    }

    [Fact]
    public void Redact_RedactsUserPropertiesAndPassword()
    {
        string raw = "java.exe --userProperties {\"profile\":[\"admin\"]} --password MySecretPassword123!";
        string redacted = CommandLineRedactor.Redact(raw);

        Assert.DoesNotContain("MySecretPassword123!", redacted);
        Assert.Contains("--password [REDACTED_PASSWORD]", redacted);
        Assert.Contains("--userProperties [REDACTED_USER_PROPERTIES]", redacted);
    }

    [Fact]
    public void Redact_HandlesNullOrEmptyString()
    {
        Assert.Equal(string.Empty, CommandLineRedactor.Redact(string.Empty));
        Assert.Equal(string.Empty, CommandLineRedactor.Redact("   "));
    }
}
