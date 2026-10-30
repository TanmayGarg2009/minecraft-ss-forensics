using System;
using System.IO;
using MinecraftSsForensics.Scanner.Process;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class AuthenticodeTrustValidatorTests
{
    [Fact]
    public void Authenticode_NonExistentFile_ReturnsUnsigned()
    {
        var result = AuthenticodeTrustValidator.VerifyFileTrust("C:\\non_existent_binary_file_123.dll");

        Assert.False(result.IsSigned);
        Assert.False(result.IsTrusted);
        Assert.Equal(AuthenticodeTrustStatus.Unsigned, result.TrustStatus);
    }

    [Fact]
    public void Authenticode_UnsignedFile_ReturnsUnsigned()
    {
        string tempFile = Path.Combine(Path.GetTempPath(), $"unsigned_test_{Guid.NewGuid():N}.dll");
        try
        {
            File.WriteAllBytes(tempFile, new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00 }); // Minimal MZ header

            var result = AuthenticodeTrustValidator.VerifyFileTrust(tempFile);

            Assert.False(result.IsSigned);
            Assert.False(result.IsTrusted);
            Assert.Equal(AuthenticodeTrustStatus.Unsigned, result.TrustStatus);
            Assert.Contains("not signed", result.StatusExplanation);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public void Authenticode_LegitimateWindowsSystemBinary_ReturnsTrusted()
    {
        if (!OperatingSystem.IsWindows()) return;

        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string exePath = Path.Combine(winDir, "explorer.exe");

        if (File.Exists(exePath))
        {
            var result = AuthenticodeTrustValidator.VerifyFileTrust(exePath);

            Assert.True(result.IsSigned);
            Assert.True(result.IsTrusted);
            Assert.Equal(AuthenticodeTrustStatus.Trusted, result.TrustStatus);
            Assert.NotNull(result.SignerSubject);
            Assert.Contains("Microsoft", result.SignerSubject);
        }
    }
}
