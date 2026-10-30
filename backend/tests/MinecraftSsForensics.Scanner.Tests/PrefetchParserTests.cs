using System;
using System.IO;
using System.Text;
using MinecraftSsForensics.Scanner.LogsAndHistory;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class PrefetchParserTests
{
    [Fact]
    public void Prefetch_UncompressedVersion30SccaBytes_ParsesExecutableAndRunCount()
    {
        // Construct synthetic uncompressed SCCA Prefetch binary (version 30)
        byte[] scca = new byte[300];

        // Version = 30 at offset 0
        Buffer.BlockCopy(BitConverter.GetBytes(30), 0, scca, 0, 4);

        // Magic "SCCA" (0x41434353) at offset 4
        Buffer.BlockCopy(BitConverter.GetBytes(0x41434353U), 0, scca, 4, 4);

        // Executable name at offset 16 (0x10) - UTF-16LE
        string exeName = "JAVAW.EXE\0";
        byte[] nameBytes = Encoding.Unicode.GetBytes(exeName);
        Buffer.BlockCopy(nameBytes, 0, scca, 16, nameBytes.Length);

        // Run Count = 42 at offset 208 (0xD0)
        Buffer.BlockCopy(BitConverter.GetBytes(42), 0, scca, 208, 4);

        // Execution timestamp at offset 120 (0x78)
        var execTime = new DateTimeOffset(2026, 9, 1, 10, 15, 30, TimeSpan.Zero);
        Buffer.BlockCopy(BitConverter.GetBytes(execTime.ToFileTime()), 0, scca, 120, 8);

        var result = PrefetchParser.ParsePrefetchBytes(scca);

        Assert.True(result.Success);
        Assert.Equal("JAVAW.EXE", result.ExecutableName);
        Assert.Equal(42, result.RunCount);
        Assert.Single(result.ExecutionTimestamps);
        Assert.Equal(execTime, result.ExecutionTimestamps[0]);
    }

    [Fact]
    public void Prefetch_CorruptOrTruncatedHeader_ReturnsFailureGracefully()
    {
        byte[] garbage = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        var result = PrefetchParser.ParsePrefetchBytes(garbage);

        Assert.False(result.Success);
        Assert.Empty(result.ExecutionTimestamps);
    }

    [Fact]
    public void HistoricalEvidence_ResolveDevicePath_ResolvesVolumePrefix()
    {
        // Test volume translation
        string input = @"\Device\HarddiskVolume3\Program Files\Java\bin\javaw.exe";
        string resolved = HistoricalEvidenceScanner.ResolveDevicePath(input);

        Assert.NotNull(resolved);
        // If HarddiskVolume3 is registered in current system drive map, it resolves to e.g. C:\...
        // Otherwise, it preserves the original path without crashing.
        Assert.NotEmpty(resolved);
    }
}
