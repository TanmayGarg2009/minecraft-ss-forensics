using System;
using System.IO;
using System.Text;
using MinecraftSsForensics.Scanner.Collectors;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class RecycleBinParserTests
{
    [Fact]
    public void RecycleBin_ParseValidVersion2IndexFile_RecoversPathAndTimestamp()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"recycle_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        string iPath = Path.Combine(tempDir, "$I123456.jar");
        string rPath = Path.Combine(tempDir, "$R123456.jar");

        try
        {
            // 1. Create matching data file
            File.WriteAllBytes(rPath, new byte[] { 0x50, 0x4B, 0x03, 0x04 }); // ZIP magic

            // 2. Construct binary $I file (Version 2 - Windows 10/11)
            using (var fs = File.Create(iPath))
            using (var bw = new BinaryWriter(fs))
            {
                bw.Write((long)2); // Version 2
                bw.Write((long)1048576); // Original size (1MB)

                // Deletion timestamp: 2026-08-20 18:00:00 UTC
                var deletionTime = new DateTimeOffset(2026, 8, 20, 18, 0, 0, TimeSpan.Zero);
                bw.Write(deletionTime.ToFileTime());

                string originalPath = @"C:\Users\Player\Downloads\vape_v4.jar";
                bw.Write((int)(originalPath.Length + 1)); // Character count including null terminator
                bw.Write(Encoding.Unicode.GetBytes(originalPath + "\0"));
            }

            var meta = FileDiscoveryScanner.ParseIndexFile(iPath);

            Assert.NotNull(meta);
            Assert.Equal(@"C:\Users\Player\Downloads\vape_v4.jar", meta.OriginalFilePath);
            Assert.Equal("vape_v4.jar", meta.OriginalFileName);
            Assert.Equal(1048576, meta.OriginalSize);
            Assert.Equal(new DateTimeOffset(2026, 8, 20, 18, 0, 0, TimeSpan.Zero), meta.DeletionTimestamp);
            Assert.Equal(rPath, meta.DataFilePath);
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void RecycleBin_ParseValidVersion1IndexFile_RecoversPathAndTimestamp()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"recycle_v1_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        string iPath = Path.Combine(tempDir, "$IAB12CD.exe");

        try
        {
            using (var fs = File.Create(iPath))
            using (var bw = new BinaryWriter(fs))
            {
                bw.Write((long)1); // Version 1 (Win 7/8)
                bw.Write((long)2048); // Size

                var deletionTime = new DateTimeOffset(2026, 7, 10, 12, 0, 0, TimeSpan.Zero);
                bw.Write(deletionTime.ToFileTime());

                string originalPath = @"C:\Users\Player\Desktop\doomsday.exe";
                byte[] pathBytes = new byte[520]; // 260 WCHARs fixed
                byte[] strBytes = Encoding.Unicode.GetBytes(originalPath + "\0");
                Buffer.BlockCopy(strBytes, 0, pathBytes, 0, strBytes.Length);
                bw.Write(pathBytes);
            }

            var meta = FileDiscoveryScanner.ParseIndexFile(iPath);

            Assert.NotNull(meta);
            Assert.Equal(@"C:\Users\Player\Desktop\doomsday.exe", meta.OriginalFilePath);
            Assert.Equal("doomsday.exe", meta.OriginalFileName);
            Assert.Equal(2048, meta.OriginalSize);
            Assert.Equal(new DateTimeOffset(2026, 7, 10, 12, 0, 0, TimeSpan.Zero), meta.DeletionTimestamp);
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void RecycleBin_CorruptedIndexFile_ReturnsNullGracefully()
    {
        string tempFile = Path.Combine(Path.GetTempPath(), $"corrupt_i_{Guid.NewGuid():N}.jar");
        try
        {
            File.WriteAllBytes(tempFile, new byte[] { 0x01, 0x02, 0x03 }); // Truncated header

            var meta = FileDiscoveryScanner.ParseIndexFile(tempFile);

            Assert.Null(meta);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }
}
