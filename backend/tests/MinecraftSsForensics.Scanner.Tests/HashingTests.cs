using System.Security.Cryptography;
using System.Text;
using MinecraftSsForensics.Scanner.Hashing;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class HashingTests
{
    private readonly StreamingFileHasher _hasher = new();

    [Fact]
    public async Task ComputeHashesAsync_ComputesAccurateSha256AndSha512()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            byte[] testBytes = Encoding.UTF8.GetBytes("Minecraft SS Forensics Test Byte Stream 123456789");
            await File.WriteAllBytesAsync(tempFile, testBytes);

            var result = await _hasher.ComputeHashesAsync(tempFile);

            Assert.True(result.Success);
            Assert.False(result.IsMutatedDuringRead);
            Assert.Equal(testBytes.Length, result.FileSizeBytes);

            // Compute reference hashes
            string expectedSha256 = Convert.ToHexString(SHA256.HashData(testBytes)).ToLowerInvariant();
            string expectedSha512 = Convert.ToHexString(SHA512.HashData(testBytes)).ToLowerInvariant();

            Assert.Equal(expectedSha256, result.Sha256);
            Assert.Equal(expectedSha512, result.Sha512);
            Assert.True(result.Murmur2 > 0);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ComputeHashesAsync_ReturnsFailure_WhenFileDoesNotExist()
    {
        var result = await _hasher.ComputeHashesAsync("C:\\NonExistent\\Path\\random_mod.jar");
        Assert.False(result.Success);
        Assert.Contains("does not exist", result.ErrorMessage);
    }

    [Fact]
    public void ComputeCurseForgeMurmur2_ComputesDeterministicHash()
    {
        byte[] data = Encoding.UTF8.GetBytes("public class TestMod extends BaseMod { }");
        uint hash1 = StreamingFileHasher.ComputeCurseForgeMurmur2(data);
        uint hash2 = StreamingFileHasher.ComputeCurseForgeMurmur2(data);

        Assert.Equal(hash1, hash2);
        Assert.True(hash1 > 0);
    }
}
