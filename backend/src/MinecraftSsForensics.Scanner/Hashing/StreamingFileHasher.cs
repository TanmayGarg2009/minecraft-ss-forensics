using System.Security.Cryptography;

namespace MinecraftSsForensics.Scanner.Hashing;

public interface IFileHasher
{
    Task<FileHashResult> ComputeHashesAsync(string filePath, CancellationToken cancellationToken = default);
}

public class StreamingFileHasher : IFileHasher
{
    private const int BufferSize = 64 * 1024; // 64 KB buffer

    public async Task<FileHashResult> ComputeHashesAsync(string filePath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(filePath))
        {
            return new FileHashResult
            {
                Success = false,
                ErrorMessage = $"File does not exist: {filePath}"
            };
        }

        FileInfo initialInfo = new(filePath);
        long initialLength = initialInfo.Length;
        DateTime initialModified = initialInfo.LastWriteTimeUtc;

        try
        {
            using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, BufferSize, useAsync: true);

            using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var sha512 = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
            using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);

            byte[] buffer = new byte[BufferSize];
            long totalBytesRead = 0;
            int bytesRead;

            // Murmur2 byte accumulator for CurseForge fingerprint
            List<byte> normalizedCurseForgeBytes = new();

            while ((bytesRead = await fileStream.ReadAsync(buffer.AsMemory(0, BufferSize), cancellationToken)) > 0)
            {
                totalBytesRead += bytesRead;
                sha256.AppendData(buffer, 0, bytesRead);
                sha512.AppendData(buffer, 0, bytesRead);
                sha1.AppendData(buffer, 0, bytesRead);

                // Collect normalized bytes for CurseForge Murmur2
                for (int i = 0; i < bytesRead; i++)
                {
                    byte b = buffer[i];
                    if (b != 9 && b != 10 && b != 13 && b != 32)
                    {
                        normalizedCurseForgeBytes.Add(b);
                    }
                }
            }

            // Post-read mutation check
            FileInfo finalInfo = new(filePath);
            bool mutated = finalInfo.Length != initialLength || finalInfo.LastWriteTimeUtc != initialModified;

            byte[] hash256Bytes = sha256.GetHashAndReset();
            byte[] hash512Bytes = sha512.GetHashAndReset();
            byte[] hash1Bytes = sha1.GetHashAndReset();

            uint murmur2Hash = ComputeCurseForgeMurmur2(normalizedCurseForgeBytes.ToArray());

            return new FileHashResult
            {
                Success = true,
                Sha256 = Convert.ToHexString(hash256Bytes).ToLowerInvariant(),
                Sha512 = Convert.ToHexString(hash512Bytes).ToLowerInvariant(),
                Sha1 = Convert.ToHexString(hash1Bytes).ToLowerInvariant(),
                Murmur2 = murmur2Hash,
                FileSizeBytes = totalBytesRead,
                IsMutatedDuringRead = mutated,
                ErrorMessage = mutated ? "File size or timestamp mutated during hashing stream." : null
            };
        }
        catch (Exception ex)
        {
            return new FileHashResult
            {
                Success = false,
                ErrorMessage = $"Hashing error: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Computes the CurseForge Murmur2 fingerprint hash.
    /// CurseForge uses Murmur2 (seed 1, m = 0x5bd1e995, r = 24).
    /// </summary>
    public static uint ComputeCurseForgeMurmur2(byte[] data)
    {
        const uint m = 0x5bd1e995;
        const int r = 24;
        uint seed = 1;

        int len = data.Length;
        uint h = seed ^ (uint)len;

        int i = 0;
        while (len >= 4)
        {
            uint k = (uint)(data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24));

            k *= m;
            k ^= k >> r;
            k *= m;

            h *= m;
            h ^= k;

            i += 4;
            len -= 4;
        }

        switch (len)
        {
            case 3:
                h ^= (uint)(data[i + 2] << 16);
                h ^= (uint)(data[i + 1] << 8);
                h ^= data[i];
                h *= m;
                break;
            case 2:
                h ^= (uint)(data[i + 1] << 8);
                h ^= data[i];
                h *= m;
                break;
            case 1:
                h ^= data[i];
                h *= m;
                break;
        }

        h ^= h >> 13;
        h *= m;
        h ^= h >> 15;

        return h;
    }
}
