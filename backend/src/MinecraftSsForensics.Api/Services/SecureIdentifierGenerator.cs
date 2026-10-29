using System.Security.Cryptography;
using System.Text;

namespace MinecraftSsForensics.Api.Services;

public class SecureIdentifierGenerator : IIdentifierGenerator
{
    private const string Base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private readonly byte[] _salt;

    public SecureIdentifierGenerator(IConfiguration? configuration = null)
    {
        var configuredSalt = configuration?["Security:HashSalt"];
        _salt = !string.IsNullOrEmpty(configuredSalt)
            ? Encoding.UTF8.GetBytes(configuredSalt)
            : Encoding.UTF8.GetBytes("MinecraftSsForensics_StaticSecretSalt_v1_2026");
    }

    public string GeneratePublicId()
    {
        // 18 bytes of entropy => ~144 bits of cryptographic randomness
        byte[] bytes = RandomNumberGenerator.GetBytes(18);
        return "mc_" + ToBase62(bytes);
    }

    public string GenerateDeletionKey()
    {
        // 32 bytes of entropy => 256 bits of cryptographic randomness
        byte[] bytes = RandomNumberGenerator.GetBytes(32);
        return "del_" + Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public string HashDeletionKey(string deletionKey)
    {
        using var hmac = new HMACSHA256(_salt);
        byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(deletionKey));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public bool VerifyDeletionKey(string deletionKey, string storedHash)
    {
        if (string.IsNullOrWhiteSpace(deletionKey) || string.IsNullOrWhiteSpace(storedHash))
        {
            return false;
        }

        string computedHash = HashDeletionKey(deletionKey);
        byte[] computedBytes = Encoding.UTF8.GetBytes(computedHash);
        byte[] storedBytes = Encoding.UTF8.GetBytes(storedHash);

        return CryptographicOperations.FixedTimeEquals(computedBytes, storedBytes);
    }

    private static string ToBase62(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
        {
            sb.Append(Base62Chars[b % Base62Chars.Length]);
        }
        return sb.ToString();
    }
}
