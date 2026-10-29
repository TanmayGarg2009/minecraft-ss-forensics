namespace MinecraftSsForensics.Scanner.Hashing;

public class FileHashResult
{
    public string Sha256 { get; set; } = string.Empty;
    public string Sha512 { get; set; } = string.Empty;
    public string Sha1 { get; set; } = string.Empty;
    public uint Murmur2 { get; set; }
    public long FileSizeBytes { get; set; }
    public bool Success { get; set; }
    public bool IsMutatedDuringRead { get; set; }
    public string? ErrorMessage { get; set; }
}
