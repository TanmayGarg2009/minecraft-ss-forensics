using MinecraftSsForensics.Scanner.Archive;
using MinecraftSsForensics.Scanner.Hashing;

namespace MinecraftSsForensics.Scanner.Verification;

public enum ModVerificationState
{
    VERIFIED_EXACT_RELEASE,
    VERIFIED_TRUSTED_SIGNATURE,
    KNOWN_PROJECT_UNVERIFIED_ARTIFACT,
    KNOWN_ARTIFACT_HASH_MISMATCH,
    KNOWN_MODIFIED_OR_REPACKAGED,
    UNKNOWN_OR_UNLISTED,
    METADATA_CONFLICT,
    VERIFICATION_UNAVAILABLE,
    INVALID_OR_UNREADABLE_ARCHIVE
}

public class DiscoveredMod
{
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public DateTime CreatedTimeUtc { get; set; }
    public DateTime ModifiedTimeUtc { get; set; }
    public FileHashResult Hashes { get; set; } = new();
    public ModMetadata Metadata { get; set; } = new();
    public string InstallationDirectory { get; set; } = string.Empty;
}

public class ModVerificationResult
{
    public ModVerificationState State { get; set; } = ModVerificationState.UNKNOWN_OR_UNLISTED;
    public string Provider { get; set; } = "None";
    public string? ProjectId { get; set; }
    public string? ProjectName { get; set; }
    public string? VersionId { get; set; }
    public string? VersionNumber { get; set; }
    public string? MatchedFileName { get; set; }
    public string? ExpectedHash { get; set; }
    public long? ExpectedSizeBytes { get; set; }
    public List<string> SupportedGameVersions { get; set; } = new();
    public List<string> SupportedLoaders { get; set; } = new();
    public string? ProjectUrl { get; set; }
    public string Explanation { get; set; } = string.Empty;
    public string Limitations { get; set; } = string.Empty;
    public bool IsCached { get; set; }
    public DateTime ReferenceDataTimestamp { get; set; } = DateTime.UtcNow;
}
