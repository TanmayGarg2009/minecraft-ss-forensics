namespace MinecraftSsForensics.Scanner.Archive;

public class ModMetadata
{
    public string? ModId { get; set; }
    public string? ModName { get; set; }
    public string? Version { get; set; }
    public string? Description { get; set; }
    public List<string> Authors { get; set; } = new();
    public string Loader { get; set; } = "Unknown";
    public string? MinecraftVersionRequirement { get; set; }
    public List<string> Dependencies { get; set; } = new();
    public List<string> MixinConfigs { get; set; } = new();
    public List<string> Entrypoints { get; set; } = new();
    public Dictionary<string, string> ManifestAttributes { get; set; } = new();
    public bool HasSuspiciousEntrypoints { get; set; }
    public List<string> SuspiciousNotes { get; set; } = new();
    public List<string> MatchedCheatSignatures { get; set; } = new();
    public BytecodeAnalysisResult BytecodeAnalysis { get; set; } = new();
    public bool ParseSuccess { get; set; }
    public string? ParseError { get; set; }
}
