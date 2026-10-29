namespace MinecraftSsForensics.Scanner.Engine;

public class ScanProgressUpdate
{
    public string CurrentCategory { get; set; } = string.Empty;
    public string CurrentAction { get; set; } = string.Empty;
    public int PercentComplete { get; set; }
    public int DiscoveredModsCount { get; set; }
    public int VerifiedModsCount { get; set; }
    public int FlaggedFindingsCount { get; set; }
    public string? CurrentFileName { get; set; }
}
