using System;

namespace MinecraftSsForensics.Scanner.Models;

/// <summary>
/// Configures user consent and explicitly chosen audit categories for the forensic scan.
/// </summary>
public class ConsentScopeConfig
{
    public bool ConsentGiven { get; set; } = false;
    public string CollectionScopeVersion { get; set; } = "2.0";
    public DateTimeOffset ConsentTimestamp { get; set; } = DateTimeOffset.UtcNow;

    // Standard audit categories (Enabled by default under standard consent)
    public bool InspectMinecraftMods { get; set; } = true;
    public bool InspectProcessesAndModules { get; set; } = true;
    public bool InspectExecutionArtifacts { get; set; } = true; // Prefetch, BAM, PCA
    public bool InspectRegistryArtifacts { get; set; } = true;  // UserAssist, Run, Shell Recent
    public bool InspectUsbHistory { get; set; } = true;        // USBSTOR for cheat flash drives
    public bool InspectFileDiscovery { get; set; } = true;      // Search user downloads/temp/desktop for cheat EXEs/JARs
    public bool InspectServicesAndDrivers { get; set; } = true; // Non-standard services, third-party drivers, Event 7045
    public bool PerformOnlineVerification { get; set; } = true; // Modrinth / CurseForge verification

    // SENSITIVE AUDIT CATEGORIES - Explicitly optional (default FALSE)
    /// <summary>
    /// Explicitly optional audit of browser history specifically matching known cheat domains (e.g. vape.gg, doomsdayclient.com).
    /// Strictly NEVER accesses passwords, cookies, tokens, or unrelated search queries.
    /// </summary>
    public bool InspectBrowserHistory { get; set; } = false;

    /// <summary>
    /// Verifies that required consent conditions are met before running any scan.
    /// </summary>
    public bool IsValidConsent(out string errorMessage)
    {
        if (!ConsentGiven)
        {
            errorMessage = "Explicit player consent is required before forensic collection can begin.";
            return false;
        }

        errorMessage = string.Empty;
        return true;
    }
}
