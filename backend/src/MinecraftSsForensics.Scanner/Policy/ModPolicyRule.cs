namespace MinecraftSsForensics.Scanner.Policy;

/// <summary>
/// A single rule within a server or gamemode mod policy.
/// Specifies which mods, versions, or signatures this rule applies to, and the resulting gameplay policy.
/// </summary>
public class ModPolicyRule
{
    /// <summary>
    /// Unique identifier for the rule (e.g., "RULE-FREECAM", "RULE-SODIUM").
    /// </summary>
    public string RuleId { get; set; } = string.Empty;

    /// <summary>
    /// Canonical display name of the mod.
    /// </summary>
    public string ModName { get; set; } = string.Empty;

    /// <summary>
    /// Gameplay policy classification for this mod under this rule.
    /// </summary>
    public GameplayPolicy Policy { get; set; } = GameplayPolicy.NEEDS_REVIEW;

    /// <summary>
    /// Behavioral domain or advantage category (e.g., HiddenInformationAdvantages, AutomatedCombatActions, ClientOptimization).
    /// </summary>
    public BehaviorCategory Behavior { get; set; } = BehaviorCategory.None;

    /// <summary>
    /// Plain-language reason for why this mod is allowed, prohibited, or restricted under this policy.
    /// </summary>
    public string PolicyReason { get; set; } = string.Empty;
    public string Reason { get => PolicyReason; set => PolicyReason = value; }

    /// <summary>
    /// Any conditions for restricted mods (e.g., "Allowed only if entity radar is disabled").
    /// </summary>
    public string? RestrictionConditions { get; set; }

    /// <summary>
    /// Link to the server's public rulebook or policy documentation.
    /// </summary>
    public string? SourceReference { get; set; }

    // Multi-signal matching criteria:

    /// <summary>
    /// Specific known SHA-256 hashes matching this rule (case-insensitive).
    /// Takes precedence over project and mod IDs.
    /// </summary>
    public List<string> Sha256Hashes { get; set; } = new();

    /// <summary>
    /// Modrinth slugs/IDs, CurseForge project IDs, or GitHub repos (e.g., "freecam", "sodium", "iris").
    /// </summary>
    public List<string> ProjectIds { get; set; } = new();

    /// <summary>
    /// Embedded mod IDs declared in fabric.mod.json, mods.toml, or mcmod.info (e.g., "freecam", "sodium").
    /// </summary>
    public List<string> ModIds { get; set; } = new();

    /// <summary>
    /// Allowed mod versions (e.g., "0.5.8", ">=0.5.0"). If empty, applies to all versions unless restricted.
    /// </summary>
    public List<string> AllowedVersions { get; set; } = new();

    /// <summary>
    /// Prohibited mod versions.
    /// </summary>
    public List<string> ProhibitedVersions { get; set; } = new();

    /// <summary>
    /// Known filename aliases or substrings (lowest priority signal, used as hints or lookalike detection).
    /// </summary>
    public List<string> Aliases { get; set; } = new();
}
