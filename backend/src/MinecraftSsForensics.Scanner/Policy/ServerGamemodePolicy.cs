namespace MinecraftSsForensics.Scanner.Policy;

/// <summary>
/// Configurable policy document governing mod permissibility for a specific server or gamemode.
/// Can be loaded from versioned JSON files or built-in presets.
/// </summary>
public class ServerGamemodePolicy
{
    public string SchemaVersion { get; set; } = "1.0.0";

    /// <summary>
    /// Unique policy identifier (e.g., "crystal-pvp-v1", "uhc-standard").
    /// </summary>
    public string PolicyId { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable policy title (e.g., "Crystal PvP Standard Competition Policy").
    /// </summary>
    public string PolicyName { get; set; } = string.Empty;

    /// <summary>
    /// Target gamemode (e.g., "Crystal PvP", "Sword PvP", "Axe PvP", "UHC", "Pot PvP", "SMP", "Default").
    /// </summary>
    public string Gamemode { get; set; } = "Default";

    /// <summary>
    /// Semantic version of this policy document.
    /// </summary>
    public string PolicyVersion { get; set; } = "1.0.0";

    /// <summary>
    /// Organization, league, or server that authored this policy.
    /// </summary>
    public string Publisher { get; set; } = "Example Competition League";

    /// <summary>
    /// Indicates whether this is an example template or server-verified ruleset.
    /// </summary>
    public bool IsExamplePolicy { get; set; } = true;

    /// <summary>
    /// Effective date of this policy (e.g., "2026-01-01").
    /// </summary>
    public string EffectiveDate { get; set; } = string.Empty;

    /// <summary>
    /// URL to the server's official rulebook or guidelines.
    /// </summary>
    public string? ServerRulesUrl { get; set; }

    /// <summary>
    /// Explicitly permitted mod IDs that bypass general restrictions.
    /// </summary>
    public List<string> ExplicitlyPermittedMods { get; set; } = new();

    /// <summary>
    /// Brief description of the competitive philosophy and expectations for this gamemode.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// How mods not explicitly recognized by any rule should be treated.
    /// Default is NEEDS_REVIEW (never assumed to be a cheat).
    /// </summary>
    public GameplayPolicy DefaultUnknownModPolicy { get; set; } = GameplayPolicy.NEEDS_REVIEW;

    /// <summary>
    /// Default explanation provided when an unrecognized mod is encountered.
    /// </summary>
    public string UnknownModPolicyReason { get; set; } =
        "This mod is not listed in the active server policy registry. It is not automatically classified as a cheat, but requires staff review.";

    /// <summary>
    /// Set of specific mod policy rules evaluated in priority order.
    /// </summary>
    public List<ModPolicyRule> Rules { get; set; } = new();
}
