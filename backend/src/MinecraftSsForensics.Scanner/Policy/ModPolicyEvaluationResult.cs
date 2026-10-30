using MinecraftSsForensics.Scanner.Verification;

namespace MinecraftSsForensics.Scanner.Policy;

/// <summary>
/// Transparent result of evaluating a discovered mod against an active server/gamemode policy.
/// Preserves the strict separation between artifact authenticity and gameplay permissibility.
/// </summary>
public class ModPolicyEvaluationResult
{
    public string ModFileName { get; set; } = string.Empty;
    public string ModName { get; set; } = string.Empty;

    /// <summary>
    /// Independent classification of whether the file matches official distribution platforms.
    /// </summary>
    public ModVerificationState AuthenticityState { get; set; } = ModVerificationState.UNKNOWN_OR_UNLISTED;

    /// <summary>
    /// Independent classification of whether the mod is permissible under server rules.
    /// </summary>
    public GameplayPolicy Policy { get; set; } = GameplayPolicy.UNKNOWN;

    /// <summary>
    /// Confidence in the policy classification (Certain, High, Medium, Low).
    /// </summary>
    public string Confidence { get; set; } = "Medium";

    /// <summary>
    /// The behavioral capability category (e.g., HiddenInformationAdvantages, AutomatedCombatActions, ClientOptimization).
    /// </summary>
    public BehaviorCategory Behavior { get; set; } = BehaviorCategory.None;

    public string? MatchedRuleId { get; set; }
    public string AppliedPolicyName { get; set; } = string.Empty;
    public string AppliedGamemode { get; set; } = string.Empty;
    public string PolicyVersion { get; set; } = string.Empty;

    /// <summary>
    /// Plain-language reason for the policy classification.
    /// </summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>
    /// Full contextual explanation, including server policy rationale.
    /// </summary>
    public string Explanation { get; set; } = string.Empty;

    /// <summary>
    /// Explicit statement of what remains uncertain or requires manual verification.
    /// </summary>
    public string LimitationsAndUncertainty { get; set; } = string.Empty;

    /// <summary>
    /// Conditions required if the mod is RESTRICTED (e.g. radar or freecam disabled).
    /// </summary>
    public string? RestrictionConditions { get; set; }

    /// <summary>
    /// Public link to the server's policy rules.
    /// </summary>
    public string? SourceReference { get; set; }

    /// <summary>
    /// True if multiple signals (hash, manifest, filename) contradicted each other.
    /// </summary>
    public bool HasConflictingSignals { get; set; }

    /// <summary>
    /// Details about conflicting signals (e.g., filename claims Sodium, but embedded ID is Freecam).
    /// </summary>
    public string? ConflictDetails { get; set; }
}
