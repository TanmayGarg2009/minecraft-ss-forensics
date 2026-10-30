namespace MinecraftSsForensics.Scanner.Policy;

/// <summary>
/// Independent classification of a mod's permissibility under specific server rules and gamemodes.
/// Note: This is separate from whether the file is an authentic official release.
/// </summary>
public enum GameplayPolicy
{
    /// <summary>
    /// Expressly allowed for competitive play under the active server policy.
    /// </summary>
    ALLOWED,

    /// <summary>
    /// Expressly prohibited under the active server policy.
    /// </summary>
    PROHIBITED,

    /// <summary>
    /// Permitted only under specific configurations, versions, or server-side restrictions.
    /// </summary>
    RESTRICTED,

    /// <summary>
    /// Ambiguous, unlisted, or modified artifact requiring staff manual review.
    /// </summary>
    NEEDS_REVIEW,

    /// <summary>
    /// The mod was not recognized by the policy registry.
    /// </summary>
    UNKNOWN
}
