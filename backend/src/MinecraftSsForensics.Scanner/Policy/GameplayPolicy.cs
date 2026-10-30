namespace MinecraftSsForensics.Scanner.Policy;

/// <summary>
/// Independent classification of a mod or software's permissibility under specific server rules and gamemodes.
/// Note: This is separate from whether the file is an authentic official release or whether execution was proven.
/// </summary>
public enum GameplayPolicy
{
    /// <summary>
    /// Expressly allowed for competitive play under the active server policy.
    /// </summary>
    ALLOWED,

    /// <summary>
    /// Prohibited solely on possession or installation: confirmed presence in game folder or system
    /// is sufficient for a policy violation regardless of whether execution or gameplay use is proven.
    /// </summary>
    PROHIBITED_POSSESSION,

    /// <summary>
    /// Prohibited on execution: execution is prohibited, whether or not gameplay use or advantage is established.
    /// </summary>
    PROHIBITED_EXECUTION,

    /// <summary>
    /// Prohibited on gameplay use: evidence of prohibited functionality or feature advantage actually being used in-game.
    /// </summary>
    PROHIBITED_GAMEPLAY_USE,

    /// <summary>
    /// Generic / legacy prohibited policy state.
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

public static class GameplayPolicyExtensions
{
    /// <summary>
    /// Returns true if the policy represents any form of prohibition.
    /// </summary>
    public static bool IsProhibited(this GameplayPolicy policy)
    {
        return policy == GameplayPolicy.PROHIBITED ||
               policy == GameplayPolicy.PROHIBITED_POSSESSION ||
               policy == GameplayPolicy.PROHIBITED_EXECUTION ||
               policy == GameplayPolicy.PROHIBITED_GAMEPLAY_USE;
    }
}
