namespace MinecraftSsForensics.Scanner.Policy;

/// <summary>
/// Describes the gameplay capability or behavioral domain associated with a mod policy rule.
/// </summary>
public enum BehaviorCategory
{
    None,
    ClientOptimization,
    CosmeticOrHud,
    AutomatedCombatActions,
    AimAssistance,
    PlayerOrEntityTracking,
    MovementAdvantages,
    HiddenInformationAdvantages,
    AutomatedInventoryBehavior,
    ProhibitedClientModification
}
