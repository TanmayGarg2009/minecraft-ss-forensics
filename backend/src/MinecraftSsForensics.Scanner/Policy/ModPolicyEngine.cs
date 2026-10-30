using MinecraftSsForensics.Scanner.Archive;
using MinecraftSsForensics.Scanner.Verification;

namespace MinecraftSsForensics.Scanner.Policy;

/// <summary>
/// Evaluates discovered mods against an active server gamemode policy.
/// Strictly enforces the architectural separation between artifact authenticity and gameplay policy.
/// Employs multi-signal matching (Hash > ProjectId > ModId > Alias) and conflict detection.
/// </summary>
public class ModPolicyEngine
{
    private readonly ModPolicyRegistry _registry;

    public ModPolicyEngine(ModPolicyRegistry? registry = null)
    {
        _registry = registry ?? new ModPolicyRegistry();
    }

    public ModPolicyRegistry Registry => _registry;

    /// <summary>
    /// Evaluates a single discovered mod against the specified policy.
    /// </summary>
    public ModPolicyEvaluationResult EvaluateMod(
        DiscoveredMod mod,
        ModVerificationResult verification,
        ServerGamemodePolicy policy)
    {
        var result = new ModPolicyEvaluationResult
        {
            ModFileName = mod.FileName,
            ModName = !string.IsNullOrWhiteSpace(mod.Metadata.ModName)
                ? mod.Metadata.ModName
                : (!string.IsNullOrWhiteSpace(verification.ProjectName) ? verification.ProjectName : mod.FileName),
            AuthenticityState = verification.State,
            AppliedPolicyName = policy.PolicyName,
            AppliedGamemode = policy.Gamemode,
            PolicyVersion = policy.PolicyVersion,
            SourceReference = policy.ServerRulesUrl
        };

        string sha256 = mod.Hashes?.Sha256?.Trim() ?? string.Empty;
        string? projectId = verification.ProjectId?.Trim();
        string? modId = mod.Metadata?.ModId?.Trim();
        string fileName = mod.FileName.ToLowerInvariant();

        // 1. Multi-signal matching in order of cryptographic / declarative strength:
        // Priority 1: Exact SHA-256 hash match against policy rules
        ModPolicyRule? matchedRule = null;
        string matchSignal = "None";

        if (!string.IsNullOrEmpty(sha256))
        {
            matchedRule = policy.Rules.FirstOrDefault(r =>
                r.Sha256Hashes.Any(h => h.Equals(sha256, StringComparison.OrdinalIgnoreCase)));
            if (matchedRule != null) matchSignal = "ExactSha256";
        }

        // Priority 2: Verified Project ID (from Modrinth / CurseForge / GitHub)
        if (matchedRule == null && !string.IsNullOrEmpty(projectId))
        {
            matchedRule = policy.Rules.FirstOrDefault(r =>
                r.ProjectIds.Any(p => p.Equals(projectId, StringComparison.OrdinalIgnoreCase)));
            if (matchedRule != null) matchSignal = "VerifiedProjectId";
        }

        // Priority 3: Embedded Mod ID (from fabric.mod.json / mods.toml)
        if (matchedRule == null && !string.IsNullOrEmpty(modId))
        {
            matchedRule = policy.Rules.FirstOrDefault(r =>
                r.ModIds.Any(m => m.Equals(modId, StringComparison.OrdinalIgnoreCase)));
            if (matchedRule != null) matchSignal = "EmbeddedModId";
        }

        // Priority 4: Aliases / Filename hint (lowest priority signal)
        if (matchedRule == null)
        {
            matchedRule = policy.Rules.FirstOrDefault(r =>
                r.Aliases.Any(a => !string.IsNullOrWhiteSpace(a) && fileName.Contains(a.ToLowerInvariant())));
            if (matchedRule != null) matchSignal = "FilenameAlias";
        }

        // 2. Conflict Detection across independent signals
        CheckForConflictingSignals(mod, verification, matchedRule, matchSignal, policy, result);

        // 3. Apply Matched Rule or Fallback
        if (matchedRule != null)
        {
            result.MatchedRuleId = matchedRule.RuleId;
            result.ModName = matchedRule.ModName;
            result.Behavior = matchedRule.Behavior;
            result.RestrictionConditions = matchedRule.RestrictionConditions;
            if (!string.IsNullOrEmpty(matchedRule.SourceReference))
            {
                result.SourceReference = matchedRule.SourceReference;
            }

            // Confidence assessment based on signal strength
            result.Confidence = matchSignal switch
            {
                "ExactSha256" => "Certain",
                "VerifiedProjectId" => "High",
                "EmbeddedModId" => "High",
                "FilenameAlias" => "Low",
                _ => "Medium"
            };

            // Version-specific restrictions check
            string version = mod.Metadata?.Version ?? verification.VersionNumber ?? string.Empty;
            if (!string.IsNullOrEmpty(version) && matchedRule.ProhibitedVersions.Contains(version, StringComparer.OrdinalIgnoreCase))
            {
                result.Policy = GameplayPolicy.PROHIBITED;
                result.Reason = $"Version {version} of '{matchedRule.ModName}' is explicitly prohibited under {policy.Gamemode} rules.";
                result.Explanation = $"{matchedRule.PolicyReason} (Prohibited version: {version})";
                return result;
            }

            // Special Case: Mod declares an ALLOWED identity, but its hash does NOT match the official release
            if (matchedRule.Policy == GameplayPolicy.ALLOWED &&
                verification.State == ModVerificationState.KNOWN_ARTIFACT_HASH_MISMATCH)
            {
                result.Policy = GameplayPolicy.NEEDS_REVIEW;
                result.Confidence = "Medium";
                result.Reason = $"Claims identity of allowed mod '{matchedRule.ModName}', but has modified internal contents (hash mismatch).";
                result.Explanation = $"The file identifies as '{matchedRule.ModName}' (ordinarily allowed under {policy.Gamemode}), but does not match the published release hash. Staff review is required to verify whether modifications are benign or unauthorized.";
                result.LimitationsAndUncertainty = "A hash mismatch proves the bytecode differs from official releases, but cannot automatically determine whether the alterations are benign custom optimizations or hidden modifications.";
                return result;
            }

            // Special Case: If conflicting signals were flagged, prioritize review over automatic allowance
            if (result.HasConflictingSignals && matchedRule.Policy == GameplayPolicy.ALLOWED)
            {
                result.Policy = GameplayPolicy.NEEDS_REVIEW;
                result.Reason = $"Conflicting identity signals detected. Staff manual review required.";
                result.Explanation = result.ConflictDetails ?? "Signal discrepancy between file name, internal metadata, and hash.";
                result.LimitationsAndUncertainty = "Conflicting signals suggest possible disguise or repackaging.";
                return result;
            }

            // Standard Policy Assignment from matched rule
            result.Policy = matchedRule.Policy;
            result.Reason = matchedRule.PolicyReason;

            // Strict Transparency & Decoupling Documentation
            if (verification.State == ModVerificationState.VERIFIED_EXACT_RELEASE)
            {
                if (result.Policy == GameplayPolicy.PROHIBITED)
                {
                    result.Explanation = $"Verified as an authentic official release of '{matchedRule.ModName}', but is expressly PROHIBITED under {policy.Gamemode} rules: {matchedRule.PolicyReason}";
                    result.LimitationsAndUncertainty = "The file is an authentic, unmodified official release, but provides prohibited competitive gameplay advantages.";
                }
                else if (result.Policy == GameplayPolicy.RESTRICTED)
                {
                    result.Explanation = $"Verified official release of '{matchedRule.ModName}'. Permitted under {policy.Gamemode} ONLY if restricted conditions are met: {matchedRule.RestrictionConditions}";
                    result.LimitationsAndUncertainty = "Scanner confirms authentic binary, but in-game configuration must be audited by staff to verify restriction compliance.";
                }
                else
                {
                    result.Explanation = $"Verified official release of '{matchedRule.ModName}'. Permitted for competitive play under {policy.Gamemode}.";
                    result.LimitationsAndUncertainty = "Authenticity and policy compliance both verified.";
                }
            }
            else
            {
                result.Explanation = $"{matchedRule.ModName} ({matchedRule.Policy}): {matchedRule.PolicyReason}";
                result.LimitationsAndUncertainty = matchSignal == "FilenameAlias"
                    ? "Matched solely on filename alias. Internal metadata could not verify project identity."
                    : "Authenticity could not be verified against official Modrinth/CurseForge repositories; policy decision based on declared metadata.";
            }
        }
        else
        {
            // 4. Fallback for Unknown / Unrecognized Mods
            result.Policy = policy.DefaultUnknownModPolicy;
            result.Behavior = BehaviorCategory.None;
            result.Confidence = "Low";
            result.Reason = policy.UnknownModPolicyReason;
            result.Explanation = $"The mod '{result.ModName}' was not recognized in the {policy.Gamemode} policy registry. It is unlisted, but NOT automatically a cheat.";
            result.LimitationsAndUncertainty = "Unlisted mods are common in Minecraft (private HUDs, custom utility packs, clan mods). Staff manual inspection of archive contents is required.";

            if (result.HasConflictingSignals)
            {
                result.Policy = GameplayPolicy.NEEDS_REVIEW;
                result.Reason = "Unrecognized mod with conflicting identity signals.";
                result.Explanation += $" Notice: {result.ConflictDetails}";
            }
        }

        return result;
    }

    private static void CheckForConflictingSignals(
        DiscoveredMod mod,
        ModVerificationResult verification,
        ModPolicyRule? matchedRule,
        string matchSignal,
        ServerGamemodePolicy policy,
        ModPolicyEvaluationResult result)
    {
        string fileName = mod.FileName.ToLowerInvariant();
        string? modId = mod.Metadata?.ModId?.ToLowerInvariant();
        string? modName = mod.Metadata?.ModName?.ToLowerInvariant();

        // 1. Filename mimics a popular allowed mod (e.g. sodium, optifine, lithium)
        // but internal mod ID indicates something else (e.g. freecam, baritone, or mismatch)
        string[] popularOptimizationAliases = { "sodium", "lithium", "optifine", "ferritecore", "iris" };
        string? claimedAllowedName = popularOptimizationAliases.FirstOrDefault(alias => fileName.Contains(alias));

        if (!string.IsNullOrEmpty(claimedAllowedName))
        {
            if (!string.IsNullOrEmpty(modId) && !modId.Contains(claimedAllowedName))
            {
                // Filename says sodium, but modId says freecam!
                result.HasConflictingSignals = true;
                result.ConflictDetails = $"Filename contains '{claimedAllowedName}', but internal metadata declares mod ID '{modId}' and name '{modName}'.";
            }
            else if (matchedRule != null && matchedRule.Policy == GameplayPolicy.PROHIBITED && matchSignal != "FilenameAlias")
            {
                // Filename says sodium, but matched rule on hash or ID is PROHIBITED
                result.HasConflictingSignals = true;
                result.ConflictDetails = $"Filename mimics allowed mod '{claimedAllowedName}', but matched prohibited rule '{matchedRule.RuleId}' ({matchedRule.ModName}).";
            }
        }

        // 2. Metadata conflict already flagged by verifier
        if (verification.State == ModVerificationState.METADATA_CONFLICT)
        {
            result.HasConflictingSignals = true;
            result.ConflictDetails = string.IsNullOrEmpty(result.ConflictDetails)
                ? verification.Explanation
                : $"{result.ConflictDetails} | {verification.Explanation}";
        }
    }
}
