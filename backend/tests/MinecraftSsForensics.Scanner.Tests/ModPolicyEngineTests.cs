using MinecraftSsForensics.Scanner.Archive;
using MinecraftSsForensics.Scanner.Hashing;
using MinecraftSsForensics.Scanner.Policy;
using MinecraftSsForensics.Scanner.Verification;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class ModPolicyEngineTests
{
    private readonly ModPolicyEngine _engine;
    private readonly ModPolicyRegistry _registry;

    public ModPolicyEngineTests()
    {
        _registry = new ModPolicyRegistry();
        _engine = new ModPolicyEngine(_registry);
    }

    [Fact]
    public void VerifiedOfficialRelease_WhenProhibitedByPolicy_ClassifiedAsProhibited_DecouplingAuthenticityFromPolicy()
    {
        // Freecam is an authentic official release from Modrinth, but Crystal PvP prohibits perspective detachment
        var crystalPolicy = _registry.GetPolicy("Crystal PvP");

        var mod = new DiscoveredMod
        {
            FileName = "freecam-fabric-0.2.1.jar",
            FilePath = "C:\\Minecraft\\.minecraft\\mods\\freecam-fabric-0.2.1.jar",
            FileSizeBytes = 120_000,
            Hashes = new FileHashResult { Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Success = true },
            Metadata = new ModMetadata { ModId = "freecam", ModName = "Freecam", Version = "0.2.1", Loader = "Fabric" }
        };

        var verification = new ModVerificationResult
        {
            State = ModVerificationState.VERIFIED_EXACT_RELEASE,
            Provider = "Modrinth",
            ProjectId = "freecam",
            ProjectName = "Freecam",
            VersionNumber = "0.2.1",
            ProjectUrl = "https://modrinth.com/mod/freecam",
            Explanation = "Matches official Modrinth release hash."
        };

        var result = _engine.EvaluateMod(mod, verification, crystalPolicy);

        // Core Requirement: Authenticity and Gameplay Policy must be independent!
        Assert.Equal(ModVerificationState.VERIFIED_EXACT_RELEASE, result.AuthenticityState);
        Assert.Equal(GameplayPolicy.PROHIBITED, result.Policy);
        Assert.Equal(BehaviorCategory.HiddenInformationAdvantages, result.Behavior);
        Assert.Contains("PROHIBITED", result.Explanation);
        Assert.Contains("Freecam", result.Explanation);
        Assert.Contains("solid obsidian", result.Reason);
    }

    [Fact]
    public void UnknownOrUnlistedMod_ClassifiedAsNeedsReview_NeverAutomaticallyClassifiedAsCheat()
    {
        var crystalPolicy = _registry.GetPolicy("Crystal PvP");

        var mod = new DiscoveredMod
        {
            FileName = "CustomClanHud-1.0.jar",
            FilePath = "C:\\Minecraft\\.minecraft\\mods\\CustomClanHud-1.0.jar",
            FileSizeBytes = 45_000,
            Hashes = new FileHashResult { Sha256 = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff", Success = true },
            Metadata = new ModMetadata { ModId = "customclanhud", ModName = "Clan HUD", Version = "1.0", Loader = "Fabric" }
        };

        var verification = new ModVerificationResult
        {
            State = ModVerificationState.UNKNOWN_OR_UNLISTED,
            Provider = "None",
            Explanation = "No matching release found on Modrinth or CurseForge."
        };

        var result = _engine.EvaluateMod(mod, verification, crystalPolicy);

        // Core Requirement: Unknown mod is NOT automatically a cheat!
        Assert.Equal(ModVerificationState.UNKNOWN_OR_UNLISTED, result.AuthenticityState);
        Assert.Equal(GameplayPolicy.NEEDS_REVIEW, result.Policy);
        Assert.Contains("NOT automatically a cheat", result.Explanation);
        Assert.Contains("Staff review required", result.Reason);
    }

    [Fact]
    public void AllowedOptimizationMod_WithExactHash_ClassifiedAsAllowed()
    {
        var policy = _registry.GetPolicy("Crystal PvP");

        var mod = new DiscoveredMod
        {
            FileName = "sodium-fabric-0.5.8.jar",
            FilePath = "C:\\Minecraft\\.minecraft\\mods\\sodium-fabric-0.5.8.jar",
            FileSizeBytes = 500_000,
            Hashes = new FileHashResult { Sha256 = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", Success = true },
            Metadata = new ModMetadata { ModId = "sodium", ModName = "Sodium", Version = "0.5.8", Loader = "Fabric" }
        };

        var verification = new ModVerificationResult
        {
            State = ModVerificationState.VERIFIED_EXACT_RELEASE,
            Provider = "Modrinth",
            ProjectId = "sodium",
            ProjectName = "Sodium",
            VersionNumber = "0.5.8"
        };

        var result = _engine.EvaluateMod(mod, verification, policy);

        Assert.Equal(GameplayPolicy.ALLOWED, result.Policy);
        Assert.Equal(BehaviorCategory.ClientOptimization, result.Behavior);
        Assert.False(result.HasConflictingSignals);
        Assert.Equal("High", result.Confidence);
    }

    [Fact]
    public void RenamedMod_MimickingSodium_DetectedAsConflictingSignals_RequiresReview()
    {
        var policy = _registry.GetPolicy("Crystal PvP");

        // The file is named sodium-patch.jar, but its internal manifest declares Freecam!
        var mod = new DiscoveredMod
        {
            FileName = "sodium-patch-0.5.8.jar",
            FilePath = "C:\\Minecraft\\.minecraft\\mods\\sodium-patch-0.5.8.jar",
            FileSizeBytes = 125_000,
            Hashes = new FileHashResult { Sha256 = "9999888877776666555544443333222211110000ffeeddccbbaa998877665544", Success = true },
            Metadata = new ModMetadata { ModId = "freecam", ModName = "Freecam", Version = "0.2.1", Loader = "Fabric" }
        };

        var verification = new ModVerificationResult
        {
            State = ModVerificationState.METADATA_CONFLICT,
            Explanation = "Declared internal mod ID 'freecam' conflicts with filename suggesting sodium."
        };

        var result = _engine.EvaluateMod(mod, verification, policy);

        Assert.True(result.HasConflictingSignals);
        Assert.NotNull(result.ConflictDetails);
        Assert.Equal(GameplayPolicy.PROHIBITED, result.Policy); // Matched prohibited freecam rule
        Assert.Contains("sodium", result.ConflictDetails.ToLowerInvariant());
    }

    [Fact]
    public void GamemodePolicyDifferences_SameModHasDifferentPoliciesAcrossGamemodes()
    {
        var crystalPolicy = _registry.GetPolicy("Crystal PvP");
        var smpPolicy = _registry.GetPolicy("SMP");
        var uhcPolicy = _registry.GetPolicy("UHC");

        var minihudMod = new DiscoveredMod
        {
            FileName = "minihud-fabric-1.20.jar",
            FilePath = "C:\\Minecraft\\mods\\minihud-fabric-1.20.jar",
            FileSizeBytes = 150_000,
            Hashes = new FileHashResult { Sha256 = "minihudhash123", Success = true },
            Metadata = new ModMetadata { ModId = "minihud", ModName = "MiniHUD", Version = "0.30.0", Loader = "Fabric" }
        };

        var freecamMod = new DiscoveredMod
        {
            FileName = "freecam-fabric-1.20.jar",
            FilePath = "C:\\Minecraft\\mods\\freecam-fabric-1.20.jar",
            FileSizeBytes = 120_000,
            Hashes = new FileHashResult { Sha256 = "freecamhash123", Success = true },
            Metadata = new ModMetadata { ModId = "freecam", ModName = "Freecam", Version = "0.2.1", Loader = "Fabric" }
        };

        var ver = new ModVerificationResult { State = ModVerificationState.VERIFIED_EXACT_RELEASE };

        // 1. MiniHUD: Prohibited in Crystal PvP & UHC, but Allowed in SMP
        var crystalMinihud = _engine.EvaluateMod(minihudMod, ver, crystalPolicy);
        var smpMinihud = _engine.EvaluateMod(minihudMod, ver, smpPolicy);
        var uhcMinihud = _engine.EvaluateMod(minihudMod, ver, uhcPolicy);

        Assert.Equal(GameplayPolicy.PROHIBITED, crystalMinihud.Policy);
        Assert.Equal(GameplayPolicy.ALLOWED, smpMinihud.Policy);
        Assert.Equal(GameplayPolicy.PROHIBITED, uhcMinihud.Policy);

        // 2. Freecam: Prohibited in Crystal PvP, but Restricted in SMP
        var crystalFreecam = _engine.EvaluateMod(freecamMod, ver, crystalPolicy);
        var smpFreecam = _engine.EvaluateMod(freecamMod, ver, smpPolicy);

        Assert.Equal(GameplayPolicy.PROHIBITED, crystalFreecam.Policy);
        Assert.Equal(GameplayPolicy.RESTRICTED, smpFreecam.Policy);
        Assert.NotNull(smpFreecam.RestrictionConditions);
    }

    [Fact]
    public void CustomJsonPolicy_WhenValid_LoadsAndRegistersSuccessfully()
    {
        string customPolicyJson = @"
        {
            ""schemaVersion"": ""1.0.0"",
            ""policyId"": ""custom-tournament-v1"",
            ""policyName"": ""Custom Community Tournament 2026"",
            ""gamemode"": ""Community Tournament"",
            ""policyVersion"": ""2.1.0"",
            ""effectiveDate"": ""2026-03-01"",
            ""serverRulesUrl"": ""https://tournament.example.com/rules"",
            ""description"": ""Special ruleset for community invitational."",
            ""defaultUnknownModPolicy"": ""NEEDS_REVIEW"",
            ""rules"": [
                {
                    ""ruleId"": ""RULE-CUSTOM-SODIUM"",
                    ""modName"": ""Sodium"",
                    ""policy"": ""ALLOWED"",
                    ""behavior"": ""ClientOptimization"",
                    ""policyReason"": ""Performance optimization is permitted."",
                    ""projectIds"": [""sodium""],
                    ""modIds"": [""sodium""]
                },
                {
                    ""ruleId"": ""RULE-CUSTOM-FREECAM"",
                    ""modName"": ""Freecam"",
                    ""policy"": ""PROHIBITED"",
                    ""behavior"": ""HiddenInformationAdvantages"",
                    ""policyReason"": ""Camera detachment is banned."",
                    ""projectIds"": [""freecam""],
                    ""modIds"": [""freecam""]
                }
            ]
        }";

        var (policy, success, errors) = _registry.LoadPolicyFromJson(customPolicyJson);

        Assert.True(success);
        Assert.Empty(errors);
        Assert.Equal("Custom Community Tournament 2026", policy.PolicyName);
        Assert.Equal("2.1.0", policy.PolicyVersion);
        Assert.Equal(2, policy.Rules.Count);

        var retrieved = _registry.GetPolicy("Community Tournament");
        Assert.NotNull(retrieved);
        Assert.Equal("custom-tournament-v1", retrieved.PolicyId);
    }

    [Fact]
    public void CustomJsonPolicy_WhenMalformed_GracefullyFallsBackToDefault()
    {
        string malformedJson = "{ invalid json content here !!!";

        var (policy, success, errors) = _registry.LoadPolicyFromJson(malformedJson);

        Assert.False(success);
        Assert.NotEmpty(errors);
        Assert.NotNull(policy);
        Assert.Equal("default", policy.PolicyId);
    }

    [Fact]
    public void AllowedMod_WithHashMismatch_ClassifiedAsNeedsReview_NotAssumedCheat()
    {
        var policy = _registry.GetPolicy("Crystal PvP");

        var mod = new DiscoveredMod
        {
            FileName = "sodium-fabric-0.5.8.jar",
            FilePath = "C:\\Minecraft\\.minecraft\\mods\\sodium-fabric-0.5.8.jar",
            FileSizeBytes = 502_000,
            Hashes = new FileHashResult { Sha256 = "tamperedhash1234567890", Success = true },
            Metadata = new ModMetadata { ModId = "sodium", ModName = "Sodium", Version = "0.5.8", Loader = "Fabric" }
        };

        var verification = new ModVerificationResult
        {
            State = ModVerificationState.KNOWN_ARTIFACT_HASH_MISMATCH,
            Provider = "Modrinth",
            ProjectId = "sodium",
            ProjectName = "Sodium",
            VersionNumber = "0.5.8",
            Explanation = "Declared version 0.5.8 expected hash AABB but got tamperedhash1234567890."
        };

        var result = _engine.EvaluateMod(mod, verification, policy);

        // Core Requirement: A modified allowed mod requires review, but is not automatically declared a cheat
        Assert.Equal(ModVerificationState.KNOWN_ARTIFACT_HASH_MISMATCH, result.AuthenticityState);
        Assert.Equal(GameplayPolicy.NEEDS_REVIEW, result.Policy);
        Assert.Contains("hash mismatch", result.Reason);
        Assert.Contains("benign custom optimizations", result.LimitationsAndUncertainty);
    }

    [Fact]
    public void VersionRestrictedMod_ProhibitedVersion_EnforcesProhibition()
    {
        var policy = new ServerGamemodePolicy
        {
            PolicyId = "custom-version-policy",
            PolicyName = "Version Restricted Policy",
            Gamemode = "Custom",
            PolicyVersion = "1.0.0",
            Rules = new List<ModPolicyRule>
            {
                new()
                {
                    RuleId = "RULE-SODIUM-VERSIONED",
                    ModName = "Sodium",
                    Policy = GameplayPolicy.ALLOWED,
                    Behavior = BehaviorCategory.ClientOptimization,
                    PolicyReason = "Sodium is allowed except for buggy version 0.4.0",
                    ModIds = new() { "sodium" },
                    ProhibitedVersions = new() { "0.4.0" }
                }
            }
        };

        var mod = new DiscoveredMod
        {
            FileName = "sodium-0.4.0.jar",
            Metadata = new ModMetadata { ModId = "sodium", ModName = "Sodium", Version = "0.4.0" },
            Hashes = new FileHashResult { Sha256 = "abc", Success = true }
        };

        var ver = new ModVerificationResult { State = ModVerificationState.VERIFIED_EXACT_RELEASE };

        var result = _engine.EvaluateMod(mod, ver, policy);

        Assert.Equal(GameplayPolicy.PROHIBITED, result.Policy);
        Assert.Contains("0.4.0", result.Reason);
    }
}
