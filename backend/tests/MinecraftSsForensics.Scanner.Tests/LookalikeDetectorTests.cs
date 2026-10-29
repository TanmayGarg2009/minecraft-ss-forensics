using MinecraftSsForensics.Scanner.Archive;
using MinecraftSsForensics.Scanner.Hashing;
using MinecraftSsForensics.Scanner.Lookalike;
using MinecraftSsForensics.Scanner.Verification;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class LookalikeDetectorTests
{
    private readonly LookalikeDetector _detector = new();

    [Fact]
    public void AnalyzeMods_DetectsLookalikeDisguise_WhenFilenameClaimsPopularMod()
    {
        var mod = new DiscoveredMod
        {
            FileName = "Sodium-1.20.4-fabric.jar",
            FilePath = "C:\\.minecraft\\mods\\Sodium-1.20.4-fabric.jar",
            Hashes = new FileHashResult { Sha256 = "1111111111111111111111111111111111111111111111111111111111111111" },
            Metadata = new ModMetadata
            {
                ParseSuccess = true,
                ModId = "baritone",
                ModName = "Baritone",
                Version = "1.10.1"
            }
        };

        var ver = new ModVerificationResult
        {
            State = ModVerificationState.UNKNOWN_OR_UNLISTED
        };

        var findings = _detector.AnalyzeMods(new[] { (mod, ver) });

        Assert.Contains(findings, f => f.RuleId == "MOD-LOOKALIKE-DISGUISE");
        var finding = findings.First(f => f.RuleId == "MOD-LOOKALIKE-DISGUISE");
        Assert.Equal("High", finding.Severity);
        Assert.Contains("Sodium", finding.Explanation);
        Assert.Contains("baritone", finding.Explanation);
    }

    [Fact]
    public void AnalyzeMods_DetectsHashMismatch_OnClaimedRelease()
    {
        var mod = new DiscoveredMod
        {
            FileName = "Sodium-0.5.8.jar",
            FilePath = "C:\\.minecraft\\mods\\Sodium-0.5.8.jar",
            Hashes = new FileHashResult { Sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
            Metadata = new ModMetadata
            {
                ParseSuccess = true,
                ModId = "sodium",
                ModName = "Sodium"
            }
        };

        var ver = new ModVerificationResult
        {
            State = ModVerificationState.KNOWN_ARTIFACT_HASH_MISMATCH,
            ExpectedHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ProjectName = "Sodium"
        };

        var findings = _detector.AnalyzeMods(new[] { (mod, ver) });

        Assert.Contains(findings, f => f.RuleId == "MOD-HASH-MISMATCH");
    }

    [Fact]
    public void AnalyzeMods_DetectsDuplicateModIdsAcrossDifferentFiles()
    {
        var mod1 = new DiscoveredMod
        {
            FileName = "Sodium-0.5.1.jar",
            FilePath = "C:\\.minecraft\\mods\\Sodium-0.5.1.jar",
            Hashes = new FileHashResult { Sha256 = "1111" },
            Metadata = new ModMetadata { ParseSuccess = true, ModId = "sodium" }
        };
        var mod2 = new DiscoveredMod
        {
            FileName = "Sodium-0.5.8.jar",
            FilePath = "C:\\.minecraft\\mods\\Sodium-0.5.8.jar",
            Hashes = new FileHashResult { Sha256 = "2222" },
            Metadata = new ModMetadata { ParseSuccess = true, ModId = "sodium" }
        };

        var findings = _detector.AnalyzeMods(new[]
        {
            (mod1, new ModVerificationResult { State = ModVerificationState.VERIFIED_EXACT_RELEASE }),
            (mod2, new ModVerificationResult { State = ModVerificationState.VERIFIED_EXACT_RELEASE })
        });

        Assert.Contains(findings, f => f.RuleId == "MOD-DUPLICATE-ID");
    }

    [Fact]
    public void AnalyzeMods_FlagsRenamedGenuineModTransparently()
    {
        var mod = new DiscoveredMod
        {
            FileName = "my_custom_sodium_name.jar",
            FilePath = "C:\\.minecraft\\mods\\my_custom_sodium_name.jar",
            Hashes = new FileHashResult { Sha256 = "9999" },
            Metadata = new ModMetadata { ParseSuccess = true, ModId = "sodium" }
        };

        var ver = new ModVerificationResult
        {
            State = ModVerificationState.VERIFIED_EXACT_RELEASE,
            MatchedFileName = "sodium-fabric-0.5.8+mc1.20.4.jar",
            ProjectName = "Sodium"
        };

        var findings = _detector.AnalyzeMods(new[] { (mod, ver) });

        Assert.Contains(findings, f => f.RuleId == "MOD-RENAMED-GENUINE");
        var finding = findings.First(f => f.RuleId == "MOD-RENAMED-GENUINE");
        Assert.Equal("Low", finding.Severity);
    }
}
