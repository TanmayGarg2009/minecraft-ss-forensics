using MinecraftSsForensics.Scanner.Verification;

namespace MinecraftSsForensics.Scanner.Lookalike;

public class LookalikeFinding
{
    public string RuleId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Severity { get; set; } = "Medium";
    public string Confidence { get; set; } = "High";
    public string Explanation { get; set; } = string.Empty;
    public string ObservedValue { get; set; } = string.Empty;
    public string ExpectedValue { get; set; } = string.Empty;
    public string EvidenceSource { get; set; } = "ModFolder";
    public string FilePath { get; set; } = string.Empty;
    public string? FileSha256 { get; set; }
    public string Limitations { get; set; } = string.Empty;
}

public class LookalikeDetector
{
    private static readonly Dictionary<string, string> PopularModNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sodium"] = "Sodium",
        ["lithium"] = "Lithium",
        ["phosphor"] = "Phosphor",
        ["optifine"] = "OptiFine",
        ["iris"] = "Iris Shaders",
        ["replaymod"] = "ReplayMod",
        ["essential"] = "Essential",
        ["appleskin"] = "AppleSkin",
        ["cloth-config"] = "Cloth Config",
        ["modmenu"] = "Mod Menu"
    };

    public List<LookalikeFinding> AnalyzeMods(IReadOnlyList<(DiscoveredMod Mod, ModVerificationResult Verification)> modsWithVerification)
    {
        var findings = new List<LookalikeFinding>();

        // 1. Check duplicate Mod IDs across different files
        var modsById = new Dictionary<string, List<(DiscoveredMod Mod, ModVerificationResult Verification)>>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in modsWithVerification)
        {
            var mod = item.Mod;
            var ver = item.Verification;

            string? modId = mod.Metadata.ModId;
            if (!string.IsNullOrEmpty(modId))
            {
                if (!modsById.TryGetValue(modId, out var list))
                {
                    list = new List<(DiscoveredMod, ModVerificationResult)>();
                    modsById[modId] = list;
                }
                list.Add(item);
            }

            // 2. Check for Lookalike / Disguised Popular Mod Names
            string filenameLower = mod.FileName.ToLowerInvariant();
            foreach (var (popularKey, popularName) in PopularModNames)
            {
                if (filenameLower.Contains(popularKey, StringComparison.OrdinalIgnoreCase))
                {
                    // Filename claims popular mod name
                    if (!string.IsNullOrEmpty(modId) &&
                        !modId.Contains(popularKey, StringComparison.OrdinalIgnoreCase) &&
                        ver.State != ModVerificationState.VERIFIED_EXACT_RELEASE)
                    {
                        findings.Add(new LookalikeFinding
                        {
                            RuleId = "MOD-LOOKALIKE-DISGUISE",
                            Title = $"Potential Disguised Lookalike: Claims '{popularName}' in Filename",
                            Severity = "High",
                            Confidence = "High",
                            Explanation = $"The file '{mod.FileName}' suggests it is '{popularName}' by filename, but internal metadata declares mod ID '{modId}'. It does not match the official {popularName} hash.",
                            ObservedValue = $"Filename='{mod.FileName}', Declared ModId='{modId}', Hash={mod.Hashes.Sha256}",
                            ExpectedValue = $"Official {popularName} mod ID and verified release digest.",
                            FilePath = mod.FilePath,
                            FileSha256 = mod.Hashes.Sha256,
                            Limitations = "User may have renamed a different mod or bundled an unofficial fork. Does not prove malicious cheat functionality on its own."
                        });
                    }
                    else if (ver.State == ModVerificationState.KNOWN_ARTIFACT_HASH_MISMATCH)
                    {
                        findings.Add(new LookalikeFinding
                        {
                            RuleId = "MOD-HASH-MISMATCH",
                            Title = $"Hash Mismatch on Claimed '{popularName}' Release",
                            Severity = "Medium",
                            Confidence = "Certain",
                            Explanation = $"File '{mod.FileName}' matches the release version of '{popularName}', but the cryptographic digest differs from the official publisher artifact.",
                            ObservedValue = $"Local SHA-256: {mod.Hashes.Sha256}",
                            ExpectedValue = $"Official {popularName} published digest: {ver.ExpectedHash ?? "Catalog Hash"}",
                            FilePath = mod.FilePath,
                            FileSha256 = mod.Hashes.Sha256,
                            Limitations = "May indicate a custom local compile, repackaged dependencies, or modified bytecode. Requires decompilation to determine intent."
                        });
                    }
                }
            }

            // 3. Renamed verified mod (Good indicator to note transparently)
            if (ver.State == ModVerificationState.VERIFIED_EXACT_RELEASE &&
                !string.IsNullOrEmpty(ver.MatchedFileName) &&
                !string.Equals(mod.FileName, ver.MatchedFileName, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new LookalikeFinding
                {
                    RuleId = "MOD-RENAMED-GENUINE",
                    Title = $"Genuine Verified Mod Renamed: '{mod.FileName}'",
                    Severity = "Low",
                    Confidence = "Certain",
                    Explanation = $"Cryptographic hash matches official verified release for {ver.ProjectName ?? ver.ProjectId}, but the file was renamed from official '{ver.MatchedFileName}' to '{mod.FileName}'.",
                    ObservedValue = $"Local Name: '{mod.FileName}'",
                    ExpectedValue = $"Published Name: '{ver.MatchedFileName}'",
                    FilePath = mod.FilePath,
                    FileSha256 = mod.Hashes.Sha256,
                    Limitations = "Renaming a mod is common practice among players and modpack creators and does not indicate foul play."
                });
            }

            // 4. Check for suspicious Java Agent entrypoints in mod folder
            if (mod.Metadata.HasSuspiciousEntrypoints)
            {
                findings.Add(new LookalikeFinding
                {
                    RuleId = "MOD-JAVA-AGENT-ENTRYPOINT",
                    Title = $"Java Agent Instrumentation Defined in Mod Archive: '{mod.FileName}'",
                    Severity = "High",
                    Confidence = "Certain",
                    Explanation = $"JAR manifest specifies 'Premain-Class' or 'Agent-Class'. Java Agents can manipulate class bytecode dynamically at runtime.",
                    ObservedValue = string.Join("; ", mod.Metadata.SuspiciousNotes),
                    ExpectedValue = "Standard mod entrypoints (e.g. ModInitializer, @Mod).",
                    FilePath = mod.FilePath,
                    FileSha256 = mod.Hashes.Sha256,
                    Limitations = "Some developer tools, profilers, and special optimization tools utilize Java Agents legitimately."
                });
            }
        }

        // Check duplicate mod IDs
        foreach (var (modId, list) in modsById)
        {
            if (list.Count > 1)
            {
                var names = list.Select(x => x.Mod.FileName).ToList();
                var first = list[0].Mod;

                findings.Add(new LookalikeFinding
                {
                    RuleId = "MOD-DUPLICATE-ID",
                    Title = $"Duplicate Mod ID Conflict: '{modId}' across multiple JARs",
                    Severity = "Medium",
                    Confidence = "High",
                    Explanation = $"Multiple files share the same declared mod ID '{modId}': {string.Join(", ", names)}. This can cause loader crashes or intentional class shadowing.",
                    ObservedValue = $"Files: {string.Join(", ", names)}",
                    ExpectedValue = "Unique mod IDs per installed archive.",
                    FilePath = first.FilePath,
                    FileSha256 = first.Hashes.Sha256,
                    Limitations = "Player may have forgotten an older version in the directory when updating."
                });
            }
        }

        return findings;
    }
}
