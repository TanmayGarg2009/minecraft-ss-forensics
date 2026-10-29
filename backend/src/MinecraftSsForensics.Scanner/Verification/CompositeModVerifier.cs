namespace MinecraftSsForensics.Scanner.Verification;

public interface IModVerifier
{
    Task<ModVerificationResult> VerifyModAsync(DiscoveredMod mod, CancellationToken ct = default);
}

public class CompositeModVerifier : IModVerifier
{
    private readonly IVerificationCache _cache;
    private readonly ModrinthVerificationProvider _modrinth;
    private readonly CurseForgeVerificationProvider _curseForge;
    private readonly GitHubVerificationProvider _github;

    public CompositeModVerifier(
        IVerificationCache cache,
        ModrinthVerificationProvider modrinth,
        CurseForgeVerificationProvider curseForge,
        GitHubVerificationProvider github)
    {
        _cache = cache;
        _modrinth = modrinth;
        _curseForge = curseForge;
        _github = github;
    }

    public async Task<ModVerificationResult> VerifyModAsync(DiscoveredMod mod, CancellationToken ct = default)
    {
        // 1. Check if archive is invalid/unreadable
        if (!mod.Metadata.ParseSuccess)
        {
            return new ModVerificationResult
            {
                State = ModVerificationState.INVALID_OR_UNREADABLE_ARCHIVE,
                Explanation = $"JAR archive could not be parsed safely: {mod.Metadata.ParseError}",
                Limitations = "Corrupted archive, zip bomb guard triggered, or non-zip format."
            };
        }

        // 2. Check local verification cache by SHA-256
        if (!string.IsNullOrEmpty(mod.Hashes.Sha256) && _cache.TryGet(mod.Hashes.Sha256, out var cachedResult))
        {
            return cachedResult;
        }

        // 3. Try Modrinth verification (by SHA-512)
        try
        {
            var modrinthResult = await _modrinth.VerifyByHashAsync(mod, ct);
            if (modrinthResult != null && modrinthResult.State != ModVerificationState.VERIFICATION_UNAVAILABLE)
            {
                _cache.Set(mod.Hashes.Sha256, modrinthResult);
                return modrinthResult;
            }
        }
        catch { /* Fall through to next provider */ }

        // 4. Try CurseForge verification (by Murmur2 fingerprint)
        try
        {
            var curseResult = await _curseForge.VerifyByFingerprintAsync(mod, ct);
            if (curseResult != null && curseResult.State != ModVerificationState.VERIFICATION_UNAVAILABLE)
            {
                _cache.Set(mod.Hashes.Sha256, curseResult);
                return curseResult;
            }
        }
        catch { /* Fall through to next provider */ }

        // 5. Try GitHub verification
        try
        {
            var githubResult = await _github.VerifyKnownRepositoryAsync(mod, ct);
            if (githubResult != null && githubResult.State != ModVerificationState.VERIFICATION_UNAVAILABLE)
            {
                _cache.Set(mod.Hashes.Sha256, githubResult);
                return githubResult;
            }
        }
        catch { /* Fall through */ }

        // 6. Check for internal metadata conflicts (e.g. filename claims one thing, embedded ID claims another)
        string fileNameWithoutExt = Path.GetFileNameWithoutExtension(mod.FileName).ToLowerInvariant();
        string? embeddedModId = mod.Metadata.ModId?.ToLowerInvariant();

        if (!string.IsNullOrEmpty(embeddedModId) &&
            !fileNameWithoutExt.Contains(embeddedModId, StringComparison.OrdinalIgnoreCase) &&
            !embeddedModId.Contains(fileNameWithoutExt, StringComparison.OrdinalIgnoreCase))
        {
            // E.g. Filename says "optifine.jar" but mod ID is "autoclicker" or "fastcraft"
            var conflictResult = new ModVerificationResult
            {
                State = ModVerificationState.METADATA_CONFLICT,
                Explanation = $"Discrepancy detected between filename '{mod.FileName}' and declared internal mod ID '{mod.Metadata.ModId}'.",
                Limitations = "Renamed mod or lookalike disguise. Does not prove malicious intent without corroborating signatures."
            };
            _cache.Set(mod.Hashes.Sha256, conflictResult);
            return conflictResult;
        }

        // 7. Unknown or unlisted mod (Legitimate private, self-built, or unindexed mod)
        var unknownResult = new ModVerificationResult
        {
            State = ModVerificationState.UNKNOWN_OR_UNLISTED,
            Explanation = "No cryptographic digest match found on Modrinth, CurseForge, or official GitHub releases. The mod may be custom, private, self-compiled, or distributed outside major platforms.",
            Limitations = "Unknown status is not proof of cheating or malicious code. Manual review or decompilation recommended if suspicion exists."
        };
        _cache.Set(mod.Hashes.Sha256, unknownResult);
        return unknownResult;
    }
}
