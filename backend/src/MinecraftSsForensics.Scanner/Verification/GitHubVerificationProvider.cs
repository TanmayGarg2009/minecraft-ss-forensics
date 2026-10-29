using System.Text.Json;

namespace MinecraftSsForensics.Scanner.Verification;

public class GitHubVerificationProvider
{
    private readonly HttpClient _httpClient;

    // Curated directory of official popular open-source Minecraft mod GitHub repositories
    private static readonly Dictionary<string, string> KnownModRepositories = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sodium"] = "CaffeineMC/sodium-fabric",
        ["lithium"] = "CaffeineMC/lithium-fabric",
        ["phosphor"] = "CaffeineMC/phosphor-fabric",
        ["iris"] = "IrisShaders/Iris",
        ["fabric-api"] = "FabricMC/fabric",
        ["viaversion"] = "ViaVersion/ViaVersion",
        ["viaspoof"] = "ViaVersion/ViaSpoof",
        ["replaymod"] = "ReplayMod/ReplayMod",
        ["optifine"] = "sp614x/optifine",
        ["baritone"] = "cabaletta/baritone"
    };

    public GitHubVerificationProvider(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        if (!_httpClient.DefaultRequestHeaders.Contains("User-Agent"))
        {
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "MinecraftSsForensics/1.0.0");
        }
    }

    public async Task<ModVerificationResult?> VerifyKnownRepositoryAsync(DiscoveredMod mod, CancellationToken ct = default)
    {
        string? modId = mod.Metadata.ModId?.ToLowerInvariant();
        if (string.IsNullOrEmpty(modId) || !KnownModRepositories.TryGetValue(modId, out var repoPath))
        {
            return null;
        }

        try
        {
            string url = $"https://api.github.com/repos/{repoPath}/releases?per_page=10";
            using var response = await _httpClient.GetAsync(url, ct);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            var root = doc.RootElement;

            if (root.ValueKind != JsonValueKind.Array) return null;

            foreach (var release in root.EnumerateArray())
            {
                string? tagName = release.TryGetProperty("tag_name", out var tProp) ? tProp.GetString() : null;
                string? releaseName = release.TryGetProperty("name", out var nProp) ? nProp.GetString() : null;
                string? htmlUrl = release.TryGetProperty("html_url", out var uProp) ? uProp.GetString() : null;
                string? body = release.TryGetProperty("body", out var bProp) ? bProp.GetString() : null;

                // Check release body for published SHA-256 hash
                if (!string.IsNullOrEmpty(body) && !string.IsNullOrEmpty(mod.Hashes.Sha256) &&
                    body.Contains(mod.Hashes.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    return new ModVerificationResult
                    {
                        State = ModVerificationState.VERIFIED_EXACT_RELEASE,
                        Provider = "GitHub",
                        ProjectId = repoPath,
                        ProjectName = releaseName ?? tagName,
                        VersionNumber = tagName,
                        ProjectUrl = htmlUrl,
                        ExpectedHash = mod.Hashes.Sha256,
                        Explanation = $"Exact SHA-256 digest verified against published release notes in official GitHub repository {repoPath} ({tagName}).",
                        Limitations = "Hash matched release notes text in authoritative repository. Binary not independently recompiled from source."
                    };
                }

                // Check release assets
                if (release.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
                {
                    foreach (var asset in assets.EnumerateArray())
                    {
                        string? assetName = asset.TryGetProperty("name", out var an) ? an.GetString() : null;
                        long? assetSize = asset.TryGetProperty("size", out var asz) ? asz.GetInt64() : null;

                        // Check if filename matches and size matches exactly
                        if (string.Equals(mod.FileName, assetName, StringComparison.OrdinalIgnoreCase))
                        {
                            if (assetSize.HasValue && assetSize.Value == mod.FileSizeBytes)
                            {
                                return new ModVerificationResult
                                {
                                    State = ModVerificationState.KNOWN_PROJECT_UNVERIFIED_ARTIFACT,
                                    Provider = "GitHub",
                                    ProjectId = repoPath,
                                    ProjectName = releaseName ?? tagName,
                                    VersionNumber = tagName,
                                    ProjectUrl = htmlUrl,
                                    MatchedFileName = assetName,
                                    ExpectedSizeBytes = assetSize,
                                    Explanation = $"Filename '{assetName}' and byte length ({assetSize}B) match official release on {repoPath}, but published checksum was not present in API metadata to confirm byte-for-byte identity.",
                                    Limitations = "Size and name match only. Does not constitute cryptographic hash verification without published digest."
                                };
                            }
                            else if (assetSize.HasValue && assetSize.Value != mod.FileSizeBytes)
                            {
                                return new ModVerificationResult
                                {
                                    State = ModVerificationState.KNOWN_ARTIFACT_HASH_MISMATCH,
                                    Provider = "GitHub",
                                    ProjectId = repoPath,
                                    ProjectName = releaseName ?? tagName,
                                    VersionNumber = tagName,
                                    ProjectUrl = htmlUrl,
                                    MatchedFileName = assetName,
                                    ExpectedSizeBytes = assetSize,
                                    Explanation = $"Filename matches official release '{assetName}' on {repoPath}, but local file size differs (Local: {mod.FileSizeBytes}B, Official: {assetSize}B).",
                                    Limitations = "File size mismatch indicates file modification, repackaging, or rebuild."
                                };
                            }
                        }
                    }
                }
            }

            return null;
        }
        catch (Exception ex)
        {
            return new ModVerificationResult
            {
                State = ModVerificationState.VERIFICATION_UNAVAILABLE,
                Provider = "GitHub",
                Explanation = $"Failed to check GitHub releases: {ex.Message}",
                Limitations = "Cannot verify GitHub metadata while offline or rate limited."
            };
        }
    }
}
