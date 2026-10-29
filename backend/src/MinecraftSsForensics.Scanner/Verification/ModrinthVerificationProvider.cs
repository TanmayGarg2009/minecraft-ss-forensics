using System.Net.Http.Json;
using System.Text.Json;

namespace MinecraftSsForensics.Scanner.Verification;

public class ModrinthVerificationProvider
{
    private readonly HttpClient _httpClient;
    private const string BaseUrl = "https://api.modrinth.com/v2";

    public ModrinthVerificationProvider(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        if (!_httpClient.DefaultRequestHeaders.Contains("User-Agent"))
        {
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "MinecraftSsForensics/1.0.0 (security-forensics-tool)");
        }
    }

    public async Task<ModVerificationResult?> VerifyByHashAsync(DiscoveredMod mod, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(mod.Hashes.Sha512))
            return null;

        try
        {
            string url = $"{BaseUrl}/version_file/{mod.Hashes.Sha512}?algorithm=sha512";
            using var response = await _httpClient.GetAsync(url, ct);

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                // Not found on Modrinth by exact SHA-512
                return null;
            }

            if (!response.IsSuccessStatusCode)
            {
                return new ModVerificationResult
                {
                    State = ModVerificationState.VERIFICATION_UNAVAILABLE,
                    Provider = "Modrinth",
                    Explanation = $"Modrinth API returned HTTP {(int)response.StatusCode}: {response.ReasonPhrase}",
                    Limitations = "External API rate limiting or temporary network outage."
                };
            }

            using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            var root = doc.RootElement;

            string? projectId = root.TryGetProperty("project_id", out var pid) ? pid.GetString() : null;
            string? versionId = root.TryGetProperty("id", out var vid) ? vid.GetString() : null;
            string? versionNumber = root.TryGetProperty("version_number", out var vn) ? vn.GetString() : null;

            List<string> gameVersions = new();
            if (root.TryGetProperty("game_versions", out var gv) && gv.ValueKind == JsonValueKind.Array)
            {
                foreach (var v in gv.EnumerateArray()) gameVersions.Add(v.GetString() ?? "");
            }

            List<string> loaders = new();
            if (root.TryGetProperty("loaders", out var ld) && ld.ValueKind == JsonValueKind.Array)
            {
                foreach (var l in ld.EnumerateArray()) loaders.Add(l.GetString() ?? "");
            }

            // Inspect files array to match this exact file
            string? matchedFileName = null;
            long? expectedSize = null;
            if (root.TryGetProperty("files", out var files) && files.ValueKind == JsonValueKind.Array)
            {
                foreach (var f in files.EnumerateArray())
                {
                    if (f.TryGetProperty("hashes", out var hashes) &&
                        hashes.TryGetProperty("sha512", out var hash512) &&
                        hash512.GetString()?.Equals(mod.Hashes.Sha512, StringComparison.OrdinalIgnoreCase) == true)
                    {
                        matchedFileName = f.TryGetProperty("filename", out var fn) ? fn.GetString() : null;
                        expectedSize = f.TryGetProperty("size", out var sz) ? sz.GetInt64() : null;
                        break;
                    }
                }
            }

            // Check if local filename matches official published filename
            bool filenameMatches = string.Equals(mod.FileName, matchedFileName, StringComparison.OrdinalIgnoreCase);

            string explanation = filenameMatches
                ? $"Exact cryptographic SHA-512 match confirmed against official Modrinth release for project {projectId} (version {versionNumber})."
                : $"Exact SHA-512 match confirmed against Modrinth project {projectId}, but local file is renamed: '{mod.FileName}' (Official: '{matchedFileName}').";

            return new ModVerificationResult
            {
                State = ModVerificationState.VERIFIED_EXACT_RELEASE,
                Provider = "Modrinth",
                ProjectId = projectId,
                VersionId = versionId,
                VersionNumber = versionNumber,
                MatchedFileName = matchedFileName,
                ExpectedHash = mod.Hashes.Sha512,
                ExpectedSizeBytes = expectedSize ?? mod.FileSizeBytes,
                SupportedGameVersions = gameVersions,
                SupportedLoaders = loaders,
                ProjectUrl = projectId != null ? $"https://modrinth.com/mod/{projectId}" : null,
                Explanation = explanation,
                Limitations = "Verified against published Modrinth release artifact. Does not inspect runtime behavior outside the JAR boundaries."
            };
        }
        catch (HttpRequestException ex)
        {
            return new ModVerificationResult
            {
                State = ModVerificationState.VERIFICATION_UNAVAILABLE,
                Provider = "Modrinth",
                Explanation = $"Network failure connecting to Modrinth API: {ex.Message}",
                Limitations = "Cannot verify authenticity while offline or blocked by firewall."
            };
        }
        catch (Exception ex)
        {
            return new ModVerificationResult
            {
                State = ModVerificationState.VERIFICATION_UNAVAILABLE,
                Provider = "Modrinth",
                Explanation = $"Error querying Modrinth: {ex.Message}",
                Limitations = "Verification lookup was not completed."
            };
        }
    }
}
