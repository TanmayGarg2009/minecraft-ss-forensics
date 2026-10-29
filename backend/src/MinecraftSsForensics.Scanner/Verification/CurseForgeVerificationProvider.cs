using System.Net.Http.Json;
using System.Text.Json;

namespace MinecraftSsForensics.Scanner.Verification;

public class CurseForgeVerificationProvider
{
    private readonly HttpClient _httpClient;
    private readonly string? _apiKey;
    private const string BaseUrl = "https://api.curseforge.com/v1";

    public CurseForgeVerificationProvider(HttpClient? httpClient = null, string? apiKey = null)
    {
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        _apiKey = apiKey ?? Environment.GetEnvironmentVariable("CURSEFORGE_API_KEY");

        if (!_httpClient.DefaultRequestHeaders.Contains("User-Agent"))
        {
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "MinecraftSsForensics/1.0.0");
        }

        if (!string.IsNullOrEmpty(_apiKey) && !_httpClient.DefaultRequestHeaders.Contains("x-api-key"))
        {
            _httpClient.DefaultRequestHeaders.Add("x-api-key", _apiKey);
        }
    }

    public async Task<ModVerificationResult?> VerifyByFingerprintAsync(DiscoveredMod mod, CancellationToken ct = default)
    {
        if (mod.Hashes.Murmur2 == 0)
            return null;

        // If no API key is available, CurseForge API cannot be directly queried without credentials
        if (string.IsNullOrEmpty(_apiKey))
        {
            return new ModVerificationResult
            {
                State = ModVerificationState.VERIFICATION_UNAVAILABLE,
                Provider = "CurseForge",
                Explanation = "CurseForge fingerprint computed locally, but CurseForge API key is not configured.",
                Limitations = "Set CURSEFORGE_API_KEY in scanner options to enable live CurseForge catalog lookups."
            };
        }

        try
        {
            var requestBody = new { fingerprints = new[] { mod.Hashes.Murmur2 } };
            using var response = await _httpClient.PostAsJsonAsync($"{BaseUrl}/mods/fingerprints", requestBody, ct);

            if (!response.IsSuccessStatusCode)
            {
                return new ModVerificationResult
                {
                    State = ModVerificationState.VERIFICATION_UNAVAILABLE,
                    Provider = "CurseForge",
                    Explanation = $"CurseForge API responded with HTTP {(int)response.StatusCode}",
                    Limitations = "API rate limit or invalid authentication credentials."
                };
            }

            using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            var root = doc.RootElement;

            if (root.TryGetProperty("data", out var data) &&
                data.TryGetProperty("exactMatches", out var exactMatches) &&
                exactMatches.ValueKind == JsonValueKind.Array &&
                exactMatches.GetArrayLength() > 0)
            {
                var match = exactMatches[0];
                int projectId = match.TryGetProperty("id", out var idProp) ? idProp.GetInt32() : 0;
                var file = match.TryGetProperty("file", out var fProp) ? fProp : default;

                string? fileName = file.ValueKind == JsonValueKind.Object && file.TryGetProperty("fileName", out var fn) ? fn.GetString() : null;
                long? fileLength = file.ValueKind == JsonValueKind.Object && file.TryGetProperty("fileLength", out var fl) ? fl.GetInt64() : null;

                bool filenameMatches = string.Equals(mod.FileName, fileName, StringComparison.OrdinalIgnoreCase);

                return new ModVerificationResult
                {
                    State = ModVerificationState.VERIFIED_EXACT_RELEASE,
                    Provider = "CurseForge",
                    ProjectId = projectId.ToString(),
                    MatchedFileName = fileName,
                    ExpectedSizeBytes = fileLength ?? mod.FileSizeBytes,
                    ProjectUrl = $"https://www.curseforge.com/minecraft/mc-mods/{projectId}",
                    Explanation = filenameMatches
                        ? $"Exact normalized Murmur2 fingerprint match verified against CurseForge project {projectId}."
                        : $"Exact Murmur2 fingerprint matched CurseForge project {projectId}, but local file was renamed: '{mod.FileName}' (Official: '{fileName}').",
                    Limitations = "Verified against published CurseForge artifact release fingerprint."
                };
            }

            // No exact fingerprint match found on CurseForge
            return null;
        }
        catch (HttpRequestException ex)
        {
            return new ModVerificationResult
            {
                State = ModVerificationState.VERIFICATION_UNAVAILABLE,
                Provider = "CurseForge",
                Explanation = $"Network failure connecting to CurseForge: {ex.Message}",
                Limitations = "Cannot verify against CurseForge while network is unavailable."
            };
        }
        catch (Exception ex)
        {
            return new ModVerificationResult
            {
                State = ModVerificationState.VERIFICATION_UNAVAILABLE,
                Provider = "CurseForge",
                Explanation = $"CurseForge error: {ex.Message}",
                Limitations = "Fingerprint lookup failed."
            };
        }
    }
}
