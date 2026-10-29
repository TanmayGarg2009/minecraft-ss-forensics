using System.Net.Http.Json;
using System.Text.Json;
using MinecraftSsForensics.Api.Models.Dtos.Ingestion;

namespace MinecraftSsForensics.Scanner.Client;

public class DeleteReportResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
}

public interface IBackendApiClient
{
    Task<SubmitReportResponse> SubmitReportAsync(SubmitReportRequest report, CancellationToken ct = default);
    Task<DeleteReportResponse> DeleteReportAsync(string publicId, string deletionKey, CancellationToken ct = default);
}

public class BackendApiClient : IBackendApiClient
{
    private readonly HttpClient _httpClient;
    private readonly string _baseUrl;
    private const long MaxPayloadBytes = 15 * 1024 * 1024; // 15 MB

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public BackendApiClient(string? baseUrl = null, HttpClient? httpClient = null)
    {
        _baseUrl = (baseUrl ?? "http://localhost:5000").TrimEnd('/');
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

        if (!_httpClient.DefaultRequestHeaders.Contains("User-Agent"))
        {
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "MinecraftSsScanner/1.0.0 (Windows NT 10.0; Win64; x64)");
        }
    }

    public async Task<SubmitReportResponse> SubmitReportAsync(SubmitReportRequest report, CancellationToken ct = default)
    {
        // 1. Validate payload locally
        byte[] payloadBytes = JsonSerializer.SerializeToUtf8Bytes(report, JsonOptions);
        if (payloadBytes.Length > MaxPayloadBytes)
        {
            throw new InvalidOperationException($"Report payload exceeds 15 MB limit ({payloadBytes.Length / (1024 * 1024)} MB).");
        }

        // 2. Submit to POST /api/v1/reports
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl}/api/v1/reports")
        {
            Content = new ByteArrayContent(payloadBytes)
        };
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json")
        {
            CharSet = "utf-8"
        };

        using var response = await _httpClient.SendAsync(request, ct);

        string responseContent = await response.Content.ReadAsStringAsync(ct);

        if (!response.IsSuccessStatusCode)
        {
            try
            {
                using var errDoc = JsonDocument.Parse(responseContent);
                if (errDoc.RootElement.TryGetProperty("message", out var msgProp))
                {
                    throw new HttpRequestException($"API Error ({(int)response.StatusCode}): {msgProp.GetString()}");
                }
            }
            catch (JsonException) { }

            throw new HttpRequestException($"Server responded with HTTP {(int)response.StatusCode}: {responseContent}");
        }

        var result = JsonSerializer.Deserialize<SubmitReportResponse>(responseContent, JsonOptions);
        if (result == null)
        {
            throw new InvalidOperationException("API response could not be deserialized into SubmitReportResponse.");
        }

        return result;
    }

    public async Task<DeleteReportResponse> DeleteReportAsync(string publicId, string deletionKey, CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, $"{_baseUrl}/api/v1/reports/{publicId}");
        request.Headers.Add("X-Deletion-Key", deletionKey);
        request.Content = JsonContent.Create(new { deletionKey });

        using var response = await _httpClient.SendAsync(request, ct);
        string responseContent = await response.Content.ReadAsStringAsync(ct);

        if (!response.IsSuccessStatusCode)
        {
            return new DeleteReportResponse
            {
                Success = false,
                Message = $"Failed to delete report: HTTP {(int)response.StatusCode}"
            };
        }

        return new DeleteReportResponse
        {
            Success = true,
            Message = $"Report {publicId} and all associated evidence were permanently deleted."
        };
    }
}
