using System;

namespace MinecraftSsForensics.Scanner.Client;

/// <summary>
/// Safely constructs and validates staff-facing report share URLs pointing to the public frontend web dashboard.
/// Ensures strict separation between backend API endpoints and public viewer URLs.
/// </summary>
public static class ReportShareUrlBuilder
{
    public const string DefaultDevFrontendUrl = "http://localhost:3000";
    public const string DefaultDevApiUrl = "http://localhost:5000";
    public const string ReportRoute = "report";

    /// <summary>
    /// Constructs a valid public report viewer URL using the configured frontend base URL.
    /// </summary>
    /// <param name="frontendBaseUrl">Configured public frontend base URL.</param>
    /// <param name="publicId">The public identifier returned by the ingestion API.</param>
    /// <param name="isProduction">Whether running in production mode requiring strict public domain validation.</param>
    /// <returns>A validated, safe shareable URL pointing directly to the frontend report viewer.</returns>
    /// <exception cref="ArgumentException">Thrown when publicId is empty or contains private credentials.</exception>
    /// <exception cref="InvalidOperationException">Thrown when frontendBaseUrl is missing in production.</exception>
    /// <exception cref="UriFormatException">Thrown when frontendBaseUrl is not a valid absolute HTTP/HTTPS URL.</exception>
    public static string BuildShareUrl(string? frontendBaseUrl, string publicId, bool isProduction = false)
    {
        if (string.IsNullOrWhiteSpace(publicId))
        {
            throw new ArgumentException("Public report identifier cannot be null or empty.", nameof(publicId));
        }

        string trimmedPublicId = publicId.Trim();

        // Security check: ensure private deletion key was not passed as the public identifier
        if (trimmedPublicId.StartsWith("del_", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Security violation: Attempted to construct a public share URL using a private deletion key.", nameof(publicId));
        }

        if (string.IsNullOrWhiteSpace(frontendBaseUrl))
        {
            if (isProduction)
            {
                throw new InvalidOperationException(
                    "Public frontend base URL is not configured. Production scans require an explicit public frontend URL to generate shareable staff links.");
            }

            // In local development mode, default to http://localhost:3000
            frontendBaseUrl = DefaultDevFrontendUrl;
        }

        string trimmedBaseUrl = frontendBaseUrl.Trim();

        if (!Uri.TryCreate(trimmedBaseUrl, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new UriFormatException(
                $"The configured frontend base URL '{trimmedBaseUrl}' is not a valid absolute HTTP or HTTPS URL.");
        }

        if (isProduction && (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || uri.Host.Equals("127.0.0.1")))
        {
            throw new InvalidOperationException(
                $"Production environment cannot use '{uri.Host}' as the public frontend report URL. A valid public domain or hostname is required.");
        }

        // Normalize trailing slashes
        string cleanBase = uri.GetLeftPart(UriPartial.Path).TrimEnd('/');

        return $"{cleanBase}/{ReportRoute}/{Uri.EscapeDataString(trimmedPublicId)}";
    }

    /// <summary>
    /// Validates both backend API and frontend URLs before launching scan or submission.
    /// </summary>
    public static (bool IsValid, string? ErrorMessage) ValidateConfiguration(
        string? apiBaseUrl, 
        string? frontendBaseUrl, 
        bool isProduction = false)
    {
        if (string.IsNullOrWhiteSpace(apiBaseUrl))
        {
            return (false, "Backend API URL is required.");
        }

        if (!Uri.TryCreate(apiBaseUrl.Trim(), UriKind.Absolute, out var apiUri) ||
            (apiUri.Scheme != Uri.UriSchemeHttp && apiUri.Scheme != Uri.UriSchemeHttps))
        {
            return (false, $"Backend API URL '{apiBaseUrl}' is not a valid absolute HTTP or HTTPS URL.");
        }

        if (string.IsNullOrWhiteSpace(frontendBaseUrl))
        {
            if (isProduction)
            {
                return (false, "Public frontend URL is required in production mode.");
            }
        }
        else
        {
            if (!Uri.TryCreate(frontendBaseUrl.Trim(), UriKind.Absolute, out var frontUri) ||
                (frontUri.Scheme != Uri.UriSchemeHttp && frontUri.Scheme != Uri.UriSchemeHttps))
            {
                return (false, $"Public frontend URL '{frontendBaseUrl}' is not a valid absolute HTTP or HTTPS URL.");
            }

            if (isProduction && (frontUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || frontUri.Host.Equals("127.0.0.1")))
            {
                return (false, "Production environment cannot use 'localhost' as the public frontend report URL.");
            }

            // Ensure the frontend URL is not pointing to the API port (prevent accidental misconfiguration)
            if (frontUri.Host.Equals(apiUri.Host, StringComparison.OrdinalIgnoreCase) && frontUri.Port == apiUri.Port && frontUri.Port != 80 && frontUri.Port != 443)
            {
                return (false, $"Configuration Warning: Frontend URL '{frontendBaseUrl}' shares the exact same port ({apiUri.Port}) as the Backend API. The frontend report viewer runs on a separate port or host.");
            }
        }

        return (true, null);
    }
}
