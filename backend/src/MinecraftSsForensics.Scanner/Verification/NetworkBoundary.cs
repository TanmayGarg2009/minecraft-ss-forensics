using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Verification;

/// <summary>
/// Transport-level network consent and SSRF defense boundary.
/// Strictly intercepts all outbound HTTP traffic and blocks any request if explicit user consent is absent,
/// if the URI scheme is not HTTPS, if the host is not on the authorized whitelist, or if the destination
/// resolves to private or loopback IP ranges.
/// Enforces the offline-first security principle at the network stack.
/// </summary>
public class ConsentEnforcingHttpMessageHandler : DelegatingHandler
{
    private readonly Func<bool> _isConsentGranted;

    private static readonly HashSet<string> AllowedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "api.modrinth.com",
        "api.curseforge.com",
        "raw.githubusercontent.com",
        "api.github.com"
    };

    public ConsentEnforcingHttpMessageHandler(Func<bool> isConsentGranted, HttpMessageHandler? innerHandler = null)
        : base(innerHandler ?? new HttpClientHandler())
    {
        _isConsentGranted = isConsentGranted ?? (() => false);
    }

    public ConsentEnforcingHttpMessageHandler(ConsentScopeConfig? consent, HttpMessageHandler? innerHandler = null)
        : this(() => consent != null && consent.ConsentGiven && consent.PerformOnlineVerification, innerHandler)
    {
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!_isConsentGranted())
        {
            string host = request.RequestUri?.Host ?? "unknown";
            throw new InvalidOperationException(
                $"Strict Offline Security Boundary: Outbound HTTP request to '{host}' blocked. " +
                "Online verification is disabled by default and requires explicit consent in ConsentScopeConfig.PerformOnlineVerification.");
        }

        if (request.RequestUri == null)
        {
            throw new ArgumentException("Request URI cannot be null.", nameof(request));
        }

        // Enforce HTTPS-only scheme
        if (!string.Equals(request.RequestUri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Insecure network protocol blocked: '{request.RequestUri.Scheme}://{request.RequestUri.Host}'. Only HTTPS is permitted for verification requests.");
        }

        string reqHost = request.RequestUri.Host;

        // SSRF & Loopback Protection
        if (IPAddress.TryParse(reqHost, out var ip))
        {
            if (IPAddress.IsLoopback(ip) || IsPrivateOrRestrictedIp(ip))
            {
                throw new InvalidOperationException(
                    $"SSRF Security Boundary: Outbound request to private/loopback IP address '{ip}' is strictly blocked.");
            }
        }

        // Enforce Whitelist of Authorized Mod Verification Repositories
        if (!AllowedHosts.Contains(reqHost))
        {
            throw new InvalidOperationException(
                $"Network Security Boundary: Outbound request to unauthorized host '{reqHost}' blocked. " +
                $"Permitted hosts: {string.Join(", ", AllowedHosts)}.");
        }

        return base.SendAsync(request, cancellationToken);
    }

    private static bool IsPrivateOrRestrictedIp(IPAddress ip)
    {
        if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal)
            return true;

        byte[] bytes = ip.GetAddressBytes();
        if (bytes.Length == 4) // IPv4
        {
            // 0.0.0.0/8
            if (bytes[0] == 0) return true;
            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            // 127.0.0.0/8
            if (bytes[0] == 127) return true;
            // 169.254.0.0/16 (Link-Local & Cloud Metadata 169.254.169.254)
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
        }

        return false;
    }
}

/// <summary>
/// Factory and management interface for strictly consent-bounded HTTP clients.
/// </summary>
public static class NetworkBoundary
{
    /// <summary>
    /// Creates an HttpClient that is strictly bounded by user consent at the transport layer.
    /// </summary>
    public static HttpClient CreateConsentBoundedClient(
        Func<bool> isConsentGranted,
        HttpMessageHandler? innerHandler = null,
        TimeSpan? timeout = null)
    {
        var handler = new ConsentEnforcingHttpMessageHandler(isConsentGranted, innerHandler);
        return new HttpClient(handler)
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(10)
        };
    }

    /// <summary>
    /// Creates an HttpClient bounded by a ConsentScopeConfig instance.
    /// </summary>
    public static HttpClient CreateConsentBoundedClient(
        ConsentScopeConfig? consent,
        HttpMessageHandler? innerHandler = null,
        TimeSpan? timeout = null)
    {
        return CreateConsentBoundedClient(
            () => consent != null && consent.ConsentGiven && consent.PerformOnlineVerification,
            innerHandler,
            timeout);
    }
}
