using System.Net;
using System.Net.Http.Json;
using System.Text;
using FluentAssertions;
using MinecraftSsForensics.Api.Models.Dtos.Ingestion;
using MinecraftSsForensics.Tests.Fixtures;
using Xunit;

namespace MinecraftSsForensics.Tests.Integration;

public class ReportIngestionTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly HttpClient _client;

    public ReportIngestionTests(CustomWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task SubmitReport_WithValidPayload_Returns201CreatedAndShareDetails()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();

        // Act
        var response = await _client.PostAsJsonAsync("/api/v1/reports", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var result = await response.Content.ReadFromJsonAsync<SubmitReportResponse>();

        result.Should().NotBeNull();
        result!.PublicId.Should().StartWith("mc_");
        result.ShareUrl.Should().Contain($"/report/{result.PublicId}");
        result.DeletionKey.Should().StartWith("del_");
        result.FindingsCount.Should().Be(2);
        result.ExpiresAt.Should().BeAfter(DateTimeOffset.UtcNow);

        response.Headers.Location.Should().NotBeNull();
        response.Headers.Location!.ToString().Should().Contain($"/api/v1/Reports/{result.PublicId}");
    }

    [Fact]
    public async Task SubmitReport_WithoutConsent_Returns400BadRequest()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        request.ConsentConfirmation.ConsentGiven = false;

        // Act
        var response = await _client.PostAsJsonAsync("/api/v1/reports", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("consent");
    }

    [Fact]
    public async Task SubmitReport_WithMalformedJson_Returns400BadRequest()
    {
        // Arrange
        var malformedContent = new StringContent("{ \"SchemaVersion\": \"1.0.0\", invalid_json_here }", Encoding.UTF8, "application/json");

        // Act
        var response = await _client.PostAsync("/api/v1/reports", malformedContent);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}
