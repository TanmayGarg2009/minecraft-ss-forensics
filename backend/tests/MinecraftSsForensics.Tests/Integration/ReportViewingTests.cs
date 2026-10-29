using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using MinecraftSsForensics.Api.Models.Dtos.Ingestion;
using MinecraftSsForensics.Api.Models.Dtos.Presentation;
using MinecraftSsForensics.Tests.Fixtures;
using Xunit;

namespace MinecraftSsForensics.Tests.Integration;

public class ReportViewingTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly HttpClient _client;

    public ReportViewingTests(CustomWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task GetReport_WithValidBearerPublicId_ReturnsReportDetails()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        var submitRes = await _client.PostAsJsonAsync("/api/v1/reports", request);
        var submitData = await submitRes.Content.ReadFromJsonAsync<SubmitReportResponse>();

        // Act
        var response = await _client.GetAsync($"/api/v1/reports/{submitData!.PublicId}");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var report = await response.Content.ReadFromJsonAsync<ReportDetailResponse>();

        report.Should().NotBeNull();
        report!.PublicId.Should().Be(submitData.PublicId);
        report.ScanMode.Should().Be("FULL");
        report.Findings.Should().HaveCount(2);
        report.EvidenceItems.Should().HaveCount(2);
        report.TimelineEvents.Should().HaveCount(3);
        report.DiagnosticItems.Should().HaveCount(2);
        report.PrivacyNotice.Should().NotBeNullOrWhiteSpace();

        // Critical security test: verify DeletionKey or hash is NEVER returned in public view
        var rawJson = await response.Content.ReadAsStringAsync();
        rawJson.ToLowerInvariant().Should().NotContain("deletionkey");
        rawJson.ToLowerInvariant().Should().NotContain("deletionkeyhash");
        rawJson.Should().NotContain(submitData.DeletionKey);

        // Cache control headers
        response.Headers.CacheControl.Should().NotBeNull();
        response.Headers.CacheControl!.NoStore.Should().BeTrue();
    }

    [Fact]
    public async Task GetReport_WithNonExistentPublicId_Returns404NotFound()
    {
        // Act
        var response = await _client.GetAsync("/api/v1/reports/mc_nonexistent_random_id_12345");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task GetEvidence_WithValidEvidenceId_ReturnsEvidencePayload()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        var submitRes = await _client.PostAsJsonAsync("/api/v1/reports", request);
        var submitData = await submitRes.Content.ReadFromJsonAsync<SubmitReportResponse>();

        // Act
        var response = await _client.GetAsync($"/api/v1/reports/{submitData!.PublicId}/evidence/ev_pref_001");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var evidence = await response.Content.ReadFromJsonAsync<EvidenceDetailDto>();
        evidence.Should().NotBeNull();
        evidence!.PublicEvidenceId.Should().Be("ev_pref_001");
        evidence.RawContent.Should().Contain("CLICKER_V2.EXE");
    }

    [Fact]
    public async Task GetEvidence_WithUnrelatedOrUnknownEvidenceId_Returns404NotFound()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        var submitRes = await _client.PostAsJsonAsync("/api/v1/reports", request);
        var submitData = await submitRes.Content.ReadFromJsonAsync<SubmitReportResponse>();

        // Act
        var response = await _client.GetAsync($"/api/v1/reports/{submitData!.PublicId}/evidence/unrelated_evidence_id");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }
}
