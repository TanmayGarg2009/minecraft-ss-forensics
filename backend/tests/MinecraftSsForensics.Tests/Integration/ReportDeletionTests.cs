using System.Net;
using System.Net.Http.Json;
using System.Text;
using FluentAssertions;
using MinecraftSsForensics.Api.Models.Dtos.Ingestion;
using MinecraftSsForensics.Api.Models.Dtos.Presentation;
using MinecraftSsForensics.Tests.Fixtures;
using Xunit;

namespace MinecraftSsForensics.Tests.Integration;

public class ReportDeletionTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly HttpClient _client;

    public ReportDeletionTests(CustomWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task DeleteReport_WithValidDeletionKeyInBody_DeletesReportSuccessfully()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        var submitRes = await _client.PostAsJsonAsync("/api/v1/reports", request);
        var submitData = await submitRes.Content.ReadFromJsonAsync<SubmitReportResponse>();

        var deleteReq = new HttpRequestMessage(HttpMethod.Delete, $"/api/v1/reports/{submitData!.PublicId}")
        {
            Content = JsonContent.Create(new DeleteReportRequest { DeletionKey = submitData.DeletionKey })
        };

        // Act
        var deleteResponse = await _client.SendAsync(deleteReq);

        // Assert
        deleteResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await deleteResponse.Content.ReadFromJsonAsync<DeleteReportResponse>();
        result.Should().NotBeNull();
        result!.Success.Should().BeTrue();

        // Verify report is permanently gone
        var getResponse = await _client.GetAsync($"/api/v1/reports/{submitData.PublicId}");
        getResponse.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task DeleteReport_WithValidDeletionKeyInHeader_DeletesReportSuccessfully()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        var submitRes = await _client.PostAsJsonAsync("/api/v1/reports", request);
        var submitData = await submitRes.Content.ReadFromJsonAsync<SubmitReportResponse>();

        var deleteReq = new HttpRequestMessage(HttpMethod.Delete, $"/api/v1/reports/{submitData!.PublicId}");
        deleteReq.Headers.Add("X-Deletion-Key", submitData.DeletionKey);

        // Act
        var deleteResponse = await _client.SendAsync(deleteReq);

        // Assert
        deleteResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Verify report is gone
        var getResponse = await _client.GetAsync($"/api/v1/reports/{submitData.PublicId}");
        getResponse.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task DeleteReport_WithInvalidDeletionKey_Returns401Unauthorized()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        var submitRes = await _client.PostAsJsonAsync("/api/v1/reports", request);
        var submitData = await submitRes.Content.ReadFromJsonAsync<SubmitReportResponse>();

        var deleteReq = new HttpRequestMessage(HttpMethod.Delete, $"/api/v1/reports/{submitData!.PublicId}")
        {
            Content = JsonContent.Create(new DeleteReportRequest { DeletionKey = "del_invalid_key_attempt_0000000000000000" })
        };

        // Act
        var deleteResponse = await _client.SendAsync(deleteReq);

        // Assert
        deleteResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // Verify report was NOT deleted
        var getResponse = await _client.GetAsync($"/api/v1/reports/{submitData.PublicId}");
        getResponse.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task DeleteReport_WithoutDeletionKey_Returns400BadRequest()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        var submitRes = await _client.PostAsJsonAsync("/api/v1/reports", request);
        var submitData = await submitRes.Content.ReadFromJsonAsync<SubmitReportResponse>();

        var deleteReq = new HttpRequestMessage(HttpMethod.Delete, $"/api/v1/reports/{submitData!.PublicId}");

        // Act
        var deleteResponse = await _client.SendAsync(deleteReq);

        // Assert
        deleteResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}
