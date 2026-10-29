using System.Net;
using MinecraftSsForensics.Api.Models.Dtos.Ingestion;
using MinecraftSsForensics.Scanner.Client;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class BackendApiClientTests
{
    private class MockHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

        public MockHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            _responder = responder;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_responder(request));
        }
    }

    [Fact]
    public async Task SubmitReportAsync_SendsPostAndDeserializesResponse()
    {
        string expectedPublicId = "mc_test_success_123";
        string expectedKey = "del_secret_token_456";

        var mockHandler = new MockHttpMessageHandler(req =>
        {
            Assert.Equal(HttpMethod.Post, req.Method);
            Assert.Contains("/api/v1/reports", req.RequestUri!.ToString());

            string json = $$"""
            {
                "publicId": "{{expectedPublicId}}",
                "shareUrl": "http://localhost:5000/report/{{expectedPublicId}}",
                "deletionKey": "{{expectedKey}}",
                "expiresAt": "2026-11-06T10:00:00Z",
                "processingStatus": "Completed",
                "findingsCount": 0,
                "message": "Report successfully ingested."
            }
            """;

            return new HttpResponseMessage(HttpStatusCode.Created)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
            };
        });

        var client = new BackendApiClient("http://localhost:5000", new HttpClient(mockHandler));

        var requestDto = new SubmitReportRequest
        {
            ScannerVersion = "1.0.0-rc2",
            ScanMode = "QUICK",
            OsName = "Windows 11 Pro",
            OsVersion = "10.0.22631",
            ConsentConfirmation = new ConsentSubmissionDto { ConsentGiven = true }
        };

        var response = await client.SubmitReportAsync(requestDto);

        Assert.Equal(expectedPublicId, response.PublicId);
        Assert.Equal(expectedKey, response.DeletionKey);
        Assert.Contains(expectedPublicId, response.ShareUrl);
    }

    [Fact]
    public async Task DeleteReportAsync_SendsDeleteWithDeletionKeyHeader()
    {
        string publicId = "mc_to_delete_999";
        string deletionKey = "del_secret_key_888";

        var mockHandler = new MockHttpMessageHandler(req =>
        {
            Assert.Equal(HttpMethod.Delete, req.Method);
            Assert.Contains($"/api/v1/reports/{publicId}", req.RequestUri!.ToString());
            Assert.True(req.Headers.Contains("X-Deletion-Key"));
            Assert.Equal(deletionKey, req.Headers.GetValues("X-Deletion-Key").First());

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"success\":true}", System.Text.Encoding.UTF8, "application/json")
            };
        });

        var client = new BackendApiClient("http://localhost:5000", new HttpClient(mockHandler));

        var result = await client.DeleteReportAsync(publicId, deletionKey);

        Assert.True(result.Success);
        Assert.Contains("permanently deleted", result.Message);
    }
}
