using System.Net;
using MinecraftSsForensics.Scanner.Archive;
using MinecraftSsForensics.Scanner.Hashing;
using MinecraftSsForensics.Scanner.Verification;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class VerificationTests
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
    public async Task ModrinthVerification_ReturnsVerifiedExactRelease_WhenHashMatches()
    {
        string testSha512 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        var mockHandler = new MockHttpMessageHandler(req =>
        {
            if (req.RequestUri!.ToString().Contains(testSha512))
            {
                string json = $$"""
                {
                    "id": "ver_12345",
                    "project_id": "AANobbMI",
                    "version_number": "0.5.8",
                    "game_versions": ["1.20.4"],
                    "loaders": ["fabric"],
                    "files": [
                        {
                            "filename": "sodium-fabric-0.5.8+mc1.20.4.jar",
                            "size": 1234567,
                            "hashes": {
                                "sha512": "{{testSha512}}"
                            }
                        }
                    ]
                }
                """;
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
                };
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var provider = new ModrinthVerificationProvider(new HttpClient(mockHandler));
        var mod = new DiscoveredMod
        {
            FileName = "sodium-fabric-0.5.8+mc1.20.4.jar",
            FileSizeBytes = 1234567,
            Hashes = new FileHashResult { Sha512 = testSha512 }
        };

        var result = await provider.VerifyByHashAsync(mod);

        Assert.NotNull(result);
        Assert.Equal(ModVerificationState.VERIFIED_EXACT_RELEASE, result.State);
        Assert.Equal("AANobbMI", result.ProjectId);
        Assert.Equal("0.5.8", result.VersionNumber);
        Assert.Contains("Exact cryptographic SHA-512 match", result.Explanation);
    }

    [Fact]
    public async Task ModrinthVerification_ReturnsNull_WhenNotFound()
    {
        var mockHandler = new MockHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        var provider = new ModrinthVerificationProvider(new HttpClient(mockHandler));

        var mod = new DiscoveredMod
        {
            Hashes = new FileHashResult { Sha512 = "unknownhash123" }
        };

        var result = await provider.VerifyByHashAsync(mod);
        Assert.Null(result);
    }

    [Fact]
    public void VerificationCache_StoresAndRetrievesEntries_WithTtl()
    {
        var cache = new VerificationCache();
        var result = new ModVerificationResult
        {
            State = ModVerificationState.VERIFIED_EXACT_RELEASE,
            ProjectId = "test_mod"
        };

        cache.Set("test_hash_1", result, TimeSpan.FromMinutes(10));

        bool found = cache.TryGet("test_hash_1", out var retrieved);
        Assert.True(found);
        Assert.Equal("test_mod", retrieved.ProjectId);
        Assert.True(retrieved.IsCached);

        // Expired entry check
        cache.Set("test_expired", result, TimeSpan.FromMilliseconds(-100));
        bool foundExpired = cache.TryGet("test_expired", out _);
        Assert.False(foundExpired);
    }

    [Fact]
    public async Task CompositeModVerifier_ReturnsInvalidArchive_WhenParseFailed()
    {
        var cache = new VerificationCache();
        var modrinth = new ModrinthVerificationProvider(new HttpClient(new MockHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound))));
        var curse = new CurseForgeVerificationProvider(new HttpClient(new MockHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound))));
        var github = new GitHubVerificationProvider(new HttpClient(new MockHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound))));

        var verifier = new CompositeModVerifier(cache, modrinth, curse, github);

        var mod = new DiscoveredMod
        {
            Metadata = new ModMetadata
            {
                ParseSuccess = false,
                ParseError = "Zip bomb protection triggered"
            }
        };

        var res = await verifier.VerifyModAsync(mod);

        Assert.Equal(ModVerificationState.INVALID_OR_UNREADABLE_ARCHIVE, res.State);
        Assert.Contains("Zip bomb", res.Explanation);
    }
}
