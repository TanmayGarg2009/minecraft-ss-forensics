using System;
using MinecraftSsForensics.Scanner.Client;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class ReportShareUrlBuilderTests
{
    [Fact]
    public void BuildShareUrl_LocalDevelopment_ConstructsFrontendUrlOnPort3000()
    {
        string publicId = "mc_fddy1tJ6mEK4IxfFRv";
        string shareUrl = ReportShareUrlBuilder.BuildShareUrl("http://localhost:3000", publicId, isProduction: false);

        Assert.Equal("http://localhost:3000/report/mc_fddy1tJ6mEK4IxfFRv", shareUrl);
        Assert.DoesNotContain("5000", shareUrl);
        Assert.DoesNotContain("api", shareUrl);
    }

    [Fact]
    public void BuildShareUrl_WhenFrontendUrlOmittedInDev_DefaultsToLocalhost3000()
    {
        string publicId = "mc_7ckiaTA61QwRTtEebT";
        string shareUrl = ReportShareUrlBuilder.BuildShareUrl(null, publicId, isProduction: false);

        Assert.Equal("http://localhost:3000/report/mc_7ckiaTA61QwRTtEebT", shareUrl);
    }

    [Fact]
    public void BuildShareUrl_ProductionConfiguration_UsesConfiguredPublicDomain()
    {
        string publicId = "mc_G23Yx38ebR86Otk4vl";
        string prodFrontend = "https://forensics.mc-server.net";

        string shareUrl = ReportShareUrlBuilder.BuildShareUrl(prodFrontend, publicId, isProduction: true);

        Assert.Equal("https://forensics.mc-server.net/report/mc_G23Yx38ebR86Otk4vl", shareUrl);
        Assert.StartsWith("https://forensics.mc-server.net", shareUrl);
    }

    [Fact]
    public void BuildShareUrl_NormalizesTrailingSlashesSafely()
    {
        string publicId = "mc_test_id";
        string frontendWithSlash = "https://ss.example.org///";

        string shareUrl = ReportShareUrlBuilder.BuildShareUrl(frontendWithSlash, publicId, isProduction: true);

        Assert.Equal("https://ss.example.org/report/mc_test_id", shareUrl);
    }

    [Fact]
    public void BuildShareUrl_ProductionMode_ThrowsWhenFrontendUrlMissing()
    {
        string publicId = "mc_test_id";

        var ex = Assert.Throws<InvalidOperationException>(() =>
            ReportShareUrlBuilder.BuildShareUrl(null, publicId, isProduction: true));

        Assert.Contains("Production scans require an explicit public frontend URL", ex.Message);
    }

    [Fact]
    public void BuildShareUrl_ProductionMode_ThrowsWhenFrontendUsesLocalhost()
    {
        string publicId = "mc_test_id";

        var ex = Assert.Throws<InvalidOperationException>(() =>
            ReportShareUrlBuilder.BuildShareUrl("http://localhost:3000", publicId, isProduction: true));

        Assert.Contains("Production environment cannot use 'localhost'", ex.Message);
    }

    [Fact]
    public void BuildShareUrl_ThrowsWhenPublicIdIsEmpty()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ReportShareUrlBuilder.BuildShareUrl("http://localhost:3000", "   "));

        Assert.Contains("Public report identifier cannot be null or empty", ex.Message);
    }

    [Fact]
    public void BuildShareUrl_SecurityViolation_ThrowsIfDeletionKeyPassedAsPublicId()
    {
        string privateDeletionKey = "del_8fa21b7c3d4e5f60718293a4b5c6d7e8f90123456789abcdef";

        var ex = Assert.Throws<ArgumentException>(() =>
            ReportShareUrlBuilder.BuildShareUrl("http://localhost:3000", privateDeletionKey));

        Assert.Contains("Security violation", ex.Message);
    }

    [Fact]
    public void ValidateConfiguration_CatchesSharedPortCollisionBetweenApiAndFrontend()
    {
        var (isValid, errorMessage) = ReportShareUrlBuilder.ValidateConfiguration(
            apiBaseUrl: "http://localhost:5000",
            frontendBaseUrl: "http://localhost:5000",
            isProduction: false);

        Assert.False(isValid);
        Assert.Contains("exact same port", errorMessage);
    }

    [Fact]
    public void ValidateConfiguration_SucceedsWithSeparateDevPorts()
    {
        var (isValid, errorMessage) = ReportShareUrlBuilder.ValidateConfiguration(
            apiBaseUrl: "http://localhost:5000",
            frontendBaseUrl: "http://localhost:3000",
            isProduction: false);

        Assert.True(isValid);
        Assert.Null(errorMessage);
    }

    [Fact]
    public void ValidateConfiguration_SucceedsWithSeparateProductionHosts()
    {
        var (isValid, errorMessage) = ReportShareUrlBuilder.ValidateConfiguration(
            apiBaseUrl: "https://api.screenshare.net",
            frontendBaseUrl: "https://view.screenshare.net",
            isProduction: true);

        Assert.True(isValid);
        Assert.Null(errorMessage);
    }
}
