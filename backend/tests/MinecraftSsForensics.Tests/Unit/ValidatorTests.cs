using FluentAssertions;
using MinecraftSsForensics.Api.Validation;
using MinecraftSsForensics.Tests.Fixtures;
using Xunit;

namespace MinecraftSsForensics.Tests.Unit;

public class ValidatorTests
{
    private readonly ReportSubmissionValidator _validator = new();

    [Fact]
    public async Task Validate_WithValidSyntheticReport_ShouldPass()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public async Task Validate_WithUnsupportedSchemaVersion_ShouldFail()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        request.SchemaVersion = "99.0.0-unsupported";

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == "SchemaVersion");
    }

    [Fact]
    public async Task Validate_WithoutExplicitConsent_ShouldFail()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        request.ConsentConfirmation.ConsentGiven = false;

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName.Contains("ConsentGiven"));
    }

    [Fact]
    public async Task Validate_WithInvalidSeverityEnum_ShouldFail()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        request.Findings[0].Severity = "ExtremelySevere"; // Invalid enum

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.ErrorMessage.Contains("Invalid Severity value"));
    }

    [Fact]
    public async Task Validate_WithInjectedScriptInTitle_ShouldFailXssCheck()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        request.Findings[0].Title = "Finding <script>alert('pwned')</script>";

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.ErrorMessage.Contains("prohibited script tokens"));
    }

    [Fact]
    public async Task Validate_WithInvalidScanMode_ShouldFail()
    {
        // Arrange
        var request = SyntheticReportFactory.CreateValidReportRequest();
        request.ScanMode = "HYPER_EXTREME";

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == "ScanMode");
    }
}
