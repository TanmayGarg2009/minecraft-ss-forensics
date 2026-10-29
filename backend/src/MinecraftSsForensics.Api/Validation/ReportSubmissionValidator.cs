using FluentValidation;
using MinecraftSsForensics.Api.Models.Domain;
using MinecraftSsForensics.Api.Models.Dtos.Ingestion;

namespace MinecraftSsForensics.Api.Validation;

public class ReportSubmissionValidator : AbstractValidator<SubmitReportRequest>
{
    private static readonly string[] AllowedSchemaVersions = { "1.0.0" };
    private static readonly string[] AllowedScanModes = { "QUICK", "FULL" };
    private static readonly string[] XssPatterns = { "<script", "javascript:", "onload=", "onerror=", "<iframe", "<object", "<embed" };

    public ReportSubmissionValidator()
    {
        RuleFor(x => x.SchemaVersion)
            .NotEmpty().WithMessage("Schema version is required.")
            .Must(v => AllowedSchemaVersions.Contains(v))
            .WithMessage($"Unsupported schema version. Supported versions: {string.Join(", ", AllowedSchemaVersions)}");

        RuleFor(x => x.ScannerVersion)
            .NotEmpty().WithMessage("Scanner version is required.")
            .MaximumLength(64).WithMessage("Scanner version exceeds 64 characters.");

        RuleFor(x => x.ScanMode)
            .NotEmpty().WithMessage("Scan mode is required.")
            .Must(m => AllowedScanModes.Contains(m.ToUpperInvariant()))
            .WithMessage("Scan mode must be 'QUICK' or 'FULL'.");

        RuleFor(x => x.OsName)
            .NotEmpty().WithMessage("Operating system name is required.")
            .MaximumLength(64);

        RuleFor(x => x.OsVersion)
            .NotEmpty().WithMessage("Operating system version is required.")
            .MaximumLength(64);

        RuleFor(x => x.ConsentConfirmation)
            .NotNull().WithMessage("Consent confirmation metadata is required.")
            .DependentRules(() =>
            {
                RuleFor(x => x.ConsentConfirmation.ConsentGiven)
                    .Equal(true)
                    .WithMessage("Explicit player consent is strictly required for report ingestion.");
            });

        RuleFor(x => x.RetentionDays)
            .InclusiveBetween(1, 30)
            .When(x => x.RetentionDays.HasValue)
            .WithMessage("Retention days must be between 1 and 30 days.");

        RuleFor(x => x.Findings)
            .Must(f => f == null || f.Count <= 1000)
            .WithMessage("Report cannot exceed 1000 findings.");

        RuleFor(x => x.TimelineEvents)
            .Must(t => t == null || t.Count <= 5000)
            .WithMessage("Report cannot exceed 5000 timeline events.");

        RuleFor(x => x.EvidenceItems)
            .Must(e => e == null || e.Count <= 500)
            .WithMessage("Report cannot exceed 500 evidence items.");

        RuleForEach(x => x.Findings).SetValidator(new FindingValidator());
        RuleForEach(x => x.EvidenceItems).SetValidator(new EvidenceValidator());
        RuleForEach(x => x.TimelineEvents).SetValidator(new TimelineEventValidator());
    }

    public static bool ContainsSuspiciousScript(string? input)
    {
        if (string.IsNullOrEmpty(input)) return false;
        var lower = input.ToLowerInvariant();
        return XssPatterns.Any(p => lower.Contains(p));
    }
}

public class FindingValidator : AbstractValidator<FindingSubmissionDto>
{
    public FindingValidator()
    {
        RuleFor(x => x.RuleId)
            .NotEmpty().WithMessage("Finding RuleId is required.")
            .MaximumLength(64);

        RuleFor(x => x.Title)
            .NotEmpty().WithMessage("Finding Title is required.")
            .MaximumLength(200)
            .Must(t => !ReportSubmissionValidator.ContainsSuspiciousScript(t))
            .WithMessage("Finding Title contains prohibited script tokens.");

        RuleFor(x => x.Explanation)
            .NotEmpty().WithMessage("Finding Explanation is required.")
            .Must(e => !ReportSubmissionValidator.ContainsSuspiciousScript(e))
            .WithMessage("Finding Explanation contains prohibited script tokens.");

        RuleFor(x => x.Severity)
            .NotEmpty()
            .Must(s => Enum.TryParse<Models.Domain.Severity>(s, true, out _))
            .WithMessage("Invalid Severity value.");

        RuleFor(x => x.Category)
            .NotEmpty()
            .Must(c => Enum.TryParse<FindingCategory>(c, true, out _))
            .WithMessage("Invalid Category value.");

        RuleFor(x => x.Confidence)
            .NotEmpty()
            .Must(c => Enum.TryParse<ConfidenceLevel>(c, true, out _))
            .WithMessage("Invalid Confidence value.");

        RuleFor(x => x.EvidenceSource)
            .NotEmpty()
            .Must(s => Enum.TryParse<EvidenceSource>(s, true, out _))
            .WithMessage("Invalid EvidenceSource value.");
    }
}

public class EvidenceValidator : AbstractValidator<EvidenceSubmissionDto>
{
    public EvidenceValidator()
    {
        RuleFor(x => x.PublicEvidenceId)
            .NotEmpty().WithMessage("Evidence PublicEvidenceId is required.")
            .MaximumLength(64);

        RuleFor(x => x.Title)
            .NotEmpty().WithMessage("Evidence Title is required.")
            .MaximumLength(200)
            .Must(t => !ReportSubmissionValidator.ContainsSuspiciousScript(t))
            .WithMessage("Evidence Title contains prohibited script tokens.");

        RuleFor(x => x.Type)
            .NotEmpty()
            .Must(t => Enum.TryParse<EvidenceType>(t, true, out _))
            .WithMessage("Invalid Evidence Type.");
    }
}

public class TimelineEventValidator : AbstractValidator<TimelineEventSubmissionDto>
{
    public TimelineEventValidator()
    {
        RuleFor(x => x.Category)
            .NotEmpty().WithMessage("Timeline category is required.")
            .MaximumLength(100);

        RuleFor(x => x.Description)
            .NotEmpty().WithMessage("Timeline description is required.")
            .Must(d => !ReportSubmissionValidator.ContainsSuspiciousScript(d))
            .WithMessage("Timeline Description contains prohibited script tokens.");

        RuleFor(x => x.Source)
            .NotEmpty().WithMessage("Timeline source is required.")
            .MaximumLength(100);

        RuleFor(x => x.Confidence)
            .Must(c => string.IsNullOrEmpty(c) || Enum.TryParse<ConfidenceLevel>(c, true, out _))
            .WithMessage("Invalid Timeline Confidence value.");
    }
}
