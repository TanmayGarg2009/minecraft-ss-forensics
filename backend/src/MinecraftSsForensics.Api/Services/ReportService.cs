using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using MinecraftSsForensics.Api.Data;
using MinecraftSsForensics.Api.Models.Domain;
using MinecraftSsForensics.Api.Models.Dtos.Ingestion;
using MinecraftSsForensics.Api.Models.Dtos.Presentation;

namespace MinecraftSsForensics.Api.Services;

public class ReportService : IReportService
{
    private readonly ForensicsDbContext _dbContext;
    private readonly IIdentifierGenerator _identifierGenerator;
    private readonly IStorageService _storageService;
    private readonly ILogger<ReportService> _logger;
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public ReportService(
        ForensicsDbContext dbContext,
        IIdentifierGenerator identifierGenerator,
        IStorageService storageService,
        ILogger<ReportService> logger)
    {
        _dbContext = dbContext;
        _identifierGenerator = identifierGenerator;
        _storageService = storageService;
        _logger = logger;
    }

    public async Task<SubmitReportResponse> SubmitReportAsync(SubmitReportRequest request, string baseUrl, CancellationToken cancellationToken = default)
    {
        var publicId = _identifierGenerator.GeneratePublicId();
        var deletionKey = _identifierGenerator.GenerateDeletionKey();
        var deletionKeyHash = _identifierGenerator.HashDeletionKey(deletionKey);

        var retentionDays = request.RetentionDays.GetValueOrDefault(7);
        if (retentionDays < 1) retentionDays = 1;
        if (retentionDays > 30) retentionDays = 30;

        var scanMode = Enum.TryParse<ScanMode>(request.ScanMode, true, out var parsedMode) ? parsedMode : ScanMode.Quick;

        var report = new Report
        {
            Id = Guid.NewGuid(),
            PublicId = publicId,
            DeletionKeyHash = deletionKeyHash,
            SchemaVersion = request.SchemaVersion,
            ScannerVersion = request.ScannerVersion,
            CreatedAt = DateTimeOffset.UtcNow,
            UploadedAt = DateTimeOffset.UtcNow,
            ScanStartedAt = request.ScanStartedAt,
            ScanCompletedAt = request.ScanCompletedAt,
            ScanMode = scanMode,
            OsName = request.OsName,
            OsVersion = request.OsVersion,
            OsArchitecture = string.IsNullOrWhiteSpace(request.OsArchitecture) ? "x64" : request.OsArchitecture,
            DetectedMinecraftVersionsJson = JsonSerializer.Serialize(request.DetectedMinecraftVersions, JsonOpts),
            DetectedLoadersJson = JsonSerializer.Serialize(request.DetectedLoaders, JsonOpts),
            ConsentGiven = request.ConsentConfirmation.ConsentGiven,
            CollectionScopeVersion = request.ConsentConfirmation.CollectionScopeVersion,
            ConsentTimestamp = request.ConsentConfirmation.ConsentTimestamp,
            ProcessingStatus = ProcessingStatus.Completed,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(retentionDays),
            TotalChecks = request.CollectionCoverage?.TotalChecks ?? 0,
            PassedChecks = request.CollectionCoverage?.PassedChecks ?? 0,
            FlaggedChecks = request.Findings.Count,
            UnavailableChecks = request.CollectionCoverage?.UnavailableChecks ?? 0
        };

        // Findings
        foreach (var findingDto in request.Findings)
        {
            var category = Enum.TryParse<FindingCategory>(findingDto.Category, true, out var cat) ? cat : FindingCategory.Other;
            var severity = Enum.TryParse<Severity>(findingDto.Severity, true, out var sev) ? sev : Severity.Informational;
            var confidence = Enum.TryParse<ConfidenceLevel>(findingDto.Confidence, true, out var conf) ? conf : ConfidenceLevel.Medium;
            var source = Enum.TryParse<EvidenceSource>(findingDto.EvidenceSource, true, out var src) ? src : EvidenceSource.Other;

            report.Findings.Add(new Finding
            {
                Id = Guid.NewGuid(),
                ReportId = report.Id,
                RuleId = findingDto.RuleId,
                Title = findingDto.Title,
                Category = category,
                Severity = severity,
                Confidence = confidence,
                Explanation = findingDto.Explanation,
                ObservedEvidenceJson = findingDto.ObservedEvidence != null
                    ? JsonSerializer.Serialize(findingDto.ObservedEvidence, JsonOpts)
                    : "{}",
                FilePath = findingDto.FilePath,
                FileSizeBytes = findingDto.FileSizeBytes,
                FileSha256 = findingDto.FileSha256,
                FileCreatedTime = findingDto.FileCreatedTime,
                FileModifiedTime = findingDto.FileModifiedTime,
                FileLastAccessTime = findingDto.FileLastAccessTime,
                ProcessId = findingDto.ProcessId,
                ProcessName = findingDto.ProcessName,
                ProcessCommandLine = findingDto.ProcessCommandLine,
                FirstObservedAt = findingDto.FirstObservedAt,
                LastObservedAt = findingDto.LastObservedAt,
                EvidenceSource = source,
                DetectionRuleVersion = findingDto.DetectionRuleVersion,
                LimitationsAndFalsePositives = findingDto.LimitationsAndFalsePositives
            });
        }

        // Evidence Items
        foreach (var evidenceDto in request.EvidenceItems)
        {
            var type = Enum.TryParse<EvidenceType>(evidenceDto.Type, true, out var evType) ? evType : EvidenceType.FileMetadata;

            var evidence = new EvidenceItem
            {
                Id = Guid.NewGuid(),
                ReportId = report.Id,
                PublicEvidenceId = evidenceDto.PublicEvidenceId,
                Type = type,
                Title = evidenceDto.Title,
                Description = evidenceDto.Description,
                Sha256Hash = evidenceDto.Sha256Hash,
                IsAvailable = evidenceDto.IsAvailable,
                DiagnosticMessage = evidenceDto.DiagnosticMessage,
                CapturedAt = evidenceDto.CapturedAt ?? DateTimeOffset.UtcNow,
                StructuredPayloadJson = evidenceDto.StructuredPayload != null
                    ? JsonSerializer.Serialize(evidenceDto.StructuredPayload, JsonOpts)
                    : null
            };

            // Store raw content via abstraction if provided
            if (!string.IsNullOrEmpty(evidenceDto.RawContent))
            {
                await _storageService.SaveEvidencePayloadAsync(publicId, evidenceDto.PublicEvidenceId, evidenceDto.RawContent, cancellationToken);
                evidence.RawContent = "[Stored in Evidence Storage]";
            }

            report.EvidenceItems.Add(evidence);
        }

        // Timeline Events
        foreach (var timelineDto in request.TimelineEvents)
        {
            var confidence = Enum.TryParse<ConfidenceLevel>(timelineDto.Confidence, true, out var conf) ? conf : ConfidenceLevel.Medium;

            report.TimelineEvents.Add(new TimelineEvent
            {
                Id = Guid.NewGuid(),
                ReportId = report.Id,
                Timestamp = timelineDto.Timestamp,
                IsInferred = timelineDto.IsInferred,
                Category = timelineDto.Category,
                Description = timelineDto.Description,
                Source = timelineDto.Source,
                Confidence = confidence,
                CorrelationGroup = timelineDto.CorrelationGroup
            });
        }

        // Diagnostic Items
        foreach (var diagDto in request.DiagnosticItems)
        {
            report.DiagnosticItems.Add(new DiagnosticItem
            {
                Id = Guid.NewGuid(),
                ReportId = report.Id,
                CheckName = diagDto.CheckName,
                Source = diagDto.Source,
                Status = diagDto.Status,
                Reason = diagDto.Reason,
                Recommendation = diagDto.Recommendation
            });
        }

        _dbContext.Reports.Add(report);
        await _dbContext.SaveChangesAsync(cancellationToken);

        _logger.LogInformation("Report {PublicId} submitted with {FindingsCount} findings. Mode: {ScanMode}. Expires: {ExpiresAt}",
            publicId, report.Findings.Count, report.ScanMode, report.ExpiresAt);

        var cleanBaseUrl = baseUrl.TrimEnd('/');
        var shareUrl = $"{cleanBaseUrl}/report/{publicId}";

        return new SubmitReportResponse
        {
            PublicId = publicId,
            ShareUrl = shareUrl,
            DeletionKey = deletionKey,
            ExpiresAt = report.ExpiresAt,
            ProcessingStatus = report.ProcessingStatus.ToString(),
            FindingsCount = report.Findings.Count,
            Message = "Report successfully ingested. Keep your DeletionKey safe; it will not be shown again."
        };
    }

    public async Task<ReportDetailResponse?> GetReportByPublicIdAsync(string publicId, CancellationToken cancellationToken = default)
    {
        var report = await _dbContext.Reports
            .Include(r => r.Findings)
            .Include(r => r.EvidenceItems)
            .Include(r => r.TimelineEvents)
            .Include(r => r.DiagnosticItems)
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.PublicId == publicId, cancellationToken);

        if (report == null)
        {
            return null;
        }

        if (report.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            _logger.LogInformation("Report {PublicId} has expired at {ExpiresAt}", publicId, report.ExpiresAt);
            return null;
        }

        var detectedVersions = DeserializeList(report.DetectedMinecraftVersionsJson);
        var detectedLoaders = DeserializeList(report.DetectedLoadersJson);

        var severitySummary = report.Findings
            .GroupBy(f => f.Severity.ToString())
            .ToDictionary(g => g.Key, g => g.Count());

        var response = new ReportDetailResponse
        {
            PublicId = report.PublicId,
            SchemaVersion = report.SchemaVersion,
            ScannerVersion = report.ScannerVersion,
            CreatedAt = report.CreatedAt,
            UploadedAt = report.UploadedAt,
            ScanStartedAt = report.ScanStartedAt,
            ScanCompletedAt = report.ScanCompletedAt,
            ScanMode = report.ScanMode.ToString().ToUpperInvariant(),
            OsName = report.OsName,
            OsVersion = report.OsVersion,
            OsArchitecture = report.OsArchitecture,
            DetectedMinecraftVersions = detectedVersions,
            DetectedLoaders = detectedLoaders,
            Consent = new ConsentDetailDto
            {
                ConsentGiven = report.ConsentGiven,
                CollectionScopeVersion = report.CollectionScopeVersion,
                ConsentTimestamp = report.ConsentTimestamp
            },
            ProcessingStatus = report.ProcessingStatus.ToString(),
            ExpiresAt = report.ExpiresAt,
            Coverage = new CoverageDetailDto
            {
                TotalChecks = report.TotalChecks,
                PassedChecks = report.PassedChecks,
                FlaggedChecks = report.FlaggedChecks,
                UnavailableChecks = report.UnavailableChecks
            },
            SeveritySummary = severitySummary,
            Findings = report.Findings.Select(f => new FindingDetailDto
            {
                RuleId = f.RuleId,
                Title = f.Title,
                Category = f.Category.ToString(),
                Severity = f.Severity.ToString(),
                Confidence = f.Confidence.ToString(),
                Explanation = f.Explanation,
                ObservedEvidence = DeserializeObject(f.ObservedEvidenceJson),
                FilePath = f.FilePath,
                FileSizeBytes = f.FileSizeBytes,
                FileSha256 = f.FileSha256,
                FileCreatedTime = f.FileCreatedTime,
                FileModifiedTime = f.FileModifiedTime,
                FileLastAccessTime = f.FileLastAccessTime,
                ProcessId = f.ProcessId,
                ProcessName = f.ProcessName,
                ProcessCommandLine = f.ProcessCommandLine,
                FirstObservedAt = f.FirstObservedAt,
                LastObservedAt = f.LastObservedAt,
                EvidenceSource = f.EvidenceSource.ToString(),
                DetectionRuleVersion = f.DetectionRuleVersion,
                LimitationsAndFalsePositives = f.LimitationsAndFalsePositives
            }).ToList(),
            EvidenceItems = report.EvidenceItems.Select(e => new EvidenceSummaryDto
            {
                PublicEvidenceId = e.PublicEvidenceId,
                Type = e.Type.ToString(),
                Title = e.Title,
                Description = e.Description,
                Sha256Hash = e.Sha256Hash,
                IsAvailable = e.IsAvailable,
                DiagnosticMessage = e.DiagnosticMessage,
                CapturedAt = e.CapturedAt,
                HasRawContent = !string.IsNullOrEmpty(e.RawContent),
                StructuredPayload = DeserializeObject(e.StructuredPayloadJson)
            }).ToList(),
            TimelineEvents = report.TimelineEvents
                .OrderBy(t => t.Timestamp)
                .Select(t => new TimelineEventDetailDto
                {
                    Timestamp = t.Timestamp,
                    IsInferred = t.IsInferred,
                    Category = t.Category,
                    Description = t.Description,
                    Source = t.Source,
                    Confidence = t.Confidence.ToString(),
                    CorrelationGroup = t.CorrelationGroup
                }).ToList(),
            DiagnosticItems = report.DiagnosticItems.Select(d => new DiagnosticItemDetailDto
            {
                CheckName = d.CheckName,
                Source = d.Source,
                Status = d.Status,
                Reason = d.Reason,
                Recommendation = d.Recommendation
            }).ToList()
        };

        return response;
    }

    public async Task<EvidenceDetailDto?> GetEvidenceItemAsync(string publicId, string evidenceId, CancellationToken cancellationToken = default)
    {
        var report = await _dbContext.Reports
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.PublicId == publicId, cancellationToken);

        if (report == null || report.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return null;
        }

        var item = await _dbContext.EvidenceItems
            .AsNoTracking()
            .FirstOrDefaultAsync(e => e.ReportId == report.Id && e.PublicEvidenceId == evidenceId, cancellationToken);

        if (item == null)
        {
            return null;
        }

        string? rawContent = item.RawContent;
        if (rawContent == "[Stored in Evidence Storage]")
        {
            rawContent = await _storageService.GetEvidencePayloadAsync(publicId, evidenceId, cancellationToken);
        }

        return new EvidenceDetailDto
        {
            PublicEvidenceId = item.PublicEvidenceId,
            Type = item.Type.ToString(),
            Title = item.Title,
            Description = item.Description,
            Sha256Hash = item.Sha256Hash,
            IsAvailable = item.IsAvailable,
            DiagnosticMessage = item.DiagnosticMessage,
            CapturedAt = item.CapturedAt,
            HasRawContent = !string.IsNullOrEmpty(rawContent),
            RawContent = rawContent,
            StructuredPayload = DeserializeObject(item.StructuredPayloadJson)
        };
    }

    public async Task<bool> DeleteReportAsync(string publicId, string deletionKey, CancellationToken cancellationToken = default)
    {
        var report = await _dbContext.Reports
            .FirstOrDefaultAsync(r => r.PublicId == publicId, cancellationToken);

        if (report == null)
        {
            return false;
        }

        if (!_identifierGenerator.VerifyDeletionKey(deletionKey, report.DeletionKeyHash))
        {
            _logger.LogWarning("Invalid deletion attempt for report {PublicId}", publicId);
            return false;
        }

        // Delete raw storage files
        try
        {
            await _storageService.DeleteReportEvidenceAsync(publicId, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error clearing raw evidence storage for report {PublicId}", publicId);
        }

        _dbContext.Reports.Remove(report);
        await _dbContext.SaveChangesAsync(cancellationToken);

        _logger.LogInformation("Report {PublicId} deleted successfully using valid deletion key", publicId);
        return true;
    }

    public async Task<int> CleanupExpiredReportsAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var candidates = await _dbContext.Reports.ToListAsync(cancellationToken);
        var expiredReports = candidates
            .Where(r => r.ExpiresAt <= now)
            .ToList();

        if (!expiredReports.Any())
        {
            return 0;
        }

        foreach (var report in expiredReports)
        {
            try
            {
                await _storageService.DeleteReportEvidenceAsync(report.PublicId, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting raw files for expired report {PublicId}", report.PublicId);
            }
        }

        _dbContext.Reports.RemoveRange(expiredReports);
        var removedCount = await _dbContext.SaveChangesAsync(cancellationToken);
        _logger.LogInformation("Cleaned up {Count} expired reports", expiredReports.Count);
        return expiredReports.Count;
    }

    private static List<string> DeserializeList(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new List<string>();
        try
        {
            return JsonSerializer.Deserialize<List<string>>(json, JsonOpts) ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }

    private static object? DeserializeObject(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            return JsonSerializer.Deserialize<JsonElement>(json, JsonOpts);
        }
        catch
        {
            return null;
        }
    }
}
