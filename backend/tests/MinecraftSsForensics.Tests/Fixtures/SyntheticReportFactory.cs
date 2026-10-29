using MinecraftSsForensics.Api.Models.Dtos.Ingestion;

namespace MinecraftSsForensics.Tests.Fixtures;

public static class SyntheticReportFactory
{
    public static SubmitReportRequest CreateValidReportRequest(string scanMode = "FULL", int retentionDays = 7)
    {
        return new SubmitReportRequest
        {
            SchemaVersion = "1.0.0",
            ScannerVersion = "1.0.0-synthetic-test",
            ScanMode = scanMode,
            OsName = "Windows 11 Pro",
            OsVersion = "10.0.22631",
            OsArchitecture = "x64",
            ScanStartedAt = DateTimeOffset.UtcNow.AddMinutes(-5),
            ScanCompletedAt = DateTimeOffset.UtcNow,
            DetectedMinecraftVersions = new List<string> { "1.8.9", "1.20.4" },
            DetectedLoaders = new List<string> { "Forge 11.15.1.2318", "Lunar Client 1.8.9" },
            ConsentConfirmation = new ConsentSubmissionDto
            {
                ConsentGiven = true,
                CollectionScopeVersion = "1.0",
                ConsentTimestamp = DateTimeOffset.UtcNow.AddMinutes(-6)
            },
            CollectionCoverage = new CoverageSubmissionDto
            {
                TotalChecks = 42,
                PassedChecks = 40,
                FlaggedChecks = 2,
                UnavailableChecks = 0
            },
            RetentionDays = retentionDays,
            Findings = new List<FindingSubmissionDto>
            {
                new()
                {
                    RuleId = "WIN-PREF-001",
                    Title = "Synthetic Detection: Unregistered Autoclicker Executable in Prefetch",
                    Category = "ExecutionArtifacts",
                    Severity = "High",
                    Confidence = "High",
                    Explanation = "Prefetch indicates an execution artifact matching known clicker signature 'clicker_v2.exe' ran 14 minutes prior to screenshare.",
                    FilePath = @"C:\Users\Player\Downloads\clicker_v2.exe",
                    FileSizeBytes = 412000,
                    FileSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    FirstObservedAt = DateTimeOffset.UtcNow.AddMinutes(-14),
                    LastObservedAt = DateTimeOffset.UtcNow.AddMinutes(-12),
                    EvidenceSource = "Prefetch",
                    DetectionRuleVersion = "1.2.0",
                    LimitationsAndFalsePositives = "Prefetch records execution only, not memory injection directly. Could be an unrelated testing utility if configured differently."
                },
                new()
                {
                    RuleId = "MC-MOD-004",
                    Title = "Synthetic Detection: Deleted JAR file recorded in USN Journal",
                    Category = "FileDeletion",
                    Severity = "Medium",
                    Confidence = "Medium",
                    Explanation = "NTFS USN Journal recorded deletion of a file named 'ReachMod.jar' from .minecraft/mods 3 minutes before investigation call.",
                    FilePath = @"C:\Users\Player\AppData\Roaming\.minecraft\mods\ReachMod.jar",
                    FileSizeBytes = 184500,
                    FirstObservedAt = DateTimeOffset.UtcNow.AddMinutes(-3),
                    LastObservedAt = DateTimeOffset.UtcNow.AddMinutes(-3),
                    EvidenceSource = "UsnJournal",
                    DetectionRuleVersion = "1.0.4",
                    LimitationsAndFalsePositives = "Normal users may delete outdated mods. Correlation with launcher restart needed for definitive assessment."
                }
            },
            EvidenceItems = new List<EvidenceSubmissionDto>
            {
                new()
                {
                    PublicEvidenceId = "ev_pref_001",
                    Type = "WindowsArtifact",
                    Title = "Prefetch Dump for javaw.exe and clicker_v2.exe",
                    Description = "Extracted prefetch header and run count records.",
                    RawContent = "[SYNTHETIC PREFETCH DUMP]\nFile: CLICKER_V2.EXE-A4B8C1D2.pf\nRun Count: 3\nLast Run: 2026-10-29T18:45:00Z",
                    Sha256Hash = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
                    IsAvailable = true
                },
                new()
                {
                    PublicEvidenceId = "ev_jvm_002",
                    Type = "JvmArguments",
                    Title = "Active Minecraft JVM Launch Arguments",
                    Description = "Parsed flags from javaw.exe process invocation.",
                    RawContent = "-Xmx4G -XX:+UseG1GC -Dminecraft.applet.TargetDirectory=C:\\Users\\Player\\AppData\\Roaming\\.minecraft",
                    IsAvailable = true
                }
            },
            TimelineEvents = new List<TimelineEventSubmissionDto>
            {
                new()
                {
                    Timestamp = DateTimeOffset.UtcNow.AddMinutes(-15),
                    IsInferred = false,
                    Category = "Execution",
                    Description = "clicker_v2.exe executed (Prefetch timestamp)",
                    Source = "Windows Prefetch",
                    Confidence = "High"
                },
                new()
                {
                    Timestamp = DateTimeOffset.UtcNow.AddMinutes(-3),
                    IsInferred = false,
                    Category = "FileDeletion",
                    Description = "ReachMod.jar deleted from .minecraft/mods",
                    Source = "USN Journal",
                    Confidence = "Medium",
                    CorrelationGroup = "CORR-01"
                },
                new()
                {
                    Timestamp = DateTimeOffset.UtcNow.AddMinutes(-1),
                    IsInferred = false,
                    Category = "Consent",
                    Description = "Player consented to diagnostic scan collection scope v1.0",
                    Source = "Scanner Agent UI",
                    Confidence = "Certain"
                }
            },
            DiagnosticItems = new List<DiagnosticItemSubmissionDto>
            {
                new()
                {
                    CheckName = "BAM / DAM Background Activity Moderator",
                    Source = "Registry (SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings)",
                    Status = "Completed",
                    Reason = "Successfully parsed 12 BAM entries."
                },
                new()
                {
                    CheckName = "Kernel Memory Driver Hook Check",
                    Source = "Driver Interface",
                    Status = "Skipped",
                    Reason = "User mode scanner does not install kernel drivers (by design for player privacy).",
                    Recommendation = "Rely on user-mode memory metadata and NTFS journal records."
                }
            }
        };
    }
}
