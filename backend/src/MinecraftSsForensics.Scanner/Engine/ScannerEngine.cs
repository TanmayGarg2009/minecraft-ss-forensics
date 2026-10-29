using System.Runtime.InteropServices;
using MinecraftSsForensics.Api.Models.Domain;
using MinecraftSsForensics.Api.Models.Dtos.Ingestion;
using MinecraftSsForensics.Scanner.Archive;
using MinecraftSsForensics.Scanner.Hashing;
using MinecraftSsForensics.Scanner.LogsAndHistory;
using MinecraftSsForensics.Scanner.Lookalike;
using MinecraftSsForensics.Scanner.Process;
using MinecraftSsForensics.Scanner.Verification;

namespace MinecraftSsForensics.Scanner.Engine;

public interface IScannerEngine
{
    Task<SubmitReportRequest> ExecuteScanAsync(
        ScanMode mode,
        string? customDirectory = null,
        bool onlyCustomDirectory = false,
        IProgress<ScanProgressUpdate>? progress = null,
        CancellationToken ct = default);
}

public class ScannerEngine : IScannerEngine
{
    private readonly IFileHasher _hasher;
    private readonly ISafeArchiveInspector _archiveInspector;
    private readonly IModVerifier _verifier;
    private readonly LookalikeDetector _lookalikeDetector;
    private readonly IProcessScanner _processScanner;
    private readonly InstallationLocator _installationLocator;
    private readonly LogAuditor _logAuditor;
    private readonly HistoricalEvidenceScanner _historicalScanner;

    public ScannerEngine(
        IFileHasher? hasher = null,
        ISafeArchiveInspector? archiveInspector = null,
        IModVerifier? verifier = null,
        LookalikeDetector? lookalikeDetector = null,
        IProcessScanner? processScanner = null,
        InstallationLocator? installationLocator = null,
        LogAuditor? logAuditor = null,
        HistoricalEvidenceScanner? historicalScanner = null)
    {
        _hasher = hasher ?? new StreamingFileHasher();
        _archiveInspector = archiveInspector ?? new SafeArchiveInspector();
        _lookalikeDetector = lookalikeDetector ?? new LookalikeDetector();
        _processScanner = processScanner ?? new ProcessScanner(_hasher);
        _installationLocator = installationLocator ?? new InstallationLocator();
        _logAuditor = logAuditor ?? new LogAuditor();
        _historicalScanner = historicalScanner ?? new HistoricalEvidenceScanner();

        if (verifier == null)
        {
            var cache = new VerificationCache();
            var modrinth = new ModrinthVerificationProvider();
            var curse = new CurseForgeVerificationProvider();
            var github = new GitHubVerificationProvider();
            _verifier = new CompositeModVerifier(cache, modrinth, curse, github);
        }
        else
        {
            _verifier = verifier;
        }
    }

    public async Task<SubmitReportRequest> ExecuteScanAsync(
        ScanMode mode,
        string? customDirectory = null,
        bool onlyCustomDirectory = false,
        IProgress<ScanProgressUpdate>? progress = null,
        CancellationToken ct = default)
    {
        DateTimeOffset scanStart = DateTimeOffset.UtcNow;
        var update = new ScanProgressUpdate { PercentComplete = 5, CurrentCategory = "Initialization" };
        progress?.Report(update);

        var report = new SubmitReportRequest
        {
            SchemaVersion = "1.0.0",
            ScannerVersion = "1.0.0-rc2",
            ScanMode = mode == ScanMode.Quick ? "QUICK" : "FULL",
            OsName = RuntimeInformation.OSDescription,
            OsVersion = Environment.OSVersion.Version.ToString(),
            OsArchitecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
            ScanStartedAt = scanStart,
            ConsentConfirmation = new ConsentSubmissionDto
            {
                ConsentGiven = true,
                CollectionScopeVersion = "1.0",
                ConsentTimestamp = scanStart
            },
            RetentionDays = 7
        };

        int totalChecks = 0;
        int passedChecks = 0;
        int flaggedChecks = 0;
        int unavailableChecks = 0;

        // 1. Discover Installations
        update.CurrentCategory = "Installation Discovery";
        update.CurrentAction = "Searching for Minecraft directories and launcher instances...";
        update.PercentComplete = 10;
        progress?.Report(update);

        var installations = _installationLocator.DiscoverInstallations(customDirectory, onlyCustomDirectory);
        totalChecks++;
        if (installations.Count > 0)
        {
            passedChecks++;
            report.DiagnosticItems.Add(new DiagnosticItemSubmissionDto
            {
                CheckName = "Minecraft Installation Discovery",
                Source = "Filesystem",
                Status = "Completed",
                Reason = $"Discovered {installations.Count} installation(s) across known launcher paths."
            });
        }
        else
        {
            unavailableChecks++;
            report.DiagnosticItems.Add(new DiagnosticItemSubmissionDto
            {
                CheckName = "Minecraft Installation Discovery",
                Source = "Filesystem",
                Status = "CompletedWithLimitations",
                Reason = "No standard Minecraft installations found automatically. User may need to select custom directory.",
                Recommendation = "Select custom instance folder if using a portable or custom launcher."
            });
        }

        // 2. Discover and Hash Mod JARs
        update.CurrentCategory = "Mod Inventory & Safe Hashing";
        update.PercentComplete = 20;
        progress?.Report(update);

        var discoveredModFiles = new List<string>();
        foreach (var inst in installations)
        {
            if (inst.HasModsFolder)
            {
                try
                {
                    var jars = Directory.GetFiles(inst.ModsPath, "*.jar", SearchOption.TopDirectoryOnly);
                    discoveredModFiles.AddRange(jars);
                }
                catch (Exception ex)
                {
                    unavailableChecks++;
                    report.DiagnosticItems.Add(new DiagnosticItemSubmissionDto
                    {
                        CheckName = $"Mod Folder Access ({inst.Name})",
                        Source = "ModFolder",
                        Status = "AccessDenied",
                        Reason = $"Could not list mods in '{inst.ModsPath}': {ex.Message}",
                        Recommendation = "Check file system permissions on your game directory."
                    });
                }
            }
        }

        update.DiscoveredModsCount = discoveredModFiles.Count;
        progress?.Report(update);

        var discoveredMods = new List<DiscoveredMod>();
        var modsWithVerification = new List<(DiscoveredMod Mod, ModVerificationResult Verification)>();

        for (int i = 0; i < discoveredModFiles.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            string modPath = discoveredModFiles[i];
            string fileName = Path.GetFileName(modPath);

            update.CurrentAction = $"Inspecting and hashing {fileName}...";
            update.CurrentFileName = fileName;
            update.PercentComplete = 20 + (int)((i / (double)Math.Max(1, discoveredModFiles.Count)) * 30);
            progress?.Report(update);

            totalChecks++;
            var hashResult = await _hasher.ComputeHashesAsync(modPath, ct);
            if (!hashResult.Success || hashResult.IsMutatedDuringRead)
            {
                unavailableChecks++;
                report.DiagnosticItems.Add(new DiagnosticItemSubmissionDto
                {
                    CheckName = $"Hash Verification ({fileName})",
                    Source = "ModFolder",
                    Status = "CompletedWithLimitations",
                    Reason = hashResult.ErrorMessage ?? "File hashing failed or mutated during read."
                });
                continue;
            }
            passedChecks++;

            totalChecks++;
            var metaResult = await _archiveInspector.InspectModJarAsync(modPath, ct);
            if (!metaResult.ParseSuccess)
            {
                unavailableChecks++;
                report.DiagnosticItems.Add(new DiagnosticItemSubmissionDto
                {
                    CheckName = $"Archive Parsing ({fileName})",
                    Source = "ModFolder",
                    Status = "CompletedWithLimitations",
                    Reason = metaResult.ParseError ?? "Archive parse error."
                });
            }
            else
            {
                passedChecks++;
            }

            var fi = new FileInfo(modPath);
            var modItem = new DiscoveredMod
            {
                FilePath = modPath,
                FileName = fileName,
                FileSizeBytes = fi.Length,
                CreatedTimeUtc = fi.CreationTimeUtc,
                ModifiedTimeUtc = fi.LastWriteTimeUtc,
                Hashes = hashResult,
                Metadata = metaResult,
                InstallationDirectory = Path.GetDirectoryName(modPath) ?? string.Empty
            };
            discoveredMods.Add(modItem);

            // Verify mod against Modrinth / CurseForge / GitHub
            totalChecks++;
            var verResult = await _verifier.VerifyModAsync(modItem, ct);
            if (verResult.State == ModVerificationState.VERIFIED_EXACT_RELEASE)
            {
                passedChecks++;
                update.VerifiedModsCount++;
            }
            else if (verResult.State == ModVerificationState.VERIFICATION_UNAVAILABLE)
            {
                unavailableChecks++;
            }
            else
            {
                flaggedChecks++;
            }

            modsWithVerification.Add((modItem, verResult));
        }

        // Add Mod Inventory Evidence item
        report.EvidenceItems.Add(new EvidenceSubmissionDto
        {
            PublicEvidenceId = "evi_mod_inventory_01",
            Type = "ModInventory",
            Title = "Discovered Mod Inventory & Cryptographic Hashes",
            Description = $"Inventory of {discoveredMods.Count} mod archive(s) inspected across active installations.",
            StructuredPayload = modsWithVerification.Select(mv => new
            {
                Name = !string.IsNullOrEmpty(mv.Mod.Metadata.ModName) ? mv.Mod.Metadata.ModName : mv.Mod.FileName,
                mv.Mod.FileName,
                SizeBytes = mv.Mod.FileSizeBytes,
                FileSizeBytes = mv.Mod.FileSizeBytes,
                Sha256 = mv.Mod.Hashes.Sha256,
                Sha512 = mv.Mod.Hashes.Sha512,
                ModId = mv.Mod.Metadata.ModId,
                ModName = mv.Mod.Metadata.ModName,
                Version = mv.Mod.Metadata.Version,
                Loader = mv.Mod.Metadata.Loader,
                Verified = mv.Verification.State == ModVerificationState.VERIFIED_EXACT_RELEASE,
                VerificationState = mv.Verification.State.ToString(),
                VerificationProvider = mv.Verification.Provider,
                VerificationExplanation = mv.Verification.Explanation,
                ProjectUrl = mv.Verification.ProjectUrl,
                mv.Mod.Metadata.SuspiciousNotes
            }).ToList(),
            CapturedAt = DateTimeOffset.UtcNow,
            IsAvailable = true
        });

        // 3. Analyze Lookalikes, Renamed Mods, and Inconsistencies
        update.CurrentCategory = "Anomalies & Lookalike Analysis";
        update.CurrentAction = "Cross-referencing mod identities and detecting renamed lookalikes...";
        update.PercentComplete = 55;
        progress?.Report(update);

        var lookalikeFindings = _lookalikeDetector.AnalyzeMods(modsWithVerification);
        foreach (var lf in lookalikeFindings)
        {
            flaggedChecks++;
            report.Findings.Add(new FindingSubmissionDto
            {
                RuleId = lf.RuleId,
                Title = lf.Title,
                Category = FindingCategory.ModIntegrity.ToString(),
                Severity = lf.Severity,
                Confidence = lf.Confidence,
                Explanation = lf.Explanation,
                ObservedEvidence = new { lf.ObservedValue, lf.ExpectedValue },
                FilePath = lf.FilePath,
                FileSha256 = lf.FileSha256,
                EvidenceSource = lf.EvidenceSource,
                DetectionRuleVersion = "1.0.0",
                LimitationsAndFalsePositives = lf.Limitations
            });
        }

        // Add unverified or hash-mismatch findings for staff transparency
        foreach (var (mod, ver) in modsWithVerification)
        {
            if (ver.State == ModVerificationState.KNOWN_ARTIFACT_HASH_MISMATCH)
            {
                flaggedChecks++;
                report.Findings.Add(new FindingSubmissionDto
                {
                    RuleId = "MOD-HASH-MISMATCH",
                    Title = $"Cryptographic Hash Mismatch on Claimed Release: {mod.FileName}",
                    Category = FindingCategory.ModIntegrity.ToString(),
                    Severity = Severity.Medium.ToString(),
                    Confidence = ConfidenceLevel.Certain.ToString(),
                    Explanation = ver.Explanation,
                    FilePath = mod.FilePath,
                    FileSha256 = mod.Hashes.Sha256,
                    FileSizeBytes = mod.FileSizeBytes,
                    EvidenceSource = EvidenceSource.ModFolder.ToString(),
                    DetectionRuleVersion = "1.0.0",
                    LimitationsAndFalsePositives = ver.Limitations
                });
            }
            else if (ver.State == ModVerificationState.METADATA_CONFLICT)
            {
                flaggedChecks++;
                report.Findings.Add(new FindingSubmissionDto
                {
                    RuleId = "MOD-METADATA-CONFLICT",
                    Title = $"Metadata Conflict Between Filename and Mod ID: {mod.FileName}",
                    Category = FindingCategory.ModIntegrity.ToString(),
                    Severity = Severity.High.ToString(),
                    Confidence = ConfidenceLevel.High.ToString(),
                    Explanation = ver.Explanation,
                    FilePath = mod.FilePath,
                    FileSha256 = mod.Hashes.Sha256,
                    EvidenceSource = EvidenceSource.ModFolder.ToString(),
                    DetectionRuleVersion = "1.0.0",
                    LimitationsAndFalsePositives = ver.Limitations
                });
            }
            else if (ver.State == ModVerificationState.INVALID_OR_UNREADABLE_ARCHIVE)
            {
                flaggedChecks++;
                report.Findings.Add(new FindingSubmissionDto
                {
                    RuleId = "MOD-ARCHIVE-UNREADABLE",
                    Title = $"Unreadable or Corrupted Mod Archive: {mod.FileName}",
                    Category = FindingCategory.ModIntegrity.ToString(),
                    Severity = Severity.Low.ToString(),
                    Confidence = ConfidenceLevel.Certain.ToString(),
                    Explanation = ver.Explanation,
                    FilePath = mod.FilePath,
                    EvidenceSource = EvidenceSource.ModFolder.ToString(),
                    DetectionRuleVersion = "1.0.0",
                    LimitationsAndFalsePositives = ver.Limitations
                });
            }
        }

        // 4. Running Process and Module Inspection
        update.CurrentCategory = "Process & Runtime Inspection";
        update.CurrentAction = "Auditing active javaw.exe processes and loaded module handles...";
        update.PercentComplete = 70;
        progress?.Report(update);

        totalChecks++;
        var processes = _processScanner.ScanProcesses(inspectModules: true);
        if (processes.Count > 0)
        {
            passedChecks++;
            var gameProc = processes.FirstOrDefault(p => p.IsGameProcess);
            if (gameProc != null)
            {
                if (!string.IsNullOrEmpty(gameProc.JavaVersion))
                {
                    report.DetectedLoaders.Add($"Java {gameProc.JavaVersion}");
                }

                // Check for unsigned modules situated in temp directories
                var unsignedTempModules = gameProc.LoadedModules
                    .Where(m => !m.IsSigned && m.IsSuspiciousLocation)
                    .ToList();

                foreach (var mod in unsignedTempModules)
                {
                    flaggedChecks++;
                    report.Findings.Add(new FindingSubmissionDto
                    {
                        RuleId = "PROC-UNSIGNED-TEMP-MODULE",
                        Title = $"Unsigned Dynamic Library in Temp Directory Mapped to javaw.exe: {mod.ModuleName}",
                        Category = FindingCategory.ProcessInjection.ToString(),
                        Severity = Severity.High.ToString(),
                        Confidence = ConfidenceLevel.High.ToString(),
                        Explanation = $"Process PID {gameProc.ProcessId} (javaw.exe) has mapped '{mod.FilePath}'. The library lacks a verified digital signature and is situated in a temporary folder.",
                        FilePath = mod.FilePath,
                        FileSha256 = mod.Sha256,
                        ProcessId = gameProc.ProcessId,
                        ProcessName = gameProc.ProcessName,
                        EvidenceSource = EvidenceSource.ProcessMemoryMetadata.ToString(),
                        DetectionRuleVersion = "1.0.0",
                        LimitationsAndFalsePositives = "Some native overlays (Discord, OBS) or launcher crash handlers may compile native stubs to temp. Verify module exports."
                    });
                }

                // Record loaded modules evidence
                report.EvidenceItems.Add(new EvidenceSubmissionDto
                {
                    PublicEvidenceId = "evi_proc_modules_01",
                    Type = "LoadedModules",
                    Title = $"Loaded Modules for {gameProc.ProcessName} (PID {gameProc.ProcessId})",
                    Description = $"Enumerated {gameProc.LoadedModules.Count} module handles.",
                    RawContent = string.Join("\n", gameProc.LoadedModules.Select(m => $"[{ (m.IsSigned ? "SIGNED" : "UNSIGNED") }] {m.ModuleName} -> {m.FilePath}")),
                    CapturedAt = DateTimeOffset.UtcNow,
                    IsAvailable = true
                });

                // Record JVM arguments evidence
                if (!string.IsNullOrEmpty(gameProc.RedactedCommandLine))
                {
                    report.EvidenceItems.Add(new EvidenceSubmissionDto
                    {
                        PublicEvidenceId = "evi_jvm_args_01",
                        Type = "JvmArguments",
                        Title = "Redacted Java Virtual Machine Command Line",
                        Description = "Process invocation arguments with authentication tokens and secrets redacted.",
                        RawContent = gameProc.RedactedCommandLine,
                        CapturedAt = DateTimeOffset.UtcNow,
                        IsAvailable = true
                    });
                }
            }
        }
        else
        {
            report.DiagnosticItems.Add(new DiagnosticItemSubmissionDto
            {
                CheckName = "Active Minecraft Process Audit",
                Source = "ProcessMemoryMetadata",
                Status = "CompletedWithLimitations",
                Reason = "No active Minecraft (javaw.exe) process was running at the time of scan.",
                Recommendation = "If player was in-game, ensure scan is performed before closing Minecraft."
            });
        }

        // 5. Minecraft Logs Audit
        update.CurrentCategory = "Minecraft Logs & Sessions";
        update.CurrentAction = "Auditing latest session logs and crash dumps...";
        update.PercentComplete = 85;
        progress?.Report(update);

        foreach (var inst in installations)
        {
            if (inst.HasLogsFolder)
            {
                totalChecks++;
                string latestLog = Path.Combine(inst.LogsPath, "latest.log");
                var logResult = await _logAuditor.AuditLogFileAsync(latestLog, ct);

                if (!string.IsNullOrEmpty(logResult.DetectedMinecraftVersion))
                {
                    if (!report.DetectedMinecraftVersions.Contains(logResult.DetectedMinecraftVersion))
                        report.DetectedMinecraftVersions.Add(logResult.DetectedMinecraftVersion);
                }
                if (!string.IsNullOrEmpty(logResult.DetectedLoader))
                {
                    if (!report.DetectedLoaders.Contains(logResult.DetectedLoader))
                        report.DetectedLoaders.Add(logResult.DetectedLoader);
                }

                if (logResult.SuspiciousLogEntries.Count > 0)
                {
                    flaggedChecks++;
                    report.Findings.Add(new FindingSubmissionDto
                    {
                        RuleId = "LOG-SUSPICIOUS-SESSION-EVENT",
                        Title = $"Anomalous Log Entries in {Path.GetFileName(inst.Name)}",
                        Category = FindingCategory.Other.ToString(),
                        Severity = Severity.Low.ToString(),
                        Confidence = ConfidenceLevel.Medium.ToString(),
                        Explanation = $"Observed {logResult.SuspiciousLogEntries.Count} log line(s) referencing agent, injection, or anticheat terms.",
                        ObservedEvidence = logResult.SuspiciousLogEntries,
                        FilePath = latestLog,
                        EvidenceSource = EvidenceSource.EventLogs.ToString(),
                        DetectionRuleVersion = "1.0.0",
                        LimitationsAndFalsePositives = "Log terms may appear in mod compatibility debug warnings or harmless exception stacks."
                    });
                }

                // Add log timeline events
                if (logResult.SessionTimestamps.Count > 0)
                {
                    report.TimelineEvents.Add(new TimelineEventSubmissionDto
                    {
                        Timestamp = DateTimeOffset.UtcNow,
                        IsInferred = true,
                        Category = "SessionLog",
                        Description = $"Session active in {inst.Name} (First log time: {logResult.LastSessionStartTime})",
                        Source = "MinecraftLog",
                        Confidence = "High",
                        CorrelationGroup = "GRP-SESSION-1"
                    });
                }

                passedChecks++;
            }
        }

        // 6. Historical Artifacts (Full Scan Mode)
        if (mode == ScanMode.Full)
        {
            update.CurrentCategory = "Historical Artifacts (Full Scan)";
            update.CurrentAction = "Checking Windows Prefetch, BAM/DAM, and Temp artifact records...";
            update.PercentComplete = 90;
            progress?.Report(update);

            totalChecks++;
            var historicalRecords = _historicalScanner.ScanHistoricalArtifacts();

            foreach (var rec in historicalRecords)
            {
                if (rec.HasAccessDenied)
                {
                    unavailableChecks++;
                    report.DiagnosticItems.Add(new DiagnosticItemSubmissionDto
                    {
                        CheckName = $"{rec.Source} Inspection",
                        Source = rec.Source,
                        Status = "AccessDenied",
                        Reason = rec.LimitationNote ?? "Access denied in non-admin user mode.",
                        Recommendation = "Run as Administrator if your server requires deep Prefetch/BAM audit."
                    });
                }
                else
                {
                    passedChecks++;
                    if (!string.IsNullOrEmpty(rec.Path))
                    {
                        report.TimelineEvents.Add(new TimelineEventSubmissionDto
                        {
                            Timestamp = rec.Timestamp ?? DateTimeOffset.UtcNow,
                            IsInferred = rec.Timestamp == null,
                            Category = "HistoricalArtifact",
                            Description = rec.Description,
                            Source = rec.Source,
                            Confidence = "High",
                            CorrelationGroup = "GRP-HIST-1"
                        });
                    }
                }
            }
        }

        // 7. Finalize Coverage Summary
        update.PercentComplete = 100;
        update.CurrentCategory = "Complete";
        update.CurrentAction = "Scan completed. Assembling report payload...";
        update.FlaggedFindingsCount = report.Findings.Count;
        progress?.Report(update);

        report.ScanCompletedAt = DateTimeOffset.UtcNow;
        report.CollectionCoverage = new CoverageSubmissionDto
        {
            TotalChecks = Math.Max(totalChecks, passedChecks + flaggedChecks + unavailableChecks),
            PassedChecks = passedChecks,
            FlaggedChecks = flaggedChecks,
            UnavailableChecks = unavailableChecks
        };

        return report;
    }
}
