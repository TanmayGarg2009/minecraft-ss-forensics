using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using MinecraftSsForensics.Scanner.Archive;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Collectors;
using MinecraftSsForensics.Scanner.Correlation;
using MinecraftSsForensics.Scanner.Hashing;
using MinecraftSsForensics.Scanner.Integrity;
using MinecraftSsForensics.Scanner.LogsAndHistory;
using MinecraftSsForensics.Scanner.Lookalike;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Policy;
using MinecraftSsForensics.Scanner.Process;
using MinecraftSsForensics.Scanner.Verification;

namespace MinecraftSsForensics.Scanner.Engine;

public interface IStandaloneScannerEngine
{
    Task<StandaloneReport> ExecuteScanAsync(
        ConsentScopeConfig consent,
        string scanMode = "QUICK",
        string? customDirectory = null,
        bool onlyCustomDirectory = false,
        IProgress<ScanProgressUpdate>? progress = null,
        ServerGamemodePolicy? policy = null,
        CancellationToken ct = default);
}

public class StandaloneScannerEngine : IStandaloneScannerEngine
{
    private readonly IFileHasher _hasher;
    private readonly ISafeArchiveInspector _archiveInspector;
    private readonly IModVerifier _verifier;
    private readonly LookalikeDetector _lookalikeDetector;
    private readonly IProcessScanner _processScanner;
    private readonly InstallationLocator _installationLocator;
    private readonly LogAuditor _logAuditor;
    private readonly HistoricalEvidenceScanner _historicalScanner;
    private readonly RegistryScanner _registryScanner;
    private readonly UsbHistoryScanner _usbScanner;
    private readonly BrowserHistoryScanner _browserScanner;
    private readonly FileDiscoveryScanner _fileDiscoveryScanner;
    private readonly ServiceAndDriverScanner _serviceScanner;
    private readonly EvidenceCorrelationEngine _correlationEngine;
    private readonly ModPolicyEngine _policyEngine;

    public StandaloneScannerEngine(
        IFileHasher? hasher = null,
        ISafeArchiveInspector? archiveInspector = null,
        IModVerifier? verifier = null,
        LookalikeDetector? lookalikeDetector = null,
        IProcessScanner? processScanner = null,
        InstallationLocator? installationLocator = null,
        LogAuditor? logAuditor = null,
        HistoricalEvidenceScanner? historicalScanner = null,
        RegistryScanner? registryScanner = null,
        UsbHistoryScanner? usbScanner = null,
        BrowserHistoryScanner? browserScanner = null,
        FileDiscoveryScanner? fileDiscoveryScanner = null,
        ServiceAndDriverScanner? serviceScanner = null,
        EvidenceCorrelationEngine? correlationEngine = null,
        ModPolicyEngine? policyEngine = null)
    {
        _hasher = hasher ?? new StreamingFileHasher();
        _archiveInspector = archiveInspector ?? new SafeArchiveInspector();
        _lookalikeDetector = lookalikeDetector ?? new LookalikeDetector();
        _processScanner = processScanner ?? new ProcessScanner(_hasher);
        _installationLocator = installationLocator ?? new InstallationLocator();
        _logAuditor = logAuditor ?? new LogAuditor();
        _historicalScanner = historicalScanner ?? new HistoricalEvidenceScanner();
        _registryScanner = registryScanner ?? new RegistryScanner();
        _usbScanner = usbScanner ?? new UsbHistoryScanner();
        _browserScanner = browserScanner ?? new BrowserHistoryScanner();
        _fileDiscoveryScanner = fileDiscoveryScanner ?? new FileDiscoveryScanner(_hasher);
        _serviceScanner = serviceScanner ?? new ServiceAndDriverScanner();
        _policyEngine = policyEngine ?? new ModPolicyEngine();
        _correlationEngine = correlationEngine ?? new EvidenceCorrelationEngine(_policyEngine);

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

    public async Task<StandaloneReport> ExecuteScanAsync(
        ConsentScopeConfig consent,
        string scanMode = "QUICK",
        string? customDirectory = null,
        bool onlyCustomDirectory = false,
        IProgress<ScanProgressUpdate>? progress = null,
        ServerGamemodePolicy? policy = null,
        CancellationToken ct = default)
    {
        if (!consent.IsValidConsent(out string consentErr))
        {
            throw new InvalidOperationException($"Scan aborted: {consentErr}");
        }

        var stopwatch = Stopwatch.StartNew();
        DateTimeOffset scanStart = DateTimeOffset.UtcNow;
        var activePolicy = policy ?? _policyEngine.Registry.GetPolicy("Crystal PvP");

        var report = new StandaloneReport
        {
            ScanMode = scanMode.ToUpperInvariant(),
            ScanStartedAt = scanStart,
            Consent = consent,
            PolicyEvaluation = new PolicyEvaluationSummary
            {
                AppliedGamemode = activePolicy.Gamemode,
                AppliedPolicyName = activePolicy.PolicyName,
                AppliedPolicyVersion = activePolicy.PolicyVersion,
                RulesDocumentationUrl = activePolicy.ServerRulesUrl ?? string.Empty
            },
            TargetSystem = new TargetSystemInfo
            {
                OsName = RuntimeInformation.OSDescription,
                OsVersion = Environment.OSVersion.Version.ToString(),
                Architecture = RuntimeInformation.ProcessArchitecture.ToString().ToUpperInvariant()
            }
        };

        var update = new ScanProgressUpdate { PercentComplete = 5, CurrentCategory = "Initialization", CurrentAction = "Starting forensic audit..." };
        progress?.Report(update);

        // 1. Locate Minecraft Installations
        update.CurrentCategory = "Game Installation Discovery";
        update.CurrentAction = "Searching for Minecraft and third-party launcher directories...";
        update.PercentComplete = 10;
        progress?.Report(update);

        var installations = new List<string>();
        if (!string.IsNullOrWhiteSpace(customDirectory) && Directory.Exists(customDirectory))
        {
            installations.Add(customDirectory);
            report.MinecraftInstallations.Add(new MinecraftInstallationInfo
            {
                Name = "Custom Specified Directory",
                RootPath = customDirectory,
                Exists = true,
                LauncherType = "Custom / Profile"
            });
        }

        if (!onlyCustomDirectory)
        {
            var discovered = _installationLocator.DiscoverInstallations(customDirectory, onlyCustomDirectory);
            foreach (var inst in discovered)
            {
                if ((inst.HasModsFolder || inst.HasLogsFolder || Directory.Exists(inst.RootPath)) &&
                    !installations.Contains(inst.RootPath, StringComparer.OrdinalIgnoreCase))
                {
                    installations.Add(inst.RootPath);
                    report.MinecraftInstallations.Add(new MinecraftInstallationInfo
                    {
                        Name = inst.Name,
                        RootPath = inst.RootPath,
                        Exists = true,
                        LauncherType = inst.LauncherType
                    });
                }
            }
        }

        report.DiagnosticChecks.Add(new DiagnosticCheckItem
        {
            CheckId = "CHK-INSTALLATIONS",
            CheckName = "Minecraft Client Discovery",
            Source = "InstallationLocator",
            Status = installations.Count > 0 ? CheckStatus.PASSED : CheckStatus.FLAGGED,
            Reason = installations.Count > 0
                ? $"Located {installations.Count} game directory profile(s)."
                : "No Minecraft directory was discovered automatically."
        });

        // 2. Discover and Inspect Mod JARs
        if (consent.InspectMinecraftMods)
        {
            update.CurrentCategory = "Mod Folder Discovery";
            update.CurrentAction = "Scanning active mods, calculating SHA-256 hashes, and inspecting JAR contents...";
            update.PercentComplete = 25;
            progress?.Report(update);

            var modJars = new List<string>();
            foreach (var instPath in installations)
            {
                string modsFolder = Path.Combine(instPath, "mods");
                if (Directory.Exists(modsFolder))
                {
                    try
                    {
                        var files = Directory.GetFiles(modsFolder, "*.jar", SearchOption.TopDirectoryOnly);
                        modJars.AddRange(files);
                    }
                    catch { /* Restricted folder permissions */ }
                }
            }

            // Deduplicate JAR paths
            modJars = modJars.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

            var modsWithVerification = new List<(DiscoveredMod Mod, ModVerificationResult Verification)>();

            for (int i = 0; i < modJars.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                string jarPath = modJars[i];
                string fileName = Path.GetFileName(jarPath);

                update.CurrentAction = $"Inspecting mod ({i + 1}/{modJars.Count}): {fileName}";
                update.PercentComplete = 25 + (int)((double)i / Math.Max(1, modJars.Count) * 25);
                progress?.Report(update);

                var hashResult = await _hasher.ComputeHashesAsync(jarPath, ct);
                var meta = await _archiveInspector.InspectModJarAsync(jarPath, ct);

                var discoveredMod = new DiscoveredMod
                {
                    FilePath = jarPath,
                    FileName = fileName,
                    FileSizeBytes = hashResult.FileSizeBytes,
                    CreatedTimeUtc = File.Exists(jarPath) ? File.GetCreationTimeUtc(jarPath) : DateTime.UtcNow,
                    ModifiedTimeUtc = File.Exists(jarPath) ? File.GetLastWriteTimeUtc(jarPath) : DateTime.UtcNow,
                    Hashes = hashResult,
                    Metadata = meta,
                    InstallationDirectory = Path.GetDirectoryName(Path.GetDirectoryName(jarPath)) ?? string.Empty
                };

                // Mod Verification
                ModVerificationResult verResult;
                if (consent.PerformOnlineVerification)
                {
                    try
                    {
                        verResult = await _verifier.VerifyModAsync(discoveredMod, ct);
                    }
                    catch
                    {
                        verResult = new ModVerificationResult
                        {
                            State = ModVerificationState.VERIFICATION_UNAVAILABLE,
                            Explanation = "Online mod verification service was unavailable or timed out."
                        };
                    }
                }
                else
                {
                    verResult = new ModVerificationResult
                    {
                        State = ModVerificationState.UNKNOWN_OR_UNLISTED,
                        Explanation = "Online verification omitted per consent scope."
                    };
                }

                bool isVerified = verResult.State == ModVerificationState.VERIFIED_EXACT_RELEASE || verResult.State == ModVerificationState.VERIFIED_TRUSTED_SIGNATURE;
                string verState = verResult.State.ToString();

                // Evaluate Policy
                var polEval = _policyEngine.EvaluateMod(discoveredMod, verResult, activePolicy);

                var modItem = new DiscoveredModItem
                {
                    Name = !string.IsNullOrWhiteSpace(meta.ModName) ? meta.ModName : (!string.IsNullOrWhiteSpace(meta.ModId) ? meta.ModId : Path.GetFileNameWithoutExtension(fileName)),
                    FileName = fileName,
                    FullPath = jarPath,
                    FileSizeBytes = hashResult.FileSizeBytes,
                    Sha256 = hashResult.Sha256 ?? string.Empty,
                    ModId = meta.ModId ?? "unknown",
                    Version = meta.Version ?? "1.0",
                    Loader = meta.Loader,
                    Verified = isVerified,
                    VerificationState = verState,
                    VerificationProvider = verResult.Provider ?? "None",
                    ProjectUrl = verResult.ProjectUrl,
                    GameplayPolicy = polEval.Policy.ToString(),
                    BehaviorCategory = polEval.Behavior.ToString(),
                    PolicyReason = polEval.Reason,
                    HasConflictingSignals = polEval.HasConflictingSignals,
                    ConflictDetails = polEval.ConflictDetails
                };

                report.ModInventory.Add(modItem);
                modsWithVerification.Add((discoveredMod, verResult));

                // Check for Known Cheat Signatures in Class Names or Filenames
                var cheatFileMatch = CheatDetectionDatabase.MatchFileName(fileName);
                if (cheatFileMatch != null)
                {
                    report.Findings.Add(new FindingRecord
                    {
                        RuleId = "CHEAT-JAR-FILENAME",
                        DetectionName = $"Known Cheat Client JAR on Disk: {cheatFileMatch.Name}",
                        Category = FindingCategory.CheatArtifact,
                        Classification = FindingClassification.ConfirmedCheatArtifact,
                        Severity = Severity.Critical,
                        Confidence = ConfidenceLevel.Certain,
                        EvidenceState = EvidenceState.CONFIRMED,
                        SoftwareState = SoftwareEvidenceState.SoftwareInstalled,
                        SoftwareStateDescription = "Known cheat client JAR is installed in the active Minecraft profile mods folder.",
                        PolicyViolationScope = "PROHIBITED_POSSESSION",
                        EvidenceSource = "ModFolder",
                        FilePath = jarPath,
                        FileSha256 = hashResult.Sha256,
                        FileSizeBytes = hashResult.FileSizeBytes,
                        TechnicalExplanation = $"Mod archive '{fileName}' matches signature for '{cheatFileMatch.Name}'. Description: {cheatFileMatch.Description}",
                        WhyItMatters = "Known competitive cheat client found in active Minecraft mods directory.",
                        AlternativeLegitimateExplanations = "None for verified cheat signatures.",
                        WhatIsProven = "Cheat file was loaded in the mods directory.",
                        WhatIsNotProven = "Does not prove in-game features were toggled during match without session correlation.",
                        Limitations = "Presence in mods folder confirms installation, but does not prove features were toggled during match without session correlation."
                    });
                }
                else if (meta.MatchedCheatSignatures.Count > 0)
                {
                    report.Findings.Add(new FindingRecord
                    {
                        RuleId = "CHEAT-BYTECODE-CLASS",
                        DetectionName = $"Cheat Bytecode / Class Match: {meta.MatchedCheatSignatures[0]}",
                        Category = FindingCategory.CheatArtifact,
                        Classification = FindingClassification.ConfirmedCheatArtifact,
                        Severity = Severity.Critical,
                        Confidence = ConfidenceLevel.Certain,
                        EvidenceState = EvidenceState.CONFIRMED,
                        SoftwareState = SoftwareEvidenceState.SoftwareInstalled,
                        SoftwareStateDescription = "Archive contains internal classes matching known cheat package.",
                        PolicyViolationScope = "PROHIBITED_POSSESSION",
                        EvidenceSource = "JAR Archive Bytecode",
                        FilePath = jarPath,
                        FileSha256 = hashResult.Sha256,
                        FileSizeBytes = hashResult.FileSizeBytes,
                        TechnicalExplanation = $"Archive '{fileName}' contains internal class matching known cheat package: {string.Join(", ", meta.MatchedCheatSignatures)}",
                        WhyItMatters = "Bytecode class analysis indicates modified or disguised cheat jar.",
                        AlternativeLegitimateExplanations = "Custom mod developer testing local build.",
                        WhatIsProven = "The mod archive contains cheat class bytecode.",
                        WhatIsNotProven = "Does not prove feature activation during gameplay.",
                        Limitations = "Bytecode match proves internal capability and possession; does not prove feature activation during gameplay."
                    });
                }
                else if (polEval.Policy.IsProhibited())
                {
                    report.Findings.Add(new FindingRecord
                    {
                        RuleId = "MOD-POLICY-PROHIBITED",
                        DetectionName = $"Prohibited Mod Under {activePolicy.Gamemode} Ruleset: {modItem.Name}",
                        Category = FindingCategory.ModIntegrity,
                        Classification = FindingClassification.ConfirmedCheatArtifact,
                        Severity = Severity.High,
                        Confidence = ConfidenceLevel.Certain,
                        EvidenceState = EvidenceState.CONFIRMED,
                        SoftwareState = SoftwareEvidenceState.SoftwareInstalled,
                        SoftwareStateDescription = $"Mod is installed in active profile mods folder under {activePolicy.Gamemode} ruleset.",
                        PolicyViolationScope = polEval.Policy.ToString(),
                        EvidenceSource = "ModPolicyEngine",
                        FilePath = jarPath,
                        FileSha256 = hashResult.Sha256,
                        FileSizeBytes = hashResult.FileSizeBytes,
                        TechnicalExplanation = $"Mod '{modItem.Name}' is prohibited under active {activePolicy.Gamemode} ruleset. Reason: {polEval.Reason}",
                        WhyItMatters = "Provides prohibited gameplay advantages in active competitive gamemode.",
                        AlternativeLegitimateExplanations = "Player may use this profile for other servers or singleplayer.",
                        WhatIsProven = "Mod is installed in the active profile.",
                        WhatIsNotProven = polEval.Policy == GameplayPolicy.PROHIBITED_POSSESSION
                            ? "Gameplay use is not proven, but is not required under the applicable possession policy."
                            : "Does not prove the feature was used during competition.",
                        Limitations = polEval.Reason
                    });
                }
                else if (meta.BytecodeAnalysis != null && meta.BytecodeAnalysis.HasAutomationCapabilities)
                {
                    report.Findings.Add(new FindingRecord
                    {
                        RuleId = "MOD-BYTECODE-AUTOMATION",
                        DetectionName = $"Automation Capabilities in Mod Bytecode: {modItem.Name}",
                        Category = FindingCategory.ModIntegrity,
                        Classification = FindingClassification.NeedsReview,
                        Severity = Severity.Medium,
                        Confidence = ConfidenceLevel.Certain,
                        EvidenceState = EvidenceState.STRONG_INDICATOR,
                        SoftwareState = SoftwareEvidenceState.SoftwareInstalled,
                        SoftwareStateDescription = "Mod archive contains constant pool bytecode references for automated combat, crystal placement, or packet manipulation.",
                        PolicyViolationScope = "NEEDS_REVIEW",
                        EvidenceSource = "StaticBytecodeAnalyzer",
                        FilePath = jarPath,
                        FileSha256 = hashResult.Sha256,
                        FileSizeBytes = hashResult.FileSizeBytes,
                        TechnicalExplanation = $"Static bytecode constant pool analysis identified capabilities: {string.Join(", ", meta.BytecodeAnalysis.DetectedCapabilities.Select(c => c.CapabilityType).Distinct())}.",
                        WhyItMatters = "Mod contains automation or packet manipulation structures that may violate competitive server policies.",
                        AlternativeLegitimateExplanations = "Mod may use mixins or packet listeners for legitimate quality-of-life or diagnostic features.",
                        WhatIsProven = "Archive contains structural capability bytecode.",
                        WhatIsNotProven = "Does NOT prove in-game use without runtime session correlation.",
                        Limitations = "Structural bytecode capability does not establish in-game execution or toggling during matches."
                    });
                }
            }

            // Lookalike check & Duplicate Mod ID check
            var lookalikeFindings = _lookalikeDetector.AnalyzeMods(modsWithVerification);
            foreach (var lookalike in lookalikeFindings)
            {
                // Renamed verified mod is purely informational; altered hash is suspicious
                bool isAuthentic = lookalike.RuleId.StartsWith("INFO-", StringComparison.OrdinalIgnoreCase);
                report.Findings.Add(new FindingRecord
                {
                    RuleId = lookalike.RuleId,
                    DetectionName = lookalike.Title,
                    Category = FindingCategory.ModIntegrity,
                    Classification = isAuthentic ? FindingClassification.Informational : FindingClassification.Suspicious,
                    Severity = isAuthentic ? Severity.Informational : Severity.High,
                    Confidence = isAuthentic ? ConfidenceLevel.Certain : ConfidenceLevel.High,
                    EvidenceSource = lookalike.EvidenceSource,
                    FilePath = lookalike.FilePath,
                    FileSha256 = lookalike.FileSha256,
                    TechnicalExplanation = lookalike.Explanation,
                    WhyItMatters = isAuthentic
                        ? "Mod file was renamed by user, but cryptographic hash confirms exact authentic release."
                        : "Potentially spoofed filename or duplicate mod ID masking custom or unlisted mod bytecode.",
                    AlternativeLegitimateExplanations = "User launcher sorting or local build numbering."
                });
            }

            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-MOD-INVENTORY",
                CheckName = "Mod Inventory & Policy Audit",
                Source = "ModPolicyEngine",
                Status = CheckStatus.PASSED,
                Reason = $"Audited {report.ModInventory.Count} mod JARs against {activePolicy.Gamemode} ruleset."
            });
        }
        else
        {
            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-MOD-INVENTORY",
                CheckName = "Mod Inventory & Policy Audit",
                Source = "ModPolicyEngine",
                Status = CheckStatus.SKIPPED,
                Reason = "Mod folder inspection was excluded from scan scope."
            });
        }

        // 3. Process & Runtime Modules (with JNA false positive mitigation)
        if (consent.InspectProcessesAndModules)
        {
            update.CurrentCategory = "Process & Runtime Inspection";
            update.CurrentAction = "Auditing active javaw.exe processes and loaded module handles...";
            update.PercentComplete = 60;
            progress?.Report(update);

            var processes = _processScanner.ScanProcesses(inspectModules: true);
            foreach (var proc in processes)
            {
                report.RunningProcesses.Add(new ProcessTelemetryItem
                {
                    ProcessId = proc.ProcessId,
                    ProcessName = proc.ProcessName,
                    ExecutablePath = proc.ExecutablePath,
                    ParentProcessId = proc.ParentProcessId,
                    ParentProcessName = proc.ParentProcessName,
                    SanitizedCommandLine = proc.RedactedCommandLine,
                    StartTime = proc.StartTime.HasValue ? new DateTimeOffset(proc.StartTime.Value) : null
                });

                if (proc.IsGameProcess)
                {
                    report.JavaRuntime.JavaExecutablePath = proc.ExecutablePath;
                    report.JavaRuntime.RawJvmArguments = proc.RedactedCommandLine;

                    foreach (var mod in proc.LoadedModules)
                    {
                        var modItem = new LoadedModuleItem
                        {
                            ProcessId = proc.ProcessId,
                            ModuleName = mod.ModuleName,
                            FilePath = mod.FilePath,
                            FileSizeBytes = mod.FileSizeBytes,
                            IsInTempDirectory = mod.IsSuspiciousLocation,
                            IsRecognizedJavaNativeLibrary = mod.IsRecognizedJavaNativeLibrary,
                            ProvenanceAssessment = mod.ProvenanceAssessment
                        };
                        report.LoadedModules.Add(modItem);

                        // Suspicious temp DLLs that are NOT legitimate Java native libraries
                        if (mod.IsSuspiciousLocation && !mod.IsRecognizedJavaNativeLibrary && !mod.IsSigned)
                        {
                            report.Findings.Add(new FindingRecord
                            {
                                RuleId = "PROC-SUSP-TEMP-MODULE",
                                DetectionName = $"Unsigned Temporary DLL Loaded into javaw.exe: {mod.ModuleName}",
                                Category = FindingCategory.ProcessInjection,
                                Classification = FindingClassification.Suspicious,
                                Severity = Severity.High,
                                Confidence = ConfidenceLevel.Medium,
                                EvidenceSource = "ProcessMemoryMetadata",
                                FilePath = mod.FilePath,
                                ProcessId = proc.ProcessId,
                                ProcessName = proc.ProcessName,
                                TechnicalExplanation = $"Process PID {proc.ProcessId} (javaw.exe) has loaded module '{mod.FilePath}' from a temporary directory without Java native library provenance (JNA/LWJGL).",
                                WhyItMatters = "Screenshare bypasses and injected cheat DLLs commonly load from temporary directories.",
                                AlternativeLegitimateExplanations = "Custom third-party screen recorder, Discord overlay, or graphics driver hook.",
                                WhatIsProven = "Module was mapped into javaw.exe process memory.",
                                WhatIsNotProven = "Does not prove malicious intent without reverse-engineering module exports."
                            });
                        }
                    }
                }
            }

            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-PROCESS-MODULES",
                CheckName = "Active Process & Loaded Module Audit",
                Source = "ProcessScanner",
                Status = processes.Any(p => p.IsGameProcess) ? CheckStatus.PASSED : CheckStatus.FLAGGED,
                Reason = processes.Any(p => p.IsGameProcess)
                    ? $"Audited active Minecraft game process (PID {processes.First(p => p.IsGameProcess).ProcessId}) and loaded modules."
                    : "No active Minecraft javaw.exe process was running during scan."
            });
        }

        // 4. Execution Artifacts (Prefetch, BAM, PCA, PowerShell)
        if (consent.InspectExecutionArtifacts)
        {
            update.CurrentCategory = "Execution History";
            update.CurrentAction = "Auditing Windows Prefetch, BAM, PCA, and command history...";
            update.PercentComplete = 75;
            progress?.Report(update);

            var histRecords = _historicalScanner.ScanHistoricalArtifacts();
            foreach (var hr in histRecords)
            {
                report.ExecutionHistory.Add(new ExecutionHistoryItem
                {
                    Source = hr.Source,
                    ApplicationName = Path.GetFileName(hr.Path),
                    ApplicationPath = hr.Path,
                    LastExecutionTime = hr.Timestamp.HasValue ? new DateTimeOffset(hr.Timestamp.Value) : null,
                    Details = hr.Description
                });
            }

            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-EXEC-HISTORY",
                CheckName = "Windows Execution History Audit",
                Source = "Prefetch/BAM",
                Status = CheckStatus.PASSED,
                Reason = $"Collected {histRecords.Count} execution history entries."
            });
        }

        // 5. Registry Artifacts (UserAssist, Run Keys, RecentDocs)
        if (consent.InspectRegistryArtifacts)
        {
            update.CurrentCategory = "Registry Forensics";
            update.CurrentAction = "Inspecting UserAssist, PcaSvc, and Run keys...";
            update.PercentComplete = 85;
            progress?.Report(update);

            var regItems = _registryScanner.ScanRegistryArtifacts(out var regFindings);
            report.RegistryEvidence.AddRange(regItems);
            report.Findings.AddRange(regFindings);

            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-REGISTRY",
                CheckName = "Windows Registry Artifacts",
                Source = "RegistryScanner",
                Status = CheckStatus.PASSED,
                Reason = $"Audited UserAssist, PCA, and Run registry hives ({regItems.Count} entries collected)."
            });
        }

        // 6. USB Storage History
        if (consent.InspectUsbHistory)
        {
            var usbDevices = _usbScanner.ScanUsbStorageDevices(out var usbFindings);
            report.UsbEvidence.AddRange(usbDevices);
            report.Findings.AddRange(usbFindings);

            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-USB-HISTORY",
                CheckName = "USB Storage Device History",
                Source = "USBSTOR",
                Status = CheckStatus.PASSED,
                Reason = $"Enumerated {usbDevices.Count} historically connected USB storage device(s)."
            });
        }

        // 7. Sensitive Category: Browser History (Explicitly Optional!)
        var browserItems = _browserScanner.ScanBrowserArtifacts(consent.InspectBrowserHistory, out var browserFindings, out var browserDiag);
        report.BrowserEvidence.AddRange(browserItems);
        report.Findings.AddRange(browserFindings);
        report.DiagnosticChecks.Add(browserDiag);

        // 8. Filesystem Discovery (Downloads, Desktop, Temp, Recycle Bin)
        if (consent.InspectFileDiscovery)
        {
            update.CurrentCategory = "File Discovery";
            update.CurrentAction = "Auditing user staging folders and $Recycle.Bin for cheat files...";
            update.PercentComplete = 90;
            progress?.Report(update);

            var discoveredFiles = _fileDiscoveryScanner.DiscoverFiles(out var fileFindings);
            report.FileDiscoveries.AddRange(discoveredFiles);
            report.Findings.AddRange(fileFindings);

            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-FILE-DISCOVERY",
                CheckName = "File Discovery & Recycle Bin Audit",
                Source = "FileDiscoveryScanner",
                Status = CheckStatus.PASSED,
                Reason = $"Discovered {discoveredFiles.Count} notable file artifacts in user staging directories."
            });
        }

        // 9. Services & Third-Party Drivers (HKLM\SYSTEM\CurrentControlSet\Services, Event 7045, SetupAPI.dev.log)
        if (consent.InspectServicesAndDrivers)
        {
            update.CurrentCategory = "Services & Drivers";
            update.CurrentAction = "Auditing Windows services, kernel drivers, and driver installation history...";
            update.PercentComplete = 95;
            progress?.Report(update);

            var serviceRecords = _serviceScanner.ScanServicesAndDrivers(out var serviceFindings, out var serviceDiag);
            report.ServicesAndDrivers.AddRange(serviceRecords);
            report.Findings.AddRange(serviceFindings);
            report.DiagnosticChecks.Add(serviceDiag);
        }

        // 10. Multi-Source Evidence Correlation & Software State Assessment
        var correlatedAssessments = _correlationEngine.Correlate(report, activePolicy);
        report.CorrelatedAssessments.AddRange(correlatedAssessments);

        // Add policy violation findings identified through correlation (such as possession-prohibited staged files)
        foreach (var assessment in correlatedAssessments.Where(a => a.IsPolicyViolation))
        {
            if (!report.Findings.Any(f => f.DetectionName.Contains(assessment.SoftwareName, StringComparison.OrdinalIgnoreCase)))
            {
                report.Findings.Add(new FindingRecord
                {
                    RuleId = assessment.Policy == GameplayPolicy.PROHIBITED_POSSESSION ? "POLICY-POSSESSION-VIOLATION" : "POLICY-CORRELATED-VIOLATION",
                    DetectionName = $"Policy Violation ({assessment.Policy}): {assessment.SoftwareName}",
                    Category = FindingCategory.PolicyViolation,
                    Classification = FindingClassification.ConfirmedCheatArtifact,
                    Severity = Severity.Critical,
                    Confidence = assessment.Confidence,
                    EvidenceState = EvidenceState.CONFIRMED,
                    SoftwareState = assessment.State,
                    SoftwareStateDescription = assessment.StateDescription,
                    PolicyViolationScope = assessment.Policy.ToString(),
                    EvidenceSource = "EvidenceCorrelationEngine",
                    FilePath = assessment.FilePath,
                    FileSha256 = assessment.Sha256,
                    TechnicalExplanation = assessment.PolicyEvaluationExplanation,
                    WhyItMatters = $"Server policy for {activePolicy.Gamemode} prohibits {assessment.Policy.ToString().ToLowerInvariant().Replace('_', ' ')} of this software.",
                    AlternativeLegitimateExplanations = assessment.AlternativeLegitimateExplanations,
                    WhatIsProven = assessment.WhatIsProven,
                    WhatIsNotProven = assessment.WhatIsNotProven,
                    Limitations = "Correlation binds presence or execution evidence to policy rules.",
                    RelatedEvidenceIds = assessment.SupportingEvidenceIds
                });
            }
        }

        // Conclude and seal report
        stopwatch.Stop();
        report.ScanCompletedAt = DateTimeOffset.UtcNow;
        report.ScanDurationMs = stopwatch.ElapsedMilliseconds;

        // Formulate Investigation Verdict
        report.RecomputeSummaryCounts();
        if (report.SummaryCounts.ConfirmedCheats > 0)
        {
            report.Verdict.OverallAssessment = "CONFIRMED CHEAT ARTIFACTS DETECTED";
            report.Verdict.Recommendation = $"{report.SummaryCounts.ConfirmedCheats} confirmed cheat artifact(s) discovered on system. Immediate staff review required.";
            report.Verdict.KeyTakeaways.Add("Identified direct cryptographic, class name, or filename matches for known Minecraft cheat software.");
        }
        else if (report.SummaryCounts.StrongIndicators > 0)
        {
            report.Verdict.OverallAssessment = "STRONG SUSPICIOUS INDICATORS IDENTIFIED";
            report.Verdict.Recommendation = "Identified execution traces matching known cheat utilities. Correlate timestamps with game session.";
        }
        else if (report.SummaryCounts.ProhibitedMods > 0 || correlatedAssessments.Any(a => a.IsPolicyViolation))
        {
            report.Verdict.OverallAssessment = "SERVER POLICY VIOLATION (PROHIBITED MODS / SOFTWARE)";
            report.Verdict.Recommendation = $"Discovered software strictly prohibited under active {activePolicy.Gamemode} ruleset.";
        }
        else
        {
            report.Verdict.OverallAssessment = "NO EVIDENCE OF CHEATING DETECTED";
            report.Verdict.Recommendation = "No confirmed cheat software, suspicious temp injections, or policy violations found in inspected scope.";
        }

        // Cryptographic Seal
        report.ReportIntegrityHash = ReportIntegrityValidator.ComputeReportSeal(report);

        update.PercentComplete = 100;
        update.CurrentCategory = "Scan Complete";
        update.CurrentAction = "Forensic report sealed and ready.";
        progress?.Report(update);

        return report;
    }
}
