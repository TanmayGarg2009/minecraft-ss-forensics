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
using MinecraftSsForensics.Scanner.Graph;
using MinecraftSsForensics.Scanner.Hashing;
using MinecraftSsForensics.Scanner.Identities;
using MinecraftSsForensics.Scanner.Integrity;
using MinecraftSsForensics.Scanner.LogsAndHistory;
using MinecraftSsForensics.Scanner.Lookalike;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Observations;
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
    private readonly Func<List<DiscoveredInstallation>>? _installationDiscoveryOverride;

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
        ModPolicyEngine? policyEngine = null,
        Func<List<DiscoveredInstallation>>? installationDiscoveryOverride = null)
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
        _installationDiscoveryOverride = installationDiscoveryOverride;

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

        if (_verifier is CompositeModVerifier cmv) { cmv.AllowNetworkRequests = consent.ConsentGiven && consent.PerformOnlineVerification; }
        var stopwatch = Stopwatch.StartNew();
        DateTimeOffset scanStart = DateTimeOffset.UtcNow;
        var activePolicy = policy ?? _policyEngine.Registry.GetPolicy("Crystal PvP");
        var instanceById = new Dictionary<string, MinecraftInstallationInfo>(StringComparer.OrdinalIgnoreCase);

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

        var observations = new List<IObservation>();
        var outcomes = new List<CollectionOutcome>();

        var update = new ScanProgressUpdate { PercentComplete = 5, CurrentCategory = "Initialization", CurrentAction = "Starting forensic audit..." };
        progress?.Report(update);

        // 1. Locate Minecraft Installations
        update.CurrentCategory = "Game Installation Discovery";
        update.CurrentAction = "Searching for Minecraft and third-party launcher directories...";
        update.PercentComplete = 10;
        progress?.Report(update);

        var swInst = Stopwatch.StartNew();
        var discoveredInstallations = _installationDiscoveryOverride != null
            ? _installationDiscoveryOverride()
            : _installationLocator.DiscoverInstallations(customDirectory, onlyCustomDirectory);
        var accessibleInstallations = new List<DiscoveredInstallation>();
        var reportedInstances = new Dictionary<string, MinecraftInstallationInfo>(StringComparer.OrdinalIgnoreCase);

        foreach (var inst in discoveredInstallations)
        {
            ct.ThrowIfCancellationRequested();
            var instanceInfo = new MinecraftInstallationInfo
            {
                InstanceId = inst.InstanceId,
                Name = inst.Name,
                LauncherType = inst.LauncherType,
                RootPath = inst.GameDirectory,
                ModsPath = inst.ModsPath,
                ConfigPath = inst.ConfigPath,
                LogsPath = inst.LogsPath,
                GameVersion = inst.GameVersion,
                Loader = inst.Loader,
                LoaderVersion = inst.LoaderVersion,
                DiscoverySource = inst.DiscoverySource,
                DiscoveryConfidence = inst.DiscoveryConfidence,
                Exists = inst.DirectoryExists,
                IsAccessible = inst.IsAccessible,
                AvailabilityNote = inst.AvailabilityNote,
                InspectionStatus = inst.IsAccessible ? "Pending" : "Unavailable"
            };
            report.MinecraftInstallations.Add(instanceInfo);
            reportedInstances[inst.InstanceId] = instanceInfo;
            instanceById[inst.InstanceId] = instanceInfo;

            observations.Add(new RawObservation
            {
                ObservationType = "InstallationObservation",
                SourceCollector = "InstallationLocator",
                SourceIdentity = "FileSystem_Directory",
                Provenance = inst.DiscoverySource,
                TargetEntityId = $"instance:{inst.InstanceId}",
                Properties = new Dictionary<string, string>
                {
                    ["InstanceId"] = inst.InstanceId,
                    ["RootPath"] = inst.GameDirectory,
                    ["ModsPath"] = inst.ModsPath,
                    ["LauncherType"] = inst.LauncherType,
                    ["Name"] = inst.Name,
                    ["GameVersion"] = inst.GameVersion ?? string.Empty,
                    ["Loader"] = inst.Loader ?? string.Empty,
                    ["DiscoveryConfidence"] = inst.DiscoveryConfidence
                }
            });

            if (inst.IsAccessible)
            {
                accessibleInstallations.Add(inst);
                if (!Directory.Exists(inst.ModsPath))
                    instanceInfo.AvailabilityNote = "Instance is readable; no mods directory exists at the configured launcher path.";
            }
            else
            {
                outcomes.Add(CollectionOutcome.SourceUnavailable($"Instance:{inst.InstanceId}", inst.AvailabilityNote ?? "Game directory is unavailable."));
                report.TechnicalLimitations.Add($"Instance '{inst.Name}' ({inst.LauncherType}) was not inspected: {inst.AvailabilityNote ?? "directory unavailable"}");
            }
        }

        swInst.Stop();
        outcomes.Add(CollectionOutcome.Succeeded("InstallationLocator", discoveredInstallations.Count, swInst.Elapsed,
            new[] { $"Accessible instances: {accessibleInstallations.Count}; unavailable instances: {discoveredInstallations.Count - accessibleInstallations.Count}." }));

        report.DiagnosticChecks.Add(new DiagnosticCheckItem
        {
            CheckId = "CHK-INSTALLATIONS",
            CheckName = "Minecraft Client Discovery",
            Source = "InstallationLocator",
            Status = discoveredInstallations.Count > 0 && accessibleInstallations.Count == discoveredInstallations.Count ? CheckStatus.PASSED : CheckStatus.UNAVAILABLE,
            Reason = discoveredInstallations.Count == 0
                ? "No Minecraft game directory was discovered in supported launcher locations."
                : $"Located {discoveredInstallations.Count} instance(s); {accessibleInstallations.Count} accessible for inspection."
        });

        // 2. Discover and Inspect Mod JARs
        if (consent.InspectMinecraftMods)
        {
            var swMods = Stopwatch.StartNew();
            update.CurrentCategory = "Mod Folder Discovery";
            update.CurrentAction = "Scanning active mods, calculating SHA-256 hashes, and inspecting JAR contents...";
            update.PercentComplete = 25;
            progress?.Report(update);

            var modJars = new List<(string Path, DiscoveredInstallation Instance)>();
            foreach (var inst in accessibleInstallations)
            {
                ct.ThrowIfCancellationRequested();
                var instanceInfo = instanceById[inst.InstanceId];
                instanceInfo.InspectionStatus = "Scanning";
                if (!Directory.Exists(inst.ModsPath))
                {
                    instanceInfo.InspectionStatus = "InspectedNoModsDirectory";
                    outcomes.Add(CollectionOutcome.PartiallySucceeded($"Instance:{inst.InstanceId}", 0, TimeSpan.Zero,
                        $"No mod directory found at the configured launcher path {inst.ModsPath}."));
                    continue;
                }

                try
                {
                    var files = Directory.GetFiles(inst.ModsPath, "*.jar", SearchOption.TopDirectoryOnly);
                    modJars.AddRange(files.Select(path => (Path: path, Instance: inst)));
                    instanceInfo.InspectionStatus = "Inspected";
                }
                catch (UnauthorizedAccessException ex)
                {
                    instanceInfo.InspectionStatus = "PermissionDenied";
                    instanceInfo.AvailabilityNote = ex.GetType().Name;
                    outcomes.Add(CollectionOutcome.AccessDenied($"Instance:{inst.InstanceId}:ModInspection", inst.ModsPath));
                }
                catch (Exception ex) when (ex is IOException or System.Security.SecurityException)
                {
                    instanceInfo.InspectionStatus = "Error";
                    instanceInfo.AvailabilityNote = ex.GetType().Name;
                    outcomes.Add(CollectionOutcome.Failed($"Instance:{inst.InstanceId}:ModInspection", ex));
                }
            }

            modJars = modJars.DistinctBy(x => x.Path, StringComparer.OrdinalIgnoreCase).ToList();

            var modsWithVerification = new List<(DiscoveredMod Mod, ModVerificationResult Verification)>();

            for (int i = 0; i < modJars.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                string jarPath = modJars[i].Path;
                string instanceId = modJars[i].Instance.InstanceId;
                var instanceInfo = instanceById[instanceId];
                string fileName = Path.GetFileName(jarPath);

                update.CurrentAction = $"Inspecting mod ({i + 1}/{modJars.Count}): {fileName}";
                update.PercentComplete = 25 + (int)((double)i / Math.Max(1, modJars.Count) * 25);
                progress?.Report(update);

                var hashResult = await _hasher.ComputeHashesAsync(jarPath, ct);
                var meta = await _archiveInspector.InspectModJarAsync(jarPath, ct);

                DateTimeOffset? modTime = null;
                try { if (File.Exists(jarPath)) modTime = new DateTimeOffset(File.GetLastWriteTimeUtc(jarPath)); } catch { }

                observations.Add(RawObservation.CreateFileObservation(
                    "ModInspection",
                    jarPath,
                    hashResult.FileSizeBytes,
                    hashResult.Sha256 ?? string.Empty,
                    modTime,
                    "ModArchiveInspection"));

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
                    MinecraftInstanceId = instanceId,
                    MinecraftInstanceName = instanceInfo.Name,
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
                    string clusterId = "CLUSTER-" + (!string.IsNullOrEmpty(hashResult.Sha256) ? hashResult.Sha256[..Math.Min(12, hashResult.Sha256.Length)] : cheatFileMatch.Name.ToLowerInvariant().Replace(" ", "-"));
                    bool isAuthenticRelease = isVerified && verResult.State == ModVerificationState.VERIFIED_EXACT_RELEASE;

                    report.Findings.Add(new FindingRecord
                    {
                        RuleId = isAuthenticRelease ? "MOD-LOOKALIKE-BENIGN-RENAMED" : "CHEAT-JAR-FILENAME",
                        DetectionName = isAuthenticRelease
                            ? $"Authentic Community Mod with Unusual Filename: {modItem.Name} (Matches '{cheatFileMatch.Name}')"
                            : $"Potential Cheat Client JAR on Disk (Filename Match): {cheatFileMatch.Name}",
                        FindingTitle = isAuthenticRelease
                            ? $"Authentic Community Mod with Unusual Filename: {modItem.Name} (Matches '{cheatFileMatch.Name}')"
                            : $"Potential Cheat Client JAR on Disk (Filename Match): {cheatFileMatch.Name}",
                        Category = isAuthenticRelease ? FindingCategory.ModIntegrity : FindingCategory.CheatArtifact,
                        EvidenceCategory = EvidenceCategory.Disk,
                        Classification = isAuthenticRelease ? FindingClassification.NeedsReview : FindingClassification.StrongIndicator,
                        Severity = isAuthenticRelease ? Severity.Low : (polEval.Policy == GameplayPolicy.PROHIBITED_POSSESSION ? Severity.High : Severity.Medium),
                        EvidenceStrength = isAuthenticRelease ? EvidenceStrength.Inconclusive : EvidenceStrength.Moderate,
                        Confidence = ConfidenceLevel.Medium,
                        DetectionMethod = DetectionMethod.MetadataRule,
                        EvidenceState = EvidenceState.STRONG_INDICATOR,
                        SoftwareState = SoftwareEvidenceState.SoftwareInstalled,
                        SoftwareStateDescription = isAuthenticRelease
                            ? $"Mod archive hash verified as authentic {verResult.ProjectName}; filename matches cheat pattern."
                            : "Known cheat client filename pattern found in active Minecraft profile mods folder. Content not verified.",
                        PolicyViolationScope = polEval.Policy == GameplayPolicy.PROHIBITED_POSSESSION ? "PROHIBITED_POSSESSION" : string.Empty,
                        EvidenceSource = "ModFolder",
                        MinecraftInstanceId = instanceId,
                        MinecraftInstanceName = instanceInfo.Name,
                        FilePath = jarPath,
                        FileSha256 = hashResult.Sha256,
                        FileSizeBytes = hashResult.FileSizeBytes,
                        IsInScanWindow = false,
                        EvidenceClusterId = clusterId,
                        Interpretation = isAuthenticRelease
                            ? $"File '{fileName}' has authentic content matching {verResult.ProjectName}, despite matching cheat filename pattern."
                            : $"Mod file '{fileName}' in active profile mods folder matches known cheat signature pattern '{cheatFileMatch.Name}'.",
                        TechnicalExplanation = isAuthenticRelease
                            ? $"Mod archive '{fileName}' matches official release hash for '{verResult.ProjectName}' on {verResult.Provider}. Filename pattern match '{cheatFileMatch.Name}' is superseded by cryptographic content verification."
                            : $"Mod archive '{fileName}' matches filename pattern for '{cheatFileMatch.Name}'. Description: {cheatFileMatch.Description}. Bytecode inspection did not confirm known cheat classes.",
                        WhyItMatters = isAuthenticRelease ? "Benign mods renamed to match cheat names cause false alarms." : "Suspicious filename in active mods directory.",
                        AlternativeLegitimateExplanations = isAuthenticRelease ? "Renamed utility mod or user repack." : "User downloaded file for review, testing, or unused on another game server.",
                        WhatIsProven = isAuthenticRelease ? "The file contents are verified authentic." : "A file with this name was physically placed in the mods directory.",
                        WhatIsNotProven = "Does not prove that cheat features were present or loaded during match without session correlation.",
                        Limitations = "Filename match proves presence of file on disk; does not prove cheat capabilities or execution without bytecode confirmation.",
                        RecommendedReview = "Review active JVM process arguments and server match logs to verify if loaded."
                    });
                }
                else if (meta.MatchedCheatSignatures.Count > 0)
                {
                    string clusterId = "CLUSTER-BC-" + meta.MatchedCheatSignatures[0].ToLowerInvariant().Replace(" ", "-");
                    report.Findings.Add(new FindingRecord
                    {
                        RuleId = "CHEAT-BYTECODE-CLASS",
                        DetectionName = $"Cheat Bytecode / Class Match: {meta.MatchedCheatSignatures[0]}",
                        FindingTitle = $"Cheat Bytecode / Class Match: {meta.MatchedCheatSignatures[0]}",
                        Category = FindingCategory.CheatArtifact,
                        EvidenceCategory = EvidenceCategory.ModIntegrity,
                        Classification = FindingClassification.ConfirmedCheatArtifact,
                        Severity = Severity.High,
                        EvidenceStrength = EvidenceStrength.Strong,
                        Confidence = ConfidenceLevel.Certain,
                        DetectionMethod = DetectionMethod.BytecodeStructure,
                        EvidenceState = EvidenceState.CONFIRMED,
                        SoftwareState = SoftwareEvidenceState.SoftwareContainsProhibitedCapabilities,
                        SoftwareStateDescription = "Archive contains internal classes matching known cheat package.",
                        PolicyViolationScope = "PROHIBITED_POSSESSION",
                        EvidenceSource = "JAR Archive Bytecode",
                        MinecraftInstanceId = instanceId,
                        MinecraftInstanceName = instanceInfo.Name,
                        FilePath = jarPath,
                        FileSha256 = hashResult.Sha256,
                        FileSizeBytes = hashResult.FileSizeBytes,
                        IsInScanWindow = false,
                        EvidenceClusterId = clusterId,
                        Interpretation = $"Mod archive '{fileName}' contains internal package/class bytecode matching known cheat: {string.Join(", ", meta.MatchedCheatSignatures)}.",
                        TechnicalExplanation = $"Archive '{fileName}' contains internal class matching known cheat package: {string.Join(", ", meta.MatchedCheatSignatures)}",
                        WhyItMatters = "Bytecode class analysis indicates modified or disguised cheat jar.",
                        AlternativeLegitimateExplanations = "Custom mod developer testing local build.",
                        WhatIsProven = "The mod archive contains cheat class bytecode.",
                        WhatIsNotProven = "Does not prove feature activation during gameplay.",
                        Limitations = "Bytecode match proves internal capability and possession; does not prove feature activation during gameplay.",
                        RecommendedReview = "Decompile classes to confirm if cheat functionality is active."
                    });
                }
                else if (polEval.Policy.IsProhibited())
                {
                    report.Findings.Add(new FindingRecord
                    {
                        RuleId = "MOD-POLICY-PROHIBITED",
                        DetectionName = $"Prohibited Mod Under {activePolicy.Gamemode} Ruleset: {modItem.Name}",
                        FindingTitle = $"Prohibited Mod Under {activePolicy.Gamemode} Ruleset: {modItem.Name}",
                        Category = FindingCategory.PolicyViolation,
                        EvidenceCategory = EvidenceCategory.PolicyViolation,
                        Classification = FindingClassification.ConfirmedCheatArtifact,
                        Severity = polEval.Policy == GameplayPolicy.PROHIBITED_POSSESSION ? Severity.High : Severity.Medium,
                        EvidenceStrength = EvidenceStrength.Strong,
                        Confidence = ConfidenceLevel.Certain,
                        DetectionMethod = DetectionMethod.MetadataRule,
                        EvidenceState = EvidenceState.CONFIRMED,
                        SoftwareState = SoftwareEvidenceState.SoftwareInstalled,
                        SoftwareStateDescription = $"Mod is installed in active profile mods folder under {activePolicy.Gamemode} ruleset.",
                        PolicyViolationScope = polEval.Policy.ToString(),
                        EvidenceSource = "ModPolicyEngine",
                        MinecraftInstanceId = instanceId,
                        MinecraftInstanceName = instanceInfo.Name,
                        FilePath = jarPath,
                        FileSha256 = hashResult.Sha256,
                        FileSizeBytes = hashResult.FileSizeBytes,
                        IsInScanWindow = false,
                        Interpretation = $"Mod '{modItem.Name}' violates active {activePolicy.Gamemode} ruleset policy ({polEval.Policy}).",
                        TechnicalExplanation = $"Mod '{modItem.Name}' is prohibited under active {activePolicy.Gamemode} ruleset. Reason: {polEval.Reason}",
                        WhyItMatters = "Provides prohibited gameplay advantages in active competitive gamemode.",
                        AlternativeLegitimateExplanations = "Player may use this profile for other servers or singleplayer.",
                        WhatIsProven = "Mod is installed in the active profile.",
                        WhatIsNotProven = polEval.Policy == GameplayPolicy.PROHIBITED_POSSESSION
                            ? "Gameplay use is not proven, but is not required under the applicable possession policy."
                            : "Does not prove the feature was used during competition.",
                        Limitations = polEval.Reason,
                        RecommendedReview = "Review server rules and match timeline."
                    });
                }
                else if (meta.BytecodeAnalysis != null && meta.BytecodeAnalysis.HasAutomationCapabilities)
                {
                    report.Findings.Add(new FindingRecord
                    {
                        RuleId = "MOD-BYTECODE-AUTOMATION",
                        DetectionName = $"Automation Capabilities in Mod Bytecode: {modItem.Name}",
                        FindingTitle = $"Automation Capabilities in Mod Bytecode: {modItem.Name}",
                        Category = FindingCategory.ModIntegrity,
                        EvidenceCategory = EvidenceCategory.ModIntegrity,
                        Classification = FindingClassification.NeedsReview,
                        Severity = Severity.Medium,
                        EvidenceStrength = EvidenceStrength.Moderate,
                        Confidence = ConfidenceLevel.Certain,
                        DetectionMethod = DetectionMethod.BytecodeStructure,
                        EvidenceState = EvidenceState.STRONG_INDICATOR,
                        SoftwareState = SoftwareEvidenceState.SoftwareContainsProhibitedCapabilities,
                        SoftwareStateDescription = "Mod archive contains constant pool bytecode references for automated combat, crystal placement, or packet manipulation.",
                        PolicyViolationScope = "NEEDS_REVIEW",
                        EvidenceSource = "StaticBytecodeAnalyzer",
                        MinecraftInstanceId = instanceId,
                        MinecraftInstanceName = instanceInfo.Name,
                        FilePath = jarPath,
                        FileSha256 = hashResult.Sha256,
                        FileSizeBytes = hashResult.FileSizeBytes,
                        IsInScanWindow = false,
                        Interpretation = $"Bytecode contains structural capabilities: {string.Join(", ", meta.BytecodeAnalysis.DetectedCapabilities.Select(c => c.CapabilityType).Distinct())}.",
                        TechnicalExplanation = $"Static bytecode constant pool analysis identified capabilities: {string.Join(", ", meta.BytecodeAnalysis.DetectedCapabilities.Select(c => c.CapabilityType).Distinct())}.",
                        WhyItMatters = "Mod contains automation or packet manipulation structures that may violate competitive server policies.",
                        AlternativeLegitimateExplanations = "Mod may use mixins or packet listeners for legitimate quality-of-life or diagnostic features.",
                        WhatIsProven = "Archive contains structural capability bytecode.",
                        WhatIsNotProven = "Does NOT prove in-game use without runtime session correlation.",
                        Limitations = "Structural bytecode capability does not establish in-game execution or toggling during matches.",
                        RecommendedReview = "Inspect method call sites and mixin injection targets."
                    });
                }
            }

            // Lookalike check & Duplicate Mod ID check
            var lookalikeFindings = _lookalikeDetector.AnalyzeMods(modsWithVerification);
            foreach (var lookalike in lookalikeFindings)
            {
                bool isAuthentic = lookalike.RuleId.StartsWith("INFO-", StringComparison.OrdinalIgnoreCase);
                report.Findings.Add(new FindingRecord
                {
                    RuleId = lookalike.RuleId,
                    DetectionName = lookalike.Title,
                    FindingTitle = lookalike.Title,
                    Category = FindingCategory.ModIntegrity,
                    EvidenceCategory = EvidenceCategory.ModIntegrity,
                    Classification = isAuthentic ? FindingClassification.Informational : FindingClassification.Suspicious,
                    Severity = isAuthentic ? Severity.Informational : Severity.High,
                    EvidenceStrength = isAuthentic ? EvidenceStrength.Strong : EvidenceStrength.Moderate,
                    Confidence = isAuthentic ? ConfidenceLevel.Certain : ConfidenceLevel.High,
                    DetectionMethod = isAuthentic ? DetectionMethod.HashMatch : DetectionMethod.MetadataRule,
                    EvidenceSource = lookalike.EvidenceSource,
                    MinecraftInstanceId = modJars.FirstOrDefault(x => x.Path.Equals(lookalike.FilePath, StringComparison.OrdinalIgnoreCase)).Instance?.InstanceId,
                    MinecraftInstanceName = modJars.FirstOrDefault(x => x.Path.Equals(lookalike.FilePath, StringComparison.OrdinalIgnoreCase)).Instance?.Name,
                    FilePath = lookalike.FilePath,
                    FileSha256 = lookalike.FileSha256,
                    IsInScanWindow = false,
                    Interpretation = lookalike.Explanation,
                    TechnicalExplanation = lookalike.Explanation,
                    WhyItMatters = isAuthentic
                        ? "Mod file was renamed by user, but cryptographic hash confirms exact authentic release."
                        : "Potentially spoofed filename or duplicate mod ID masking custom or unlisted mod bytecode.",
                    AlternativeLegitimateExplanations = "User launcher sorting or local build numbering.",
                    Limitations = lookalike.Limitations,
                    RecommendedReview = "Verify official publisher repository and hashes."
                });
            }

            swMods.Stop();
            outcomes.Add(CollectionOutcome.Succeeded("ModInspection", modJars.Count, swMods.Elapsed));

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
            outcomes.Add(CollectionOutcome.SourceUnavailable("ModInspection", "Mod folder inspection was excluded from scan scope."));
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
            var swProc = Stopwatch.StartNew();
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
                    ImageSha256 = proc.ImageSha256,
                    ProcessInstanceId = proc.ProcessInstanceId,
                    ParentProcessId = proc.ParentProcessId,
                    ParentProcessName = proc.ParentProcessName,
                    SanitizedCommandLine = proc.RedactedCommandLine,
                    Architecture = proc.Architecture,
                    StartTime = proc.StartTime.HasValue ? new DateTimeOffset(proc.StartTime.Value) : null,
                    CollectionTimeUtc = proc.CollectionTimeUtc,
                    ModuleStatus = proc.ModuleEnumerationStatus,
                    ModuleStatusNote = proc.ModuleEnumerationNote,
                    AmbiguityReason = proc.AmbiguityReason
                });

                observations.Add(RawObservation.CreateProcessObservation(
                    "ProcessScanner",
                    proc.ProcessId,
                    proc.ProcessName,
                    proc.ExecutablePath ?? string.Empty,
                    proc.StartTime.HasValue ? new DateTimeOffset(proc.StartTime.Value) : null,
                    proc.RedactedCommandLine,
                    proc.ProcessInstanceId));

                if (proc.IsGameProcess)
                {
                    report.JavaRuntime.JavaExecutablePath = proc.ExecutablePath;
                    report.JavaRuntime.RawJvmArguments = proc.RedactedCommandLine;

                    foreach (var mod in proc.LoadedModules)
                    {
                        var modItem = new LoadedModuleItem
                        {
                            ProcessId = proc.ProcessId,
                            ProcessInstanceId = proc.ProcessInstanceId,
                            ModuleInstanceId = mod.ModuleInstanceId,
                            ModuleName = mod.ModuleName,
                            FilePath = mod.FilePath,
                            BaseAddressHex = mod.BaseAddressHex,
                            Sha256 = mod.Sha256,
                            FileSizeBytes = mod.FileSizeBytes,
                            CollectionTimeUtc = mod.CollectionTimeUtc,
                            LastWriteTimeUtc = mod.LastWriteTimeUtc,
                            IsSigned = mod.IsSigned,
                            IsTrustedSignature = mod.IsTrustedSignature,
                            SignerSubject = mod.SignerSubject,
                            TrustStatusExplanation = mod.TrustStatusExplanation,
                            EnumerationStatus = mod.ModuleEnumerationStatus,
                            EnumerationNote = mod.ModuleEnumerationNote,
                            IsInTempDirectory = mod.IsSuspiciousLocation,
                            IsRecognizedJavaNativeLibrary = mod.IsRecognizedJavaNativeLibrary,
                            ProvenanceAssessment = mod.ProvenanceAssessment
                        };
                        report.LoadedModules.Add(modItem);

                        observations.Add(new RawObservation
                        {
                            ObservationType = "ModuleObservation",
                            SourceCollector = "ProcessScanner",
                            SourceIdentity = "VirtualMemory_Module",
                            Provenance = "EnumProcessModulesEx",
                            TargetEntityId = mod.ModuleInstanceId ?? $"mod:{proc.ProcessInstanceId}:{mod.BaseAddressHex ?? "0x0"}:{mod.FileSizeBytes ?? 0}:{mod.Sha256 ?? "unknown"}",
                            Properties = new Dictionary<string, string>
                            {
                                ["ModuleName"] = mod.ModuleName,
                                ["FilePath"] = mod.FilePath,
                                ["ProcessId"] = proc.ProcessId.ToString(),
                                ["ProcessInstanceId"] = proc.ProcessInstanceId ?? string.Empty,
                                ["BaseAddressHex"] = mod.BaseAddressHex ?? "0x0",
                                ["ModuleEnumerationStatus"] = mod.ModuleEnumerationStatus.ToString(),
                                ["IsRecognizedJavaNativeLibrary"] = mod.IsRecognizedJavaNativeLibrary.ToString(),
                                ["ProvenanceAssessment"] = mod.ProvenanceAssessment
                            }
                        });

                        // Suspicious temp DLLs that are NOT legitimate Java native libraries
                        if (mod.IsSuspiciousLocation && !mod.IsRecognizedJavaNativeLibrary && !mod.IsSigned)
                        {
                            report.Findings.Add(new FindingRecord
                            {
                                RuleId = "PROC-SUSP-TEMP-MODULE",
                                DetectionName = $"Unsigned Temporary DLL Loaded into javaw.exe: {mod.ModuleName}",
                                FindingTitle = $"Unsigned Temporary DLL Loaded into javaw.exe: {mod.ModuleName}",
                                Category = FindingCategory.ProcessInjection,
                                EvidenceCategory = EvidenceCategory.LoadedModule,
                                Classification = FindingClassification.Suspicious,
                                Severity = Severity.Medium,
                                EvidenceStrength = EvidenceStrength.Moderate,
                                Confidence = ConfidenceLevel.Medium,
                                DetectionMethod = DetectionMethod.RuntimeObservation,
                                SoftwareState = SoftwareEvidenceState.SoftwareInteractingWithMinecraft,
                                SoftwareStateDescription = "Unsigned DLL mapped into javaw.exe address space from temporary directory.",
                                EvidenceSource = "ProcessMemoryMetadata",
                                FilePath = mod.FilePath,
                                ProcessId = proc.ProcessId,
                                ProcessName = proc.ProcessName,
                                IsInScanWindow = true,
                                EvidenceClusterId = "CLUSTER-MOD-" + mod.ModuleName.ToLowerInvariant(),
                                Interpretation = $"Process PID {proc.ProcessId} (javaw.exe) has loaded module '{mod.ModuleName}' from temporary directory without Java native library provenance.",
                                TechnicalExplanation = $"Process PID {proc.ProcessId} (javaw.exe) has loaded module '{mod.FilePath}' from a temporary directory without Java native library provenance (JNA/LWJGL).",
                                WhyItMatters = "Screenshare bypasses and injected cheat DLLs commonly load from temporary directories.",
                                AlternativeLegitimateExplanations = "Custom third-party screen recorder, Discord overlay, or graphics driver hook.",
                                WhatIsProven = "Module was mapped into javaw.exe process memory.",
                                WhatIsNotProven = "Does not prove malicious intent without reverse-engineering module exports.",
                                Limitations = "Module mapping indicates memory presence, but does not prove malicious intent or packet modification without reverse engineering.",
                                RecommendedReview = "Examine module export table, digital signature, and parent process."
                            });
                        }
                    }

                    // Audit JVM -javaagent arguments
                    foreach (var agent in proc.JavaAgents)
                    {
                        var agentSig = CheatDetectionDatabase.MatchFileName(Path.GetFileName(agent));
                        bool isTemp = agent.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                                      agent.Contains(@"/temp/", StringComparison.OrdinalIgnoreCase);
                        bool agentExists = File.Exists(agent);
                        bool agentContentVerified = false;
                        string agentHash = string.Empty;

                        if (agentExists)
                        {
                            try
                            {
                                using var stream = new FileStream(agent, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                agentHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();

                                using var zip = System.IO.Compression.ZipFile.OpenRead(agent);
                                foreach (var entry in zip.Entries)
                                {
                                    if (entry.FullName.EndsWith(".class", StringComparison.OrdinalIgnoreCase) &&
                                        CheatDetectionDatabase.MatchClassOrPackage(entry.FullName) != null)
                                    {
                                        agentContentVerified = true;
                                        break;
                                    }
                                }
                            }
                            catch { /* Inaccessible file */ }
                        }

                        if (agentSig != null)
                        {
                            report.Findings.Add(new FindingRecord
                            {
                                RuleId = "PROC-CHEAT-JAVA-AGENT",
                                DetectionName = agentContentVerified
                                    ? $"Verified Cheat Java Agent Attached: {agentSig.Name}"
                                    : $"Java Agent Launch Parameter References Cheat Name: {agentSig.Name}",
                                FindingTitle = agentContentVerified
                                    ? $"Verified Cheat Java Agent Attached: {agentSig.Name}"
                                    : $"Java Agent Launch Parameter References Cheat Name: {agentSig.Name}",
                                Category = FindingCategory.JvmEnvironment,
                                EvidenceCategory = agentContentVerified ? EvidenceCategory.Injected : EvidenceCategory.JvmEnvironment,
                                Classification = agentContentVerified ? FindingClassification.ConfirmedCheatArtifact : FindingClassification.StrongIndicator,
                                Severity = agentContentVerified ? Severity.Critical : Severity.High,
                                EvidenceStrength = agentContentVerified ? EvidenceStrength.Strong : EvidenceStrength.Moderate,
                                Confidence = agentContentVerified ? ConfidenceLevel.Certain : ConfidenceLevel.Medium,
                                DetectionMethod = agentContentVerified ? DetectionMethod.BytecodeStructure : DetectionMethod.MetadataRule,
                                SoftwareState = agentContentVerified ? SoftwareEvidenceState.SoftwareInteractingWithMinecraft : SoftwareEvidenceState.SoftwarePresent,
                                ExecutionState = agentContentVerified ? ExecutionEvidenceState.MinecraftProcessAssociation : ExecutionEvidenceState.LaunchConfigurationReference,
                                SoftwareStateDescription = agentContentVerified
                                    ? $"Java Agent containing verified cheat bytecode '{agentSig.Name}' passed via -javaagent to javaw.exe."
                                    : $"Java Agent parameter matching known cheat filename '{agentSig.Name}' passed to javaw.exe. " + (agentExists ? "Agent content was not confirmed as cheat." : "Agent file was not found on disk."),
                                EvidenceSource = "JvmArguments",
                                FilePath = agent,
                                FileSha256 = agentHash,
                                ProcessId = proc.ProcessId,
                                ProcessName = proc.ProcessName,
                                IsInScanWindow = agentContentVerified,
                                EvidenceClusterId = "CLUSTER-AGENT-" + agentSig.Name.ToLowerInvariant().Replace(" ", "-"),
                                Interpretation = agentContentVerified
                                    ? $"A verified cheat Java Agent was attached to the running Minecraft JVM (PID {proc.ProcessId})."
                                    : $"Process PID {proc.ProcessId} launch arguments contain -javaagent parameter '{agent}'. File content was not verified as cheat bytecode.",
                                TechnicalExplanation = $"Command line arguments for javaw.exe (PID {proc.ProcessId}) include -javaagent targeting '{agent}'. " +
                                    (agentExists ? $"Agent file exists on disk (SHA-256: {agentHash})." : "Agent file does not exist on disk at specified path."),
                                WhyItMatters = "Java agents possess full bytecode instrumentation capabilities to intercept and modify game classes at runtime.",
                                AlternativeLegitimateExplanations = "Custom launcher or diagnostic tool using test filename.",
                                WhatIsProven = $"Process PID {proc.ProcessId} was launched with -javaagent argument '{agent}'.",
                                WhatIsNotProven = agentContentVerified
                                    ? "Does not prove individual features were toggled during a specific match moment."
                                    : "Does not prove the agent file exists, contained functional cheat code, or successfully instrumented classes.",
                                Limitations = "JVM argument proves parameter was passed at process startup. Without verified bytecode, malicious intent is not confirmed.",
                                RecommendedReview = "Review launcher profile configuration and parent process."
                            });
                        }
                        else if (isTemp)
                        {
                            report.Findings.Add(new FindingRecord
                            {
                                RuleId = "PROC-SUSP-JAVA-AGENT",
                                DetectionName = $"Unverified Java Agent Loaded from Temp: {Path.GetFileName(agent)}",
                                FindingTitle = $"Unverified Java Agent Loaded from Temp: {Path.GetFileName(agent)}",
                                Category = FindingCategory.JvmEnvironment,
                                EvidenceCategory = EvidenceCategory.JvmEnvironment,
                                Classification = FindingClassification.Suspicious,
                                Severity = Severity.High,
                                EvidenceStrength = EvidenceStrength.Moderate,
                                Confidence = ConfidenceLevel.Medium,
                                DetectionMethod = DetectionMethod.MetadataRule,
                                SoftwareState = SoftwareEvidenceState.SoftwarePresent,
                                ExecutionState = ExecutionEvidenceState.LaunchConfigurationReference,
                                SoftwareStateDescription = "Java Agent referenced from temporary directory in launch arguments.",
                                EvidenceSource = "JvmArguments",
                                FilePath = agent,
                                ProcessId = proc.ProcessId,
                                ProcessName = proc.ProcessName,
                                IsInScanWindow = true,
                                EvidenceClusterId = "CLUSTER-AGENT-" + Path.GetFileNameWithoutExtension(agent).ToLowerInvariant(),
                                Interpretation = $"Unverified Java Agent '{Path.GetFileName(agent)}' loaded from temporary directory into javaw.exe.",
                                TechnicalExplanation = $"Process PID {proc.ProcessId} (javaw.exe) was launched with -javaagent targeting temporary path '{agent}'.",
                                WhyItMatters = "Attackers frequently stage bytecode modification agents in %TEMP% to evade static mod folder scanning.",
                                AlternativeLegitimateExplanations = "Custom launcher or diagnostic profiler agent.",
                                WhatIsProven = "Java Agent was attached to the active game process.",
                                WhatIsNotProven = "Intent requires bytecode decompilation of the agent JAR.",
                                Limitations = "Detects argument attachment; requires archive inspection.",
                                RecommendedReview = "Inspect agent archive bytecode and manifest."
                            });
                        }
                    }
                }
            }

            swProc.Stop();
            outcomes.Add(CollectionOutcome.Succeeded("ProcessScanner", processes.Count, swProc.Elapsed));

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
        else
        {
            outcomes.Add(CollectionOutcome.SourceUnavailable("ProcessScanner", "Process inspection excluded from scan scope."));
            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-PROCESS-MODULES",
                CheckName = "Active Process & Loaded Module Audit",
                Source = "ProcessScanner",
                Status = CheckStatus.SKIPPED,
                Reason = "Process and loaded module audit was excluded from scan scope."
            });
        }

        // 4. Execution Artifacts (Prefetch, BAM, PCA, PowerShell)
        if (consent.InspectExecutionArtifacts)
        {
            var swHist = Stopwatch.StartNew();
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
                    CollectionTimeUtc = hr.CollectionTimeUtc,
                    ExecutionCount = hr.RunCount,
                    IsCorruptOrMalformed = hr.IsCorruptOrMalformed,
                    ParseFailureReason = hr.ParseFailureReason,
                    Details = hr.Description
                });

                observations.Add(RawObservation.CreateHistoricalObservation(
                    "HistoricalEvidenceScanner",
                    hr.Source,
                    Path.GetFileName(hr.Path),
                    hr.Timestamp.HasValue ? new DateTimeOffset(hr.Timestamp.Value) : DateTimeOffset.UtcNow,
                    hr.Source));
            }

            swHist.Stop();
            outcomes.Add(CollectionOutcome.Succeeded("HistoricalEvidenceScanner", histRecords.Count, swHist.Elapsed));

            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-EXEC-HISTORY",
                CheckName = "Windows Execution History Audit",
                Source = "Prefetch/BAM",
                Status = CheckStatus.PASSED,
                Reason = $"Collected {histRecords.Count} execution history entries."
            });
        }
        else
        {
            outcomes.Add(CollectionOutcome.SourceUnavailable("HistoricalEvidenceScanner", "Execution history excluded from scan scope."));
            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-EXEC-HISTORY",
                CheckName = "Windows Execution History Audit",
                Source = "Prefetch/BAM",
                Status = CheckStatus.SKIPPED,
                Reason = "Execution history audit was excluded from scan scope."
            });
        }

        // 5. Registry Artifacts (UserAssist, Run Keys, RecentDocs)
        if (consent.InspectRegistryArtifacts)
        {
            var swReg = Stopwatch.StartNew();
            update.CurrentCategory = "Registry Forensics";
            update.CurrentAction = "Inspecting UserAssist, PcaSvc, and Run keys...";
            update.PercentComplete = 85;
            progress?.Report(update);

            var regItems = _registryScanner.ScanRegistryArtifacts(out var regFindings);
            report.RegistryEvidence.AddRange(regItems);
            report.Findings.AddRange(regFindings);

            foreach (var item in regItems)
            {
                observations.Add(new RawObservation
                {
                    ObservationType = "RegistryObservation",
                    SourceCollector = "RegistryScanner",
                    SourceIdentity = "WindowsRegistry",
                    Provenance = "Registry",
                    TargetEntityId = $"reg:{item.KeyPath.ToLowerInvariant()}:{item.ValueName.ToLowerInvariant()}",
                    Properties = new Dictionary<string, string>
                    {
                        ["KeyPath"] = item.KeyPath,
                        ["ValueName"] = item.ValueName,
                        ["ValueData"] = item.ValueData,
                        ["ArtifactCategory"] = item.Significance
                    }
                });
            }

            swReg.Stop();
            outcomes.Add(CollectionOutcome.Succeeded("RegistryScanner", regItems.Count, swReg.Elapsed));

            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-REGISTRY",
                CheckName = "Windows Registry Artifacts",
                Source = "RegistryScanner",
                Status = CheckStatus.PASSED,
                Reason = $"Audited UserAssist, PCA, and Run registry hives ({regItems.Count} entries collected)."
            });
        }
        else
        {
            outcomes.Add(CollectionOutcome.SourceUnavailable("RegistryScanner", "Registry inspection excluded from scan scope."));
            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-REGISTRY",
                CheckName = "Windows Registry Artifacts",
                Source = "RegistryScanner",
                Status = CheckStatus.SKIPPED,
                Reason = "Registry artifacts audit was excluded from scan scope."
            });
        }

        // 6. USB Storage History
        if (consent.InspectUsbHistory)
        {
            var swUsb = Stopwatch.StartNew();
            var usbDevices = _usbScanner.ScanUsbStorageDevices(out var usbFindings);
            report.UsbEvidence.AddRange(usbDevices);
            report.Findings.AddRange(usbFindings);

            foreach (var usb in usbDevices)
            {
                observations.Add(new RawObservation
                {
                    ObservationType = "UsbObservation",
                    SourceCollector = "UsbHistoryScanner",
                    SourceIdentity = "USBSTOR",
                    Provenance = "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
                    TargetEntityId = $"usb:{usb.SerialNumber.ToLowerInvariant()}",
                    Properties = new Dictionary<string, string>
                    {
                        ["DeviceName"] = usb.DeviceName,
                        ["SerialNumber"] = usb.SerialNumber,
                        ["LastConnected"] = usb.LastConnectedTime?.ToString("O") ?? string.Empty
                    }
                });
            }

            swUsb.Stop();
            outcomes.Add(CollectionOutcome.Succeeded("UsbHistoryScanner", usbDevices.Count, swUsb.Elapsed));

            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-USB-HISTORY",
                CheckName = "USB Storage Device History",
                Source = "USBSTOR",
                Status = CheckStatus.PASSED,
                Reason = $"Enumerated {usbDevices.Count} historically connected USB storage device(s)."
            });
        }
        else
        {
            outcomes.Add(CollectionOutcome.SourceUnavailable("UsbHistoryScanner", "USB inspection excluded from scan scope."));
            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-USB-HISTORY",
                CheckName = "USB Storage Device History",
                Source = "USBSTOR",
                Status = CheckStatus.SKIPPED,
                Reason = "USB device history audit was excluded from scan scope."
            });
        }

        // 7. Sensitive Category: Browser History (Explicitly Optional!)
        var swBrowser = Stopwatch.StartNew();
        var browserItems = _browserScanner.ScanBrowserArtifacts(consent.InspectBrowserHistory, out var browserFindings, out var browserDiag);
        report.BrowserEvidence.AddRange(browserItems);
        report.Findings.AddRange(browserFindings);
        report.DiagnosticChecks.Add(browserDiag);

        if (consent.InspectBrowserHistory)
        {
            foreach (var b in browserItems)
            {
                observations.Add(new RawObservation
                {
                    ObservationType = "BrowserObservation",
                    SourceCollector = "BrowserHistoryScanner",
                    SourceIdentity = b.BrowserName,
                    Provenance = "BrowserHistory",
                    TargetEntityId = $"browser:{b.Domain.ToLowerInvariant()}",
                    Properties = new Dictionary<string, string>
                    {
                        ["Browser"] = b.BrowserName,
                        ["Domain"] = b.Domain,
                        ["Category"] = b.MatchedCheatCategory,
                        ["VisitTime"] = b.VisitTime?.ToString("O") ?? string.Empty
                    }
                });
            }
            swBrowser.Stop();
            outcomes.Add(CollectionOutcome.Succeeded("BrowserHistoryScanner", browserItems.Count, swBrowser.Elapsed));
        }
        else
        {
            swBrowser.Stop();
            outcomes.Add(CollectionOutcome.SourceUnavailable("BrowserHistoryScanner", "Browser history excluded from scan scope."));
        }

        // 8. Filesystem Discovery (Downloads, Desktop, Temp, Recycle Bin)
        if (consent.InspectFileDiscovery)
        {
            var swFile = Stopwatch.StartNew();
            update.CurrentCategory = "File Discovery";
            update.CurrentAction = "Auditing user staging folders and $Recycle.Bin for cheat files...";
            update.PercentComplete = 90;
            progress?.Report(update);

            var discoveredFiles = _fileDiscoveryScanner.DiscoverFiles(out var fileFindings);
            report.FileDiscoveries.AddRange(discoveredFiles);
            report.Findings.AddRange(fileFindings);

            foreach (var df in discoveredFiles)
            {
                observations.Add(RawObservation.CreateFileObservation(
                    "FileDiscoveryScanner",
                    df.FilePath,
                    df.FileSizeBytes,
                    df.Sha256,
                    df.LastModified,
                    df.SuspicionReason));
            }

            swFile.Stop();
            outcomes.Add(CollectionOutcome.Succeeded("FileDiscoveryScanner", discoveredFiles.Count, swFile.Elapsed));

            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-FILE-DISCOVERY",
                CheckName = "File Discovery & Recycle Bin Audit",
                Source = "FileDiscoveryScanner",
                Status = CheckStatus.PASSED,
                Reason = $"Discovered {discoveredFiles.Count} notable file artifacts in user staging directories."
            });
        }
        else
        {
            outcomes.Add(CollectionOutcome.SourceUnavailable("FileDiscoveryScanner", "File discovery excluded from scan scope."));
            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-FILE-DISCOVERY",
                CheckName = "File Discovery & Recycle Bin Audit",
                Source = "FileDiscoveryScanner",
                Status = CheckStatus.SKIPPED,
                Reason = "File discovery audit was excluded from scan scope."
            });
        }

        // 9. Services & Third-Party Drivers (HKLM\SYSTEM\CurrentControlSet\Services, Event 7045, SetupAPI.dev.log)
        if (consent.InspectServicesAndDrivers)
        {
            var swSvc = Stopwatch.StartNew();
            update.CurrentCategory = "Services & Drivers";
            update.CurrentAction = "Auditing Windows services, kernel drivers, and driver installation history...";
            update.PercentComplete = 95;
            progress?.Report(update);

            var serviceRecords = _serviceScanner.ScanServicesAndDrivers(out var serviceFindings, out var serviceDiag);
            report.ServicesAndDrivers.AddRange(serviceRecords);
            report.Findings.AddRange(serviceFindings);
            report.DiagnosticChecks.Add(serviceDiag);

            foreach (var s in serviceRecords)
            {
                observations.Add(new RawObservation
                {
                    ObservationType = "ServiceDriverObservation",
                    SourceCollector = "ServiceAndDriverScanner",
                    SourceIdentity = s.IsDriver ? "Driver" : "Service",
                    Provenance = s.Source,
                    TargetEntityId = $"service:{s.Name.ToLowerInvariant()}",
                    Properties = new Dictionary<string, string>
                    {
                        ["ServiceName"] = s.Name,
                        ["DisplayName"] = s.DisplayName,
                        ["BinaryPath"] = s.ImagePath,
                        ["ServiceType"] = s.ServiceType.ToString()
                    }
                });
            }

            swSvc.Stop();
            outcomes.Add(CollectionOutcome.Succeeded("ServiceAndDriverScanner", serviceRecords.Count, swSvc.Elapsed));
        }
        else
        {
            outcomes.Add(CollectionOutcome.SourceUnavailable("ServiceAndDriverScanner", "Services and drivers excluded from scan scope."));
            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-SERVICES-DRIVERS",
                CheckName = "Services & Kernel Drivers",
                Source = "ServiceAndDriverScanner",
                Status = CheckStatus.SKIPPED,
                Reason = "Services and drivers audit was excluded from scan scope."
            });
        }

        // Workstream A (F-001, F-002, F-003, F-014, F-015, F-016):
        // Attach observations, collection outcomes, and build in-memory Evidence Graph
        report.RawObservations = observations;
        report.CollectionOutcomes = outcomes;

        var graphBridge = new GraphSerializationBridge();
        report.EvidenceGraph = graphBridge.BuildGraphFromObservations(observations, report);

        // Validate Evidence Graph and record diagnostic check
        if (report.EvidenceGraph == null || !report.EvidenceGraph.IsValid || report.EvidenceGraph.IsResourceBounded)
        {
            string err = report.EvidenceGraph?.IsResourceBounded == true
                ? "Evidence Graph exceeded maximum node or edge resource limits; scan graph is incomplete."
                : (report.EvidenceGraph != null && !report.EvidenceGraph.IsValid
                    ? $"Evidence Graph validation failed: {string.Join("; ", report.EvidenceGraph.ValidationErrors)}"
                    : "Evidence Graph construction failed.");

            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-EVIDENCE-GRAPH",
                CheckName = "Evidence Graph Integrity & Bounds",
                Source = "EvidenceGraph",
                Status = CheckStatus.ERROR,
                Reason = err
            });
        }
        else
        {
            report.DiagnosticChecks.Add(new DiagnosticCheckItem
            {
                CheckId = "CHK-EVIDENCE-GRAPH",
                CheckName = "Evidence Graph Integrity & Bounds",
                Source = "EvidenceGraph",
                Status = CheckStatus.PASSED,
                Reason = $"Constructed and validated Directed Attributed Evidence Graph ({report.EvidenceGraph.NodeCount} nodes, {report.EvidenceGraph.EdgeCount} edges)."
            });
        }

        // Document any restricted or unavailable collector outcomes into technical limitations
        foreach (var outcome in outcomes.Where(o => o.Status != CollectionStatus.Success))
        {
            string lim = $"{outcome.CollectorName} ({outcome.Status}): {outcome.Reason ?? "Scope restricted or unavailable"}";
            if (!report.TechnicalLimitations.Contains(lim))
            {
                report.TechnicalLimitations.Add(lim);
            }
        }

        // 10. Multi-Source Evidence Correlation & Software State Assessment
        var correlatedAssessments = _correlationEngine.Correlate(report, activePolicy);
        report.CorrelatedAssessments.AddRange(correlatedAssessments);

        // Add or update policy violation findings identified through correlation
        foreach (var assessment in correlatedAssessments.Where(a => a.IsPolicyViolation))
        {
            var existing = report.Findings.FirstOrDefault(f => f.DetectionName.Contains(assessment.SoftwareName, StringComparison.OrdinalIgnoreCase));
            if (existing != null)
            {
                existing.PolicyViolationScope = assessment.Policy.ToString();
                if (assessment.Policy == GameplayPolicy.PROHIBITED_POSSESSION && existing.Severity < Severity.High)
                {
                    existing.Severity = Severity.High;
                }
                existing.TechnicalExplanation += $" • Policy Violation: {assessment.PolicyEvaluationExplanation}";
            }
            else
            {
                var evidenceCat = assessment.State == SoftwareEvidenceState.SoftwarePresent ? EvidenceCategory.Disk :
                                  assessment.State == SoftwareEvidenceState.SoftwareActiveDuringSession ? EvidenceCategory.ActiveInScanWindow :
                                  assessment.State == SoftwareEvidenceState.SoftwareInteractingWithMinecraft ? EvidenceCategory.Injected :
                                  assessment.State == SoftwareEvidenceState.SoftwareExecuted ? EvidenceCategory.RunningProcess :
                                  EvidenceCategory.PolicyViolation;

                // Forensic Correctness (FND-005): Possession violation of idle file on disk is StrongIndicator, NOT ConfirmedCheatArtifact
                var classification = (assessment.Policy == GameplayPolicy.PROHIBITED_POSSESSION && assessment.State == SoftwareEvidenceState.SoftwarePresent)
                    ? FindingClassification.StrongIndicator
                    : (evidenceCat == EvidenceCategory.ActiveInScanWindow ? FindingClassification.ConfirmedCheatArtifact : FindingClassification.StrongIndicator);

                var evState = (classification == FindingClassification.ConfirmedCheatArtifact && assessment.Confidence == ConfidenceLevel.Certain)
                    ? EvidenceState.CONFIRMED
                    : EvidenceState.STRONG_INDICATOR;

                report.Findings.Add(new FindingRecord
                {
                    RuleId = assessment.Policy == GameplayPolicy.PROHIBITED_POSSESSION ? "POLICY-POSSESSION-VIOLATION" : "POLICY-CORRELATED-VIOLATION",
                    DetectionName = $"Policy Violation ({assessment.Policy}): {assessment.SoftwareName}",
                    FindingTitle = $"Policy Violation ({assessment.Policy}): {assessment.SoftwareName}",
                    Category = FindingCategory.PolicyViolation,
                    EvidenceCategory = evidenceCat,
                    Classification = classification,
                    Severity = (evidenceCat == EvidenceCategory.ActiveInScanWindow || evidenceCat == EvidenceCategory.Injected) ? Severity.Critical : Severity.High,
                    EvidenceStrength = EvidenceStrength.Strong,
                    Confidence = assessment.Confidence,
                    DetectionMethod = DetectionMethod.MetadataRule,
                    EvidenceState = evState,
                    SoftwareState = assessment.State,
                    SoftwareStateDescription = assessment.StateDescription,
                    PolicyViolationScope = assessment.Policy.ToString(),
                    EvidenceSource = "EvidenceCorrelationEngine",
                    FilePath = assessment.FilePath,
                    FileSha256 = assessment.Sha256,
                    IsInScanWindow = evidenceCat == EvidenceCategory.ActiveInScanWindow || evidenceCat == EvidenceCategory.Injected,
                    EvidenceClusterId = "CLUSTER-" + assessment.SoftwareName.ToLowerInvariant().Replace(" ", "-"),
                    Interpretation = assessment.WhatIsProven,
                    TechnicalExplanation = assessment.PolicyEvaluationExplanation,
                    WhyItMatters = $"Server policy for {activePolicy.Gamemode} prohibits {assessment.Policy.ToString().ToLowerInvariant().Replace('_', ' ')} of this software.",
                    AlternativeLegitimateExplanations = assessment.AlternativeLegitimateExplanations,
                    WhatIsProven = assessment.WhatIsProven,
                    WhatIsNotProven = assessment.WhatIsNotProven,
                    Limitations = "Possession on disk violates server policy; does not prove execution, injection, or active gameplay use.",
                    RecommendedReview = "Review policy documentation and player history.",
                    RelatedEvidenceIds = assessment.SupportingEvidenceIds
                });
            }
        }

        // Conclude and seal report
        stopwatch.Stop();
        report.ScanCompletedAt = DateTimeOffset.UtcNow;
        report.ScanDurationMs = stopwatch.ElapsedMilliseconds;

        // Formulate Differentiated Investigation Verdict (F-009)
        report.RecomputeSummaryCounts();

        bool hasMinecraftAssociatedCheat = report.Findings.Any(f =>
            (f.Classification == FindingClassification.ConfirmedCheatArtifact || f.Severity == Severity.Critical) &&
            (f.EvidenceCategory == EvidenceCategory.Injected ||
             (f.EvidenceCategory == EvidenceCategory.ActiveInScanWindow && f.RuleId != "PROC-CHEAT-PROCESS-RUNNING") ||
             (f.TargetProcessName != null && f.TargetProcessName.Contains("javaw", StringComparison.OrdinalIgnoreCase) && f.EvidenceCategory != EvidenceCategory.Disk && f.EvidenceCategory != EvidenceCategory.RunningProcess)));

        bool hasSuspiciousRuntime = report.Findings.Any(f =>
            (f.Classification == FindingClassification.Suspicious || f.Classification == FindingClassification.NeedsReview || f.Severity >= Severity.Medium) &&
            (f.EvidenceCategory == EvidenceCategory.RunningProcess ||
             f.EvidenceCategory == EvidenceCategory.LoadedModule ||
             f.EvidenceCategory == EvidenceCategory.Injected ||
             f.EvidenceCategory == EvidenceCategory.ActiveInScanWindow));

        bool hasProhibitedArtifactDiskOrHistory = report.Findings.Any(f =>
            (f.Classification == FindingClassification.ConfirmedCheatArtifact || f.Severity >= Severity.Medium) &&
            (f.EvidenceCategory == EvidenceCategory.Disk || f.EvidenceCategory == EvidenceCategory.Historical || f.EvidenceCategory == EvidenceCategory.FileDeletion));

        var requiredCheckIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "CHK-INSTALLATIONS",
            "CHK-MOD-INVENTORY",
            "CHK-PROCESS-MODULES",
            "CHK-FILE-DISCOVERY",
            "CHK-EVIDENCE-GRAPH"
        };

        bool hasUnavailableRequiredTelemetry =
            report.DiagnosticChecks.Any(c => requiredCheckIds.Contains(c.CheckId) && c.Status != CheckStatus.PASSED) ||
            report.CollectionOutcomes.Any(o =>
                (o.CollectorName is "InstallationLocator" or "ModInspection" or "ProcessScanner" or "FileDiscoveryScanner") &&
                o.Status is not (CollectionStatus.Success or CollectionStatus.PartialSuccess)) ||
            report.CollectionOutcomes.Any(o =>
                (o.CollectorName is "InstallationLocator" or "ModInspection" or "ProcessScanner" or "FileDiscoveryScanner") &&
                o.Status == CollectionStatus.PartialSuccess) ||
            report.RunningProcesses.Any(p => p.ModuleStatus != ModuleEnumerationStatus.Complete) ||
            report.DiagnosticChecks.Any(c => c.CheckId == "CHK-EVIDENCE-GRAPH" && (c.Status == CheckStatus.FLAGGED || c.Status == CheckStatus.ERROR)) ||
            (report.EvidenceGraph == null || !report.EvidenceGraph.IsValid || report.EvidenceGraph.IsResourceBounded);

        if (hasMinecraftAssociatedCheat)
        {
            report.Verdict.OverallAssessment = InvestigationVerdict.StrongEvidenceMinecraft;
            report.Verdict.Recommendation = "Confirmed prohibited cheat artifact with direct runtime association to the Minecraft process. Immediate review required.";
            report.Verdict.KeyTakeaways.Add("Verified technical connection (Java agent, memory module, or active session loading) between cheat software and Minecraft.");
        }
        else if (hasSuspiciousRuntime)
        {
            report.Verdict.OverallAssessment = InvestigationVerdict.SuspiciousRuntimeReview;
            report.Verdict.Recommendation = "Identified suspicious runtime processes or unverified memory modules executing during scan. Human staff review required.";
            report.Verdict.KeyTakeaways.Add("Runtime observations require verification of module provenance and active process behavior.");
        }
        else if (hasProhibitedArtifactDiskOrHistory)
        {
            report.Verdict.OverallAssessment = InvestigationVerdict.ProhibitedArtifactNotActive;
            report.Verdict.Recommendation = "Prohibited software artifact or historical execution trace identified on system. No active runtime association with Minecraft was observed during this scan.";
            report.Verdict.KeyTakeaways.Add("Confirmed file on disk or historical execution artifact; no proof of runtime activity in the inspected Minecraft session.");
            report.Verdict.UnansweredQuestions.Add("Did the player use this software during earlier unmonitored matches or outside this server?");
        }
        else if (hasUnavailableRequiredTelemetry)
        {
            report.Verdict.OverallAssessment = InvestigationVerdict.InconclusiveTelemetry;
            report.Verdict.Recommendation = "Critical forensic telemetry was restricted or inaccessible in current scan context. Investigation is inconclusive.";
            report.Verdict.KeyTakeaways.Add("One or more required diagnostic collectors could not access system telemetry.");
        }
        else
        {
            report.Verdict.OverallAssessment = InvestigationVerdict.NoProhibitedIndicators;
            report.Verdict.Recommendation = "All evaluated checks completed normally. No known prohibited cheat software, suspicious temp injections, or policy violations found in inspected scope.";
            report.Verdict.KeyTakeaways.Add("No confirmed signatures or anomalous runtime modules detected within tested coverage.");
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
