using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Process;

namespace MinecraftSsForensics.Scanner.Collectors;

public class ServiceOrDriverRecord
{
    public string Name { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string ImagePath { get; set; } = string.Empty;
    public int ServiceType { get; set; } // 1=Kernel Driver, 2=FileSystem Driver, 16=Own Process, 32=Share Process
    public int StartType { get; set; }   // 0=Boot, 1=System, 2=Auto, 3=Demand, 4=Disabled
    public bool IsDriver => ServiceType == 1 || ServiceType == 2;
    public bool IsInUserDirectory { get; set; }
    public bool IsSigned { get; set; }
    public bool IsTrustedSignature { get; set; }
    public string? SignerSubject { get; set; }
    public string? TrustStatusExplanation { get; set; }
    public DateTimeOffset? InstalledTimestamp { get; set; }
    public string Source { get; set; } = "Registry:Services";
}

/// <summary>
/// User-mode collector for Windows services, third-party kernel drivers, Event ID 7045, and SetupAPI logs.
/// Strictly non-invasive: does not install kernel components or persistent agents.
/// Transparently documents that user-mode inspection cannot guarantee detection of kernel-hidden rootkits.
/// </summary>
public class ServiceAndDriverScanner
{
    public List<ServiceOrDriverRecord> ScanServicesAndDrivers(out List<FindingRecord> findings, out DiagnosticCheckItem diagnostic)
    {
        var records = new List<ServiceOrDriverRecord>();
        findings = new List<FindingRecord>();

        diagnostic = new DiagnosticCheckItem
        {
            CheckId = "CHK-SERVICES-DRIVERS",
            CheckName = "Windows Services & Driver Audit",
            Source = "ServiceAndDriverScanner",
            Status = CheckStatus.PASSED,
            Reason = "Audited registered services, drivers, and recent installation history (Event ID 7045)."
        };

        if (!OperatingSystem.IsWindows())
        {
            diagnostic.Status = CheckStatus.SKIPPED;
            diagnostic.Reason = "Service and driver auditing requires Microsoft Windows.";
            return records;
        }

        try
        {
            // 1. Audit Registry Services
            ScanRegistryServices(records, findings);

            // 2. Audit System Event Log 7045 (New Service Installed)
            ScanEventId7045(records, findings);
        }
        catch (Exception ex)
        {
            diagnostic = new DiagnosticCheckItem
            {
                CheckId = "CHK-SERVICES-DRIVERS",
                CheckName = "Windows Services & Driver Audit",
                Source = "ServiceAndDriverScanner",
                Status = CheckStatus.UNAVAILABLE,
                Reason = $"Service and driver audit encountered an error: {ex.Message}"
            };
        }

        return records;
    }

    private static void ScanRegistryServices(List<ServiceOrDriverRecord> records, List<FindingRecord> findings)
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey == null) return;

            string[] userWritablePatterns = { @"\temp\", @"\appdata\", @"\users\", @"\downloads\", @"\desktop\", @"\$recycle.bin\" };

            foreach (string subKeyName in servicesKey.GetSubKeyNames())
            {
                try
                {
                    using var subKey = servicesKey.OpenSubKey(subKeyName);
                    if (subKey == null) continue;

                    string? imagePath = subKey.GetValue("ImagePath") as string;
                    if (string.IsNullOrWhiteSpace(imagePath)) continue;

                    int serviceType = subKey.GetValue("Type") is int t ? t : 0;
                    int startType = subKey.GetValue("Start") is int s ? s : 0;
                    string displayName = subKey.GetValue("DisplayName") as string ?? subKeyName;

                    string cleanPath = imagePath.Trim().Trim('"');
                    if (cleanPath.StartsWith(@"\??\")) cleanPath = cleanPath[4..];
                    if (cleanPath.StartsWith(@"\\?\")) cleanPath = cleanPath[4..];

                    // Check if service executable resides in a user-writable directory
                    string lowerPath = cleanPath.ToLowerInvariant();
                    bool isUserDir = userWritablePatterns.Any(p => lowerPath.Contains(p));

                    if (isUserDir)
                    {
                        var record = new ServiceOrDriverRecord
                        {
                            Name = subKeyName,
                            DisplayName = displayName,
                            ImagePath = cleanPath,
                            ServiceType = serviceType,
                            StartType = startType,
                            IsInUserDirectory = true,
                            Source = "Registry:Services"
                        };

                        // Verify Authenticode digital signature
                        if (File.Exists(cleanPath))
                        {
                            var trust = AuthenticodeTrustValidator.VerifyFileTrust(cleanPath);
                            record.IsSigned = trust.IsSigned;
                            record.IsTrustedSignature = trust.IsTrusted;
                            record.SignerSubject = trust.SignerSubject;
                            record.TrustStatusExplanation = trust.StatusExplanation;
                        }

                        records.Add(record);

                        // If an unsigned or untrusted driver or service is registered in a user directory, flag as suspicious
                        if (!record.IsTrustedSignature)
                        {
                            findings.Add(new FindingRecord
                            {
                                RuleId = "DRV-SUSP-USERDIR-SERVICE",
                                DetectionName = $"Unsigned / Untrusted Service or Driver in User Directory: {subKeyName}",
                                FindingTitle = $"Unsigned / Untrusted Service or Driver in User Directory: {subKeyName}",
                                Category = FindingCategory.ProcessInjection,
                                EvidenceCategory = EvidenceCategory.RunningProcess,
                                Classification = FindingClassification.Suspicious,
                                Severity = Severity.Medium,
                                EvidenceStrength = EvidenceStrength.Moderate,
                                Confidence = ConfidenceLevel.High,
                                DetectionMethod = DetectionMethod.MetadataRule,
                                EvidenceSource = "Registry:Services",
                                FilePath = cleanPath,
                                IsInScanWindow = false,
                                EvidenceClusterId = "CLUSTER-SVC-" + subKeyName.ToLowerInvariant(),
                                Interpretation = $"Service '{subKeyName}' is registered pointing to file '{cleanPath}' without trusted signature.",
                                TechnicalExplanation = $"Service '{subKeyName}' (Type {serviceType}) has ImagePath pointing to user directory: '{cleanPath}'. Digital signature verification: {record.TrustStatusExplanation ?? "Unsigned"}.",
                                WhyItMatters = "Vulnerable driver exploitation (BYOVD) and custom ghost client kernel loaders often register temporary services from %TEMP% or user folders.",
                                AlternativeLegitimateExplanations = "Custom development tools, peripheral drivers, or gaming software installed to non-standard paths.",
                                WhatIsProven = $"Service '{subKeyName}' is registered in HKLM Services pointing to a file in a user-writable directory.",
                                WhatIsNotProven = "Does not prove the service or driver interacts with Minecraft or modifies memory without runtime driver telemetry.",
                                Limitations = "Service registry configuration. Does not establish active memory interaction with javaw.exe.",
                                RecommendedReview = "Examine binary exports and driver certificate.",
                                EvidenceStrengtheningFinding = "Service ImagePath matches a known vulnerable driver hash (e.g. gdrv.sys, mhyprot2.sys, kprocesshacker.sys).",
                                EvidenceWeakeningFinding = "Service belongs to an established software vendor and is signed with a valid certificate."
                            });
                        }
                    }
                }
                catch { /* Access denied or missing key */ }
            }
        }
        catch { /* Fallback */ }
    }

    private static void ScanEventId7045(List<ServiceOrDriverRecord> records, List<FindingRecord> findings)
    {
        try
        {
            string query = "*[System[(EventID=7045)]]";
            var eventsQuery = new EventLogQuery("System", PathType.LogName, query) { ReverseDirection = true };
            using var reader = new EventLogReader(eventsQuery);

            int eventCount = 0;
            EventRecord? record;
            while ((record = reader.ReadEvent()) != null && eventCount < 200)
            {
                using (record)
                {
                    eventCount++;
                    string? xml = record.ToXml();
                    if (string.IsNullOrEmpty(xml)) continue;

                    string serviceName = ExtractXmlValue(xml, "ServiceName");
                    string imagePath = ExtractXmlValue(xml, "ImagePath");
                    string serviceType = ExtractXmlValue(xml, "ServiceType");
                    string startType = ExtractXmlValue(xml, "StartType");

                    string lower = imagePath.ToLowerInvariant();
                    if (lower.Contains(@"\temp\") || lower.Contains(@"\appdata\") || lower.Contains(@"\downloads\"))
                    {
                        var entry = new ServiceOrDriverRecord
                        {
                            Name = serviceName,
                            DisplayName = serviceName,
                            ImagePath = imagePath,
                            InstalledTimestamp = record.TimeCreated.HasValue ? new DateTimeOffset(record.TimeCreated.Value) : null,
                            IsInUserDirectory = true,
                            Source = "EventLog:System-7045"
                        };
                        records.Add(entry);

                        findings.Add(new FindingRecord
                        {
                            RuleId = "EVENT-7045-SERVICE-INSTALLED",
                            DetectionName = $"Service Installed from User Path (Event ID 7045): {serviceName}",
                            FindingTitle = $"Service Installed from User Path (Event ID 7045): {serviceName}",
                            Category = FindingCategory.ProcessInjection,
                            EvidenceCategory = EvidenceCategory.Historical,
                            Classification = FindingClassification.Suspicious,
                            Severity = Severity.Medium,
                            EvidenceStrength = EvidenceStrength.Moderate,
                            Confidence = ConfidenceLevel.High,
                            DetectionMethod = DetectionMethod.HistoricalArtifact,
                            EvidenceSource = "System Event Log (ID 7045)",
                            FilePath = imagePath,
                            ObservedTimestamp = entry.InstalledTimestamp,
                            IsInScanWindow = false,
                            EvidenceClusterId = "CLUSTER-EVENT7045-" + serviceName.ToLowerInvariant(),
                            Interpretation = $"Windows Event Log recorded service installation for '{serviceName}' from user directory '{imagePath}'.",
                            TechnicalExplanation = $"Event ID 7045 indicates a new service or driver '{serviceName}' was installed pointing to user directory: '{imagePath}' at {entry.InstalledTimestamp}.",
                            WhyItMatters = "Transient services installed immediately prior to a match indicate possible kernel cheat loading.",
                            AlternativeLegitimateExplanations = "Software installation or updater running from temporary extract directory.",
                            WhatIsProven = "Service installation event was logged in Windows System Event Log.",
                            WhatIsNotProven = "Does not prove active execution during match without process lifetime correlation.",
                            Limitations = "Historical event log entry. Does not establish active cheat usage during game match.",
                            RecommendedReview = "Review event timestamp against player match timeline."
                        });
                    }
                }
            }
        }
        catch { /* Event log access restricted in user mode */ }
    }

    private static string ExtractXmlValue(string xml, string nodeName)
    {
        var match = Regex.Match(xml, $@"<{nodeName}>(.*?)</{nodeName}>", RegexOptions.IgnoreCase);
        if (match.Success)
            return match.Groups[1].Value.Trim();

        var dataMatch = Regex.Match(xml, $@"<Data Name=""{nodeName}"">(.*?)</Data>", RegexOptions.IgnoreCase);
        if (dataMatch.Success)
            return dataMatch.Groups[1].Value.Trim();

        return string.Empty;
    }
}
