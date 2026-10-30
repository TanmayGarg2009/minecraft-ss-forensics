using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using MinecraftSsForensics.Scanner.Models;

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
    public string? SignerSubject { get; set; }
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

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            diagnostic = new DiagnosticCheckItem
            {
                CheckId = "CHK-SERVICES-DRIVERS",
                CheckName = "Windows Services & Driver Audit",
                Source = "ServiceAndDriverScanner",
                Status = CheckStatus.SKIPPED,
                Reason = "Operating system is not Windows."
            };
            return records;
        }

        try
        {
            // 1. Audit Registry Services Hive: HKLM\SYSTEM\CurrentControlSet\Services
            ScanRegistryServices(records, findings);

            // 2. Query System Event Log for Event ID 7045 (Service/Driver Installed)
            ScanEventId7045(records, findings);

            // 3. Scan SetupAPI.dev.log for recent driver installation entries
            ScanSetupApiLog(records, findings);

            diagnostic = new DiagnosticCheckItem
            {
                CheckId = "CHK-SERVICES-DRIVERS",
                CheckName = "Windows Services & Driver Audit",
                Source = "ServiceAndDriverScanner",
                Status = findings.Any(f => f.Classification == FindingClassification.ConfirmedCheatArtifact || f.Classification == FindingClassification.StrongIndicator)
                    ? CheckStatus.FLAGGED
                    : CheckStatus.PASSED,
                Reason = $"Audited Windows service and driver registry entries. Found {records.Count} notable services/drivers ({records.Count(r => r.IsDriver)} drivers). Note: User-mode scan cannot guarantee detection of DKOM or kernel-level hidden rootkits."
            };
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
                    cleanPath = Environment.ExpandEnvironmentVariables(cleanPath);

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

                        // Check digital signature
                        if (File.Exists(cleanPath))
                        {
                            try
                            {
                                var cert = X509Certificate.CreateFromSignedFile(cleanPath);
                                record.IsSigned = cert != null;
                                record.SignerSubject = cert?.Subject;
                            }
                            catch
                            {
                                record.IsSigned = false;
                            }
                        }

                        records.Add(record);

                        // If an unsigned driver or service is registered in a temporary or user directory, flag as suspicious
                        if (!record.IsSigned)
                        {
                            findings.Add(new FindingRecord
                            {
                                RuleId = "DRV-SUSP-USERDIR-SERVICE",
                                DetectionName = $"Unsigned Service or Driver in User Directory: {subKeyName}",
                                Category = FindingCategory.ProcessInjection,
                                Classification = FindingClassification.Suspicious,
                                Severity = Severity.High,
                                Confidence = ConfidenceLevel.High,
                                EvidenceSource = "Registry:Services",
                                FilePath = cleanPath,
                                TechnicalExplanation = $"Service '{subKeyName}' (Type {serviceType}) has ImagePath pointing to user directory: '{cleanPath}'. Digital signature is missing or unverified.",
                                WhyItMatters = "Vulnerable driver exploitation (BYOVD) and custom ghost client kernel loaders often register temporary services from %TEMP% or user folders.",
                                AlternativeLegitimateExplanations = "Custom hardware diagnostic tool, overclocking utility, or third-party emulator.",
                                WhatIsProven = "Service registry entry exists pointing to an executable in a user-writable path.",
                                WhatIsNotProven = "Does not prove the service was loaded specifically to modify Minecraft memory.",
                                Limitations = "User-mode scan checks registry registration; does not intercept kernel memory calls."
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
            var eventsQuery = new EventLogQuery("System", PathType.LogName, query);
            using var reader = new EventLogReader(eventsQuery);

            int eventCount = 0;
            EventRecord record;
            while ((record = reader.ReadEvent()) != null && eventCount < 50)
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
                            Category = FindingCategory.ExecutionArtifacts,
                            Classification = FindingClassification.StrongIndicator,
                            Severity = Severity.High,
                            Confidence = ConfidenceLevel.Certain,
                            EvidenceSource = "Windows Event Log: System Event 7045",
                            FilePath = imagePath,
                            ObservedTimestamp = entry.InstalledTimestamp,
                            TechnicalExplanation = $"Windows Event Log records installation of service '{serviceName}' with binary '{imagePath}' at {entry.InstalledTimestamp}.",
                            WhyItMatters = "Confirms historical installation of a service or driver during the event log retention period.",
                            AlternativeLegitimateExplanations = "Software installation or portable driver utility run by user.",
                            WhatIsProven = "Service installation event occurred at the recorded timestamp.",
                            WhatIsNotProven = "Does not prove the service was running during active Minecraft gameplay without timestamp correlation."
                        });
                    }
                }
            }
        }
        catch { /* Event log requires appropriate read permissions */ }
    }

    private static void ScanSetupApiLog(List<ServiceOrDriverRecord> records, List<FindingRecord> findings)
    {
        try
        {
            string setupApiLog = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "inf", "setupapi.dev.log");
            if (!File.Exists(setupApiLog)) return;

            using var stream = new FileStream(setupApiLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);

            string? line;
            int linesRead = 0;
            var recentDriverRegex = new Regex(@"Device Install \((?:DiShowUpdateDevice|DriverPackageInstall)\) - (.+)", RegexOptions.Compiled);

            while ((line = reader.ReadLine()) != null && linesRead < 5000)
            {
                linesRead++;
                var match = recentDriverRegex.Match(line);
                if (match.Success)
                {
                    string driverTarget = match.Groups[1].Value.Trim();
                    if (driverTarget.Contains(@"\temp\") || driverTarget.Contains(@"\appdata\"))
                    {
                        records.Add(new ServiceOrDriverRecord
                        {
                            Name = Path.GetFileName(driverTarget),
                            ImagePath = driverTarget,
                            IsInUserDirectory = true,
                            Source = "SetupAPI.dev.log"
                        });
                    }
                }
            }
        }
        catch { /* Best effort file read */ }
    }

    private static string ExtractXmlValue(string xml, string elementName)
    {
        var match = Regex.Match(xml, $"<{elementName}>([^<]+)</{elementName}>", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value.Trim() : string.Empty;
    }
}
