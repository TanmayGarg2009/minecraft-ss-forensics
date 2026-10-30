using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Data.Sqlite;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Collectors;

/// <summary>
/// Strictly scoped, privacy-compliant Chromium browser history auditor.
/// Operates ONLY when explicit consent for sensitive browser auditing is granted.
/// Uses a read-only SQLite parser to query specific known Minecraft cheat distribution domains.
/// NEVER fabricates visit timestamps; parses authentic Chromium WebKit timestamps.
/// Safely copies SQLite databases and WAL files to prevent locking conflicts.
/// </summary>
public class BrowserHistoryScanner
{
    // Epoch for Chromium WebKit timestamps: January 1, 1601 UTC (Windows FILETIME epoch)
    private static readonly DateTimeOffset WebKitEpoch = new(1601, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public List<BrowserHistoryItem> ScanBrowserArtifacts(bool isExplicitlyConsented, out List<FindingRecord> findings, out DiagnosticCheckItem diagnostic)
    {
        var items = new List<BrowserHistoryItem>();
        findings = new List<FindingRecord>();

        if (!isExplicitlyConsented)
        {
            diagnostic = new DiagnosticCheckItem
            {
                CheckId = "CHK-BROWSER-HISTORY",
                CheckName = "Browser History Audit (Cheat Domains)",
                Source = "BrowserHistoryView",
                Status = CheckStatus.SKIPPED,
                Reason = "Browser history auditing was not selected in the player's consent scope (Sensitive category)."
            };
            return items;
        }

        diagnostic = new DiagnosticCheckItem
        {
            CheckId = "CHK-BROWSER-HISTORY",
            CheckName = "Browser History Audit (Cheat Domains)",
            Source = "BrowserHistoryView",
            Status = CheckStatus.PASSED,
            Reason = "Audited local browser history using read-only SQLite parser for known Minecraft cheat distribution domains."
        };

        var browserTargets = new (string BrowserName, string HistoryPath)[]
        {
            ("Google Chrome", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data\Default\History")),
            ("Microsoft Edge", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\User Data\Default\History")),
            ("Brave Browser", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"BraveSoftware\Brave-Browser\User Data\Default\History")),
            ("Opera", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Opera Software\Opera Stable\History"))
        };

        int auditedCount = 0;
        int failedCount = 0;

        foreach (var (browser, path) in browserTargets)
        {
            if (File.Exists(path))
            {
                auditedCount++;
                bool success = QueryChromiumSqlite(browser, path, items, findings, out string errorNote);
                if (!success)
                {
                    failedCount++;
                }
            }
        }

        if (auditedCount == 0)
        {
            diagnostic.Status = CheckStatus.SKIPPED;
            diagnostic.Reason = "No standard Chromium browser history databases were discovered on this user profile.";
        }
        else if (failedCount == auditedCount)
        {
            diagnostic.Status = CheckStatus.ERROR;
            diagnostic.Reason = "All discovered Chromium browser history files could not be read or opened via SQLite.";
        }

        return items;
    }

    /// <summary>
    /// Safely copies the SQLite database and WAL files, then queries the urls table using parameterized SQL.
    /// </summary>
    public bool QueryChromiumSqlite(string browserName, string historyFilePath, List<BrowserHistoryItem> items, List<FindingRecord> findings, out string errorNote)
    {
        errorNote = string.Empty;
        if (!File.Exists(historyFilePath)) return true;

        string tempDir = Path.Combine(Path.GetTempPath(), $"ss_hist_{Guid.NewGuid():N}");

        try
        {
            Directory.CreateDirectory(tempDir);
            string tempDb = Path.Combine(tempDir, "History");
            string tempWal = Path.Combine(tempDir, "History-wal");
            string tempShm = Path.Combine(tempDir, "History-shm");

            string srcWal = historyFilePath + "-wal";
            string srcShm = historyFilePath + "-shm";

            // Safe copy of main database with shared read/write
            using (var src = new FileStream(historyFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var dst = new FileStream(tempDb, FileMode.Create, FileAccess.Write))
            {
                src.CopyTo(dst);
            }

            // Copy WAL file if it exists to preserve recent transactions
            if (File.Exists(srcWal))
            {
                try
                {
                    using var src = new FileStream(srcWal, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    using var dst = new FileStream(tempWal, FileMode.Create, FileAccess.Write);
                    src.CopyTo(dst);
                }
                catch { /* Non-fatal WAL copy failure */ }
            }

            if (File.Exists(srcShm))
            {
                try
                {
                    using var src = new FileStream(srcShm, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    using var dst = new FileStream(tempShm, FileMode.Create, FileAccess.Write);
                    src.CopyTo(dst);
                }
                catch { /* Non-fatal */ }
            }

            // Open read-only SQLite connection
            string connString = new SqliteConnectionStringBuilder
            {
                DataSource = tempDb,
                Mode = SqliteOpenMode.ReadOnly
            }.ToString();

            using var conn = new SqliteConnection(connString);
            conn.Open();

            // Construct parameterized query for known cheat domains
            var domainList = new List<string>(CheatDetectionDatabase.KnownCheatDomains);
            if (domainList.Count == 0) return true;

            var whereClauses = new List<string>();
            using var cmd = conn.CreateCommand();

            for (int i = 0; i < domainList.Count; i++)
            {
                string paramName = $"@d{i}";
                whereClauses.Add($"url LIKE {paramName}");
                cmd.Parameters.AddWithValue(paramName, $"%{domainList[i]}%");
            }

            cmd.CommandText = $"SELECT url, title, visit_count, last_visit_time FROM urls WHERE {string.Join(" OR ", whereClauses)}";

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                string rawUrl = reader.IsDBNull(0) ? string.Empty : reader.GetString(0);
                string title = reader.IsDBNull(1) ? string.Empty : reader.GetString(1);
                int visitCount = reader.IsDBNull(2) ? 1 : reader.GetInt32(2);
                long rawTimeMicroseconds = reader.IsDBNull(3) ? 0 : reader.GetInt64(3);

                DateTimeOffset? authenticVisitTime = ParseWebKitTimestamp(rawTimeMicroseconds);

                // Identify matched cheat domain
                string matchedDomain = string.Empty;
                foreach (var d in domainList)
                {
                    if (rawUrl.Contains(d, StringComparison.OrdinalIgnoreCase))
                    {
                        matchedDomain = d;
                        break;
                    }
                }

                if (string.IsNullOrEmpty(matchedDomain)) continue;

                // Sanitize URL to protect privacy: remove personal query parameters
                string sanitizedUrl = SanitizeUrl(rawUrl);

                var item = new BrowserHistoryItem
                {
                    BrowserName = browserName,
                    Domain = matchedDomain,
                    MatchedCheatCategory = "Known Cheat Distribution / Resource Portal",
                    VisitTime = authenticVisitTime ?? DateTimeOffset.MinValue,
                    VisitCount = visitCount
                };
                items.Add(item);

                findings.Add(new FindingRecord
                {
                    RuleId = "BROWSER-CHEAT-SITE-VISIT",
                    DetectionName = $"Browser History Match: {matchedDomain}",
                    Category = FindingCategory.BrowserHistory,
                    Classification = FindingClassification.Suspicious,
                    Severity = Severity.Medium,
                    Confidence = authenticVisitTime.HasValue ? ConfidenceLevel.High : ConfidenceLevel.Medium,
                    EvidenceSource = $"Browser History ({browserName})",
                    ObservedTimestamp = authenticVisitTime,
                    TechnicalExplanation = $"Discovered visit to known cheat domain '{matchedDomain}' in {browserName} history database. " +
                        (authenticVisitTime.HasValue ? $"Authentic recorded visit time: {authenticVisitTime:yyyy-MM-dd HH:mm:ss} UTC." : "Timestamp unrecorded."),
                    WhyItMatters = "Indicates that the player navigated to or researched known cheat client websites.",
                    AlternativeLegitimateExplanations = "Player may have followed a link from a news article, YouTube video, or forum discussion without downloading cheat software.",
                    WhatIsProven = $"A URL containing '{matchedDomain}' was visited in {browserName} on this user profile.",
                    WhatIsNotProven = "Does not prove that cheat software was downloaded, executed, or active during a Minecraft session.",
                    EvidenceStrengtheningFinding = "Discovered cheat executable in Downloads/Desktop or Prefetch/BAM execution record.",
                    EvidenceWeakeningFinding = "No executable, JAR, or memory artifacts matching the cheat were found on the machine."
                });
            }

            return true;
        }
        catch (Exception ex)
        {
            errorNote = ex.Message;
            return false;
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempDir))
                {
                    Directory.Delete(tempDir, recursive: true);
                }
            }
            catch { /* Best effort temporary file cleanup */ }
        }
    }

    /// <summary>
    /// Parses a Chromium WebKit timestamp (microseconds since January 1, 1601 UTC).
    /// Returns null if the timestamp is 0 or invalid.
    /// </summary>
    public static DateTimeOffset? ParseWebKitTimestamp(long microseconds)
    {
        if (microseconds <= 0) return null;

        try
        {
            // Windows FILETIME is in 100-nanosecond intervals (1 microsecond = 10 intervals)
            long fileTimeTicks = checked(microseconds * 10);
            return DateTimeOffset.FromFileTime(fileTimeTicks);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Sanitizes URL to strip tracking tokens and sensitive query parameters.
    /// </summary>
    private static string SanitizeUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return string.Empty;
        int queryIndex = url.IndexOf('?');
        if (queryIndex > 0)
        {
            return url[..queryIndex] + " [QUERY-REDACTED]";
        }
        return url;
    }
}
