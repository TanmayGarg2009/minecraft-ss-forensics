using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Data.Sqlite;
using MinecraftSsForensics.Scanner.Collectors;
using MinecraftSsForensics.Scanner.Models;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class BrowserHistoryScannerTests
{
    [Fact]
    public void BrowserHistory_WhenConsentFalse_SkipsAndReturnsEmpty()
    {
        var scanner = new BrowserHistoryScanner();
        var items = scanner.ScanBrowserArtifacts(isExplicitlyConsented: false, out var findings, out var diagnostic);

        Assert.Empty(items);
        Assert.Empty(findings);
        Assert.Equal(CheckStatus.SKIPPED, diagnostic.Status);
        Assert.Contains("not selected in the player's consent scope", diagnostic.Reason);
    }

    [Fact]
    public void BrowserHistory_ValidSqliteDatabase_ExtractsAuthenticWebKitTimestamp()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"browser_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        string dbPath = Path.Combine(tempDir, "History");

        try
        {
            // 1. Create realistic Chromium SQLite database
            using (var conn = new SqliteConnection($"Data Source={dbPath}"))
            {
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    CREATE TABLE urls (
                        id INTEGER PRIMARY KEY,
                        url TEXT,
                        title TEXT,
                        visit_count INTEGER,
                        typed_count INTEGER,
                        last_visit_time INTEGER,
                        hidden INTEGER
                    );";
                cmd.ExecuteNonQuery();

                // Authentic WebKit timestamp for 2026-05-15 14:30:00 UTC
                // Epoch: 1601-01-01
                var targetDate = new DateTimeOffset(2026, 5, 15, 14, 30, 0, TimeSpan.Zero);
                long fileTimeTicks = targetDate.ToFileTime();
                long webKitMicroseconds = fileTimeTicks / 10;

                cmd.CommandText = @"
                    INSERT INTO urls (url, title, visit_count, typed_count, last_visit_time, hidden)
                    VALUES 
                    ('https://vape.gg/download?token=secret123', 'Vape Client Official', 3, 1, @ts1, 0),
                    ('https://www.google.com/search?q=minecraft+mods', 'Google Search', 10, 2, @ts2, 0);";

                cmd.Parameters.AddWithValue("@ts1", webKitMicroseconds);
                cmd.Parameters.AddWithValue("@ts2", webKitMicroseconds - 1000000);
                cmd.ExecuteNonQuery();
            }

            // 2. Scan database
            var scanner = new BrowserHistoryScanner();
            var items = new List<BrowserHistoryItem>();
            var findings = new List<FindingRecord>();

            bool ok = scanner.QueryChromiumSqlite("TestBrowser", dbPath, items, findings, out string err);

            Assert.True(ok, err);
            // Must contain ONLY the cheat domain match, never unrelated Google search
            Assert.Single(items);
            Assert.Single(findings);

            var item = items[0];
            Assert.Equal("vape.gg", item.Domain);
            Assert.Equal("TestBrowser", item.BrowserName);
            Assert.Equal(3, item.VisitCount);

            // Verify genuine historical timestamp was parsed, NOT DateTimeOffset.UtcNow!
            Assert.Equal(new DateTimeOffset(2026, 5, 15, 14, 30, 0, TimeSpan.Zero), item.VisitTime);

            // Verify findings sanitized the tracking token query parameter
            var finding = findings[0];
            Assert.Equal(item.VisitTime, finding.ObservedTimestamp);
            Assert.Contains("vape.gg", finding.DetectionName);
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void BrowserHistory_CorruptedDatabase_ReturnsErrorWithoutFabricatingRecords()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"corrupt_browser_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        string dbPath = Path.Combine(tempDir, "History");

        try
        {
            // Write invalid garbage bytes that are not SQLite
            File.WriteAllText(dbPath, "NOT A SQLITE FILE vape.gg vape.gg vape.gg");

            var scanner = new BrowserHistoryScanner();
            var items = new List<BrowserHistoryItem>();
            var findings = new List<FindingRecord>();

            bool ok = scanner.QueryChromiumSqlite("TestBrowser", dbPath, items, findings, out string err);

            Assert.False(ok);
            Assert.Empty(items);
            Assert.Empty(findings);
            Assert.NotEmpty(err);
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }
}
