using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using MinecraftSsForensics.Scanner.Engine;
using MinecraftSsForensics.Scanner.Export;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Policy;

namespace MinecraftSsForensics.Scanner.App;

/// <summary>
/// Main application entry point supporting both WPF graphical UI and headless CLI invocation.
/// </summary>
public partial class App : Application
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AllocConsole();

    private const int ATTACH_PARENT_PROCESS = -1;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (e.Args.Length > 0 && IsCliInvocation(e.Args))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            // Attach to calling terminal console or allocate console window
            if (!AttachConsole(ATTACH_PARENT_PROCESS))
            {
                AllocConsole();
            }

            int exitCode = await RunCliAsync(e.Args);
            Environment.Exit(exitCode);
            return;
        }

        // Graphical User Interface Mode
        ShutdownMode = ShutdownMode.OnMainWindowClose;
        var mainWindow = new MainWindow();
        MainWindow = mainWindow;
        mainWindow.Show();
    }

    private static bool IsCliInvocation(string[] args)
    {
        if (args.Length == 0) return false;
        string first = args[0].ToLowerInvariant();
        return first == "scan" || first == "--scan" || first == "-h" || first == "--help" || first == "help";
    }

    private static async Task<int> RunCliAsync(string[] args)
    {
        string outputDir = Path.Combine(Directory.GetCurrentDirectory(), "reports");
        string scanMode = "FULL";
        string gamemode = "Crystal PvP";
        string? customDir = null;
        string format = "all";
        bool includeBrowser = false;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i].ToLowerInvariant();
            if (arg == "-h" || arg == "--help" || arg == "help")
            {
                PrintHelp();
                return 0;
            }
            else if ((arg == "-o" || arg == "--output") && i + 1 < args.Length)
            {
                outputDir = args[++i];
            }
            else if ((arg == "-m" || arg == "--mode") && i + 1 < args.Length)
            {
                scanMode = args[++i].ToUpperInvariant();
            }
            else if ((arg == "-g" || arg == "--gamemode") && i + 1 < args.Length)
            {
                gamemode = args[++i];
            }
            else if ((arg == "-d" || arg == "--dir") && i + 1 < args.Length)
            {
                customDir = args[++i];
            }
            else if ((arg == "-f" || arg == "--format") && i + 1 < args.Length)
            {
                format = args[++i].ToLowerInvariant();
            }
            else if (arg == "--browser")
            {
                includeBrowser = true;
            }
        }

        Console.WriteLine("========================================================================");
        Console.WriteLine(" Minecraft SS Forensics - Headless CLI Scanner");
        Console.WriteLine(" Automated, Read-Only Screen-Share & System Forensics Engine");
        Console.WriteLine("========================================================================");
        Console.WriteLine($"[CONFIG] Scan Mode       : {scanMode}");
        Console.WriteLine($"[CONFIG] Gamemode Policy : {gamemode}");
        Console.WriteLine($"[CONFIG] Output Directory: {Path.GetFullPath(outputDir)}");
        Console.WriteLine($"[CONFIG] Target Formats  : {format}");
        if (!string.IsNullOrEmpty(customDir))
        {
            Console.WriteLine($"[CONFIG] Custom Directory: {customDir}");
        }
        Console.WriteLine("------------------------------------------------------------------------");

        var policyRegistry = new ModPolicyRegistry();
        var policy = policyRegistry.GetPolicy(gamemode);

        var consent = new ConsentScopeConfig
        {
            ConsentGiven = true,
            InspectMinecraftMods = true,
            InspectProcessesAndModules = true,
            InspectExecutionArtifacts = true,
            InspectRegistryArtifacts = true,
            InspectUsbHistory = true,
            InspectFileDiscovery = true,
            InspectBrowserHistory = includeBrowser
        };

        var progress = new Progress<ScanProgressUpdate>(update =>
        {
            Console.WriteLine($"[{update.PercentComplete,3}%] {update.CurrentCategory}: {update.CurrentAction}");
        });

        try
        {
            var engine = new StandaloneScannerEngine();
            Console.WriteLine("[INFO] Starting forensic collection pipeline...");

            var report = await engine.ExecuteScanAsync(
                consent,
                scanMode,
                customDir,
                onlyCustomDirectory: false,
                progress,
                policy,
                CancellationToken.None);

            Console.WriteLine("[INFO] Forensic collection and correlation complete.");

            Directory.CreateDirectory(outputDir);
            string baseFileName = $"report-{report.ReportId}";

            bool exportAll = format == "all";

            if (exportAll || format.Contains("json"))
            {
                string jsonPath = Path.Combine(outputDir, $"{baseFileName}.json");
                string jsonContent = PortableJsonExporter.ExportToJson(report);
                await File.WriteAllTextAsync(jsonPath, jsonContent);
                Console.WriteLine($"[SAVED] JSON Report       -> {jsonPath}");
            }

            if (exportAll || format.Contains("html"))
            {
                string htmlPath = Path.Combine(outputDir, $"{baseFileName}.html");
                string htmlContent = StandaloneHtmlExporter.ExportToHtml(report);
                await File.WriteAllTextAsync(htmlPath, htmlContent);
                Console.WriteLine($"[SAVED] Interactive HTML  -> {htmlPath}");
            }

            if (exportAll || format.Contains("md") || format.Contains("markdown"))
            {
                string mdPath = Path.Combine(outputDir, $"{baseFileName}.md");
                string mdContent = MarkdownExporter.ExportToMarkdown(report);
                await File.WriteAllTextAsync(mdPath, mdContent);
                Console.WriteLine($"[SAVED] Markdown Summary  -> {mdPath}");
            }

            if (exportAll || format.Contains("csv"))
            {
                string csvPath = Path.Combine(outputDir, $"{baseFileName}.csv");
                string csvContent = CsvExporter.ExportToCsv(report);
                await File.WriteAllTextAsync(csvPath, csvContent);
                Console.WriteLine($"[SAVED] CSV Findings Table -> {csvPath}");
            }

            Console.WriteLine("------------------------------------------------------------------------");
            Console.WriteLine($"[SUMMARY] Total Findings: {report.Findings.Count}");
            Console.WriteLine($"[SUMMARY] Integrity Seal: {(!string.IsNullOrEmpty(report.ReportIntegrityHash) ? report.ReportIntegrityHash : "N/A")}");
            Console.WriteLine("[DONE] Forensic scan completed successfully.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine($"[ERROR] Scan execution failed: {ex.Message}");
            Console.Error.WriteLine(ex.StackTrace);
            Console.ResetColor();
            return 1;
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Minecraft SS Forensics Scanner");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  MinecraftSsForensics.exe scan [options]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  -o, --output <dir>       Directory where reports will be saved (default: ./reports)");
        Console.WriteLine("  -m, --mode <QUICK|FULL>  Scan mode depth (default: FULL)");
        Console.WriteLine("  -g, --gamemode <name>    Gamemode policy (default: 'Crystal PvP')");
        Console.WriteLine("  -d, --dir <path>         Custom Minecraft installation path to scan");
        Console.WriteLine("  -f, --format <format>    Export formats: json, html, markdown, csv, or all (default: all)");
        Console.WriteLine("      --browser            Include browser history scanning (optional)");
        Console.WriteLine("  -h, --help               Display this help text");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  MinecraftSsForensics.exe scan --output C:\\SS_Reports");
        Console.WriteLine("  MinecraftSsForensics.exe scan -o ./out -f html,json -g \"Sword PvP\"");
    }
}
