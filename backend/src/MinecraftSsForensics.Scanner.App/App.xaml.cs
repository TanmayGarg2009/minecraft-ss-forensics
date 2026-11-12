using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using MinecraftSsForensics.Scanner.Cli;
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetStdHandle(int nStdHandle, IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    private const int ATTACH_PARENT_PROCESS = -1;
    private const int STD_INPUT_HANDLE = -10;
    private const int STD_OUTPUT_HANDLE = -11;
    private const int STD_ERROR_HANDLE = -12;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x1;
    private const uint FILE_SHARE_WRITE = 0x2;
    private const uint OPEN_EXISTING = 3;
    private static readonly IntPtr InvalidHandleValue = new(-1);

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (e.Args.Length > 0 && IsCliInvocation(e.Args))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            InitializeConsole();

            int exitCode = await RunCliAsync(e.Args);
            Environment.Exit(exitCode);
            return;
        }

        ShutdownMode = ShutdownMode.OnMainWindowClose;
        var mainWindow = new MainWindow();
        MainWindow = mainWindow;
        mainWindow.Show();
    }

    private static void InitializeConsole()
    {
        if (!AttachConsole(ATTACH_PARENT_PROCESS))
            AllocConsole();

        IntPtr output = CreateFile("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (output != InvalidHandleValue)
        {
            SetStdHandle(STD_OUTPUT_HANDLE, output);
            SetStdHandle(STD_ERROR_HANDLE, output);
        }

        IntPtr input = CreateFile("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (input != InvalidHandleValue)
            SetStdHandle(STD_INPUT_HANDLE, input);

        Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
        Console.SetError(new StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
    }

    private static bool IsCliInvocation(string[] args)
    {
        if (args.Length == 0) return false;
        string first = args[0].ToLowerInvariant();
        return first is "scan" or "--scan" or "-h" or "--help" or "help";
    }

    private static async Task<int> RunCliAsync(string[] args)
    {
        if (args[0] is "-h" or "--help" or "help")
        {
            PrintHelp();
            return 0;
        }

        var parsed = ScanCliOptions.Parse(args[0] == "--scan" ? new[] { "scan" }.Concat(args[1..]).ToArray() : args);
        if (!parsed.Success || parsed.Options == null)
        {
            Console.Error.WriteLine($"[ERROR] {parsed.ErrorMessage}");
            Console.Error.WriteLine("Run 'MinecraftSsForensics.exe --help' for usage.");
            return 2;
        }

        var options = parsed.Options;
        Console.WriteLine("========================================================================");
        Console.WriteLine(" Minecraft SS Forensics - Headless CLI Scanner");
        Console.WriteLine(" Read-only local collection; scans only after explicit --consent.");
        Console.WriteLine("========================================================================");
        Console.WriteLine($"[CONFIG] Scan Mode       : {options.ScanMode}");
        Console.WriteLine($"[CONFIG] Gamemode Policy : {options.Gamemode}");
        Console.WriteLine($"[CONFIG] Output Directory: {Path.GetFullPath(options.OutputDirectory)}");
        Console.WriteLine($"[CONFIG] Target Formats  : {string.Join(",", options.Formats)}");
        if (options.IncludeBrowserHistory)
            Console.WriteLine("[CONFIG] Browser history  : Included by explicit --browser option");
        Console.WriteLine("------------------------------------------------------------------------");

        var policy = new ModPolicyRegistry().GetPolicy(options.Gamemode);
        var consent = new ConsentScopeConfig
        {
            ConsentGiven = true,
            InspectMinecraftMods = true,
            InspectProcessesAndModules = true,
            InspectExecutionArtifacts = true,
            InspectRegistryArtifacts = true,
            InspectUsbHistory = true,
            InspectFileDiscovery = true,
            InspectServicesAndDrivers = true,
            InspectBrowserHistory = options.IncludeBrowserHistory,
            PerformOnlineVerification = false
        };

        var progress = new Progress<ScanProgressUpdate>(update =>
            Console.WriteLine($"[{update.PercentComplete,3}%] {update.CurrentCategory}: {update.CurrentAction}"));

        try
        {
            var engine = new StandaloneScannerEngine();
            Console.WriteLine("[INFO] Starting forensic collection pipeline...");
            var report = await engine.ExecuteScanAsync(
                consent,
                options.ScanMode,
                options.CustomDirectory,
                onlyCustomDirectory: false,
                progress: progress,
                policy: policy,
                ct: CancellationToken.None);

            Directory.CreateDirectory(options.OutputDirectory);
            string baseName = $"report-{report.ReportId}";
            foreach (string format in options.Formats)
            {
                string extension = format == "markdown" ? "md" : format;
                string path = Path.GetFullPath(Path.Combine(options.OutputDirectory, $"{baseName}.{extension}"));
                string content = format switch
                {
                    "json" => PortableJsonExporter.ExportToJson(report),
                    "html" => StandaloneHtmlExporter.ExportToHtml(report),
                    "csv" => CsvExporter.ExportToCsv(report),
                    "markdown" => MarkdownExporter.ExportToMarkdown(report),
                    _ => throw new InvalidOperationException($"Unsupported report format '{format}'.")
                };
                await File.WriteAllTextAsync(path, content);
                Console.WriteLine($"[SAVED] {format.ToUpperInvariant()} report -> {path}");
            }

            Console.WriteLine("------------------------------------------------------------------------");
            Console.WriteLine($"[SUMMARY] Verdict         : {report.Verdict.OverallAssessment}");
            Console.WriteLine($"[SUMMARY] Total Findings  : {report.Findings.Count}");
            Console.WriteLine($"[SUMMARY] Incomplete checks: {report.SummaryCounts.IncompleteOrFailedChecks}");
            Console.WriteLine($"[SUMMARY] Integrity Seal  : {report.ReportIntegrityHash}");
            Console.WriteLine($"[DONE] Reports saved in: {Path.GetFullPath(options.OutputDirectory)}");

            return report.Verdict.OverallAssessment == InvestigationVerdict.NoProhibitedIndicators ? 0 : 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ERROR] Scan execution failed: {ex.Message}");
            return 1;
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Minecraft SS Forensics Scanner");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  MinecraftSsForensics.exe scan --consent [options]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --consent               Required acknowledgement of the described local scan scope");
        Console.WriteLine("  -o, --output <dir>       Report directory (default: ./reports)");
        Console.WriteLine("  -m, --mode <QUICK|FULL>  Scan depth (default: FULL)");
        Console.WriteLine("  -g, --gamemode <name>    Registered policy name (default: 'Crystal PvP')");
        Console.WriteLine("  -d, --dir <path>         Existing Minecraft directory to include in discovery");
        Console.WriteLine("  -f, --format <formats>   json, html, csv, markdown, or all (comma-separated)");
        Console.WriteLine("  --browser                Include optional sensitive browser history audit");
        Console.WriteLine("  -h, --help               Display this help text");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  MinecraftSsForensics.exe scan --consent --output C:\\SS_Reports --format all");
        Console.WriteLine("  MinecraftSsForensics.exe scan --consent -o .\\out -f html,json -g 'Sword PvP'");
        Console.WriteLine();
        Console.WriteLine("Exit codes: 0 clean within inspected scope; 1 scan/export error; 2 invalid arguments or non-clean/inconclusive assessment.");
    }
}
