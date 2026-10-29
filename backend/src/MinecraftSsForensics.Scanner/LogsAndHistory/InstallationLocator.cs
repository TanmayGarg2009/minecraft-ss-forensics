namespace MinecraftSsForensics.Scanner.LogsAndHistory;

public class DiscoveredInstallation
{
    public string Name { get; set; } = string.Empty;
    public string RootPath { get; set; } = string.Empty;
    public string ModsPath { get; set; } = string.Empty;
    public string LogsPath { get; set; } = string.Empty;
    public bool HasModsFolder => Directory.Exists(ModsPath);
    public bool HasLogsFolder => Directory.Exists(LogsPath);
    public string LauncherType { get; set; } = "Standard";
}

public class InstallationLocator
{
    public List<DiscoveredInstallation> DiscoverInstallations(string? customPath = null, bool onlyCustomPath = false)
    {
        var installations = new List<DiscoveredInstallation>();

        // Custom path if specified
        if (!string.IsNullOrEmpty(customPath) && Directory.Exists(customPath))
        {
            installations.Add(new DiscoveredInstallation
            {
                Name = $"Custom Directory ({Path.GetFileName(customPath)})",
                RootPath = customPath,
                ModsPath = Path.Combine(customPath, "mods"),
                LogsPath = Path.Combine(customPath, "logs"),
                LauncherType = "Custom"
            });

            if (onlyCustomPath)
            {
                return installations;
            }
        }

        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // 1. Standard Vanilla .minecraft
        string standardMc = Path.Combine(appData, ".minecraft");
        if (Directory.Exists(standardMc))
        {
            installations.Add(new DiscoveredInstallation
            {
                Name = "Default Minecraft (.minecraft)",
                RootPath = standardMc,
                ModsPath = Path.Combine(standardMc, "mods"),
                LogsPath = Path.Combine(standardMc, "logs"),
                LauncherType = "Mojang Standard"
            });
        }

        // 2. Prism Launcher Instances
        string prismPath = Path.Combine(appData, "PrismLauncher", "instances");
        if (Directory.Exists(prismPath))
        {
            AddSubInstances(prismPath, "Prism Launcher", installations);
        }

        // 3. Modrinth App Profiles
        string modrinthPath = Path.Combine(appData, "ModrinthApp", "profiles");
        if (Directory.Exists(modrinthPath))
        {
            AddSubInstances(modrinthPath, "Modrinth App", installations);
        }

        // 4. CurseForge Instances
        string cursePath = Path.Combine(userProfile, "curseforge", "minecraft", "Instances");
        if (Directory.Exists(cursePath))
        {
            AddSubInstances(cursePath, "CurseForge", installations);
        }

        // 5. Feather Client
        string featherPath = Path.Combine(appData, ".feather");
        if (Directory.Exists(featherPath))
        {
            installations.Add(new DiscoveredInstallation
            {
                Name = "Feather Client",
                RootPath = featherPath,
                ModsPath = Path.Combine(featherPath, "user-mods"),
                LogsPath = Path.Combine(featherPath, "logs"),
                LauncherType = "Feather"
            });
        }

        // 6. Lunar Client
        string lunarPath = Path.Combine(userProfile, ".lunarclient", "offline", "multiver");
        if (Directory.Exists(lunarPath))
        {
            installations.Add(new DiscoveredInstallation
            {
                Name = "Lunar Client",
                RootPath = lunarPath,
                ModsPath = Path.Combine(lunarPath, "mods"),
                LogsPath = Path.Combine(lunarPath, "logs"),
                LauncherType = "Lunar Client"
            });
        }

        return installations;
    }

    private static void AddSubInstances(string parentDir, string launcherName, List<DiscoveredInstallation> list)
    {
        try
        {
            foreach (var dir in Directory.GetDirectories(parentDir))
            {
                string instanceName = Path.GetFileName(dir);
                string modsPath = Path.Combine(dir, "minecraft", "mods");
                string logsPath = Path.Combine(dir, "minecraft", "logs");

                // Direct or nested inside .minecraft
                if (!Directory.Exists(modsPath))
                {
                    modsPath = Path.Combine(dir, ".minecraft", "mods");
                    logsPath = Path.Combine(dir, ".minecraft", "logs");
                }
                if (!Directory.Exists(modsPath))
                {
                    modsPath = Path.Combine(dir, "mods");
                    logsPath = Path.Combine(dir, "logs");
                }

                list.Add(new DiscoveredInstallation
                {
                    Name = $"{launcherName} ({instanceName})",
                    RootPath = dir,
                    ModsPath = modsPath,
                    LogsPath = logsPath,
                    LauncherType = launcherName
                });
            }
        }
        catch
        {
            // Permission or directory read error
        }
    }
}
