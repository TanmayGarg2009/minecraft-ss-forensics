using System.Text.Json;

namespace MinecraftSsForensics.Scanner.LogsAndHistory;

/// <summary>One independently identified Minecraft game directory.</summary>
public class DiscoveredInstallation
{
    public string InstanceId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string LauncherType { get; set; } = "Unknown";
    public string GameDirectory { get; set; } = string.Empty;
    public string RootPath { get => GameDirectory; set => GameDirectory = value; }
    public string ModsPath { get; set; } = string.Empty;
    public string ConfigPath { get; set; } = string.Empty;
    public string LogsPath { get; set; } = string.Empty;
    public string? GameVersion { get; set; }
    public string? Loader { get; set; }
    public string? LoaderVersion { get; set; }
    public string DiscoverySource { get; set; } = string.Empty;
    public string DiscoveryConfidence { get; set; } = "Medium";
    public bool DirectoryExists { get; set; }
    public bool IsAccessible { get; set; }
    public string? AvailabilityNote { get; set; }
    public bool HasModsFolder => Directory.Exists(ModsPath);
    public bool HasLogsFolder => Directory.Exists(LogsPath);
}

/// <summary>
/// Discovers known Minecraft launcher directories from bounded, standard per-user locations and
/// launcher metadata. It does not recursively search unrelated disks or user directories.
/// </summary>
public class InstallationLocator
{
    private readonly string _appData;
    private readonly string _localAppData;
    private readonly string _userProfile;

    public InstallationLocator(string? appData = null, string? localAppData = null, string? userProfile = null)
    {
        _appData = appData ?? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    }

    public List<DiscoveredInstallation> DiscoverInstallations(string? customPath = null, bool onlyCustomPath = false)
    {
        var candidates = new List<DiscoveredInstallation>();
        if (!string.IsNullOrWhiteSpace(customPath))
        {
            candidates.Add(CreateInstance("Custom Instance", "Custom", customPath, "UserProvidedPath", "Certain"));
            if (onlyCustomPath)
                return candidates;
        }

        string standard = Path.Combine(_appData, ".minecraft");
        if (Directory.Exists(standard))
        {
            candidates.Add(CreateInstance("Default Minecraft (.minecraft)", "Official Launcher", standard,
                "OfficialDefaultDirectory", "High"));
            ReadOfficialLauncherProfiles(standard, candidates);
        }

        AddPrismInstances(Path.Combine(_appData, "PrismLauncher", "instances"), "Prism Launcher", candidates);
        AddPrismInstances(Path.Combine(_appData, "MultiMC", "instances"), "MultiMC", candidates);
        AddPrismInstances(Path.Combine(_localAppData, "PrismLauncher", "instances"), "Prism Launcher", candidates);
        AddPrismInstances(Path.Combine(_localAppData, "MultiMC", "instances"), "MultiMC", candidates);

        AddModrinthProfiles(Path.Combine(_appData, "com.modrinth.theseus", "profiles"), candidates);
        AddModrinthProfiles(Path.Combine(_appData, "ModrinthApp", "profiles"), candidates);
        AddModrinthProfiles(Path.Combine(_localAppData, "com.modrinth.theseus", "profiles"), candidates);
        AddModrinthProfiles(Path.Combine(_localAppData, "ModrinthApp", "profiles"), candidates);

        AddDirectoryInstances(Path.Combine(_userProfile, "curseforge", "minecraft", "Instances"), "CurseForge", candidates,
            "CurseForgeInstancesDirectory", "High");
        AddDirectoryInstances(Path.Combine(_userProfile, "Documents", "CurseForge", "Minecraft", "Instances"), "CurseForge", candidates,
            "CurseForgeInstancesDirectory", "Medium");

        string feather = Path.Combine(_appData, ".feather");
        if (Directory.Exists(feather))
        {
            var instance = CreateInstance("Feather Client", "Feather", feather, "FeatherDefaultDirectory", "Medium");
            instance.ModsPath = Path.Combine(feather, "user-mods");
            candidates.Add(instance);
        }

        string lunar = Path.Combine(_userProfile, ".lunarclient", "offline", "multiver");
        AddDirectoryInstances(lunar, "Lunar Client", candidates, "LunarOfflineInstances", "Low");

        return DeduplicateAndRefresh(candidates);
    }

    private void ReadOfficialLauncherProfiles(string minecraftRoot, List<DiscoveredInstallation> candidates)
    {
        string profilesFile = Path.Combine(minecraftRoot, "launcher_profiles.json");
        if (!File.Exists(profilesFile))
            return;

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(profilesFile), new JsonDocumentOptions { MaxDepth = 32 });
            if (!document.RootElement.TryGetProperty("profiles", out var profiles) || profiles.ValueKind != JsonValueKind.Object)
                return;

            foreach (var profile in profiles.EnumerateObject())
            {
                var value = profile.Value;
                if (value.ValueKind != JsonValueKind.Object)
                    continue;

                string? gameDir = GetString(value, "gameDir");
                string directory = string.IsNullOrWhiteSpace(gameDir) ? minecraftRoot : ExpandUserPath(gameDir);
                string name = GetString(value, "name") ?? profile.Name;
                var instance = CreateInstance(name, "Official Launcher", directory,
                    "launcher_profiles.json", string.IsNullOrWhiteSpace(gameDir) ? "Medium" : "High");
                instance.GameVersion = GetString(value, "lastVersionId");
                candidates.Add(instance);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            candidates.Add(CreateUnavailable("Official Launcher profile metadata", "Official Launcher", minecraftRoot,
                "launcher_profiles.json", ex.Message));
        }
    }

    private void AddPrismInstances(string instancesPath, string launcher, List<DiscoveredInstallation> candidates)
    {
        if (!Directory.Exists(instancesPath))
            return;

        IEnumerable<string> directories;
        try { directories = Directory.EnumerateDirectories(instancesPath).ToArray(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            candidates.Add(CreateUnavailable($"{launcher} instances", launcher, instancesPath, "InstancesDirectory", ex.Message));
            return;
        }

        foreach (string root in directories)
        {
            string cfgPath = Path.Combine(root, "instance.cfg");
            string name = Path.GetFileName(root);
            string? version = null;
            string? loader = null;
            string? loaderVersion = null;
            try
            {
                if (File.Exists(cfgPath))
                {
                    var config = ParseKeyValueFile(cfgPath);
                    if (config.TryGetValue("name", out var configuredName)) name = configuredName;
                    if (config.TryGetValue("IntendedVersion", out var intendedVersion)) version = intendedVersion;
                    if (config.TryGetValue("ComponentList", out var componentList))
                        (version, loader, loaderVersion) = ParseMmcComponents(root, version, componentList);
                }
                if (File.Exists(Path.Combine(root, "mmc-pack.json")))
                    (version, loader, loaderVersion) = ParseMmcPack(Path.Combine(root, "mmc-pack.json"), version);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                candidates.Add(CreateUnavailable(name, launcher, root, cfgPath, ex.Message));
                continue;
            }

            string game = FindGameDirectory(root, "minecraft", ".minecraft", root);
            var instance = CreateInstance(name, launcher, game, File.Exists(cfgPath) ? "instance.cfg" : "InstancesDirectory",
                File.Exists(cfgPath) ? "High" : "Medium");
            instance.GameVersion = version;
            instance.Loader = loader;
            instance.LoaderVersion = loaderVersion;
            candidates.Add(instance);
        }
    }

    private void AddModrinthProfiles(string profilesPath, List<DiscoveredInstallation> candidates)
    {
        if (!Directory.Exists(profilesPath))
            return;

        IEnumerable<string> directories;
        try { directories = Directory.EnumerateDirectories(profilesPath).ToArray(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            candidates.Add(CreateUnavailable("Modrinth profiles", "Modrinth App", profilesPath, "ProfilesDirectory", ex.Message));
            return;
        }

        foreach (string root in directories)
        {
            string metadataPath = Path.Combine(root, "profile.json");
            try
            {
                string? name = null;
                string? version = null;
                string? loader = null;
                string? loaderVersion = null;
                if (File.Exists(metadataPath))
                {
                    using var document = JsonDocument.Parse(File.ReadAllText(metadataPath), new JsonDocumentOptions { MaxDepth = 32 });
                    var metadata = document.RootElement;
                    name = GetString(metadata, "name");
                    version = GetString(metadata, "gameVersion") ?? GetString(metadata, "game_version");
                    loader = GetString(metadata, "loader");
                    loaderVersion = GetString(metadata, "loaderVersion") ?? GetString(metadata, "loader_version");
                }

                var instance = CreateInstance(name ?? Path.GetFileName(root), "Modrinth App", root,
                    File.Exists(metadataPath) ? "profile.json" : "ProfilesDirectory", File.Exists(metadataPath) ? "High" : "Medium");
                instance.GameVersion = version;
                instance.Loader = loader;
                instance.LoaderVersion = loaderVersion;
                candidates.Add(instance);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                candidates.Add(CreateUnavailable(Path.GetFileName(root), "Modrinth App", root, metadataPath, ex.Message));
            }
        }
    }

    private void AddDirectoryInstances(string parent, string launcher, List<DiscoveredInstallation> candidates, string source, string confidence)
    {
        if (!Directory.Exists(parent))
            return;

        try
        {
            foreach (string directory in Directory.EnumerateDirectories(parent))
            {
                var instance = CreateInstance(Path.GetFileName(directory), launcher,
                    FindGameDirectory(directory, "minecraft", ".minecraft", directory), source, confidence);
                ReadVersionMetadata(instance);
                candidates.Add(instance);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            candidates.Add(CreateUnavailable($"{launcher} instances", launcher, parent, source, ex.Message));
        }
    }

    private static (string? GameVersion, string? Loader, string? LoaderVersion) ParseMmcPack(string path, string? currentVersion)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions { MaxDepth = 32 });
        string? gameVersion = currentVersion;
        string? loader = null;
        string? loaderVersion = null;
        if (document.RootElement.TryGetProperty("components", out var components) && components.ValueKind == JsonValueKind.Array)
        {
            foreach (var component in components.EnumerateArray())
            {
                string? uid = GetString(component, "uid");
                string? version = GetString(component, "version");
                if (uid == "net.minecraft") gameVersion = version ?? gameVersion;
                else if (uid != null && (uid.Contains("fabric", StringComparison.OrdinalIgnoreCase) || uid.Contains("forge", StringComparison.OrdinalIgnoreCase) || uid.Contains("quilt", StringComparison.OrdinalIgnoreCase) || uid.Contains("neoforge", StringComparison.OrdinalIgnoreCase)))
                {
                    loader = uid.Contains("fabric", StringComparison.OrdinalIgnoreCase) ? "Fabric" : uid.Contains("quilt", StringComparison.OrdinalIgnoreCase) ? "Quilt" : uid.Contains("neoforge", StringComparison.OrdinalIgnoreCase) ? "NeoForge" : "Forge";
                    loaderVersion = version;
                }
            }
        }
        return (gameVersion, loader, loaderVersion);
    }

    private static (string? GameVersion, string? Loader, string? LoaderVersion) ParseMmcComponents(string root, string? currentVersion, string raw)
    {
        string? loader = null;
        string? loaderVersion = null;
        foreach (string component in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (component.Contains("fabric", StringComparison.OrdinalIgnoreCase)) { loader = "Fabric"; loaderVersion = component; }
            else if (component.Contains("quilt", StringComparison.OrdinalIgnoreCase)) { loader = "Quilt"; loaderVersion = component; }
            else if (component.Contains("forge", StringComparison.OrdinalIgnoreCase)) { loader = "Forge"; loaderVersion = component; }
        }
        if (File.Exists(Path.Combine(root, "mmc-pack.json")))
            return ParseMmcPack(Path.Combine(root, "mmc-pack.json"), currentVersion);
        return (currentVersion, loader, loaderVersion);
    }

    private static Dictionary<string, string> ParseKeyValueFile(string path)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in File.ReadLines(path))
        {
            int separator = line.IndexOf('=');
            if (separator <= 0) continue;
            values[line[..separator].Trim()] = line[(separator + 1)..].Trim();
        }
        return values;
    }

    private static string FindGameDirectory(string root, params string[] candidates)
    {
        foreach (string relative in candidates)
        {
            string path = relative == root ? root : Path.Combine(root, relative);
            if (Directory.Exists(path) && (Directory.Exists(Path.Combine(path, "mods")) || Directory.Exists(Path.Combine(path, "versions")) || relative == "minecraft" || relative == ".minecraft"))
                return path;
        }
        return Path.Combine(root, ".minecraft");
    }

    private static DiscoveredInstallation CreateInstance(string name, string launcher, string directory, string source, string confidence)
    {
        string fullPath;
        try { fullPath = Path.GetFullPath(directory); }
        catch { fullPath = directory; }
        bool exists = Directory.Exists(fullPath);
        bool accessible = exists;
        string? note = exists ? null : "Game directory is not present.";
        if (exists)
        {
            try { _ = Directory.EnumerateFileSystemEntries(fullPath).Take(1).ToArray(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { accessible = false; note = ex.GetType().Name; }
        }
        return new DiscoveredInstallation
        {
            InstanceId = $"instance:{launcher.ToLowerInvariant()}:{Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(fullPath.ToLowerInvariant())))[..12].ToLowerInvariant()}",
            Name = name,
            LauncherType = launcher,
            GameDirectory = fullPath,
            ModsPath = Path.Combine(fullPath, launcher == "Feather" ? "user-mods" : "mods"),
            ConfigPath = Path.Combine(fullPath, "config"),
            LogsPath = Path.Combine(fullPath, "logs"),
            DiscoverySource = source,
            DiscoveryConfidence = confidence,
            DirectoryExists = exists,
            IsAccessible = accessible,
            AvailabilityNote = note
        };
    }

    private static DiscoveredInstallation CreateUnavailable(string name, string launcher, string path, string source, string reason) => new()
    {
        InstanceId = $"instance:{launcher.ToLowerInvariant()}:{Guid.NewGuid():N}",
        Name = name,
        LauncherType = launcher,
        GameDirectory = path,
        ModsPath = Path.Combine(path, "mods"),
        ConfigPath = Path.Combine(path, "config"),
        LogsPath = Path.Combine(path, "logs"),
        DiscoverySource = source,
        DiscoveryConfidence = "Low",
        DirectoryExists = Directory.Exists(path),
        IsAccessible = false,
        AvailabilityNote = reason
    };

    private static List<DiscoveredInstallation> DeduplicateAndRefresh(List<DiscoveredInstallation> candidates)
    {
        var results = new List<DiscoveredInstallation>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in candidates)
        {
            string key;
            try { key = Path.GetFullPath(candidate.GameDirectory).TrimEnd(Path.DirectorySeparatorChar); }
            catch { key = candidate.GameDirectory; }
            if (seen.Add(key))
                results.Add(candidate);
        }
        return results;
    }

    private static void ReadVersionMetadata(DiscoveredInstallation instance)
    {
        string versionFile = Path.Combine(instance.GameDirectory, "versions");
        if (!Directory.Exists(versionFile)) return;
        try
        {
            foreach (string metadata in Directory.EnumerateFiles(versionFile, "*.json", SearchOption.AllDirectories).Take(64))
            {
                using var document = JsonDocument.Parse(File.ReadAllText(metadata), new JsonDocumentOptions { MaxDepth = 24 });
                if (document.RootElement.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String)
                    instance.GameVersion ??= id.GetString();
                break;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            instance.AvailabilityNote = $"Version metadata unavailable: {ex.GetType().Name}";
        }
    }

    private static string? GetString(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private static string ExpandUserPath(string path) => Environment.ExpandEnvironmentVariables(path);
}
