using System.Text.Json;
using MinecraftSsForensics.Scanner.LogsAndHistory;

namespace MinecraftSsForensics.Scanner.Tests;

public class InstallationLocatorTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "ssing-instances-" + Guid.NewGuid().ToString("N"));
    private readonly string _appData;
    private readonly string _localAppData;
    private readonly string _userProfile;

    public InstallationLocatorTests()
    {
        _appData = Path.Combine(_root, "Roaming");
        _localAppData = Path.Combine(_root, "Local");
        _userProfile = Path.Combine(_root, "User");
        Directory.CreateDirectory(_appData);
        Directory.CreateDirectory(_localAppData);
        Directory.CreateDirectory(_userProfile);
    }

    [Fact]
    public void DiscoverInstallations_FindsOfficialProfilesWithCustomGameDirectories()
    {
        string officialRoot = Path.Combine(_appData, ".minecraft");
        string customRoot = Path.Combine(_root, "Games", "CrystalProfile");
        Directory.CreateDirectory(officialRoot);
        Directory.CreateDirectory(Path.Combine(customRoot, "mods"));
        File.WriteAllText(Path.Combine(officialRoot, "launcher_profiles.json"), JsonSerializer.Serialize(new
        {
            profiles = new
            {
                defaultProfile = new { name = "Release", lastVersionId = "1.20.4", gameDir = customRoot }
            }
        }));

        var instances = new InstallationLocator(_appData, _localAppData, _userProfile).DiscoverInstallations();

        var official = Assert.Single(instances.Where(x => x.Name == "Default Minecraft (.minecraft)"));
        Assert.Equal(Path.Combine(officialRoot, "mods"), official.ModsPath);
        var profile = Assert.Single(instances.Where(x => x.Name == "Release"));
        Assert.Equal(customRoot, profile.GameDirectory);
        Assert.Equal("1.20.4", profile.GameVersion);
        Assert.True(profile.IsAccessible);
        Assert.Equal("launcher_profiles.json", profile.DiscoverySource);
    }

    [Theory]
    [InlineData("PrismLauncher", "Prism Launcher", "Crystal-1", "instance.cfg", "name=Crystal PvP\n", "Crystal PvP")]
    [InlineData("MultiMC", "MultiMC", "Combat-2", "instance.cfg", "name=Combat\n", "Combat")]
    public void DiscoverInstallations_UsesPrismAndMultiMcInstanceMetadata(string launcherFolder, string launcherName, string instanceFolder, string metadataName, string metadata, string expectedName)
    {
        string root = Path.Combine(_appData, launcherFolder, "instances", instanceFolder);
        string game = Path.Combine(root, ".minecraft");
        Directory.CreateDirectory(Path.Combine(game, "mods"));
        File.WriteAllText(Path.Combine(root, metadataName), metadata);
        File.WriteAllText(Path.Combine(root, "mmc-pack.json"), """{"components":[{"uid":"net.minecraft","version":"1.20.4"},{"uid":"net.fabricmc.fabric-loader","version":"0.15.0"}]}""");

        var instance = Assert.Single(new InstallationLocator(_appData, _localAppData, _userProfile)
            .DiscoverInstallations().Where(x => x.LauncherType == launcherName));

        Assert.Equal(expectedName, instance.Name);
        Assert.Equal(game, instance.GameDirectory);
        Assert.Equal(Path.Combine(game, "mods"), instance.ModsPath);
        Assert.Equal("1.20.4", instance.GameVersion);
        Assert.Equal("Fabric", instance.Loader);
        Assert.Equal("0.15.0", instance.LoaderVersion);
        Assert.True(instance.IsAccessible);
    }

    [Fact]
    public void DiscoverInstallations_FindsModrinthAndCurseForgeInstances()
    {
        string modrinthProfile = Path.Combine(_appData, "com.modrinth.theseus", "profiles", "profile-id");
        string curseProfile = Path.Combine(_userProfile, "curseforge", "minecraft", "Instances", "Crystal Pack");
        Directory.CreateDirectory(Path.Combine(modrinthProfile, "mods"));
        Directory.CreateDirectory(Path.Combine(curseProfile, "mods"));
        File.WriteAllText(Path.Combine(modrinthProfile, "profile.json"), """{"name":"Modrinth Crystal","gameVersion":"1.20.4","loader":"fabric","loaderVersion":"0.15.0"}""");

        var instances = new InstallationLocator(_appData, _localAppData, _userProfile).DiscoverInstallations();

        Assert.Contains(instances, x => x.LauncherType == "Modrinth App" && x.Name == "Modrinth Crystal");
        Assert.Contains(instances, x => x.LauncherType == "CurseForge" && x.Name == "Crystal Pack");
    }

    [Fact]
    public void DiscoverInstallations_DeduplicatesSameGameDirectoryAndDoesNotSearchUnrelatedFolders()
    {
        string defaultRoot = Path.Combine(_appData, ".minecraft");
        Directory.CreateDirectory(defaultRoot);
        Directory.CreateDirectory(Path.Combine(_root, "unrelated", "mods"));

        var instances = new InstallationLocator(_appData, _localAppData, _userProfile).DiscoverInstallations();

        Assert.Single(instances.Where(x => Path.GetFullPath(x.GameDirectory).Equals(Path.GetFullPath(defaultRoot), StringComparison.OrdinalIgnoreCase)));
        Assert.DoesNotContain(instances, x => x.GameDirectory.Contains("unrelated", StringComparison.OrdinalIgnoreCase));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }
}
