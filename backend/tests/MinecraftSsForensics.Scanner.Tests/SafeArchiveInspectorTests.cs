using System.IO.Compression;
using System.Text;
using MinecraftSsForensics.Scanner.Archive;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class SafeArchiveInspectorTests
{
    private readonly SafeArchiveInspector _inspector = new();

    [Fact]
    public async Task InspectModJarAsync_ParsesFabricModJsonAccurately()
    {
        string tempJar = Path.Combine(Path.GetTempPath(), $"fabric_test_{Guid.NewGuid():N}.jar");
        try
        {
            using (var zip = ZipFile.Open(tempJar, ZipArchiveMode.Create))
            {
                var entry = zip.CreateEntry("fabric.mod.json");
                using var writer = new StreamWriter(entry.Open());
                writer.Write("""
                {
                    "schemaVersion": 1,
                    "id": "sodium",
                    "name": "Sodium",
                    "version": "0.5.8",
                    "description": "Modern rendering engine for Minecraft",
                    "authors": ["JellySquid", "IMS"],
                    "depends": {
                        "minecraft": ">=1.20.4",
                        "fabricloader": ">=0.15.0"
                    },
                    "entrypoints": {
                        "client": ["net.caffeinemc.mods.sodium.client.SodiumClientMod"]
                    }
                }
                """);
            }

            var metadata = await _inspector.InspectModJarAsync(tempJar);

            Assert.True(metadata.ParseSuccess);
            Assert.Equal("Fabric", metadata.Loader);
            Assert.Equal("sodium", metadata.ModId);
            Assert.Equal("Sodium", metadata.ModName);
            Assert.Equal("0.5.8", metadata.Version);
            Assert.Contains("JellySquid", metadata.Authors);
            Assert.Equal(">=1.20.4", metadata.MinecraftVersionRequirement);
            Assert.Contains("client: net.caffeinemc.mods.sodium.client.SodiumClientMod", metadata.Entrypoints);
        }
        finally
        {
            if (File.Exists(tempJar)) File.Delete(tempJar);
        }
    }

    [Fact]
    public async Task InspectModJarAsync_ParsesForgeModsTomlAccurately()
    {
        string tempJar = Path.Combine(Path.GetTempPath(), $"forge_test_{Guid.NewGuid():N}.jar");
        try
        {
            using (var zip = ZipFile.Open(tempJar, ZipArchiveMode.Create))
            {
                var entry = zip.CreateEntry("META-INF/mods.toml");
                using var writer = new StreamWriter(entry.Open());
                writer.Write("""
                modLoader="javafml"
                loaderVersion="[47,)"
                license="LGPL-3.0"

                [[mods]]
                modId="jei"
                version="15.2.0.27"
                displayName="Just Enough Items"
                authors="mezz"
                description='''Simple item and recipe viewer.'''
                """);
            }

            var metadata = await _inspector.InspectModJarAsync(tempJar);

            Assert.True(metadata.ParseSuccess);
            Assert.Equal("Forge", metadata.Loader);
            Assert.Equal("jei", metadata.ModId);
            Assert.Equal("Just Enough Items", metadata.ModName);
            Assert.Equal("15.2.0.27", metadata.Version);
            Assert.Contains("mezz", metadata.Authors);
        }
        finally
        {
            if (File.Exists(tempJar)) File.Delete(tempJar);
        }
    }

    [Fact]
    public async Task InspectModJarAsync_DetectsJavaAgentInstrumentationInManifest()
    {
        string tempJar = Path.Combine(Path.GetTempPath(), $"agent_test_{Guid.NewGuid():N}.jar");
        try
        {
            using (var zip = ZipFile.Open(tempJar, ZipArchiveMode.Create))
            {
                var entry = zip.CreateEntry("META-INF/MANIFEST.MF");
                using var writer = new StreamWriter(entry.Open());
                writer.Write("Manifest-Version: 1.0\r\nPremain-Class: net.hack.PremainHook\r\nCan-Redefine-Classes: true\r\n");
            }

            var metadata = await _inspector.InspectModJarAsync(tempJar);

            Assert.True(metadata.ParseSuccess);
            Assert.True(metadata.HasSuspiciousEntrypoints);
            Assert.Contains(metadata.SuspiciousNotes, n => n.Contains("Premain-Class"));
        }
        finally
        {
            if (File.Exists(tempJar)) File.Delete(tempJar);
        }
    }

    [Fact]
    public async Task InspectModJarAsync_DetectsDirectoryTraversalEntries()
    {
        string tempJar = Path.Combine(Path.GetTempPath(), $"traversal_test_{Guid.NewGuid():N}.jar");
        try
        {
            using (var zip = ZipFile.Open(tempJar, ZipArchiveMode.Create))
            {
                zip.CreateEntry("../../windows/system32/cmd.exe");
            }

            var metadata = await _inspector.InspectModJarAsync(tempJar);

            Assert.True(metadata.ParseSuccess);
            Assert.Contains(metadata.SuspiciousNotes, n => n.Contains("traversal"));
        }
        finally
        {
            if (File.Exists(tempJar)) File.Delete(tempJar);
        }
    }

    [Fact]
    public async Task InspectModJarAsync_ReturnsFailure_OnCorruptedZip()
    {
        string tempJar = Path.Combine(Path.GetTempPath(), $"corrupt_test_{Guid.NewGuid():N}.jar");
        try
        {
            await File.WriteAllBytesAsync(tempJar, Encoding.UTF8.GetBytes("Not a zip file header"));

            var metadata = await _inspector.InspectModJarAsync(tempJar);

            Assert.False(metadata.ParseSuccess);
            Assert.NotNull(metadata.ParseError);
        }
        finally
        {
            if (File.Exists(tempJar)) File.Delete(tempJar);
        }
    }
}
