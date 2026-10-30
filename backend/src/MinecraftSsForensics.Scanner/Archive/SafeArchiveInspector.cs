using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace MinecraftSsForensics.Scanner.Archive;

public interface ISafeArchiveInspector
{
    Task<ModMetadata> InspectModJarAsync(string filePath, CancellationToken cancellationToken = default);
}

public class SafeArchiveInspector : ISafeArchiveInspector
{
    private const int MaxEntries = 10_000;
    private const long MaxTotalUncompressedBytes = 250 * 1024 * 1024; // 250 MB
    private const double MaxCompressionRatio = 100.0; // 100:1
    private const int MaxMetadataReadBytes = 2 * 1024 * 1024; // 2 MB max per metadata file

    public async Task<ModMetadata> InspectModJarAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var metadata = new ModMetadata();

        if (!File.Exists(filePath))
        {
            metadata.ParseSuccess = false;
            metadata.ParseError = "Archive file not found.";
            return metadata;
        }

        try
        {
            using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var archive = new ZipArchive(fileStream, ZipArchiveMode.Read, leaveOpen: false);

            if (archive.Entries.Count > MaxEntries)
            {
                metadata.ParseSuccess = false;
                metadata.ParseError = $"Archive exceeds safe entry limit: {archive.Entries.Count} > {MaxEntries}";
                return metadata;
            }

            long totalUncompressed = 0;
            long totalCompressed = 0;

            foreach (var entry in archive.Entries)
            {
                // Path traversal check
                if (entry.FullName.Contains("..") || entry.FullName.StartsWith('/') || entry.FullName.StartsWith('\\'))
                {
                    metadata.SuspiciousNotes.Add($"Archive entry contains directory traversal path: {entry.FullName}");
                }

                if (entry.FullName.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                {
                    var cheatSig = Cheats.CheatDetectionDatabase.MatchClassOrPackage(entry.FullName);
                    if (cheatSig != null)
                    {
                        metadata.HasSuspiciousEntrypoints = true;
                        metadata.MatchedCheatSignatures.Add($"{cheatSig.Name} (Class: {entry.FullName})");
                        metadata.SuspiciousNotes.Add($"Archive contains known cheat class: {entry.FullName} ({cheatSig.Name})");
                    }
                    else
                    {
                        var keyword = Cheats.CheatDetectionDatabase.MatchCombatBytecodeKeyword(entry.FullName);
                        if (keyword != null)
                        {
                            metadata.SuspiciousNotes.Add($"Archive contains suspicious combat capability class: {entry.FullName}");
                        }
                    }
                }

                totalUncompressed += entry.Length;
                totalCompressed += entry.CompressedLength;
            }

            if (totalUncompressed > MaxTotalUncompressedBytes)
            {
                metadata.ParseSuccess = false;
                metadata.ParseError = $"Archive exceeds total uncompressed size limit: {totalUncompressed / (1024 * 1024)}MB > {MaxTotalUncompressedBytes / (1024 * 1024)}MB";
                return metadata;
            }

            if (totalCompressed > 0)
            {
                double ratio = (double)totalUncompressed / totalCompressed;
                if (ratio > MaxCompressionRatio)
                {
                    metadata.ParseSuccess = false;
                    metadata.ParseError = $"Archive exceeds safe compression ratio: {ratio:F1}:1 > {MaxCompressionRatio}:1 (Potential zip bomb)";
                    return metadata;
                }
            }

            // Look for metadata files in order of preference
            var fabricEntry = archive.GetEntry("fabric.mod.json");
            var quiltEntry = archive.GetEntry("quilt.mod.json");
            var neoForgeEntry = archive.GetEntry("META-INF/neoforge.mods.toml");
            var forgeEntry = archive.GetEntry("META-INF/mods.toml");
            var legacyForgeEntry = archive.GetEntry("mcmod.info");
            var manifestEntry = archive.GetEntry("META-INF/MANIFEST.MF");

            // 1. MANIFEST.MF Inspection
            if (manifestEntry != null && manifestEntry.Length <= MaxMetadataReadBytes)
            {
                string manifestText = await ReadEntryTextAsync(manifestEntry, cancellationToken);
                ParseManifest(manifestText, metadata);
            }

            // 2. Fabric Mod JSON
            if (fabricEntry != null && fabricEntry.Length <= MaxMetadataReadBytes)
            {
                string jsonText = await ReadEntryTextAsync(fabricEntry, cancellationToken);
                ParseFabricModJson(jsonText, metadata);
            }
            // 3. Quilt Mod JSON
            else if (quiltEntry != null && quiltEntry.Length <= MaxMetadataReadBytes)
            {
                string jsonText = await ReadEntryTextAsync(quiltEntry, cancellationToken);
                ParseQuiltModJson(jsonText, metadata);
            }
            // 4. NeoForge / Forge mods.toml
            else if (neoForgeEntry != null && neoForgeEntry.Length <= MaxMetadataReadBytes)
            {
                string tomlText = await ReadEntryTextAsync(neoForgeEntry, cancellationToken);
                ParseModsToml(tomlText, metadata, "NeoForge");
            }
            else if (forgeEntry != null && forgeEntry.Length <= MaxMetadataReadBytes)
            {
                string tomlText = await ReadEntryTextAsync(forgeEntry, cancellationToken);
                ParseModsToml(tomlText, metadata, "Forge");
            }
            // 5. Legacy mcmod.info
            else if (legacyForgeEntry != null && legacyForgeEntry.Length <= MaxMetadataReadBytes)
            {
                string jsonText = await ReadEntryTextAsync(legacyForgeEntry, cancellationToken);
                ParseLegacyForgeJson(jsonText, metadata);
            }
            else
            {
                metadata.Loader = "Vanilla / Plain JAR";
            }

            // Deep static bytecode capability inspection (packets, automation, combat, mixins)
            try
            {
                metadata.BytecodeAnalysis = StaticBytecodeAnalyzer.AnalyzeArchive(archive);
                foreach (var cap in metadata.BytecodeAnalysis.DetectedCapabilities)
                {
                    metadata.SuspiciousNotes.Add($"Bytecode capability: {cap.CapabilityType} in {cap.ClassName} ({cap.ObservedSymbolOrMethod})");
                }
            }
            catch { /* Skip unparseable class structures safely */ }

            metadata.ParseSuccess = true;
            return metadata;
        }
        catch (InvalidDataException ex)
        {
            metadata.ParseSuccess = false;
            metadata.ParseError = $"Corrupt or invalid zip archive: {ex.Message}";
            return metadata;
        }
        catch (Exception ex)
        {
            metadata.ParseSuccess = false;
            metadata.ParseError = $"Archive inspection failed: {ex.Message}";
            return metadata;
        }
    }

    private static async Task<string> ReadEntryTextAsync(ZipArchiveEntry entry, CancellationToken ct)
    {
        using var stream = entry.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return await reader.ReadToEndAsync(ct);
    }

    private static void ParseManifest(string text, ModMetadata metadata)
    {
        var lines = text.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            int colon = line.IndexOf(':');
            if (colon > 0 && colon < line.Length - 1)
            {
                string key = line[..colon].Trim();
                string val = line[(colon + 1)..].Trim();
                metadata.ManifestAttributes[key] = val;

                // Flag Java Agents or custom classloader tweaks
                if (key.Equals("Premain-Class", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("Agent-Class", StringComparison.OrdinalIgnoreCase))
                {
                    metadata.HasSuspiciousEntrypoints = true;
                    metadata.SuspiciousNotes.Add($"JAR defines Java Instrumentation Agent entrypoint: {key}={val}");
                }
                else if (key.Equals("TweakClass", StringComparison.OrdinalIgnoreCase))
                {
                    metadata.SuspiciousNotes.Add($"JAR defines LaunchWrapper TweakClass: {val}");
                }
            }
        }
    }

    private static void ParseFabricModJson(string jsonText, ModMetadata metadata)
    {
        try
        {
            using var doc = JsonDocument.Parse(jsonText);
            var root = doc.RootElement;

            metadata.Loader = "Fabric";

            if (root.TryGetProperty("id", out var idProp))
                metadata.ModId = idProp.GetString();

            if (root.TryGetProperty("name", out var nameProp))
                metadata.ModName = nameProp.GetString();

            if (root.TryGetProperty("version", out var verProp))
                metadata.Version = verProp.GetString();

            if (root.TryGetProperty("description", out var descProp))
                metadata.Description = descProp.GetString();

            if (root.TryGetProperty("authors", out var authorsProp))
            {
                if (authorsProp.ValueKind == JsonValueKind.Array)
                {
                    foreach (var author in authorsProp.EnumerateArray())
                    {
                        if (author.ValueKind == JsonValueKind.String)
                            metadata.Authors.Add(author.GetString() ?? "");
                        else if (author.ValueKind == JsonValueKind.Object && author.TryGetProperty("name", out var aName))
                            metadata.Authors.Add(aName.GetString() ?? "");
                    }
                }
            }

            if (root.TryGetProperty("depends", out var dependsProp) && dependsProp.ValueKind == JsonValueKind.Object)
            {
                foreach (var dep in dependsProp.EnumerateObject())
                {
                    metadata.Dependencies.Add($"{dep.Name} ({dep.Value})");
                    if (dep.Name.Equals("minecraft", StringComparison.OrdinalIgnoreCase))
                    {
                        metadata.MinecraftVersionRequirement = dep.Value.ToString();
                    }
                }
            }

            if (root.TryGetProperty("entrypoints", out var entrypointsProp) && entrypointsProp.ValueKind == JsonValueKind.Object)
            {
                foreach (var ep in entrypointsProp.EnumerateObject())
                {
                    if (ep.Value.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var v in ep.Value.EnumerateArray())
                            metadata.Entrypoints.Add($"{ep.Name}: {v}");
                    }
                    else
                    {
                        metadata.Entrypoints.Add($"{ep.Name}: {ep.Value}");
                    }
                }
            }

            if (root.TryGetProperty("mixins", out var mixinsProp) && mixinsProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var m in mixinsProp.EnumerateArray())
                {
                    metadata.MixinConfigs.Add(m.ToString());
                }
            }
        }
        catch (Exception ex)
        {
            metadata.SuspiciousNotes.Add($"Failed to parse fabric.mod.json: {ex.Message}");
        }
    }

    private static void ParseQuiltModJson(string jsonText, ModMetadata metadata)
    {
        try
        {
            using var doc = JsonDocument.Parse(jsonText);
            var root = doc.RootElement;
            metadata.Loader = "Quilt";

            if (root.TryGetProperty("quilt_loader", out var ql))
            {
                if (ql.TryGetProperty("id", out var idProp))
                    metadata.ModId = idProp.GetString();

                if (ql.TryGetProperty("version", out var verProp))
                    metadata.Version = verProp.GetString();

                if (ql.TryGetProperty("metadata", out var meta))
                {
                    if (meta.TryGetProperty("name", out var nameProp))
                        metadata.ModName = nameProp.GetString();
                    if (meta.TryGetProperty("description", out var descProp))
                        metadata.Description = descProp.GetString();
                }
            }
        }
        catch (Exception ex)
        {
            metadata.SuspiciousNotes.Add($"Failed to parse quilt.mod.json: {ex.Message}");
        }
    }

    private static void ParseModsToml(string tomlText, ModMetadata metadata, string loader)
    {
        metadata.Loader = loader;

        // Simple robust regex parsing for TOML values
        var modIdMatch = Regex.Match(tomlText, @"modId\s*=\s*[""']([^""']+)[""']");
        if (modIdMatch.Success) metadata.ModId = modIdMatch.Groups[1].Value;

        var versionMatch = Regex.Match(tomlText, @"version\s*=\s*[""']([^""']+)[""']");
        if (versionMatch.Success) metadata.Version = versionMatch.Groups[1].Value;

        var displayNameMatch = Regex.Match(tomlText, @"displayName\s*=\s*[""']([^""']+)[""']");
        if (displayNameMatch.Success) metadata.ModName = displayNameMatch.Groups[1].Value;

        var descriptionMatch = Regex.Match(tomlText, @"description\s*=\s*'''([^']+)'''", RegexOptions.Singleline);
        if (descriptionMatch.Success)
        {
            metadata.Description = descriptionMatch.Groups[1].Value.Trim();
        }
        else
        {
            var singleLineDesc = Regex.Match(tomlText, @"description\s*=\s*[""']([^""']+)[""']");
            if (singleLineDesc.Success) metadata.Description = singleLineDesc.Groups[1].Value;
        }

        var authorsMatch = Regex.Match(tomlText, @"authors\s*=\s*[""']([^""']+)[""']");
        if (authorsMatch.Success) metadata.Authors.Add(authorsMatch.Groups[1].Value);
    }

    private static void ParseLegacyForgeJson(string jsonText, ModMetadata metadata)
    {
        try
        {
            using var doc = JsonDocument.Parse(jsonText);
            metadata.Loader = "Forge (Legacy)";

            JsonElement targetElement = doc.RootElement;
            if (targetElement.ValueKind == JsonValueKind.Array && targetElement.GetArrayLength() > 0)
            {
                targetElement = targetElement[0];
            }
            else if (targetElement.ValueKind == JsonValueKind.Object && targetElement.TryGetProperty("modList", out var listProp))
            {
                if (listProp.ValueKind == JsonValueKind.Array && listProp.GetArrayLength() > 0)
                {
                    targetElement = listProp[0];
                }
            }

            if (targetElement.TryGetProperty("modid", out var idProp))
                metadata.ModId = idProp.GetString();

            if (targetElement.TryGetProperty("name", out var nameProp))
                metadata.ModName = nameProp.GetString();

            if (targetElement.TryGetProperty("version", out var verProp))
                metadata.Version = verProp.GetString();

            if (targetElement.TryGetProperty("description", out var descProp))
                metadata.Description = descProp.GetString();
        }
        catch (Exception ex)
        {
            metadata.SuspiciousNotes.Add($"Failed to parse mcmod.info: {ex.Message}");
        }
    }
}
