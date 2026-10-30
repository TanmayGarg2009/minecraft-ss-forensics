using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Cheats;

public class CheatSignature
{
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = "GhostClient"; // GhostClient, Injection, HackedClient, Autoclicker, MacroTool
    public List<string> Aliases { get; set; } = new();
    public List<string> KnownFileNames { get; set; } = new();
    public List<string> KnownClassNames { get; set; } = new();
    public List<string> KnownPackagePrefixes { get; set; } = new();
    public List<string> MemoryStrings { get; set; } = new();
    public List<string> RegistryPaths { get; set; } = new();
    public List<string> KnownDomains { get; set; } = new();
    public string Description { get; set; } = string.Empty;
    public FindingClassification DefaultClassification { get; set; } = FindingClassification.ConfirmedCheatArtifact;
}

/// <summary>
/// Structured repository of known Minecraft cheat signatures, ghost client indicators,
/// injection patterns, and macro software artifacts derived from forensic anti-cheat telemetry.
/// </summary>
public static class CheatDetectionDatabase
{
    public static readonly List<CheatSignature> Signatures = new()
    {
        new CheatSignature
        {
            Name = "Doomsday Client",
            Category = "GhostClient",
            Aliases = new() { "Doomsday", "DoomsdayClient" },
            KnownFileNames = new() { "doomsday.jar", "doomsdayclient.jar", "doomsday.exe" },
            KnownClassNames = new() { "DoomsdayClient", "Doomsday", "bot.Doomsday" },
            MemoryStrings = new() { "DoomsdayClient", "DoomsdayClient:::bot", "DoomsdayClient:::u;<r,7NVce;Ga25" },
            KnownDomains = new() { "doomsdayclient.com", "doomsday.gg" },
            Description = "Known competitive ghost client featuring automated crystal and combat macros."
        },
        new CheatSignature
        {
            Name = "Prestige Client",
            Category = "GhostClient",
            Aliases = new() { "Prestige", "PsaClient" },
            KnownFileNames = new() { "prestige.jar", "psaclient.jar", "prestige_4.properties" },
            KnownClassNames = new() { "prestige.client", "vip.prestigeclient" },
            MemoryStrings = new() { "prestigeclient.vip", "prestigeclient.vip0", "assets/minecraft/optifine/cit/profile/prestige/", ".psaclient" },
            KnownDomains = new() { "prestigeclient.vip" },
            Description = "Obfuscated ghost client utilizing disguised resource pack and config signatures."
        },
        new CheatSignature
        {
            Name = "Vape Client",
            Category = "Injection",
            Aliases = new() { "Vape V4", "Vape Lite", "Kangaroo" },
            KnownFileNames = new() { "vape.exe", "vape-loader.exe", "kangaroo.exe", "vape_v4.exe" },
            MemoryStrings = new() { "vape.gg", "Vape v4", "Vape Lite", "vape_injection" },
            KnownDomains = new() { "vape.gg", "forums.vape.gg" },
            Description = "Commercial injection client injecting dynamic hooks directly into javaw.exe memory."
        },
        new CheatSignature
        {
            Name = "Drip Client",
            Category = "Injection",
            Aliases = new() { "Drip Lite", "Drip" },
            KnownFileNames = new() { "drip.exe", "driplite.exe" },
            MemoryStrings = new() { "drip.gg", "DripLite" },
            KnownDomains = new() { "drip.gg" },
            Description = "High-tier screenshare-evasive external injection cheat."
        },
        new CheatSignature
        {
            Name = "Meteor Client",
            Category = "HackedClient",
            Aliases = new() { "Meteor" },
            KnownFileNames = new() { "meteor-client.jar" },
            KnownPackagePrefixes = new() { "minegame159.meteorclient", "meteordevelopment.meteorclient" },
            KnownDomains = new() { "meteorclient.com" },
            Description = "Open-source fabric utility client containing automated crystal PvP, aura, and flight."
        },
        new CheatSignature
        {
            Name = "Wurst Client",
            Category = "HackedClient",
            Aliases = new() { "Wurst" },
            KnownFileNames = new() { "wurst.jar", "wurstclient.jar" },
            KnownPackagePrefixes = new() { "net.wurstclient" },
            KnownDomains = new() { "wurstclient.net" },
            Description = "Well-known open-source hacked client package."
        },
        new CheatSignature
        {
            Name = "LiquidBounce",
            Category = "HackedClient",
            Aliases = new() { "LiquidBounce" },
            KnownFileNames = new() { "liquidbounce.jar" },
            KnownPackagePrefixes = new() { "net.ccbluex.liquidbounce" },
            KnownDomains = new() { "liquidbounce.net" },
            Description = "Custom injection / Forge utility client."
        },
        new CheatSignature
        {
            Name = "Aristois",
            Category = "HackedClient",
            Aliases = new() { "Aristois" },
            KnownFileNames = new() { "aristois.jar" },
            KnownPackagePrefixes = new() { "me.deftware" },
            KnownDomains = new() { "aristois.net" },
            Description = "Multi-version utility client using custom Deftware framework."
        },
        new CheatSignature
        {
            Name = "Future Client",
            Category = "HackedClient",
            Aliases = new() { "Future" },
            KnownFileNames = new() { "future.jar", "futureclient.jar" },
            KnownPackagePrefixes = new() { "net.futureclient" },
            KnownDomains = new() { "futureclient.net" },
            Description = "Proprietary anarchy and PvP hacked client."
        },
        new CheatSignature
        {
            Name = "Rusherhack",
            Category = "HackedClient",
            Aliases = new() { "Rusherhack" },
            KnownFileNames = new() { "rusherhack.jar" },
            KnownPackagePrefixes = new() { "org.rusherhack" },
            KnownDomains = new() { "rusherhack.org" },
            Description = "Popular 1.12.2 and modern utility mod."
        },
        new CheatSignature
        {
            Name = "Slinky",
            Category = "Injection",
            Aliases = new() { "Slinky" },
            KnownFileNames = new() { "slinky.exe" },
            MemoryStrings = new() { "slinky.gg" },
            KnownDomains = new() { "slinky.gg" },
            Description = "Modern screenshare-bypass injection tool."
        },
        new CheatSignature
        {
            Name = "Itami Autoclicker",
            Category = "Autoclicker",
            Aliases = new() { "Itami" },
            KnownFileNames = new() { "itami.exe" },
            Description = "Open-source C++ external autoclicker."
        },
        new CheatSignature
        {
            Name = "JNativeHook Autoclicker Artifact",
            Category = "Autoclicker",
            Aliases = new() { "JNativeHook" },
            KnownFileNames = new() { "jnativehook*.dll" },
            Description = "Global low-level Windows keyboard/mouse hook library frequently unpacked to %TEMP% by autoclickers."
        }
    };

    /// <summary>
    /// Suspicious module names and combat capabilities inside mod bytecode.
    /// </summary>
    public static readonly List<string> CombatCheatBytecodeKeywords = new()
    {
        "autoclicker", "aimassist", "killaura", "crystalaur", "anchoraura",
        "autocrystal", "anchormacro", "fastplace", "legittotem", "legitretotem",
        "autodtap", "autohitcrystal", "selfdestruct", "autoinventorytotem",
        "autoshielddisabler", "automace"
    };

    /// <summary>
    /// Known cheat domains to cross-reference during browser activity auditing.
    /// </summary>
    public static readonly HashSet<string> KnownCheatDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "vape.gg", "forums.vape.gg", "doomsdayclient.com", "prestigeclient.vip",
        "drip.gg", "slinky.gg", "meteorclient.com", "wurstclient.net",
        "liquidbounce.net", "rusherhack.org", "futureclient.net", "aristois.net",
        "skilledclient.com", "cryptclient.com", "spezz.exchange", "intent.store"
    };

    /// <summary>
    /// Match an archive or executable filename against known cheat signatures with strict word boundary handling.
    /// </summary>
    public static CheatSignature? MatchFileName(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)) return null;
        string clean = Path.GetFileName(fileName).ToLowerInvariant();
        string nameWithoutExt = Path.GetFileNameWithoutExtension(clean);

        foreach (var sig in Signatures)
        {
            foreach (var k in sig.KnownFileNames)
            {
                if (clean.Equals(k, StringComparison.OrdinalIgnoreCase))
                    return sig;

                if (k.Contains('*'))
                {
                    // Pattern matching like jnativehook*.dll
                    string pattern = "^" + Regex.Escape(k).Replace("\\*", ".*") + "$";
                    if (Regex.IsMatch(clean, pattern, RegexOptions.IgnoreCase))
                        return sig;
                }

                string kStem = Path.GetFileNameWithoutExtension(k).ToLowerInvariant();
                if (nameWithoutExt.Equals(kStem, StringComparison.OrdinalIgnoreCase))
                    return sig;

                if (nameWithoutExt.StartsWith(kStem + "-", StringComparison.OrdinalIgnoreCase) ||
                    nameWithoutExt.StartsWith(kStem + "_", StringComparison.OrdinalIgnoreCase) ||
                    nameWithoutExt.StartsWith(kStem + "client", StringComparison.OrdinalIgnoreCase) ||
                    nameWithoutExt.StartsWith(kStem + "v", StringComparison.OrdinalIgnoreCase))
                {
                    return sig;
                }
            }
        }
        return null;
    }

    /// <summary>
    /// Match a package name or class name against known cheat signatures.
    /// </summary>
    public static CheatSignature? MatchClassOrPackage(string classOrPackage)
    {
        if (string.IsNullOrWhiteSpace(classOrPackage)) return null;

        foreach (var sig in Signatures)
        {
            if (sig.KnownPackagePrefixes.Any(p => classOrPackage.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                return sig;

            if (sig.KnownClassNames.Any(c => classOrPackage.Contains(c, StringComparison.OrdinalIgnoreCase)))
                return sig;
        }
        return null;
    }

    /// <summary>
    /// Check whether a class name contains common combat cheat keywords.
    /// </summary>
    public static string? MatchCombatBytecodeKeyword(string className)
    {
        if (string.IsNullOrWhiteSpace(className)) return null;
        string lower = className.ToLowerInvariant();

        foreach (var kw in CombatCheatBytecodeKeywords)
        {
            if (lower.Contains(kw))
            {
                return kw;
            }
        }
        return null;
    }

    /// <summary>
    /// Checks whether a domain name matches a known cheat distribution site.
    /// </summary>
    public static bool IsKnownCheatDomain(string domain, out string matchedCheat)
    {
        matchedCheat = string.Empty;
        if (string.IsNullOrWhiteSpace(domain)) return false;

        string cleanDomain = domain.Trim().ToLowerInvariant().Replace("www.", "").Replace("https://", "").Replace("http://", "").Split('/')[0];

        if (KnownCheatDomains.Contains(cleanDomain))
        {
            matchedCheat = cleanDomain;
            return true;
        }

        foreach (var sig in Signatures)
        {
            if (sig.KnownDomains.Any(d => cleanDomain.EndsWith(d, StringComparison.OrdinalIgnoreCase)))
            {
                matchedCheat = sig.Name;
                return true;
            }
        }

        return false;
    }
}
