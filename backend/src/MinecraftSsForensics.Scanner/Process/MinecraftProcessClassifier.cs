using System;
using System.Collections.Generic;
using System.Linq;

namespace MinecraftSsForensics.Scanner.Process;

/// <summary>
/// Conservative Minecraft process identification based on executable identity plus launch markers.
/// A Java process alone is not sufficient evidence that Minecraft is running.
/// </summary>
public static class MinecraftProcessClassifier
{
    private static readonly HashSet<string> KnownMinecraftClientNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "minecraft", "minecraftlauncher", "lunar client", "badlion client", "feather", "labymod"
    };

    private static readonly string[] JavaLaunchMarkers =
    {
        "net.minecraft.client.",
        "net.minecraft.client.main.Main",
        "net.minecraft.client.main.GameConfig",
        "net.fabricmc.loader.impl.launch.knot.KnotClient",
        "net.minecraftforge.client.",
        "--launchTarget forgeclient",
        "--launchTarget neoforgeclient",
        "org.quiltmc.loader.impl.launch.knot.KnotClient"
    };

    public static bool IsMinecraftProcess(string? processName, string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(processName))
            return false;

        string normalizedName = System.IO.Path.GetFileNameWithoutExtension(processName.Trim());
        if (KnownMinecraftClientNames.Contains(normalizedName))
            return true;

        bool isJava = normalizedName.Equals("java", StringComparison.OrdinalIgnoreCase) ||
                      normalizedName.Equals("javaw", StringComparison.OrdinalIgnoreCase);
        if (!isJava || string.IsNullOrWhiteSpace(commandLine))
            return false;

        return JavaLaunchMarkers.Any(marker => commandLine.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }
}
