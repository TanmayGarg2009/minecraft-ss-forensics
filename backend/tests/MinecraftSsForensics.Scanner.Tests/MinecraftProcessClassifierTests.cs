using MinecraftSsForensics.Scanner.Process;

namespace MinecraftSsForensics.Scanner.Tests;

public class MinecraftProcessClassifierTests
{
    [Theory]
    [InlineData("javaw.exe", "-Xmx4G -jar unrelated-server.jar", false)]
    [InlineData("java.exe", "-Dspring.profiles.active=prod com.example.Service", false)]
    [InlineData("javaw.exe", "-Xmx4G -cp libraries net.minecraft.client.main.Main --gameDir C:\\Games\\.minecraft", true)]
    [InlineData("javaw.exe", "-cp libraries net.fabricmc.loader.impl.launch.knot.KnotClient", true)]
    [InlineData("java.exe", "cpw.mods.modlauncher.Launcher --launchTarget forgeclient", true)]
    [InlineData("javaw.exe", "org.quiltmc.loader.impl.launch.knot.KnotClient", true)]
    [InlineData("Lunar Client", "", true)]
    [InlineData("notepad", "net.minecraft.client.main.Main", false)]
    public void IsMinecraftProcess_UsesExecutableAndLaunchIdentity(string processName, string commandLine, bool expected)
    {
        Assert.Equal(expected, MinecraftProcessClassifier.IsMinecraftProcess(processName, commandLine));
    }
}
