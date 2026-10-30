using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Archive;

public enum BytecodeCapabilityType
{
    CrystalAutomation,
    CombatAutomation,
    PacketManipulation,
    ClientGameplayAutomation,
    InputSimulation,
    HooksAndMixins,
    NativeLibraryLoading,
    ExternalProcessIntegration,
    None
}

public class BytecodeCapabilityFinding
{
    public BytecodeCapabilityType CapabilityType { get; set; }
    public string ClassName { get; set; } = string.Empty;
    public string ObservedSymbolOrMethod { get; set; } = string.Empty;
    public string CapabilityDescription { get; set; } = string.Empty;
    public string EvidentiaryScope { get; set; } = "Establishes structural bytecode capability; does NOT establish actual in-game use without runtime packet/session correlation.";
    public ConfidenceLevel Confidence { get; set; } = ConfidenceLevel.Certain;
}

public class BytecodeAnalysisResult
{
    public int TotalClassesAnalyzed { get; set; }
    public List<BytecodeCapabilityFinding> DetectedCapabilities { get; set; } = new();
    public List<string> MixinTargets { get; set; } = new();
    public List<string> EmbeddedStrings { get; set; } = new();
    public bool HasAutomationCapabilities => DetectedCapabilities.Any(c =>
        c.CapabilityType == BytecodeCapabilityType.CrystalAutomation ||
        c.CapabilityType == BytecodeCapabilityType.CombatAutomation ||
        c.CapabilityType == BytecodeCapabilityType.PacketManipulation ||
        c.CapabilityType == BytecodeCapabilityType.InputSimulation);
}

/// <summary>
/// Safe static bytecode analyzer that inspects Java class file constant pools in memory.
/// Identifies structural capabilities (packets, combat, crystal placement, input simulation, mixins)
/// without relying on filenames, folder names, or blind string matching.
/// </summary>
public static class StaticBytecodeAnalyzer
{
    private const uint JavaMagic = 0xCAFEBABE;
    private const int MaxClassBytesToParse = 512 * 1024; // 512 KB max per class file to prevent DOS
    private const int MaxClassesToAnalyzePerJar = 200;

    /// <summary>
    /// Analyzes class files within a ZIP/JAR archive and extracts structural capabilities.
    /// </summary>
    public static BytecodeAnalysisResult AnalyzeArchive(ZipArchive archive)
    {
        var result = new BytecodeAnalysisResult();
        int analyzedCount = 0;

        foreach (var entry in archive.Entries)
        {
            if (!entry.FullName.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                continue;

            if (analyzedCount >= MaxClassesToAnalyzePerJar)
                break;

            if (entry.Length > MaxClassBytesToParse || entry.Length < 10)
                continue;

            try
            {
                using var entryStream = entry.Open();
                using var memoryStream = new MemoryStream();
                entryStream.CopyTo(memoryStream);
                byte[] classBytes = memoryStream.ToArray();

                var poolStrings = ParseConstantPoolStrings(classBytes);
                if (poolStrings.Count > 0)
                {
                    analyzedCount++;
                    InspectPoolForCapabilities(entry.FullName, poolStrings, result);
                }
            }
            catch
            {
                // Unreadable or obfuscated malformed class: skip safely
            }
        }

        result.TotalClassesAnalyzed = analyzedCount;
        return result;
    }

    /// <summary>
    /// Safely parses the constant pool Utf8 string table from a Java class file.
    /// </summary>
    public static HashSet<string> ParseConstantPoolStrings(byte[] classBytes)
    {
        var strings = new HashSet<string>(StringComparer.Ordinal);
        if (classBytes.Length < 10) return strings;

        // Big-endian magic check: 0xCAFEBABE
        uint magic = (uint)((classBytes[0] << 24) | (classBytes[1] << 16) | (classBytes[2] << 8) | classBytes[3]);
        if (magic != JavaMagic) return strings;

        int offset = 8; // Skip magic (4), minor_version (2), major_version (2)
        if (offset + 2 > classBytes.Length) return strings;

        int constantPoolCount = (classBytes[offset] << 8) | classBytes[offset + 1];
        offset += 2;

        for (int i = 1; i < constantPoolCount && offset < classBytes.Length; i++)
        {
            byte tag = classBytes[offset++];
            switch (tag)
            {
                case 1: // CONSTANT_Utf8
                    if (offset + 2 > classBytes.Length) return strings;
                    int length = (classBytes[offset] << 8) | classBytes[offset + 1];
                    offset += 2;

                    if (offset + length <= classBytes.Length && length > 0)
                    {
                        string str = Encoding.UTF8.GetString(classBytes, offset, length);
                        strings.Add(str);
                        offset += length;
                    }
                    else
                    {
                        offset += length;
                    }
                    break;

                case 3: // CONSTANT_Integer
                case 4: // CONSTANT_Float
                    offset += 4;
                    break;

                case 5: // CONSTANT_Long
                case 6: // CONSTANT_Double
                    offset += 8;
                    i++; // Long and Double take 2 constant pool slots in JVM specification
                    break;

                case 7:  // CONSTANT_Class
                case 8:  // CONSTANT_String
                case 16: // CONSTANT_MethodType
                case 19: // CONSTANT_Module
                case 20: // CONSTANT_Package
                    offset += 2;
                    break;

                case 9:  // CONSTANT_Fieldref
                case 10: // CONSTANT_Methodref
                case 11: // CONSTANT_InterfaceMethodref
                case 12: // CONSTANT_NameAndType
                case 17: // CONSTANT_Dynamic
                case 18: // CONSTANT_InvokeDynamic
                    offset += 4;
                    break;

                case 15: // CONSTANT_MethodHandle
                    offset += 3;
                    break;

                default:
                    // Unknown or unsupported tag: terminate constant pool parsing safely
                    return strings;
            }
        }

        return strings;
    }

    private static void InspectPoolForCapabilities(string className, HashSet<string> poolStrings, BytecodeAnalysisResult result)
    {
        bool hasCrystalPlacement = false;
        bool hasCombatAutomation = false;
        bool hasPacketManipulation = false;
        bool hasInputSimulation = false;

        foreach (var str in poolStrings)
        {
            // 1. Crystal Placement & Breaking Automation
            if (!hasCrystalPlacement)
            {
                if (str.Contains("EndCrystalEntity") || str.Contains("END_CRYSTAL") || str.Contains("end_crystal"))
                {
                    if (poolStrings.Any(s => s.Contains("interactBlock") || s.Contains("attackEntity") || s.Contains("crystalAura") || s.Contains("autoCrystal") || s.Contains("crystalPlace")))
                    {
                        hasCrystalPlacement = true;
                        result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                        {
                            CapabilityType = BytecodeCapabilityType.CrystalAutomation,
                            ClassName = className,
                            ObservedSymbolOrMethod = "EndCrystalEntity + interactBlock / autoCrystal logic",
                            CapabilityDescription = "Automated end-crystal placement or detonation loop logic detected in bytecode.",
                            Confidence = ConfidenceLevel.Certain
                        });
                    }
                }
            }

            // 2. Automated Combat & Reach Modification
            if (!hasCombatAutomation)
            {
                if (str.Contains("killaura") || str.Contains("killAura") || str.Contains("triggerBot") || str.Contains("triggerbot") ||
                    str.Contains("reachDistance") || str.Contains("extendedReach") || str.Contains("hitboxMultiplier") ||
                    (str.Contains("attack") && poolStrings.Any(s => s.Contains("resetLastAttackedTicks") || s.Contains("getClosestPlayer") || s.Contains("rotateToEntity"))))
                {
                    hasCombatAutomation = true;
                    result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                    {
                        CapabilityType = BytecodeCapabilityType.CombatAutomation,
                        ClassName = className,
                        ObservedSymbolOrMethod = str,
                        CapabilityDescription = "Automated attack targeting, reach extension, or attack cooldown bypass routine.",
                        Confidence = ConfidenceLevel.High
                    });
                }
            }

            // 3. Packet Manipulation & Simulation
            if (!hasPacketManipulation)
            {
                if (str.Contains("C03PacketPlayer") || str.Contains("C0APacketAnimation") ||
                    str.Contains("PlayerMoveC2SPacket") || str.Contains("PlayerActionC2SPacket") ||
                    (str.Contains("sendPacket") && poolStrings.Any(s => s.Contains("cancel") || s.Contains("PacketModifier") || s.Contains("spoof"))))
                {
                    hasPacketManipulation = true;
                    result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                    {
                        CapabilityType = BytecodeCapabilityType.PacketManipulation,
                        ClassName = className,
                        ObservedSymbolOrMethod = str,
                        CapabilityDescription = "Synthetic network packet creation, spoofing, or cancellation routine.",
                        Confidence = ConfidenceLevel.High
                    });
                }
            }

            // 4. Input Simulation
            if (!hasInputSimulation)
            {
                if (str.Contains("java/awt/Robot") || str.Contains("setKeyBindState") || str.Contains("glfwSetCursorPos") || str.Contains("mouseClickSynthetic"))
                {
                    hasInputSimulation = true;
                    result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                    {
                        CapabilityType = BytecodeCapabilityType.InputSimulation,
                        ClassName = className,
                        ObservedSymbolOrMethod = str,
                        CapabilityDescription = "Synthetic hardware input simulation or automated keybind state manipulation.",
                        Confidence = ConfidenceLevel.Certain
                    });
                }
            }

            // 5. Hooks & Mixin Targets
            if (str.StartsWith("net/minecraft/client/", StringComparison.Ordinal))
            {
                if (str.Contains("MinecraftClient") || str.Contains("ClientPlayerEntity") || str.Contains("ClientPlayerInteractionManager"))
                {
                    if (!result.MixinTargets.Contains(str))
                    {
                        result.MixinTargets.Add(str);
                    }
                }
            }

            // 6. Native Library Loading
            if (str.Equals("java/lang/System", StringComparison.Ordinal) && poolStrings.Contains("loadLibrary"))
            {
                result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                {
                    CapabilityType = BytecodeCapabilityType.NativeLibraryLoading,
                    ClassName = className,
                    ObservedSymbolOrMethod = "System.loadLibrary",
                    CapabilityDescription = "Dynamically loads native library binary at runtime.",
                    Confidence = ConfidenceLevel.High
                });
            }

            // 7. External Process Execution
            if (str.Contains("java/lang/ProcessBuilder") || str.Contains("Runtime;->exec"))
            {
                result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                {
                    CapabilityType = BytecodeCapabilityType.ExternalProcessIntegration,
                    ClassName = className,
                    ObservedSymbolOrMethod = str,
                    CapabilityDescription = "Spawns or interfaces with external operating system subprocesses.",
                    Confidence = ConfidenceLevel.High
                });
            }
        }
    }
}
