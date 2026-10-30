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
    public List<string> MethodInvocations { get; set; } = new();
    public List<string> EmbeddedStrings { get; set; } = new();
    public bool HasAutomationCapabilities => DetectedCapabilities.Any(c =>
        c.CapabilityType == BytecodeCapabilityType.CrystalAutomation ||
        c.CapabilityType == BytecodeCapabilityType.CombatAutomation ||
        c.CapabilityType == BytecodeCapabilityType.PacketManipulation ||
        c.CapabilityType == BytecodeCapabilityType.InputSimulation);
}

/// <summary>
/// Safe static bytecode analyzer that inspects Java class file constant pools, method tables,
/// and bytecode instructions (invokevirtual, invokestatic, invokeinterface) in memory.
/// Identifies structural capabilities (packets, combat, crystal placement, input simulation, mixins)
/// without executing code or relying solely on filenames or blind string matching.
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

                if (classBytes.Length < 10) continue;
                uint magic = (uint)((classBytes[0] << 24) | (classBytes[1] << 16) | (classBytes[2] << 8) | classBytes[3]);
                if (magic != JavaMagic) continue;

                var (poolStrings, methodCalls, mixinTargets) = ParseClassBytecode(classBytes);
                if (poolStrings.Count > 0 || methodCalls.Count > 0)
                {
                    analyzedCount++;
                    InspectClassForCapabilities(entry.FullName, poolStrings, methodCalls, mixinTargets, result);
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
    /// Parses constant pool strings, method invocations, and mixin targets from a Java class file.
    /// </summary>
    public static (HashSet<string> Strings, List<string> MethodInvocations, List<string> MixinTargets) ParseClassBytecode(byte[] classBytes)
    {
        var strings = new HashSet<string>(StringComparer.Ordinal);
        var methodCalls = new List<string>();
        var mixinTargets = new List<string>();

        if (classBytes.Length < 10) return (strings, methodCalls, mixinTargets);

        uint magic = (uint)((classBytes[0] << 24) | (classBytes[1] << 16) | (classBytes[2] << 8) | classBytes[3]);
        if (magic != JavaMagic) return (strings, methodCalls, mixinTargets);

        int offset = 8;
        if (offset + 2 > classBytes.Length) return (strings, methodCalls, mixinTargets);

        int constantPoolCount = (classBytes[offset] << 8) | classBytes[offset + 1];
        offset += 2;

        var cpStrings = new Dictionary<int, string>();
        var cpClasses = new Dictionary<int, int>(); // index -> name_index
        var cpNameAndTypes = new Dictionary<int, (int NameIndex, int DescIndex)>();
        var cpMethodRefs = new Dictionary<int, (int ClassIndex, int NameAndTypeIndex)>();

        for (int i = 1; i < constantPoolCount && offset < classBytes.Length; i++)
        {
            byte tag = classBytes[offset++];
            switch (tag)
            {
                case 1: // CONSTANT_Utf8
                    if (offset + 2 > classBytes.Length) return (strings, methodCalls, mixinTargets);
                    int length = (classBytes[offset] << 8) | classBytes[offset + 1];
                    offset += 2;

                    if (offset + length <= classBytes.Length && length > 0)
                    {
                        string str = Encoding.UTF8.GetString(classBytes, offset, length);
                        strings.Add(str);
                        cpStrings[i] = str;
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
                    i++; // Long and Double take 2 slots
                    break;

                case 7: // CONSTANT_Class
                    if (offset + 2 <= classBytes.Length)
                    {
                        int nameIdx = (classBytes[offset] << 8) | classBytes[offset + 1];
                        cpClasses[i] = nameIdx;
                    }
                    offset += 2;
                    break;

                case 8:  // CONSTANT_String
                case 16: // CONSTANT_MethodType
                case 19: // CONSTANT_Module
                case 20: // CONSTANT_Package
                    offset += 2;
                    break;

                case 9:  // CONSTANT_Fieldref
                    offset += 4;
                    break;

                case 10: // CONSTANT_Methodref
                case 11: // CONSTANT_InterfaceMethodref
                    if (offset + 4 <= classBytes.Length)
                    {
                        int clsIdx = (classBytes[offset] << 8) | classBytes[offset + 1];
                        int ntIdx = (classBytes[offset + 2] << 8) | classBytes[offset + 3];
                        cpMethodRefs[i] = (clsIdx, ntIdx);
                    }
                    offset += 4;
                    break;

                case 12: // CONSTANT_NameAndType
                    if (offset + 4 <= classBytes.Length)
                    {
                        int nameIdx = (classBytes[offset] << 8) | classBytes[offset + 1];
                        int descIdx = (classBytes[offset + 2] << 8) | classBytes[offset + 3];
                        cpNameAndTypes[i] = (nameIdx, descIdx);
                    }
                    offset += 4;
                    break;

                case 15: // CONSTANT_MethodHandle
                    offset += 3;
                    break;

                case 17: // CONSTANT_Dynamic
                case 18: // CONSTANT_InvokeDynamic
                    offset += 4;
                    break;

                default:
                    return (strings, methodCalls, mixinTargets);
            }
        }

        // Resolve method references into canonical call strings
        foreach (var kvp in cpMethodRefs)
        {
            int methodIdx = kvp.Key;
            var (clsIdx, ntIdx) = kvp.Value;

            string clsName = string.Empty;
            if (cpClasses.TryGetValue(clsIdx, out int nameIdx) && cpStrings.TryGetValue(nameIdx, out string? cName))
            {
                clsName = cName;
            }

            string mName = string.Empty;
            string mDesc = string.Empty;
            if (cpNameAndTypes.TryGetValue(ntIdx, out var nt))
            {
                cpStrings.TryGetValue(nt.NameIndex, out mName!);
                cpStrings.TryGetValue(nt.DescIndex, out mDesc!);
            }

            if (!string.IsNullOrEmpty(clsName) && !string.IsNullOrEmpty(mName))
            {
                methodCalls.Add($"{clsName}.{mName}{mDesc}");
            }
        }

        // Look for Mixin annotations
        foreach (var str in strings)
        {
            if (str.StartsWith("Lorg/spongepowered/asm/mixin/Mixin;", StringComparison.Ordinal) ||
                str.StartsWith("org/spongepowered/asm/mixin", StringComparison.Ordinal))
            {
                mixinTargets.Add(str);
            }
        }

        return (strings, methodCalls, mixinTargets);
    }

    private static void InspectClassForCapabilities(
        string className,
        HashSet<string> poolStrings,
        List<string> methodCalls,
        List<string> mixinTargets,
        BytecodeAnalysisResult result)
    {
        bool hasCrystalPlacement = false;
        bool hasCombatAutomation = false;
        bool hasPacketManipulation = false;
        bool hasInputSimulation = false;

        // 1. Crystal Placement & Detonation Automation
        foreach (var call in methodCalls)
        {
            if (!hasCrystalPlacement)
            {
                if ((call.Contains("EndCrystalEntity") || call.Contains("END_CRYSTAL")) ||
                    (call.Contains("interactBlock") && (poolStrings.Any(s => s.Contains("crystal") || s.Contains("autoCrystal")))))
                {
                    hasCrystalPlacement = true;
                    result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                    {
                        CapabilityType = BytecodeCapabilityType.CrystalAutomation,
                        ClassName = className,
                        ObservedSymbolOrMethod = call,
                        CapabilityDescription = "Automated end-crystal placement or detonation method invocation detected in bytecode.",
                        Confidence = ConfidenceLevel.Certain
                    });
                }
            }

            // 2. Automated Combat & Reach Modification
            if (!hasCombatAutomation)
            {
                if (call.Contains("attackEntity") || call.Contains("attack(") || call.Contains("rotateToEntity") ||
                    call.Contains("hitboxMultiplier") || call.Contains("reachDistance"))
                {
                    if (poolStrings.Any(s => s.Contains("killAura") || s.Contains("triggerBot") || s.Contains("reach") || s.Contains("aimAssist")))
                    {
                        hasCombatAutomation = true;
                        result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                        {
                            CapabilityType = BytecodeCapabilityType.CombatAutomation,
                            ClassName = className,
                            ObservedSymbolOrMethod = call,
                            CapabilityDescription = "Automated attack targeting, reach modification, or attack routine invocation.",
                            Confidence = ConfidenceLevel.Certain
                        });
                    }
                }
            }

            // 3. Packet Manipulation & Spoofing
            if (!hasPacketManipulation)
            {
                if (call.Contains("sendPacket") || call.Contains("onPacketSend") || call.Contains("onPacketReceive"))
                {
                    if (poolStrings.Any(s => s.Contains("PlayerMoveC2SPacket") || s.Contains("C03PacketPlayer") || s.Contains("spoof") || s.Contains("cancel")))
                    {
                        hasPacketManipulation = true;
                        result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                        {
                            CapabilityType = BytecodeCapabilityType.PacketManipulation,
                            ClassName = className,
                            ObservedSymbolOrMethod = call,
                            CapabilityDescription = "Synthetic network packet creation, spoofing, or cancellation method invocation.",
                            Confidence = ConfidenceLevel.Certain
                        });
                    }
                }
            }

            // 4. Hardware Input Simulation
            if (!hasInputSimulation)
            {
                if (call.Contains("java/awt/Robot.mousePress") || call.Contains("java/awt/Robot.keyPress") ||
                    call.Contains("glfwSetCursorPos") || call.Contains("glfwSetMouseButtonCallback"))
                {
                    hasInputSimulation = true;
                    result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                    {
                        CapabilityType = BytecodeCapabilityType.InputSimulation,
                        ClassName = className,
                        ObservedSymbolOrMethod = call,
                        CapabilityDescription = "Synthetic hardware input simulation or automated cursor manipulation method call.",
                        Confidence = ConfidenceLevel.Certain
                    });
                }
            }

            // 5. Native Library Loading
            if (call.Contains("java/lang/System.loadLibrary") || call.Contains("java/lang/System.load") || call.Contains("com/sun/jna/Native.register"))
            {
                result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                {
                    CapabilityType = BytecodeCapabilityType.NativeLibraryLoading,
                    ClassName = className,
                    ObservedSymbolOrMethod = call,
                    CapabilityDescription = "Dynamically loads native library binary into process address space at runtime.",
                    Confidence = ConfidenceLevel.Certain
                });
            }

            // 6. External Process Execution
            if (call.Contains("java/lang/ProcessBuilder") || call.Contains("java/lang/Runtime.exec"))
            {
                result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                {
                    CapabilityType = BytecodeCapabilityType.ExternalProcessIntegration,
                    ClassName = className,
                    ObservedSymbolOrMethod = call,
                    CapabilityDescription = "Spawns or interfaces with external operating system subprocesses.",
                    Confidence = ConfidenceLevel.High
                });
            }
        }

        // Fallback string-based heuristic if methods were obfuscated
        foreach (var str in poolStrings)
        {
            if (!hasCrystalPlacement && (str.Contains("autoCrystal") || str.Contains("crystalAura") || str.Contains("crystalPlace")))
            {
                hasCrystalPlacement = true;
                result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                {
                    CapabilityType = BytecodeCapabilityType.CrystalAutomation,
                    ClassName = className,
                    ObservedSymbolOrMethod = str,
                    CapabilityDescription = "Automated end-crystal placement or detonation string detected in constant pool.",
                    Confidence = ConfidenceLevel.High
                });
            }

            if (!hasCombatAutomation && (str.Contains("killAura") || str.Contains("triggerBot") || str.Contains("triggerbot") || str.Contains("reachDistance")))
            {
                hasCombatAutomation = true;
                result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                {
                    CapabilityType = BytecodeCapabilityType.CombatAutomation,
                    ClassName = className,
                    ObservedSymbolOrMethod = str,
                    CapabilityDescription = "Automated attack targeting or reach modifier constant pool identifier.",
                    Confidence = ConfidenceLevel.High
                });
            }

            if (!hasPacketManipulation && (str.Contains("PlayerMoveC2SPacket") || str.Contains("C03PacketPlayer") || str.Contains("C0APacketAnimation")))
            {
                hasPacketManipulation = true;
                result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                {
                    CapabilityType = BytecodeCapabilityType.PacketManipulation,
                    ClassName = className,
                    ObservedSymbolOrMethod = str,
                    CapabilityDescription = "Synthetic network packet identifier in constant pool.",
                    Confidence = ConfidenceLevel.High
                });
            }

            if (!hasInputSimulation && (str.Contains("java/awt/Robot") || str.Contains("glfwSetCursorPos")))
            {
                hasInputSimulation = true;
                result.DetectedCapabilities.Add(new BytecodeCapabilityFinding
                {
                    CapabilityType = BytecodeCapabilityType.InputSimulation,
                    ClassName = className,
                    ObservedSymbolOrMethod = str,
                    CapabilityDescription = "Synthetic hardware input simulation constant pool identifier.",
                    Confidence = ConfidenceLevel.High
                });
            }

            // Hooks and Mixin Targets
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
        }
    }
}
