using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MinecraftSsForensics.Scanner.Policy;

/// <summary>
/// Distributable, versioned JSON policy format for server anti-cheat rules and gamemode policies.
/// Decoupled from forensic evidence; operates 100% offline.
/// </summary>
public class PolicyPack
{
    public string SchemaVersion { get; set; } = "2.0.0";
    public string PackId { get; set; } = string.Empty;
    public string PolicyName { get; set; } = string.Empty;
    public string Gamemode { get; set; } = "Default"; // Crystal PvP, Sword, Axe, UHC, Pot, SMP
    public string Version { get; set; } = "2.0.0";
    public string Publisher { get; set; } = "Official Example Policy";
    public bool IsExamplePolicy { get; set; } = true;
    public string ServerRulesUrl { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string IntegrityHash { get; set; } = string.Empty;

    public GameplayPolicy DefaultUnknownPolicy { get; set; } = GameplayPolicy.NEEDS_REVIEW;
    public string UnknownPolicyReason { get; set; } = "Unlisted mod requires manual staff review. Unknown status is not proof of cheating.";

    public List<ModPolicyRule> Rules { get; set; } = new();
    public List<string> ExplicitlyPermittedMods { get; set; } = new();

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>
    /// Computes the SHA-256 seal of the policy pack payload.
    /// </summary>
    public string ComputeIntegrityHash()
    {
        string current = IntegrityHash;
        IntegrityHash = string.Empty;
        try
        {
            string json = JsonSerializer.Serialize(this, JsonOpts);
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(json));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        finally
        {
            IntegrityHash = current;
        }
    }

    /// <summary>
    /// Exports the policy pack to JSON.
    /// </summary>
    public string ExportToJson()
    {
        IntegrityHash = ComputeIntegrityHash();
        return JsonSerializer.Serialize(this, JsonOpts);
    }

    /// <summary>
    /// Loads a policy pack from JSON and validates its structure.
    /// </summary>
    public static (bool Success, PolicyPack? Pack, string ErrorMessage) LoadFromJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return (false, null, "Policy pack JSON is empty.");

        try
        {
            var pack = JsonSerializer.Deserialize<PolicyPack>(json, JsonOpts);
            if (pack == null)
                return (false, null, "Deserialization produced a null policy pack.");

            if (string.IsNullOrWhiteSpace(pack.PackId) || string.IsNullOrWhiteSpace(pack.Gamemode))
                return (false, null, "Policy pack is missing required fields (packId or gamemode).");

            return (true, pack, string.Empty);
        }
        catch (Exception ex)
        {
            return (false, null, $"Invalid policy pack JSON: {ex.Message}");
        }
    }

    /// <summary>
    /// Converts this policy pack to a ServerGamemodePolicy instance for engine evaluation.
    /// </summary>
    public ServerGamemodePolicy ToGamemodePolicy()
    {
        var policy = new ServerGamemodePolicy
        {
            SchemaVersion = SchemaVersion,
            PolicyId = PackId,
            PolicyName = PolicyName,
            Gamemode = Gamemode,
            PolicyVersion = Version,
            Publisher = Publisher,
            IsExamplePolicy = IsExamplePolicy,
            ServerRulesUrl = ServerRulesUrl,
            Description = Description,
            DefaultUnknownModPolicy = DefaultUnknownPolicy,
            UnknownModPolicyReason = UnknownPolicyReason,
            Rules = new List<ModPolicyRule>(Rules),
            ExplicitlyPermittedMods = new List<string>(ExplicitlyPermittedMods)
        };
        return policy;
    }
}
