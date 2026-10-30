using System.Text.Json;
using System.Text.Json.Serialization;

namespace MinecraftSsForensics.Scanner.Policy;

/// <summary>
/// Registry of built-in server gamemode policies and custom policy loader.
/// Supports versioned JSON serialization, validation, and safe fallback.
/// </summary>
public class ModPolicyRegistry
{
    private readonly Dictionary<string, ServerGamemodePolicy> _policies = new(StringComparer.OrdinalIgnoreCase);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public ModPolicyRegistry()
    {
        RegisterBuiltInPolicies();
    }

    /// <summary>
    /// Gets all registered policies.
    /// </summary>
    public IReadOnlyCollection<ServerGamemodePolicy> GetAllPolicies() => _policies.Values.ToList().AsReadOnly();

    /// <summary>
    /// Retrieves a policy by its ID or Gamemode name, falling back to Default policy if not found.
    /// </summary>
    public ServerGamemodePolicy GetPolicy(string? gamemodeOrPolicyId)
    {
        if (string.IsNullOrWhiteSpace(gamemodeOrPolicyId))
        {
            return _policies["default"];
        }

        if (_policies.TryGetValue(gamemodeOrPolicyId.Trim(), out var policy))
        {
            return policy;
        }

        // Try matching by Gamemode property
        var byGamemode = _policies.Values.FirstOrDefault(p =>
            p.Gamemode.Equals(gamemodeOrPolicyId.Trim(), StringComparison.OrdinalIgnoreCase) ||
            p.PolicyName.Equals(gamemodeOrPolicyId.Trim(), StringComparison.OrdinalIgnoreCase));

        return byGamemode ?? _policies["default"];
    }

    /// <summary>
    /// Registers or overwrites a policy in the registry after validation.
    /// </summary>
    public bool RegisterPolicy(ServerGamemodePolicy policy, out List<string> validationErrors)
    {
        if (!ValidatePolicy(policy, out validationErrors))
        {
            return false;
        }

        _policies[policy.PolicyId] = policy;
        _policies[policy.Gamemode] = policy;
        return true;
    }

    /// <summary>
    /// Loads and registers a policy from a JSON string. Returns the loaded policy or fallback to default on error.
    /// </summary>
    public (ServerGamemodePolicy Policy, bool Success, List<string> Errors) LoadPolicyFromJson(string json)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(json))
        {
            errors.Add("Policy JSON is empty.");
            return (GetPolicy("default"), false, errors);
        }

        try
        {
            var policy = JsonSerializer.Deserialize<ServerGamemodePolicy>(json, JsonOptions);
            if (policy == null)
            {
                errors.Add("Deserialized policy was null.");
                return (GetPolicy("default"), false, errors);
            }

            if (!ValidatePolicy(policy, out var valErrors))
            {
                return (GetPolicy("default"), false, valErrors);
            }

            _policies[policy.PolicyId] = policy;
            _policies[policy.Gamemode] = policy;
            return (policy, true, errors);
        }
        catch (Exception ex)
        {
            errors.Add($"JSON parsing error: {ex.Message}");
            return (GetPolicy("default"), false, errors);
        }
    }

    /// <summary>
    /// Loads a policy from a file path. Returns the loaded policy or fallback to default on error.
    /// </summary>
    public (ServerGamemodePolicy Policy, bool Success, List<string> Errors) LoadPolicyFromFile(string filePath)
    {
        var errors = new List<string>();
        try
        {
            if (!File.Exists(filePath))
            {
                errors.Add($"Policy file not found: {filePath}");
                return (GetPolicy("default"), false, errors);
            }

            string json = File.ReadAllText(filePath);
            return LoadPolicyFromJson(json);
        }
        catch (Exception ex)
        {
            errors.Add($"Error reading policy file: {ex.Message}");
            return (GetPolicy("default"), false, errors);
        }
    }

    /// <summary>
    /// Serializes a policy to formatted JSON.
    /// </summary>
    public string ExportPolicyToJson(ServerGamemodePolicy policy)
    {
        return JsonSerializer.Serialize(policy, JsonOptions);
    }

    /// <summary>
    /// Validates a policy for required fields, versioning, and internal consistency.
    /// </summary>
    public static bool ValidatePolicy(ServerGamemodePolicy? policy, out List<string> errors)
    {
        errors = new List<string>();
        if (policy == null)
        {
            errors.Add("Policy cannot be null.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(policy.PolicyId))
            errors.Add("PolicyId is required.");

        if (string.IsNullOrWhiteSpace(policy.PolicyName))
            errors.Add("PolicyName is required.");

        if (string.IsNullOrWhiteSpace(policy.Gamemode))
            errors.Add("Gamemode is required.");

        if (string.IsNullOrWhiteSpace(policy.PolicyVersion))
            errors.Add("PolicyVersion is required.");

        if (policy.Rules == null)
        {
            errors.Add("Rules list cannot be null.");
            return false;
        }

        // Check for duplicate rule IDs
        var ruleIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in policy.Rules)
        {
            if (string.IsNullOrWhiteSpace(rule.RuleId))
            {
                errors.Add($"Rule for mod '{rule.ModName}' has an empty RuleId.");
            }
            else if (!ruleIds.Add(rule.RuleId))
            {
                errors.Add($"Duplicate RuleId found in policy: {rule.RuleId}");
            }

            if (string.IsNullOrWhiteSpace(rule.ModName))
            {
                errors.Add($"Rule '{rule.RuleId}' has an empty ModName.");
            }
        }

        return errors.Count == 0;
    }

    private void RegisterBuiltInPolicies()
    {
        var crystal = CreateCrystalPvpPolicy();
        var sword = CreateSwordPvpPolicy();
        var axe = CreateAxePvpPolicy();
        var uhc = CreateUhcPolicy();
        var pot = CreatePotPvpPolicy();
        var smp = CreateSmpPolicy();
        var def = CreateDefaultPolicy();

        RegisterInternal(crystal);
        RegisterInternal(sword);
        RegisterInternal(axe);
        RegisterInternal(uhc);
        RegisterInternal(pot);
        RegisterInternal(smp);
        RegisterInternal(def);
    }

    private void RegisterInternal(ServerGamemodePolicy policy)
    {
        policy.IsExamplePolicy = true;
        if (string.IsNullOrEmpty(policy.Publisher) || policy.Publisher == "Example Competition League")
        {
            policy.Publisher = "PhoenixMC Reference Policy (Example Only - Not Official Server Rules)";
        }

        _policies[policy.PolicyId] = policy;
        _policies[policy.Gamemode] = policy;

        // Support both full names (Sword PvP) and concise names (Sword, Axe, Pot)
        if (policy.Gamemode.EndsWith(" PvP", StringComparison.OrdinalIgnoreCase))
        {
            string shortName = policy.Gamemode[..^4].Trim();
            _policies[shortName] = policy;
        }
    }

    // -------------------------------------------------------------
    // BUILT-IN POLICIES
    // -------------------------------------------------------------

    private static List<ModPolicyRule> CreateCoreOptimizationRules()
    {
        return new List<ModPolicyRule>
        {
            new()
            {
                RuleId = "RULE-SODIUM",
                ModName = "Sodium",
                Policy = GameplayPolicy.ALLOWED,
                Behavior = BehaviorCategory.ClientOptimization,
                PolicyReason = "Standard open-source client rendering optimization.",
                ProjectIds = new() { "sodium", "rubidium", "embeddium" },
                ModIds = new() { "sodium", "rubidium", "embeddium" },
                Aliases = new() { "sodium", "rubidium" }
            },
            new()
            {
                RuleId = "RULE-LITHIUM",
                ModName = "Lithium",
                Policy = GameplayPolicy.ALLOWED,
                Behavior = BehaviorCategory.ClientOptimization,
                PolicyReason = "General physics and chunk tick optimization.",
                ProjectIds = new() { "lithium", "canary", "radium" },
                ModIds = new() { "lithium", "canary", "radium" },
                Aliases = new() { "lithium" }
            },
            new()
            {
                RuleId = "RULE-FERRITECORE",
                ModName = "FerriteCore",
                Policy = GameplayPolicy.ALLOWED,
                Behavior = BehaviorCategory.ClientOptimization,
                PolicyReason = "Memory usage optimization.",
                ProjectIds = new() { "ferrite-core", "ferritecore" },
                ModIds = new() { "ferritecore" },
                Aliases = new() { "ferritecore" }
            },
            new()
            {
                RuleId = "RULE-IRIS",
                ModName = "Iris Shaders",
                Policy = GameplayPolicy.ALLOWED,
                Behavior = BehaviorCategory.ClientOptimization,
                PolicyReason = "Shader rendering engine compatible with Sodium.",
                ProjectIds = new() { "iris", "oculus" },
                ModIds = new() { "iris", "oculus" },
                Aliases = new() { "iris", "oculus" }
            },
            new()
            {
                RuleId = "RULE-INDIUM",
                ModName = "Indium",
                Policy = GameplayPolicy.ALLOWED,
                Behavior = BehaviorCategory.ClientOptimization,
                PolicyReason = "Sodium Fabric Rendering API implementation.",
                ProjectIds = new() { "indium" },
                ModIds = new() { "indium" },
                Aliases = new() { "indium" }
            },
            new()
            {
                RuleId = "RULE-FABRIC-API",
                ModName = "Fabric API",
                Policy = GameplayPolicy.ALLOWED,
                Behavior = BehaviorCategory.ClientOptimization,
                PolicyReason = "Essential core library for Fabric mods.",
                ProjectIds = new() { "fabric-api" },
                ModIds = new() { "fabric-api", "fabric" },
                Aliases = new() { "fabric-api" }
            },
            new()
            {
                RuleId = "RULE-OPTIFINE",
                ModName = "OptiFine",
                Policy = GameplayPolicy.ALLOWED,
                Behavior = BehaviorCategory.ClientOptimization,
                PolicyReason = "Standard rendering optimization and shader pipeline.",
                ProjectIds = new() { "optifine" },
                ModIds = new() { "optifine" },
                Aliases = new() { "optifine" }
            }
        };
    }

    private static List<ModPolicyRule> CreateCoreProhibitedCheatRules()
    {
        return new List<ModPolicyRule>
        {
            new()
            {
                RuleId = "RULE-BARITONE",
                ModName = "Baritone",
                Policy = GameplayPolicy.PROHIBITED_POSSESSION,
                Behavior = BehaviorCategory.AutomatedCombatActions,
                PolicyReason = "Possession of automated pathfinding, combat bot, and mining routines is strictly prohibited.",
                ProjectIds = new() { "baritone" },
                ModIds = new() { "baritone", "baritone-api" },
                Aliases = new() { "baritone" }
            },
            new()
            {
                RuleId = "RULE-XRAY",
                ModName = "X-Ray Mod",
                Policy = GameplayPolicy.PROHIBITED_POSSESSION,
                Behavior = BehaviorCategory.HiddenInformationAdvantages,
                PolicyReason = "Possession of ore, cave, and block x-ray renderers is strictly prohibited.",
                ProjectIds = new() { "xray", "advanced-xray", "xray-fabric" },
                ModIds = new() { "xray", "advancedxray", "xrayfabric" },
                Aliases = new() { "xray", "x-ray" }
            },
            new()
            {
                RuleId = "RULE-METEOR",
                ModName = "Meteor Client",
                Policy = GameplayPolicy.PROHIBITED_POSSESSION,
                Behavior = BehaviorCategory.ProhibitedClientModification,
                PolicyReason = "Possession of combat, movement, and render automation utility client is strictly prohibited.",
                ProjectIds = new() { "meteor-client" },
                ModIds = new() { "meteor-client" },
                Aliases = new() { "meteor" }
            },
            new()
            {
                RuleId = "RULE-WURST",
                ModName = "Wurst Client",
                Policy = GameplayPolicy.PROHIBITED_POSSESSION,
                Behavior = BehaviorCategory.ProhibitedClientModification,
                PolicyReason = "Possession of hacked client incorporating combat and movement modifications is strictly prohibited.",
                ProjectIds = new() { "wurst-client" },
                ModIds = new() { "wurst" },
                Aliases = new() { "wurst" }
            },
            new()
            {
                RuleId = "RULE-ARISTOIS",
                ModName = "Aristois Client",
                Policy = GameplayPolicy.PROHIBITED_POSSESSION,
                Behavior = BehaviorCategory.ProhibitedClientModification,
                PolicyReason = "Possession of utility/cheat client with automated gameplay modifications is strictly prohibited.",
                ProjectIds = new() { "aristois" },
                ModIds = new() { "aristois" },
                Aliases = new() { "aristois" }
            }
        };
    }

    /// <summary>
    /// Crystal PvP: Strict competitive rules.
    /// Freecam, Tweakeroo, MiniHUD, and Baritone are PROHIBITED.
    /// Optimization mods are ALLOWED.
    /// </summary>
    public static ServerGamemodePolicy CreateCrystalPvpPolicy()
    {
        var policy = new ServerGamemodePolicy
        {
            SchemaVersion = "1.0.0",
            PolicyId = "crystal-pvp-v1",
            PolicyName = "Crystal PvP Standard Competition Policy",
            Gamemode = "Crystal PvP",
            PolicyVersion = "1.2.0",
            EffectiveDate = "2026-01-01",
            ServerRulesUrl = "https://rules.example-pvp.net/crystal-pvp",
            Description = "Enforces strict anti-automation and fair perspective in end crystal combat. Perspective manipulation (Freecam), fast placement (Tweakeroo), and structure bounding box overlays are prohibited.",
            DefaultUnknownModPolicy = GameplayPolicy.NEEDS_REVIEW,
            UnknownModPolicyReason = "Unregistered mod in competitive Crystal PvP. Staff review required to verify absence of macro/placement automation."
        };

        policy.Rules.AddRange(CreateCoreOptimizationRules());
        policy.Rules.AddRange(CreateCoreProhibitedCheatRules());

        // Freecam is strictly PROHIBITED in Crystal PvP
        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-CRYSTAL-FREECAM",
            ModName = "Freecam",
            Policy = GameplayPolicy.PROHIBITED,
            Behavior = BehaviorCategory.HiddenInformationAdvantages,
            PolicyReason = "Freecam allows players to view positions, traps, and players through solid obsidian/crying obsidian without line of sight.",
            ProjectIds = new() { "freecam", "mod-freecam" },
            ModIds = new() { "freecam" },
            Aliases = new() { "freecam", "free-cam" }
        });

        // Tweakeroo is strictly PROHIBITED in Crystal PvP (fast place / placement rotation)
        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-CRYSTAL-TWEAKEROO",
            ModName = "Tweakeroo",
            Policy = GameplayPolicy.PROHIBITED,
            Behavior = BehaviorCategory.AutomatedCombatActions,
            PolicyReason = "Tweakeroo placement features (fast placement, flexible placement, rotation lock) give automated crystal placement advantages.",
            ProjectIds = new() { "tweakeroo" },
            ModIds = new() { "tweakeroo" },
            Aliases = new() { "tweakeroo" }
        });

        // MiniHUD is PROHIBITED in Crystal PvP (bounding boxes, coordinate/structure overlays)
        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-CRYSTAL-MINIHUD",
            ModName = "MiniHUD",
            Policy = GameplayPolicy.PROHIBITED,
            Behavior = BehaviorCategory.HiddenInformationAdvantages,
            PolicyReason = "Structure bounding boxes, light levels, and raycast info give tactical advantage in crystal battles.",
            ProjectIds = new() { "minihud" },
            ModIds = new() { "minihud" },
            Aliases = new() { "minihud" }
        });

        // Minimap with entity radar is PROHIBITED
        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-CRYSTAL-MINIMAP",
            ModName = "Xaero's Minimap / JourneyMap",
            Policy = GameplayPolicy.PROHIBITED,
            Behavior = BehaviorCategory.PlayerOrEntityTracking,
            PolicyReason = "Minimaps providing player radar or cave mapping are prohibited in competitive Crystal PvP.",
            ProjectIds = new() { "xaeros-minimap", "journeymap" },
            ModIds = new() { "xaerominimap", "journeymap" },
            Aliases = new() { "xaerominimap", "journeymap" }
        });

        // AppleSkin is ALLOWED in Crystal PvP
        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-CRYSTAL-APPLESKIN",
            ModName = "AppleSkin",
            Policy = GameplayPolicy.ALLOWED,
            Behavior = BehaviorCategory.CosmeticOrHud,
            PolicyReason = "HUD food and saturation visualization is permitted in Crystal PvP.",
            ProjectIds = new() { "appleskin" },
            ModIds = new() { "appleskin" },
            Aliases = new() { "appleskin" }
        });

        return policy;
    }

    /// <summary>
    /// Sword PvP: Standard 1.8 / 1.9+ sword combat rules.
    /// Focuses on aim assist, reach, triggerbot, and radar prohibition.
    /// </summary>
    public static ServerGamemodePolicy CreateSwordPvpPolicy()
    {
        var policy = new ServerGamemodePolicy
        {
            SchemaVersion = "1.0.0",
            PolicyId = "sword-pvp-v1",
            PolicyName = "Sword PvP Standard Competition Policy",
            Gamemode = "Sword PvP",
            PolicyVersion = "1.1.0",
            EffectiveDate = "2026-01-01",
            ServerRulesUrl = "https://rules.example-pvp.net/sword-pvp",
            Description = "Enforces clean mechanics in sword duels. Hitbox expansion, aim assistance, triggerbot, reach modifications, and radar are strictly prohibited.",
            DefaultUnknownModPolicy = GameplayPolicy.NEEDS_REVIEW,
            UnknownModPolicyReason = "Unregistered mod in Sword PvP. Staff review required to verify no combat modifications exist."
        };

        policy.Rules.AddRange(CreateCoreOptimizationRules());
        policy.Rules.AddRange(CreateCoreProhibitedCheatRules());

        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-SWORD-FREECAM",
            ModName = "Freecam",
            Policy = GameplayPolicy.PROHIBITED,
            Behavior = BehaviorCategory.HiddenInformationAdvantages,
            PolicyReason = "Perspective detachment is prohibited in duels.",
            ProjectIds = new() { "freecam", "mod-freecam" },
            ModIds = new() { "freecam" },
            Aliases = new() { "freecam" }
        });

        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-SWORD-MINIMAP",
            ModName = "Minimap with Radar",
            Policy = GameplayPolicy.PROHIBITED,
            Behavior = BehaviorCategory.PlayerOrEntityTracking,
            PolicyReason = "Minimaps displaying player positions or entity indicators are prohibited.",
            ProjectIds = new() { "xaeros-minimap", "journeymap" },
            ModIds = new() { "xaerominimap", "journeymap" }
        });

        return policy;
    }

    /// <summary>
    /// Axe PvP: Shield and axe combat mechanics.
    /// Focuses on shield-break macro, weapon-swap automation, and reach prohibition.
    /// </summary>
    public static ServerGamemodePolicy CreateAxePvpPolicy()
    {
        var policy = new ServerGamemodePolicy
        {
            SchemaVersion = "1.0.0",
            PolicyId = "axe-pvp-v1",
            PolicyName = "Axe & Shield PvP Competition Policy",
            Gamemode = "Axe PvP",
            PolicyVersion = "1.1.0",
            EffectiveDate = "2026-01-01",
            ServerRulesUrl = "https://rules.example-pvp.net/axe-pvp",
            Description = "Prohibits automatic shield-disabling macros, hotbar swap scripts, and reach assistance in Axe PvP.",
            DefaultUnknownModPolicy = GameplayPolicy.NEEDS_REVIEW,
            UnknownModPolicyReason = "Unregistered mod in Axe PvP. Staff review required to verify absence of hotkey/macro scripts."
        };

        policy.Rules.AddRange(CreateCoreOptimizationRules());
        policy.Rules.AddRange(CreateCoreProhibitedCheatRules());

        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-AXE-FREECAM",
            ModName = "Freecam",
            Policy = GameplayPolicy.PROHIBITED,
            Behavior = BehaviorCategory.HiddenInformationAdvantages,
            PolicyReason = "Perspective detachment is prohibited.",
            ProjectIds = new() { "freecam", "mod-freecam" },
            ModIds = new() { "freecam" }
        });

        return policy;
    }

    /// <summary>
    /// UHC: Ultra Hardcore competition.
    /// Cave finding, X-ray, Gamma override, Freecam, and entity radar are strictly prohibited.
    /// AppleSkin is RESTRICTED (depending on whether exact saturation is allowed).
    /// </summary>
    public static ServerGamemodePolicy CreateUhcPolicy()
    {
        var policy = new ServerGamemodePolicy
        {
            SchemaVersion = "1.0.0",
            PolicyId = "uhc-v1",
            PolicyName = "Ultra Hardcore (UHC) Competition Policy",
            Gamemode = "UHC",
            PolicyVersion = "1.3.0",
            EffectiveDate = "2026-01-01",
            ServerRulesUrl = "https://rules.example-pvp.net/uhc",
            Description = "Ultra Hardcore survival rules. All underground exploration aids, cave renderers, fullbright/gamma hacks, freecam, and entity tracking are strictly prohibited.",
            DefaultUnknownModPolicy = GameplayPolicy.NEEDS_REVIEW,
            UnknownModPolicyReason = "Unregistered mod in UHC. Staff must inspect to ensure no cave/ore/tracking features are included."
        };

        policy.Rules.AddRange(CreateCoreOptimizationRules());
        policy.Rules.AddRange(CreateCoreProhibitedCheatRules());

        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-UHC-FREECAM",
            ModName = "Freecam",
            Policy = GameplayPolicy.PROHIBITED,
            Behavior = BehaviorCategory.HiddenInformationAdvantages,
            PolicyReason = "Freecam reveals underground caves, ore veins, and player bases without digging.",
            ProjectIds = new() { "freecam", "mod-freecam" },
            ModIds = new() { "freecam" },
            Aliases = new() { "freecam" }
        });

        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-UHC-MINIHUD",
            ModName = "MiniHUD",
            Policy = GameplayPolicy.PROHIBITED,
            Behavior = BehaviorCategory.HiddenInformationAdvantages,
            PolicyReason = "MiniHUD displays light levels, structure bounds, and coordinates, bypassing hardcore survival mechanics.",
            ProjectIds = new() { "minihud" },
            ModIds = new() { "minihud" }
        });

        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-UHC-MINIMAP",
            ModName = "Minimap / Radar",
            Policy = GameplayPolicy.PROHIBITED,
            Behavior = BehaviorCategory.PlayerOrEntityTracking,
            PolicyReason = "Minimaps and entity trackers bypass hardcore exploration and tracking skills.",
            ProjectIds = new() { "xaeros-minimap", "journeymap" },
            ModIds = new() { "xaerominimap", "journeymap" }
        });

        // AppleSkin in UHC is RESTRICTED (some hosts allow hunger bar icons, but disallow saturation overlay)
        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-UHC-APPLESKIN",
            ModName = "AppleSkin",
            Policy = GameplayPolicy.RESTRICTED,
            Behavior = BehaviorCategory.CosmeticOrHud,
            PolicyReason = "Permitted only if saturation value tooltips comply with the tournament organizer's HUD rules.",
            RestrictionConditions = "Allowed only if saturation numbers are not used to time health regeneration ticks.",
            ProjectIds = new() { "appleskin" },
            ModIds = new() { "appleskin" },
            Aliases = new() { "appleskin" }
        });

        return policy;
    }

    /// <summary>
    /// Pot PvP: Potion combat / Nodebuff.
    /// Prohibits auto-potting, inventory refill macros, and triggerbot.
    /// </summary>
    public static ServerGamemodePolicy CreatePotPvpPolicy()
    {
        var policy = new ServerGamemodePolicy
        {
            SchemaVersion = "1.0.0",
            PolicyId = "pot-pvp-v1",
            PolicyName = "Pot PvP / Nodebuff Competition Policy",
            Gamemode = "Pot PvP",
            PolicyVersion = "1.1.0",
            EffectiveDate = "2026-01-01",
            ServerRulesUrl = "https://rules.example-pvp.net/pot-pvp",
            Description = "Enforces manual potion hotkeying and inventory management in Nodebuff/Pot PvP. Auto-splash macros and inventory cleaners are strictly prohibited.",
            DefaultUnknownModPolicy = GameplayPolicy.NEEDS_REVIEW,
            UnknownModPolicyReason = "Unregistered mod in Pot PvP. Staff review required to verify no inventory automation exists."
        };

        policy.Rules.AddRange(CreateCoreOptimizationRules());
        policy.Rules.AddRange(CreateCoreProhibitedCheatRules());

        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-POT-FREECAM",
            ModName = "Freecam",
            Policy = GameplayPolicy.PROHIBITED,
            Behavior = BehaviorCategory.HiddenInformationAdvantages,
            PolicyReason = "Perspective detachment is prohibited in duels.",
            ProjectIds = new() { "freecam", "mod-freecam" },
            ModIds = new() { "freecam" }
        });

        return policy;
    }

    /// <summary>
    /// SMP: Survival Multiplayer / Technical vanilla+.
    /// More permissive: MiniHUD is ALLOWED, Freecam is RESTRICTED (allowed for building),
    /// Litematica is RESTRICTED (schematics allowed, easy place restricted).
    /// </summary>
    public static ServerGamemodePolicy CreateSmpPolicy()
    {
        var policy = new ServerGamemodePolicy
        {
            SchemaVersion = "1.0.0",
            PolicyId = "smp-v1",
            PolicyName = "Survival Multiplayer (SMP) Policy",
            Gamemode = "SMP",
            PolicyVersion = "1.4.0",
            EffectiveDate = "2026-01-01",
            ServerRulesUrl = "https://rules.example-pvp.net/smp",
            Description = "Permits standard technical and quality-of-life utilities for SMP building and redstone. Hacked clients and malicious griefing tools remain strictly prohibited.",
            DefaultUnknownModPolicy = GameplayPolicy.ALLOWED,
            UnknownModPolicyReason = "Unregistered mods in standard SMP are permitted by default unless identified as harmful cheat clients."
        };

        policy.Rules.AddRange(CreateCoreOptimizationRules());
        policy.Rules.AddRange(CreateCoreProhibitedCheatRules());

        // MiniHUD is ALLOWED in SMP
        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-SMP-MINIHUD",
            ModName = "MiniHUD",
            Policy = GameplayPolicy.ALLOWED,
            Behavior = BehaviorCategory.CosmeticOrHud,
            PolicyReason = "MiniHUD is permitted for technical building, redstone diagnostics, and spawn checking.",
            ProjectIds = new() { "minihud" },
            ModIds = new() { "minihud" }
        });

        // Freecam is RESTRICTED in SMP (allowed for building inspection, prohibited for raiding/X-ray)
        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-SMP-FREECAM",
            ModName = "Freecam",
            Policy = GameplayPolicy.RESTRICTED,
            Behavior = BehaviorCategory.HiddenInformationAdvantages,
            PolicyReason = "Permitted for building inspection and cinematic recording; strictly prohibited for inspecting claimed bases or hidden chests.",
            RestrictionConditions = "Must not be used during PvP encounters or to locate hidden competitor bases.",
            ProjectIds = new() { "freecam", "mod-freecam" },
            ModIds = new() { "freecam" }
        });

        // Litematica is RESTRICTED in SMP (holograms allowed, easy place restricted depending on server)
        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-SMP-LITEMATICA",
            ModName = "Litematica",
            Policy = GameplayPolicy.RESTRICTED,
            Behavior = BehaviorCategory.AutomatedInventoryBehavior,
            PolicyReason = "Schematic projection is permitted. Easy-place mode is restricted on survival servers.",
            RestrictionConditions = "Schematic visual guidance allowed; printer/easy-place automation restricted.",
            ProjectIds = new() { "litematica" },
            ModIds = new() { "litematica" }
        });

        // AppleSkin is ALLOWED in SMP
        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-SMP-APPLESKIN",
            ModName = "AppleSkin",
            Policy = GameplayPolicy.ALLOWED,
            Behavior = BehaviorCategory.CosmeticOrHud,
            PolicyReason = "Hunger and saturation visualization is permitted in SMP.",
            ProjectIds = new() { "appleskin" },
            ModIds = new() { "appleskin" }
        });

        return policy;
    }

    /// <summary>
    /// Default general policy: Standard competitive baseline.
    /// </summary>
    public static ServerGamemodePolicy CreateDefaultPolicy()
    {
        var policy = new ServerGamemodePolicy
        {
            SchemaVersion = "1.0.0",
            PolicyId = "default",
            PolicyName = "General Competitive Standard Policy",
            Gamemode = "Default",
            PolicyVersion = "1.0.0",
            EffectiveDate = "2026-01-01",
            ServerRulesUrl = "https://rules.example-pvp.net/standard",
            Description = "Standard competitive baseline for general Minecraft PvP. Optimization and cosmetic mods are allowed; automated combat and perspective detachment mods require review or are prohibited.",
            DefaultUnknownModPolicy = GameplayPolicy.NEEDS_REVIEW,
            UnknownModPolicyReason = "Unregistered mod. Staff manual review required to verify absence of unfair combat advantage."
        };

        policy.Rules.AddRange(CreateCoreOptimizationRules());
        policy.Rules.AddRange(CreateCoreProhibitedCheatRules());

        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-DEFAULT-FREECAM",
            ModName = "Freecam",
            Policy = GameplayPolicy.PROHIBITED,
            Behavior = BehaviorCategory.HiddenInformationAdvantages,
            PolicyReason = "Out-of-body camera perspective is prohibited in competitive matches.",
            ProjectIds = new() { "freecam", "mod-freecam" },
            ModIds = new() { "freecam" }
        });

        policy.Rules.Add(new ModPolicyRule
        {
            RuleId = "RULE-DEFAULT-APPLESKIN",
            ModName = "AppleSkin",
            Policy = GameplayPolicy.ALLOWED,
            Behavior = BehaviorCategory.CosmeticOrHud,
            PolicyReason = "Hunger HUD indicator is allowed.",
            ProjectIds = new() { "appleskin" },
            ModIds = new() { "appleskin" }
        });

        return policy;
    }
}
