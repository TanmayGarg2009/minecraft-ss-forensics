# Server Policy Packs & Gamemode Rulesets

Minecraft SS Forensics decouples **forensic fact-finding** from **gameplay policy evaluation**.

While the scanner determines *what* files are present, *what* was executed, and *what* bytecode capabilities exist, the **Policy Engine** evaluates whether those findings violate a specific server's competitive rules.

---

## 1. Built-In Reference Policies

The scanner includes 6 pre-configured reference policy packs:

| Gamemode | Policy ID | Philosophy & Key Rules | Example Prohibitions |
| :--- | :--- | :--- | :--- |
| **Crystal PvP** | `crystal-pvp-v1` | Fast-paced combat requiring strict packet integrity, placement mechanics, and anchor/crystal detonation controls. | Auto-Crystal, Packet Anchor, MarLow Crystal Optimizer, Macro placement tools. (All set to `PROHIBITED_POSSESSION`). |
| **Sword PvP** | `sword-pvp-v1` | Traditional 1.8 and 1.9+ melee combat emphasizing manual aim, CPS, spacing, and movement. | TriggerBot, KillAura, Reach/Hitbox expanders, AutoClickers. (`PROHIBITED_POSSESSION` or `PROHIBITED_EXECUTION`). |
| **Axe PvP** | `axe-pvp-v1` | Shield and axe timing, critical hits, and precision weapon switching. | Auto-Shield, FastBreak, Auto-Crit, Macro weapon cyclers. |
| **UHC** | `uhc-standard-v1` | Ultra Hardcore survival combat without natural regeneration. Full environmental and player awareness. | X-Ray, Cave Finders, Freecam, Entity Radar, Chest ESP, Baritone pathfinders. |
| **Pot PvP** | `pot-pvp-v1` | Nodebuff combat focused on potion management, pearls, and healing speed. | Auto-Pot, Fast-Heal, Refill macros, Pearl trajectory predictions. |
| **SMP** | `smp-general-v1` | General survival multiplayer balancing quality-of-life enhancements against dupe exploits. | Duplication utilities, flight cheats, Baritone auto-mining, Speed hacks. |

> [!IMPORTANT]
> **Example Policy Notice**:
> All bundled policies are published with `isExamplePolicy: true`. They are provided as reference templates for tournament hosts and server staff. Every competitive community retains full sovereignty to customize, sign, and enforce their own policy packs.

---

## 2. Policy Pack JSON Schema

Policy packs are stored as versioned, portable `.json` files.

```json
{
  "$schema": "https://raw.githubusercontent.com/minecraft-ss-forensics/minecraft-ss-forensics/master/schema/policy-pack.v2.json",
  "schemaVersion": "2.0.0",
  "packId": "custom-tournament-2026",
  "policyName": "Winter Championship Official Ruleset",
  "gamemode": "Crystal PvP",
  "version": "2.1.0",
  "publisher": "Winter Tournament Committee",
  "isExamplePolicy": false,
  "serverRulesUrl": "https://example.com/rules",
  "description": "Official ruleset for Winter 2026 Crystal PvP Invitational.",
  "integrityHash": "4a7b9c1d2e...",
  "defaultUnknownPolicy": "NEEDS_REVIEW",
  "unknownPolicyReason": "Unlisted mods require tournament staff review prior to match start.",
  "rules": [
    {
      "ruleId": "RULE-METEOR",
      "modName": "Meteor Client",
      "policy": "PROHIBITED_POSSESSION",
      "behavior": "AutomatedCombatActions",
      "policyReason": "Possession of hacked client is strictly prohibited.",
      "sha256Hashes": [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      ],
      "aliases": ["meteor", "meteor-client"]
    },
    {
      "ruleId": "RULE-SODIUM",
      "modName": "Sodium",
      "policy": "ALLOWED",
      "behavior": "ClientOptimization",
      "policyReason": "Standard client optimization rendering engine."
    }
  ],
  "explicitlyPermittedMods": [
    "sodium",
    "lithium",
    "ferritecore",
    "modmenu",
    "appleskin"
  ]
}
```

---

## 3. Cryptographic Sealing & Tamper Detection

Every policy pack includes an `integrityHash` computed across its serialized payload:

```csharp
var pack = new PolicyPack { ... };
string sealedJson = pack.ExportToJson();
// pack.IntegrityHash is automatically calculated and embedded
```

When the scanner or viewer loads a policy pack, it verifies the SHA-256 seal. If any rule or policy has been modified in transit, the application alerts staff immediately of the seal mismatch.

---

## 4. Policy Rules vs Authenticity

The scanner enforces strict separation between **Authenticity** and **Gameplay Policy**:

1. An official, cryptographically verified Modrinth release of **Freecam** is authentic, but its gameplay policy under UHC or Crystal PvP is `PROHIBITED_POSSESSION`.
2. A locally built, unlisted HUD mod is unverified (`UNKNOWN_OR_UNLISTED`), but its gameplay policy is `NEEDS_REVIEW`, never assumed to be a cheat without evidence.
