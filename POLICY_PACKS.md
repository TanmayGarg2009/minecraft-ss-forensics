# Policy Packs & Ruleset Guide

Minecraft SS Forensics decouples **forensic fact-finding** from **gameplay policy evaluation**.

While the scanner determines *what* files are present, *what* was executed, and *what* bytecode capabilities exist, the **Policy Engine** evaluates whether those findings violate a specific server's competitive rules.

---

## 1. Built-In Policy Packs

The scanner includes 3 standard built-in policy packs:

### 1.1 Casual Ruleset (`casual-v1`)
- **Philosophy**: Lenient policy for casual survival and minigame servers. Focuses exclusively on active gameplay disruption.
- **Rule Standards**:
  - `PROHIBITED_EXECUTION` for known cheat software.
  - Cosmetic, minimap, performance, and UI utility mods are `ALLOWED`.
  - Unknown mods default to `ALLOWED`.

### 1.2 Competitive Ruleset (`competitive-v1`)
- **Philosophy**: Standard tournament ruleset for ranked PvP, UHC, and competitive leagues.
- **Rule Standards**:
  - `PROHIBITED_POSSESSION` for commercial and open-source cheat clients (Meteor, Aristois, LiquidBounce, Wurst, Vape, Doomsday).
  - Strict performance mod whitelist (Sodium, Lithium, FerriteCore, Iris, Phosphor).
  - Minimaps with cave-mapping or player entity radar are `PROHIBITED_POSSESSION`.
  - Unknown mods default to `NEEDS_REVIEW`.

### 1.3 Strict HCF Ruleset (`strict-hcf-v1`)
- **Philosophy**: Zero-tolerance policy for Hardcore Factions and high-stakes crystal/sword tournaments.
- **Rule Standards**:
  - `PROHIBITED_POSSESSION` for any macro tools, auto-clickers, crystal placers, or input simulators.
  - Strict whitelist enforcement: only explicitly permitted client optimization mods are allowed.
  - Any unverified mod or modified JAR is flagged as `PROHIBITED_POSSESSION`.
  - Unsigned drivers loaded into system kernel trigger immediate review.

---

## 2. Policy Enforcement Standards

The engine supports distinct enforcement standards per rule:

| Standard | Required Evidentiary Proof | Example Scenario |
| :--- | :--- | :--- |
| **`PROHIBITED_POSSESSION`** | File identified on disk, in staging, or in Recycle Bin (`SoftwarePresent` or `SoftwareInstalled`). | Having a meteor-client.jar in Downloads or Recycle Bin. |
| **`PROHIBITED_EXECUTION`** | Artifact recorded in Prefetch, BAM/DAM, or UserAssist (`SoftwareExecuted` or higher). | Having run a macro utility 3 days ago. |
| **`PROHIBITED_GAMEPLAY_USE`** | Telemetry proves active execution during match session (`SoftwareActiveDuringSession` or `ProhibitedFunctionalityUsed`). | Running an auto-crystal mod concurrently with the active game process. |
| **`ALLOWED`** | Explicitly permitted by server rules. | Verified Sodium or Lithium release. |
| **`RESTRICTED`** | Permitted with specific configuration restrictions. | ReplayMod permitted only with live recording disabled. |
| **`NEEDS_REVIEW`** | Unverified or custom mod requiring staff manual review. | Custom guild HUD mod. |
| **`UNKNOWN`** | No rule defined; falls back to default policy behavior. | Third-party unlisted JAR. |

---

## 3. Creating Custom Policy Packs

Servers can define custom policy packs as portable JSON files:

```json
{
  "$schema": "https://raw.githubusercontent.com/minecraft-ss-forensics/minecraft-ss-forensics/master/schema/policy-pack.v2.json",
  "schemaVersion": "2.0.0",
  "packId": "championship-hcf-2026",
  "policyName": "Championship HCF Season 5",
  "gamemode": "Strict HCF",
  "version": "2.1.0",
  "publisher": "HCF League Staff",
  "isExamplePolicy": false,
  "serverRulesUrl": "https://rules.examplehcf.net",
  "description": "Zero tolerance competitive ruleset for Season 5.",
  "defaultUnknownPolicy": "NEEDS_REVIEW",
  "unknownPolicyReason": "Unverified mods must be reviewed by staff prior to match.",
  "rules": [
    {
      "ruleId": "RULE-METEOR",
      "modName": "Meteor Client",
      "policy": "PROHIBITED_POSSESSION",
      "behavior": "AutomatedCombatActions",
      "policyReason": "Possession of hacked clients is banned.",
      "aliases": ["meteor", "meteor-client"]
    },
    {
      "ruleId": "RULE-SODIUM",
      "modName": "Sodium",
      "policy": "ALLOWED",
      "behavior": "ClientOptimization",
      "policyReason": "Official client optimization rendering engine."
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

### Sealing Custom Policy Packs
Custom policy packs can be loaded into `MinecraftSsForensics.exe` by placing them in the application folder or selecting them via the UI. The engine verifies the file's SHA-256 integrity hash on load.
