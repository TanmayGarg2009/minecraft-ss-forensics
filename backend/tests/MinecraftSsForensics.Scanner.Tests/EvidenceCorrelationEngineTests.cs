using System;
using System.Linq;
using MinecraftSsForensics.Scanner.Correlation;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Policy;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class EvidenceCorrelationEngineTests
{
    [Fact]
    public void Correlation_VanillaMinecraftRunning_DoesNotFlagInactiveModUnderExecutionPolicy()
    {
        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy
        {
            Gamemode = "Crystal PvP",
            PolicyName = "Crystal PvP Standard"
        };
        policy.Rules.Add(new ModPolicyRule
        {
            ModName = "RestrictedUtilityMod",
            Policy = GameplayPolicy.PROHIBITED_EXECUTION,
            Reason = "Execution of unverified utility mods during competitive matches is prohibited."
        });

        var report = new StandaloneReport();

        // Active Java process running completely vanilla Minecraft without this mod
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 1234,
            ProcessName = "javaw.exe",
            SanitizedCommandLine = "-Xmx4G -classpath net/minecraft/client/main/Main --version 1.20.4"
        });

        // Mod is installed in an inactive profile folder, never loaded
        report.ModInventory.Add(new DiscoveredModItem
        {
            Name = "RestrictedUtilityMod",
            FileName = "RestrictedUtilityMod-1.0.jar",
            FullPath = "C:\\Users\\Player\\AppData\\Roaming\\.minecraft\\profiles\\old_profile\\mods\\RestrictedUtilityMod-1.0.jar",
            GameplayPolicy = "PROHIBITED_EXECUTION"
        });

        var assessments = engine.Correlate(report, policy);
        var assessment = assessments.FirstOrDefault(a => a.SoftwareName == "RestrictedUtilityMod");

        Assert.NotNull(assessment);
        // Crucial fix verification: The mod must NOT be flagged as a policy violation!
        Assert.False(assessment.IsPolicyViolation);
        Assert.Equal(SoftwareEvidenceState.SoftwareInstalled, assessment.State);
        Assert.Contains("COMPLIANT (EXECUTION UNPROVEN)", assessment.PolicyEvaluationExplanation);
        Assert.DoesNotContain("VIOLATION", assessment.PolicyEvaluationExplanation);
    }

    [Fact]
    public void Correlation_LoadedModInClasspath_IsFlaggedUnderExecutionPolicy()
    {
        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy
        {
            Gamemode = "Sword PvP",
            PolicyName = "Sword PvP Ruleset"
        };
        policy.Rules.Add(new ModPolicyRule
        {
            ModName = "ExternalClicker",
            Policy = GameplayPolicy.PROHIBITED_EXECUTION,
            Reason = "Auto clickers are prohibited during match execution."
        });

        var report = new StandaloneReport();

        // Process running with this specific mod explicitly in JVM classpath
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 4455,
            ProcessName = "javaw.exe",
            SanitizedCommandLine = "-classpath C:\\Users\\Player\\.minecraft\\mods\\ExternalClicker.jar net.minecraft.client.main.Main"
        });

        report.ModInventory.Add(new DiscoveredModItem
        {
            Name = "ExternalClicker",
            FileName = "ExternalClicker.jar",
            FullPath = "C:\\Users\\Player\\.minecraft\\mods\\ExternalClicker.jar",
            GameplayPolicy = "PROHIBITED_EXECUTION"
        });

        var assessments = engine.Correlate(report, policy);
        var assessment = assessments.FirstOrDefault(a => a.SoftwareName == "ExternalClicker");

        Assert.NotNull(assessment);
        Assert.True(assessment.IsPolicyViolation);
        Assert.Equal(SoftwareEvidenceState.SoftwareActiveDuringSession, assessment.State);
        Assert.Contains("VIOLATION (EXECUTION BANNED)", assessment.PolicyEvaluationExplanation);
    }

    [Fact]
    public void Correlation_PossessionPolicy_TriggersViolationWithoutExecution()
    {
        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy
        {
            Gamemode = "General",
            PolicyName = "Strict Server Policy"
        };
        policy.Rules.Add(new ModPolicyRule
        {
            ModName = "Vape v4",
            Policy = GameplayPolicy.PROHIBITED_POSSESSION,
            Reason = "Possession of cheat client on disk is strictly banned."
        });

        var report = new StandaloneReport();
        // Zero running Java processes, zero execution records
        report.ModInventory.Add(new DiscoveredModItem
        {
            Name = "Vape v4",
            FileName = "vape-loader.jar",
            FullPath = "C:\\Users\\Player\\.minecraft\\mods\\vape-loader.jar",
            GameplayPolicy = "PROHIBITED_POSSESSION"
        });

        var assessments = engine.Correlate(report, policy);
        var assessment = assessments.FirstOrDefault(a => a.SoftwareName == "Vape v4");

        Assert.NotNull(assessment);
        Assert.True(assessment.IsPolicyViolation);
        Assert.Equal(GameplayPolicy.PROHIBITED_POSSESSION, assessment.Policy);
        Assert.Contains("VIOLATION (POSSESSION BANNED)", assessment.PolicyEvaluationExplanation);
        Assert.Contains("is not required under the applicable possession policy", assessment.WhatIsNotProven);
    }
}
