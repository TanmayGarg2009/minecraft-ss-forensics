import type { FindingDetail, ReportDetail } from '../types/report';

export interface FindingPresentation {
  simpleTitle: string;
  simpleExplanation: string;
  whatWasObserved: string;
  whyItMatters: string;
  whatItDoesNotEstablish: string;
  possibleLegitimateExplanations: string[];
  referenceDetails?: {
    expectedRelease?: string;
    expectedHash?: string;
    provider?: string;
    internalModId?: string;
  };
  identifier?: string;
  identifierType?: 'file' | 'process' | 'log' | 'system';
}

/**
 * Translates technical scanner finding data into understandable, plain language
 * while preserving strict forensic accuracy and caveats.
 */
export function formatFindingForPresentation(finding: FindingDetail): FindingPresentation {
  const ruleId = finding.ruleId || '';
  const title = finding.title || '';
  const explanation = finding.explanation || '';
  const evidenceSource = finding.evidenceSource || '';
  const observed = finding.observedEvidence || {};

  let simpleTitle = title;
  let simpleExplanation = explanation;
  let whatWasObserved = explanation;
  let whyItMatters = 'Helps staff determine if modified or unauthorized software was present during gameplay.';
  let whatItDoesNotEstablish = 'This indicator alone does not prove the player used cheats during the match.';
  const possibleLegitimateExplanations: string[] = [];
  let identifier: string | undefined = finding.filePath ? finding.filePath.split(/[/\\]/).pop() : undefined;
  let identifierType: 'file' | 'process' | 'log' | 'system' = 'file';

  if (finding.processName) {
    identifier = `${finding.processName}${finding.processId ? ` (PID ${finding.processId})` : ''}`;
    identifierType = 'process';
  }

  // 1. Modified Mod Artifact / Hash Mismatch
  if (ruleId.includes('HASH-MISMATCH') || title.toLowerCase().includes('hash mismatch')) {
    simpleTitle = 'Modified Mod Artifact';
    simpleExplanation = 'The file claims to be a known mod release, but its internal contents have been altered.';
    whatWasObserved = `The mod file '${identifier || 'archive'}' claims release metadata, but its cryptographic hash does not match the official release published on Modrinth or CurseForge.`;
    whyItMatters = 'Cheat clients occasionally repackage altered bytecode inside legitimate mod filenames to evade casual inspection.';
    whatItDoesNotEstablish = 'Does not establish that the alterations are malicious. Custom builds, translations, or modified configs can alter the hash.';
    possibleLegitimateExplanations.push('The player or modpack author compiled a custom build with experimental bug fixes.');
    possibleLegitimateExplanations.push('Asset or language files inside the JAR were customized by the user.');
  }
  // 2. Mod Identity Mismatch / Lookalike
  else if (ruleId.includes('LOOKALIKE') || title.toLowerCase().includes('lookalike')) {
    simpleTitle = 'Mod Identity Mismatch (Lookalike)';
    simpleExplanation = 'This file uses a trusted name on the outside, but contains a different mod identity on the inside.';
    whatWasObserved = `The file name looks like a popular mod (such as OptiFine or Sodium), but the internal manifest declares a different mod ID (${observed.ObservedValue || 'unknown'}).`;
    whyItMatters = 'Renaming cheat archives to mimic standard optimization mods is a known disguise technique.';
    whatItDoesNotEstablish = 'Does not prove the file is a cheat. A developer or user may have renamed an unrelated utility.';
    possibleLegitimateExplanations.push('A player renamed a utility mod for alphabetical organization in their launcher.');
  }
  // 3. Duplicate JAR File or Duplicate Mod ID
  else if (ruleId.includes('DUPLICATE') || title.toLowerCase().includes('duplicate')) {
    simpleTitle = 'Duplicate JAR File';
    simpleExplanation = 'Two or more files in the mods directory have identical contents or share the same internal mod identifier.';
    whatWasObserved = explanation || 'Multiple JAR files share identical cryptographic hashes or duplicate internal mod IDs.';
    whyItMatters = 'Duplicate mods can cause game instability, or indicate an older cheat version left in the folder.';
    whatItDoesNotEstablish = 'Does not indicate malicious activity; accidental copy-paste or lingering modpack versions are very common.';
    possibleLegitimateExplanations.push('The player duplicated a file by accident when copying mods between launcher instances.');
    possibleLegitimateExplanations.push('A mod updater downloaded a new version without deleting the older file.');
  }
  // 4. Unknown or Unlisted Mod Artifact
  else if (ruleId.includes('UNKNOWN') || ruleId.includes('UNLISTED') || title.toLowerCase().includes('unlisted') || title.toLowerCase().includes('unknown')) {
    simpleTitle = 'Unknown Mod Artifact';
    simpleExplanation = 'This mod file is not indexed in public repositories like Modrinth or CurseForge.';
    whatWasObserved = `The file '${identifier || 'JAR'}' could not be matched against any public release in official mod databases.`;
    whyItMatters = 'Private cheats and custom client modifications will not match public databases.';
    whatItDoesNotEstablish = 'Does NOT mean the file is a cheat. Thousands of legitimate private mods, custom server HUDs, and university mods exist.';
    possibleLegitimateExplanations.push('Custom private HUD or keystrokes mod developed for a specific server or clan.');
    possibleLegitimateExplanations.push('Mod downloaded from an independent developer’s personal GitHub or Discord.');
  }
  // 5. Suspicious Runtime Module (Process Injection / Temp DLL)
  else if (ruleId.includes('PROC') || ruleId.includes('MODULE') || title.toLowerCase().includes('module') || evidenceSource === 'ProcessMemoryMetadata') {
    simpleTitle = 'Suspicious Runtime Module';
    simpleExplanation = 'An unsigned dynamic library (.dll) located in a temporary directory was loaded into the Minecraft process.';
    whatWasObserved = explanation || 'javaw.exe address space mapped an unsigned dynamic library from a temporary directory.';
    whyItMatters = 'External cheats frequently inject dynamic libraries into javaw.exe from temporary directories to hide on disk.';
    whatItDoesNotEstablish = 'Does not prove injection of a cheat. Overlay software (Discord, OBS, Nvidia GeForce) frequently loads DLLs into game processes.';
    possibleLegitimateExplanations.push('Recording or streaming software (OBS, Medal, GeForce Experience) injected a capture hook.');
    possibleLegitimateExplanations.push('Voice chat or controller overlay software hooked into the game window.');
  }
  // 6. Historical File Evidence / Prefetch / BAM / DAM
  else if (ruleId.includes('HIST') || evidenceSource === 'Prefetch' || evidenceSource === 'BamDam' || evidenceSource === 'UsnJournal') {
    simpleTitle = 'Historical File Evidence Found';
    simpleExplanation = 'Windows contains a historical record of this file on the system. This does not prove the file was executed in Minecraft.';
    whatWasObserved = explanation || 'A historical artifact was recorded in Windows system logs (Prefetch or NTFS journal).';
    whyItMatters = 'Indicates a suspicious or deleted executable file existed on the computer in recent days or hours.';
    whatItDoesNotEstablish = 'Crucial distinction: A historical Windows record proves the file existed on disk, but does NOT prove it was executed or injected into Minecraft during server play.';
    possibleLegitimateExplanations.push('The file may have been downloaded days ago for an unrelated game or singleplayer testing.');
    possibleLegitimateExplanations.push('The file may have been deleted as routine cleanup prior to the screenshare.');
  }
  // 7. Log Tampering / Anomalous Logs
  else if (ruleId.includes('LOG') || title.toLowerCase().includes('log')) {
    simpleTitle = title.toLowerCase().includes('tamper') ? 'Log Tampering Detected' : 'Anomalous Session Log Entry';
    simpleExplanation = 'The Minecraft session log contains traces of dynamic loading, reflection, or agent hooks.';
    whatWasObserved = explanation || 'Specific log lines reference agent hooks, bytecode injection, or unmapped classes.';
    whyItMatters = 'Session logs record what Minecraft actually loaded when starting up.';
    whatItDoesNotEstablish = 'Log entries do not prove cheating if triggered by standard mod compatibility debug statements or forge crashes.';
    possibleLegitimateExplanations.push('A harmless optimization mod or fabric loader printed debug reflection messages.');
  }
  // 8. Incomplete Scan Coverage
  else if (ruleId.includes('COVERAGE') || title.toLowerCase().includes('incomplete') || title.toLowerCase().includes('coverage')) {
    simpleTitle = 'Scan Coverage Incomplete';
    simpleExplanation = 'Some security checks could not be completed because permissions were restricted in normal user mode.';
    whatWasObserved = explanation || 'Non-admin user mode restricted access to deep system directories (e.g. C:\\Windows\\Prefetch).';
    whyItMatters = 'Incomplete coverage means the scanner cannot vouch for locations it could not read.';
    whatItDoesNotEstablish = 'Does not mean the player tried to hide anything; standard Windows user accounts cannot read Prefetch by design.';
    possibleLegitimateExplanations.push('Player ran the scanner without Administrator elevation as standard procedure.');
  }
  // 9. Prohibited Mod Under Active Policy
  else if (ruleId.includes('POLICY-PROHIBITED') || title.toLowerCase().includes('prohibited mod')) {
    simpleTitle = 'Prohibited Mod Under Server Rules';
    simpleExplanation = 'This mod is disallowed under the active server/gamemode rules due to competitive gameplay advantage.';
    whatWasObserved = explanation || 'Discovered mod matches a prohibited rule under the active server policy.';
    whyItMatters = 'Competitive rules prohibit features like camera detachment (Freecam), automated placement, or radar to preserve fair competition.';
    whatItDoesNotEstablish = 'Crucial distinction: Does NOT prove the file is malware or a modified cheat client. It may be an unmodified official release that is simply banned under this specific gamemode.';
    possibleLegitimateExplanations.push('The player installed the mod for singleplayer building or for playing on a different server.');
    possibleLegitimateExplanations.push('The mod was bundled in a general-purpose community modpack.');
  }
  // 10. Conflicting Identity & Policy Signals
  else if (ruleId.includes('POLICY-CONFLICTING') || title.toLowerCase().includes('conflicting identity')) {
    simpleTitle = 'Mod Policy Identity Conflict';
    simpleExplanation = 'The mod\'s file name, internal manifest, and cryptographic hash contradict each other.';
    whatWasObserved = explanation || 'File name mimics an allowed mod, but internal bytecode or hash identifies it differently.';
    whyItMatters = 'Renaming cheat or prohibited archives to mimic standard optimization mods (such as Sodium) is a common evasion technique.';
    whatItDoesNotEstablish = 'Does not prove malicious intent; players sometimes rename files for alphabetical sorting in their launcher.';
    possibleLegitimateExplanations.push('The player renamed a utility mod for alphabetical organization in their launcher.');
  }
  // 11. Restricted Mod
  else if (ruleId.includes('POLICY-RESTRICTED') || title.toLowerCase().includes('restricted mod')) {
    simpleTitle = 'Restricted Mod Configuration';
    simpleExplanation = 'This mod is permitted only if specific features or settings are disabled.';
    whatWasObserved = explanation || 'Mod is permitted under conditions, but requires staff configuration audit.';
    whyItMatters = 'Certain mods have dual utility (e.g. schematic holograms) but include restricted features (e.g. easy-place automation or radar).';
    whatItDoesNotEstablish = 'Does not prove the restricted features were used during the match.';
    possibleLegitimateExplanations.push('Player uses the mod exclusively for schematic guidance or client performance.');
  }

  // Populate reference details if observed
  let referenceDetails: FindingPresentation['referenceDetails'] = undefined;
  if (observed.ExpectedValue || observed.ExpectedHash || observed.ObservedValue) {
    referenceDetails = {
      expectedRelease: observed.ExpectedValue,
      expectedHash: observed.ExpectedHash,
      provider: observed.Provider,
      internalModId: observed.ModId || observed.ObservedValue
    };
  }

  // Default legitimate explanations if none matched
  if (possibleLegitimateExplanations.length === 0) {
    if (finding.limitationsAndFalsePositives) {
      possibleLegitimateExplanations.push(finding.limitationsAndFalsePositives);
    } else {
      possibleLegitimateExplanations.push('Harmless software conflict or non-standard mod configuration.');
    }
  }

  return {
    simpleTitle,
    simpleExplanation,
    whatWasObserved,
    whyItMatters,
    whatItDoesNotEstablish,
    possibleLegitimateExplanations,
    referenceDetails,
    identifier,
    identifierType
  };
}

export interface ReportOverviewMetrics {
  overallStatus: string;
  isCompleted: boolean;
  completionLabel: string;
  findingsForReviewCount: number;
  verifiedModsCount: number;
  unverifiedOrModifiedCount: number;
  duplicateFilesCount: number;
  scanErrorsOrUnavailableCount: number;
  summaryExplanation: string;
  prohibitedModsCount: number;
  restrictedModsCount: number;
  allowedModsCount: number;
  policyReviewCount: number;
  appliedGamemode: string;
  appliedPolicyName: string;
}

/**
 * Calculates simplified, high-level overview metrics for ordinary players and staff.
 */
export function extractReportOverviewMetrics(report: ReportDetail): ReportOverviewMetrics {
  const findings = report.findings || [];
  const diagnostics = report.diagnosticItems || [];
  const coverage = report.coverage || { totalChecks: 0, passedChecks: 0, flaggedChecks: 0, unavailableChecks: 0 };

  // 1. Mod counts from ModInventory evidence if present
  const modInventoryEvidence = report.evidenceItems?.find(
    e => e.type === 'ModInventory' || e.publicEvidenceId.includes('mod')
  );
  const mods: any[] = Array.isArray(modInventoryEvidence?.structuredPayload)
    ? modInventoryEvidence.structuredPayload
    : [];

  let verifiedModsCount = 0;
  let unverifiedOrModifiedCount = 0;
  let prohibitedModsCount = 0;
  let restrictedModsCount = 0;
  let allowedModsCount = 0;
  let policyReviewCount = 0;

  mods.forEach(m => {
    const isVerified = m.verified === true || m.verificationState === 'VERIFIED_EXACT_RELEASE';
    if (isVerified) {
      verifiedModsCount++;
    } else {
      unverifiedOrModifiedCount++;
    }

    const policy = (m.gameplayPolicy || m.policy || '').toUpperCase();
    if (policy === 'PROHIBITED') prohibitedModsCount++;
    else if (policy === 'RESTRICTED') restrictedModsCount++;
    else if (policy === 'ALLOWED') allowedModsCount++;
    else if (policy === 'NEEDS_REVIEW' || policy === 'UNKNOWN') policyReviewCount++;
  });

  // If mod inventory evidence didn't explicitly have policy, deduce from findings
  if (prohibitedModsCount === 0) {
    prohibitedModsCount = findings.filter(f => f.ruleId?.includes('POLICY-PROHIBITED') || f.title?.toLowerCase().includes('prohibited mod')).length;
  }
  if (restrictedModsCount === 0) {
    restrictedModsCount = findings.filter(f => f.ruleId?.includes('POLICY-RESTRICTED') || f.title?.toLowerCase().includes('restricted mod')).length;
  }

  // If mod inventory wasn't in evidence payload, deduce from findings
  if (mods.length === 0) {
    unverifiedOrModifiedCount = findings.filter(f => f.category === 'ModIntegrity').length;
  }

  // 2. Duplicate files count
  let duplicateFilesCount = 0;
  const hashCounts: Record<string, number> = {};
  mods.forEach(m => {
    if (m.sha256) {
      hashCounts[m.sha256] = (hashCounts[m.sha256] || 0) + 1;
    }
  });
  Object.values(hashCounts).forEach(c => {
    if (c > 1) duplicateFilesCount += (c - 1);
  });

  // Also include findings with ruleId containing DUPLICATE
  const duplicateFindingsCount = findings.filter(f => 
    f.ruleId.includes('DUPLICATE') || f.title.toLowerCase().includes('duplicate')
  ).length;
  if (duplicateFilesCount === 0 && duplicateFindingsCount > 0) {
    duplicateFilesCount = duplicateFindingsCount;
  }

  // 3. Scan errors or unavailable checks
  const scanErrorsOrUnavailableCount = (coverage.unavailableChecks || 0) +
    diagnostics.filter(d => ['skipped', 'accessdenied', 'unsupported', 'failed'].includes(d.status.toLowerCase())).length;

  // 4. Overall status & completion
  const isCompleted = scanErrorsOrUnavailableCount === 0 && report.processingStatus.toLowerCase() === 'completed';
  const completionLabel = isCompleted ? 'Scan Completed Successfully' : 'Partial Scan (Some checks limited)';

  const findingsForReviewCount = findings.length;

  let overallStatus = 'NO SUSPICIOUS INDICATORS FOUND';
  let summaryExplanation = 'All scanned checks completed without discovering altered or unauthorized software.';

  const criticalOrHighCount = findings.filter(f => f.severity === 'Critical' || f.severity === 'High').length;

  if (criticalOrHighCount >= 2) {
    overallStatus = 'STRONG EVIDENCE FOUND';
    summaryExplanation = `${findingsForReviewCount} findings require staff review, including multiple high-priority indicators.`;
  } else if (findingsForReviewCount > 0) {
    overallStatus = 'SUSPICIOUS INDICATORS FOUND';
    summaryExplanation = `${findingsForReviewCount} finding(s) require review. Click any item below to inspect the observed evidence.`;
  } else if (scanErrorsOrUnavailableCount > 3) {
    overallStatus = 'INCOMPLETE SCAN';
    summaryExplanation = 'Several diagnostic checks were restricted by user-mode permissions.';
  }

  return {
    overallStatus,
    isCompleted,
    completionLabel,
    findingsForReviewCount,
    verifiedModsCount,
    unverifiedOrModifiedCount,
    duplicateFilesCount,
    scanErrorsOrUnavailableCount,
    summaryExplanation,
    prohibitedModsCount,
    restrictedModsCount,
    allowedModsCount,
    policyReviewCount,
    appliedGamemode: report.appliedGamemode || 'Standard PvP',
    appliedPolicyName: report.appliedPolicyName || 'Default Policy'
  };
}
