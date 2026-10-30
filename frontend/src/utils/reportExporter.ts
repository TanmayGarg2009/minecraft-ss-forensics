import type { ReportDetail, ModInventoryItem, FindingDetail } from '../types/report';

export type ReportExportFormat = 'json' | 'md';

export interface ReportExportResult {
  content: string;
  suggestedFileName: string;
  mimeType: string;
  format: ReportExportFormat;
  byteCount: number;
}

/**
 * Redacts sensitive tokens and credentials from Minecraft process command lines and JVM arguments.
 */
export function redactCommandLine(cmd?: string): string {
  if (!cmd) return '';
  return cmd
    .replace(/(--accessToken\s+)[^\s]+/gi, '$1[REDACTED]')
    .replace(/(--session\s+)[^\s]+/gi, '$1[REDACTED]')
    .replace(/(--uuid\s+)[^\s]+/gi, '$1[REDACTED]')
    .replace(/(--userProperties\s+)[^\s]+/gi, '$1[REDACTED]')
    .replace(/(-Dauth\.token=)[^\s]+/gi, '$1[REDACTED]')
    .replace(/(password[=:]\s*)[^\s]+/gi, '$1[REDACTED]');
}

/**
 * Escapes pipe and newline characters for markdown table cells.
 */
function sanitizeMd(text?: string | null): string {
  if (!text) return '';
  return String(text).replace(/\|/g, '\\|').replace(/\r/g, ' ').replace(/\n/g, ' ').trim();
}

/**
 * Formats a list of strings as markdown code spans or returns 'None Detected'.
 */
function formatList(list?: string[] | null): string {
  if (!list || list.length === 0) return '`None Detected`';
  return list.map(i => `\`${i}\``).join(', ');
}

/**
 * Extracts mod inventory items from report evidence items.
 */
export function extractModInventory(report: ReportDetail): ModInventoryItem[] {
  const modEvidence = report.evidenceItems.find(
    e => e.type === 'ModInventory' || e.publicEvidenceId?.includes('mod')
  );

  if (!modEvidence || !modEvidence.structuredPayload) return [];

  if (Array.isArray(modEvidence.structuredPayload)) {
    return modEvidence.structuredPayload as ModInventoryItem[];
  }

  if (Array.isArray((modEvidence.structuredPayload as any).mods)) {
    return (modEvidence.structuredPayload as any).mods as ModInventoryItem[];
  }

  return [];
}

/**
 * Generates a consistent, descriptive filename containing the scan date and public report identifier.
 */
export function generateSuggestedFilename(report: ReportDetail, format: ReportExportFormat): string {
  const rawDate = report.scanCompletedAt || report.scanStartedAt || report.uploadedAt || report.createdAt;
  const dateStr = rawDate ? new Date(rawDate).toISOString().slice(0, 10) : new Date().toISOString().slice(0, 10);
  const idPart = (report.publicId || 'local').trim();
  const ext = format === 'md' ? 'md' : 'json';
  return `MinecraftForensicReport_${dateStr}_${idPart}.${ext}`;
}

/**
 * Generates why a specific finding matters for anti-cheat investigation.
 */
function getWhyItMatters(f: FindingDetail): string {
  const ruleId = f.ruleId.toUpperCase();
  if (ruleId.includes('PROHIBITED'))
    return 'This mod provides direct mechanical or perspective advantages strictly disallowed under active competition rules.';
  if (ruleId.includes('LOOKALIKE') || ruleId.includes('METADATA-CONFLICT'))
    return 'Renaming cheat archives to mimic trusted optimization utilities (e.g. Sodium) is a common evasion technique.';
  if (ruleId.includes('HASH-MISMATCH'))
    return 'Indicates bytecode modification. Repackaging cheats within legitimate mod releases avoids casual visual detection.';
  if (ruleId.includes('PROC') || ruleId.includes('MODULE'))
    return 'Cheat software often maps unsigned dynamic libraries into javaw.exe from temporary directories to hide disk artifacts.';
  if (ruleId.includes('HIST') || f.evidenceSource === 'Prefetch')
    return 'Proves recent execution of the executable on the operating system within the historical window.';
  return 'Forensic indicator helps staff assess whether unauthorized client modifications were active during gameplay.';
}

/**
 * Generates what a specific finding does NOT prove.
 */
function getWhatItDoesNotProve(f: FindingDetail): string {
  const ruleId = f.ruleId.toUpperCase();
  if (ruleId.includes('PROHIBITED'))
    return 'Does NOT prove the file is malware or a hacked client. It may be an official release that is simply disallowed in this specific gamemode.';
  if (ruleId.includes('HIST') || f.evidenceSource === 'Prefetch')
    return 'Proves the executable existed and ran on disk, but does NOT prove it was executed or injected during the specific Minecraft match.';
  if (ruleId.includes('HASH-MISMATCH'))
    return 'Does not prove malicious intent; user-modified translations, custom patches, or asset customizations also alter the hash.';
  if (ruleId.includes('LOOKALIKE'))
    return 'Does not prove cheating; a player may have renamed a harmless utility for launcher sorting.';
  return 'This individual indicator alone does not establish intentional cheating during match play.';
}

/**
 * Generates suggested next investigative checks.
 */
function getSuggestedNextChecks(f: FindingDetail): string {
  const ruleId = f.ruleId.toUpperCase();
  if (ruleId.includes('PROHIBITED'))
    return '1. Check in-game keybinds and configuration screen for active features.\n2. Inquire if player uses this launcher profile for other servers or building.';
  if (ruleId.includes('LOOKALIKE') || ruleId.includes('HASH-MISMATCH'))
    return '1. Inspect internal archive entries and .class bytecode headers.\n2. Cross-reference file creation timestamp with session match times.';
  if (ruleId.includes('PROC'))
    return '1. Review parent process launch command line.\n2. Verify digital signature and certificates on disk DLL.';
  return '1. Compare timestamps with match logs.\n2. Request unredacted configuration files from player with consent.';
}

/**
 * Generates AI or human investigator questions based on report evidence.
 */
function generateInvestigationQuestions(report: ReportDetail, mods: ModInventoryItem[]): string[] {
  const questions: string[] = [];

  const prohibitedMods = mods.filter(m => (m.gameplayPolicy || m.policy)?.toUpperCase() === 'PROHIBITED');
  if (prohibitedMods.length > 0) {
    const names = prohibitedMods.map(m => m.name || m.fileName).slice(0, 3).join(', ');
    questions.push(`**Prohibited Mods:** Discovered prohibited mod(s) [${names}]. Was this mod loaded during the match under investigation, or does the player maintain multiple profiles for different servers?`);
  }

  const modifiedMods = mods.filter(m => m.verificationState?.includes('MISMATCH') || m.verificationState?.includes('MODIFIED'));
  if (modifiedMods.length > 0) {
    const names = modifiedMods.map(m => m.name || m.fileName).slice(0, 2).join(', ');
    questions.push(`**Bytecode Integrity:** Discovered altered mod archive(s) [${names}]. Did the player manually recompile or customize this mod (e.g. language pack, keybind tweaks), or is it an unofficial repacked build?`);
  }

  const unverifiedMods = mods.filter(m => !m.verified && !m.verificationState?.includes('MISMATCH'));
  if (unverifiedMods.length > 0) {
    questions.push(`**Unverified Mods:** Discovered ${unverifiedMods.length} unlisted or unknown mod(s). Where were these JARs obtained, and do their internal class paths match legitimate projects?`);
  }

  const deletedFindings = report.findings.filter(f => f.category === 'FileDeletion' || f.evidenceSource === 'UsnJournal');
  if (deletedFindings.length > 0) {
    questions.push('**File Deletion:** Discovered recent file deletion records in the Minecraft or Temp directories. What files were deleted around the match time, and was it routine launcher cleanup or intentional artifact destruction?');
  }

  const prefetchFindings = report.findings.filter(f => f.evidenceSource === 'Prefetch' || f.category === 'ExecutionArtifacts');
  if (prefetchFindings.length > 0) {
    questions.push('**Historical Execution:** Discovered execution artifacts from known external utilities. Does the execution timestamp match the active game session, or did this occur outside the competition window?');
  }

  const unavailableChecks = report.diagnosticItems.filter(d => d.status === 'AccessDenied' || d.status === 'Failed');
  if (unavailableChecks.length > 0) {
    questions.push(`**Scan Limitations:** ${unavailableChecks.length} forensic check(s) were unavailable due to non-elevated user permissions. Is manual inspection of Prefetch or USN journal required to confirm timeline integrity?`);
  }

  if (questions.length === 0) {
    questions.push('No anomalous indicators were identified. Can staff confirm that the scan was executed immediately after the match without system reboots or launcher reinstalls?');
  }

  return questions;
}

/**
 * Exports the complete forensic report as a valid, self-contained, properly indented JSON string.
 * Redacts sensitive tokens and excludes deletion credentials.
 */
export function exportReportToJson(report: ReportDetail): string {
  // Redact command lines in findings
  const sanitizedFindings = report.findings.map(f => ({
    ...f,
    processCommandLine: f.processCommandLine ? redactCommandLine(f.processCommandLine) : undefined,
  }));

  // Redact JVM argument raw content in evidence items
  const sanitizedEvidence = report.evidenceItems.map(e => ({
    ...e,
    rawContent: e.type === 'JvmArguments' && e.rawContent ? redactCommandLine(e.rawContent) : e.rawContent,
  }));

  const exportPayload = {
    exportMetadata: {
      exportSchemaVersion: '1.0.0',
      exportFormat: 'FullForensicJson',
      exportedAtUtc: new Date().toISOString(),
      reportId: report.publicId,
      isLocalExport: false,
      exporter: 'Minecraft SS Forensics Web Exporter v1.0.0',
      redactionDisclosure: 'Minecraft session tokens, account passwords, and player deletion credentials are strictly excluded or redacted.',
    },
    report: {
      publicId: report.publicId,
      schemaVersion: report.schemaVersion,
      scannerVersion: report.scannerVersion,
      createdAt: report.createdAt,
      uploadedAt: report.uploadedAt,
      scanStartedAt: report.scanStartedAt,
      scanCompletedAt: report.scanCompletedAt,
      scanMode: report.scanMode,
      osName: report.osName,
      osVersion: report.osVersion,
      osArchitecture: report.osArchitecture,
      detectedMinecraftVersions: report.detectedMinecraftVersions,
      detectedLoaders: report.detectedLoaders,
      appliedPolicyName: report.appliedPolicyName,
      appliedPolicyVersion: report.appliedPolicyVersion,
      appliedGamemode: report.appliedGamemode,
      appliedPolicyRulesUrl: report.appliedPolicyRulesUrl,
      consent: report.consent,
      processingStatus: report.processingStatus,
      expiresAt: report.expiresAt,
      coverage: report.coverage,
      severitySummary: report.severitySummary,
      findings: sanitizedFindings,
      evidenceItems: sanitizedEvidence,
      timelineEvents: report.timelineEvents,
      diagnosticItems: report.diagnosticItems,
      privacyNotice: report.privacyNotice,
    },
  };

  return JSON.stringify(exportPayload, null, 2);
}

/**
 * Exports the report as an AI-friendly, human-readable 13-section Markdown document.
 */
export function exportReportToMarkdown(report: ReportDetail): string {
  const lines: string[] = [];
  const mods = extractModInventory(report);

  // 1. Report Overview
  lines.push('# Minecraft Screenshare Forensic Investigation Report');
  lines.push('');
  lines.push('## 1. Report Overview');
  lines.push(`- **Report ID**: \`${report.publicId}\``);
  lines.push(`- **Scan Mode**: \`${report.scanMode}\``);
  lines.push(`- **Scanner Version**: \`${report.scannerVersion}\` (Schema: \`${report.schemaVersion}\`)`);
  lines.push(`- **Operating System**: \`${report.osName} ${report.osVersion} (${report.osArchitecture})\``);
  lines.push(`- **Scan Started**: \`${report.scanStartedAt || report.uploadedAt}\``);
  lines.push(`- **Scan Completed**: \`${report.scanCompletedAt || report.uploadedAt}\``);
  lines.push(`- **Export Generated**: \`${new Date().toISOString()}\``);
  lines.push(`- **Active Server Gamemode Ruleset**: \`${report.appliedGamemode || 'Standard PvP'}\``);
  if (report.appliedPolicyName) {
    lines.push(`- **Applied Policy Rulebook**: \`${report.appliedPolicyName}\` (v\`${report.appliedPolicyVersion || '1.0'}\`)`);
  }
  if (report.appliedPolicyRulesUrl) {
    lines.push(`- **Server Rules Documentation**: ${report.appliedPolicyRulesUrl}`);
  }
  lines.push(`- **Detected Minecraft Versions**: ${formatList(report.detectedMinecraftVersions)}`);
  lines.push(`- **Detected Mod Loaders & Clients**: ${formatList(report.detectedLoaders)}`);
  lines.push(`- **Player Scope Consent Given**: \`${report.consent?.consentGiven ? 'YES (Explicit Consent Confirmed)' : 'NO'}\``);
  lines.push('');

  // 2. Scan Completeness & Limitations
  lines.push('## 2. Scan Completeness and Limitations');
  if (report.coverage) {
    lines.push(`- **Total Diagnostic Checks**: \`${report.coverage.totalChecks}\``);
    lines.push(`- **Passed Checks**: \`${report.coverage.passedChecks}\``);
    lines.push(`- **Flagged Checks**: \`${report.coverage.flaggedChecks}\``);
    lines.push(`- **Unavailable / Inaccessible Checks**: \`${report.coverage.unavailableChecks}\``);
  }
  lines.push('');
  lines.push('> **Forensic Boundary Notice:** This scanner operates exclusively in standard Windows user mode without kernel drivers or elevation. Deep system artifacts (such as Prefetch or raw NTFS USN journals) may report access denial on non-admin accounts. The presence of unavailable checks represents a boundary limitation, not proof of evasion or tampering.');
  lines.push('');

  // 3. AI Analysis Guide
  lines.push('## 3. AI Analysis Guide');
  lines.push('');
  lines.push('> **Instructions for AI Forensic Reviewer:**');
  lines.push('> You are reviewing a Minecraft screenshare forensic report. Analyze only the evidence contained in this report unless external research is explicitly requested.');
  lines.push('>');
  lines.push('> Separate:');
  lines.push('> - Directly observed facts.');
  lines.push('> - Verified artifact identity.');
  lines.push('> - Server-policy violations.');
  lines.push('> - Correlations between independent findings.');
  lines.push('> - Inferences.');
  lines.push('> - Unknowns and unavailable evidence.');
  lines.push('>');
  lines.push('> Do not assume that an unknown mod is malicious, that a renamed mod is a cheat, or that a hash mismatch proves malicious intent.');
  lines.push('>');
  lines.push('> Do not treat a file existing on disk as proof that it executed. Distinguish historical presence, current presence, process association, module loading, and evidence of actual behavior.');
  lines.push('>');
  lines.push('> Identify findings that deserve further investigation, explain possible false positives, and suggest concrete additional checks.');
  lines.push('>');
  lines.push('> Identify contradictions and gaps in the available evidence.');
  lines.push('>');
  lines.push('> Provide a concise executive summary, a prioritized list of findings, confidence explanations, and unanswered questions.');
  lines.push('>');
  lines.push('> Do not invent evidence or claim certainty beyond what the report supports.');
  lines.push('');

  // 4. Key Findings
  lines.push('## 4. Key Findings');
  lines.push('');
  if (report.findings.length === 0) {
    lines.push('No suspicious indicators or policy violations were flagged within the inspected scope.');
    lines.push('');
  } else {
    report.findings.forEach((f, idx) => {
      lines.push(`### Finding ${idx + 1}: [${f.severity.toUpperCase()}] ${f.title}`);
      lines.push(`- **Rule ID**: \`${f.ruleId}\` (Version: \`${f.detectionRuleVersion || '1.0'}\`)`);
      lines.push(`- **Category**: \`${f.category}\``);
      lines.push(`- **Confidence**: \`${f.confidence}\``);
      lines.push(`- **Evidence Source**: \`${f.evidenceSource}\``);
      lines.push('');
      lines.push('**What was observed:**');
      lines.push(`${f.explanation}`);
      lines.push('');
      lines.push('**Supporting evidence:**');
      if (f.filePath) lines.push(`- File Path: \`${f.filePath}\``);
      if (f.fileSha256) lines.push(`- SHA-256 Digest: \`${f.fileSha256}\``);
      if (f.fileSizeBytes) {
        lines.push(`- File Size: \`${f.fileSizeBytes.toLocaleString()} bytes (${(f.fileSizeBytes / 1024).toFixed(1)} KB)\``);
      }
      if (f.processId) lines.push(`- Process: \`${f.processName || 'javaw.exe'}\` (PID: \`${f.processId}\`)`);
      if (f.processCommandLine) lines.push(`- Command Line: \`${redactCommandLine(f.processCommandLine)}\``);
      if (f.observedEvidence) {
        lines.push(`- Observed Payload: \`${JSON.stringify(f.observedEvidence)}\``);
      }
      lines.push('');
      lines.push('**Why it may matter:**');
      lines.push(getWhyItMatters(f));
      lines.push('');
      lines.push('**Alternative explanations & false positives:**');
      lines.push(f.limitationsAndFalsePositives ? `- ${f.limitationsAndFalsePositives}` : '- Software version differences or non-standard mod configuration.');
      lines.push('');
      lines.push('**What it does not prove:**');
      lines.push(getWhatItDoesNotProve(f));
      lines.push('');
      lines.push('**Additional checks that could clarify it:**');
      lines.push(getSuggestedNextChecks(f));
      lines.push('');
    });
  }

  // 5. Minecraft Installations & Environment Metadata
  lines.push('## 5. Minecraft Installations and Environment Metadata');
  lines.push('');
  const jvmEvidence = report.evidenceItems.find(e => e.type === 'JvmArguments');
  if (jvmEvidence && jvmEvidence.rawContent) {
    lines.push('### Parsed JVM Launch Arguments');
    lines.push('```');
    lines.push(redactCommandLine(jvmEvidence.rawContent));
    lines.push('```');
    lines.push('');
  }

  // 6. Complete Discovered Mod Inventory
  lines.push('## 6. Complete Discovered Mod Inventory');
  lines.push('');
  if (mods.length === 0) {
    lines.push('No mod JAR records were found or attached to this scan mode.');
    lines.push('');
  } else {
    lines.push('| Mod Name | File Name | Size (KB) | SHA-256 Digest | Mod ID | Version | Loader |');
    lines.push('| :--- | :--- | :--- | :--- | :--- | :--- | :--- |');
    mods.forEach(m => {
      const name = sanitizeMd(m.name || m.fileName || 'Unknown');
      const fileName = sanitizeMd(m.fileName || 'Unknown');
      const sizeBytes = m.fileSizeBytes ?? m.sizeBytes;
      const size = sizeBytes ? (sizeBytes / 1024).toFixed(1) : 'N/A';
      const sha256 = m.sha256 ? `\`${m.sha256.slice(0, 16)}...\`` : 'No Hash';
      const modId = sanitizeMd(m.modId || '-');
      const ver = sanitizeMd(m.version || '-');
      const loader = sanitizeMd(m.loader || '-');

      lines.push(`| **${name}** | \`${fileName}\` | ${size} | ${sha256} | \`${modId}\` | \`${ver}\` | \`${loader}\` |`);
    });
    lines.push('');
  }

  // 7. Artifact Authenticity Verification
  lines.push('## 7. Artifact Authenticity Verification');
  lines.push('');
  lines.push('> **Definition:** Artifact authenticity confirms whether a JAR byte-for-byte matches an official release published on Modrinth, CurseForge, or GitHub. Authenticity does NOT determine whether a mod is allowed under competitive server rules.');
  lines.push('');

  if (mods.length > 0) {
    lines.push('| Mod | File Name | Authenticity State | Provider | Project / Reference URL | Verification Notes |');
    lines.push('| :--- | :--- | :--- | :--- | :--- | :--- |');
    mods.forEach(m => {
      const name = sanitizeMd(m.name || m.fileName || 'Unknown');
      const fileName = sanitizeMd(m.fileName || 'Unknown');
      const state = m.verificationState || (m.verified ? 'VERIFIED_EXACT_RELEASE' : 'UNKNOWN_OR_UNLISTED');
      const provider = sanitizeMd(m.verificationProvider || 'None');
      const url = m.projectUrl ? `<${m.projectUrl}>` : '-';
      const notes = sanitizeMd(m.verificationExplanation || '-');

      lines.push(`| **${name}** | \`${fileName}\` | \`${state}\` | ${provider} | ${url} | ${notes} |`);
    });
    lines.push('');
  }

  // 8. Server Policy Compliance
  lines.push('## 8. Server Policy Compliance');
  lines.push('');
  lines.push(`- **Applied Gamemode**: \`${report.appliedGamemode || 'Standard PvP'}\``);
  lines.push(`- **Rulebook Version**: \`${report.appliedPolicyVersion || '1.0.0'}\``);
  lines.push('');
  lines.push('> **Core Principle:** Authenticity and gameplay policy are evaluated independently. An authentic release (e.g. Freecam) may be prohibited under competitive rules. An unlisted mod is not automatically a cheat.');
  lines.push('');

  if (mods.length > 0) {
    lines.push('| Mod Name | Gameplay Policy | Behavioral Domain | Policy Rationale | Restrictions / Conditions |');
    lines.push('| :--- | :--- | :--- | :--- | :--- |');
    mods.forEach(m => {
      const name = sanitizeMd(m.name || m.fileName || 'Unknown');
      const pol = m.gameplayPolicy || m.policy || 'UNKNOWN';
      const behavior = sanitizeMd(m.behaviorCategory || 'None');
      const reason = sanitizeMd(m.policyReason || 'Evaluated against active rulebook.');
      const conditions = sanitizeMd(m.restrictionConditions || '-');

      lines.push(`| **${name}** | \`${pol}\` | \`${behavior}\` | ${reason} | ${conditions} |`);
    });
    lines.push('');
  }

  // 9. Process & Runtime Module Findings
  lines.push('## 9. Process and Runtime Module Findings');
  lines.push('');
  const procFindings = report.findings.filter(f => f.category === 'ProcessInjection' || f.evidenceSource === 'ProcessMemoryMetadata');
  if (procFindings.length === 0) {
    lines.push('No unsigned temp-mapped DLL modules or unauthorized memory injections detected.');
    lines.push('');
  } else {
    procFindings.forEach(pf => {
      lines.push(`- **${pf.title}** (PID: \`${pf.processId || 'Unknown'}\`): ${pf.explanation}`);
    });
    lines.push('');
  }

  // 10. Log and Historical Evidence
  lines.push('## 10. Log and Historical Evidence');
  lines.push('');
  const histFindings = report.findings.filter(f => 
    f.category === 'ExecutionArtifacts' || 
    f.category === 'FileDeletion' || 
    f.evidenceSource === 'Prefetch' || 
    f.evidenceSource === 'BamDam' || 
    f.evidenceSource === 'UsnJournal'
  );
  if (histFindings.length === 0) {
    lines.push('No historical execution traces, deleted cheat artifacts, or suspicious session events found.');
    lines.push('');
  } else {
    histFindings.forEach(hf => {
      lines.push(`- **[${hf.severity}] ${hf.title}**: ${hf.explanation}`);
    });
    lines.push('');
  }

  // 11. Evidence Correlation and Timeline
  lines.push('## 11. Evidence Correlation and Timeline');
  lines.push('');
  if (report.timelineEvents.length === 0) {
    lines.push('No correlated timeline events recorded.');
    lines.push('');
  } else {
    lines.push('| Timestamp (UTC) | Category | Source | Event Description | Confidence |');
    lines.push('| :--- | :--- | :--- | :--- | :--- |');
    const sorted = [...report.timelineEvents].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    sorted.forEach(evt => {
      const time = new Date(evt.timestamp).toISOString().replace('T', ' ').slice(0, 19);
      const cat = sanitizeMd(evt.category);
      const src = sanitizeMd(evt.source);
      const desc = sanitizeMd(evt.description);
      const conf = evt.confidence;

      lines.push(`| \`${time}\` | \`${cat}\` | \`${src}\` | ${desc} | \`${conf}\` |`);
    });
    lines.push('');
  }

  // 12. Failed, Skipped, or Unavailable Checks
  lines.push('## 12. Failed, Skipped, or Unavailable Checks');
  lines.push('');
  if (report.diagnosticItems.length === 0) {
    lines.push('All scheduled diagnostic checks completed without errors or access restrictions.');
    lines.push('');
  } else {
    lines.push('| Check Name | Source | Status | Reason / Limitation | Staff Recommendation |');
    lines.push('| :--- | :--- | :--- | :--- | :--- |');
    report.diagnosticItems.forEach(diag => {
      const name = sanitizeMd(diag.checkName);
      const src = sanitizeMd(diag.source);
      const status = diag.status;
      const reason = sanitizeMd(diag.reason);
      const rec = sanitizeMd(diag.recommendation || '-');

      lines.push(`| **${name}** | \`${src}\` | \`${status}\` | ${reason} | ${rec} |`);
    });
    lines.push('');
  }

  // 13. Questions Requiring Further Investigation
  lines.push('## 13. Questions Requiring Further Investigation');
  lines.push('');
  const questions = generateInvestigationQuestions(report, mods);
  questions.forEach(q => {
    lines.push(`- ${q}`);
  });
  lines.push('');

  // 14. Full Structured Evidence Appendix
  lines.push('## 14. Full Structured Evidence Appendix');
  lines.push('');
  lines.push('| Evidence ID | Type | Title | Status | Captured (UTC) |');
  lines.push('| :--- | :--- | :--- | :--- | :--- |');
  report.evidenceItems.forEach(ev => {
    const id = ev.publicEvidenceId;
    const type = ev.type;
    const title = sanitizeMd(ev.title);
    const status = ev.isAvailable ? 'Available' : 'Unavailable';
    const time = ev.capturedAt ? new Date(ev.capturedAt).toISOString().replace('T', ' ').slice(0, 19) : '-';

    lines.push(`| \`${id}\` | \`${type}\` | ${title} | \`${status}\` | \`${time}\` |`);
  });
  lines.push('');
  lines.push('---');
  lines.push('*End of Forensic Report. Generated by Minecraft SS Forensics Web Dashboard.*');

  return lines.join('\n');
}

/**
 * Initiates a browser-triggered file download with the designated content and MIME type.
 */
export function downloadReportFile(report: ReportDetail, format: ReportExportFormat): void {
  if (!report) {
    throw new Error('No valid report data provided for download.');
  }

  const filename = generateSuggestedFilename(report, format);
  let content: string;
  let mimeType: string;

  if (format === 'md') {
    content = exportReportToMarkdown(report);
    mimeType = 'text/markdown;charset=utf-8';
  } else {
    content = exportReportToJson(report);
    mimeType = 'application/json;charset=utf-8';
  }

  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
