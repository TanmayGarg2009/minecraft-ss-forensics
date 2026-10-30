import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import type { ReportDetail } from '../types/report';
import { 
  exportReportToJson, 
  exportReportToMarkdown, 
  generateSuggestedFilename, 
  downloadReportFile,
  redactCommandLine
} from '../utils/reportExporter';
import { ExportModal } from '../components/ReportViewer/ExportModal';

const sampleReport: ReportDetail = {
  publicId: 'rep_vitest_exp123',
  schemaVersion: '1.0.0',
  scannerVersion: '1.0.0',
  createdAt: '2026-10-30T10:00:00Z',
  uploadedAt: '2026-10-30T10:01:00Z',
  scanStartedAt: '2026-10-30T10:00:10Z',
  scanCompletedAt: '2026-10-30T10:00:55Z',
  scanMode: 'FULL',
  osName: 'Microsoft Windows 11 Pro',
  osVersion: '10.0.22631',
  osArchitecture: 'X64',
  detectedMinecraftVersions: ['1.20.4'],
  detectedLoaders: ['Fabric 0.15.7'],
  appliedPolicyName: 'Crystal PvP Standard',
  appliedPolicyVersion: '1.0.0',
  appliedGamemode: 'Crystal PvP',
  appliedPolicyRulesUrl: 'https://rules.example.com/crystal',
  consent: {
    consentGiven: true,
    collectionScopeVersion: '1.0',
    consentTimestamp: '2026-10-30T10:00:05Z',
  },
  processingStatus: 'Completed',
  expiresAt: '2026-11-13T10:01:00Z',
  coverage: {
    totalChecks: 12,
    passedChecks: 10,
    flaggedChecks: 1,
    unavailableChecks: 1,
  },
  severitySummary: {
    High: 1,
    Low: 0,
    Medium: 0,
    Critical: 0,
  },
  findings: [
    {
      ruleId: 'MOD-POLICY-PROHIBITED',
      title: 'Prohibited Advantage Mod Detected: Freecam',
      category: 'ModIntegrity',
      severity: 'High',
      confidence: 'Certain',
      explanation: 'Discovered freecam-fabric-1.20.4.jar which provides camera decoupling.',
      filePath: 'C:\\Users\\Player\\.minecraft\\mods\\freecam-fabric-1.20.4.jar',
      fileSizeBytes: 128450,
      fileSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      processId: 1234,
      processName: 'javaw.exe',
      processCommandLine: 'javaw.exe -Xmx4G --accessToken secret_token_abc --uuid player-uuid-12345678 net.fabricmc.loader.launch.knot.KnotClient',
      evidenceSource: 'ModFolder',
      detectionRuleVersion: '1.0.0',
      limitationsAndFalsePositives: 'Player may use this profile for building.',
    },
  ],
  evidenceItems: [
    {
      publicEvidenceId: 'evi_mod_01',
      type: 'ModInventory',
      title: 'Discovered Mod Inventory',
      description: 'Active mod files',
      isAvailable: true,
      hasRawContent: false,
      capturedAt: '2026-10-30T10:00:20Z',
      structuredPayload: [
        {
          name: 'Freecam',
          fileName: 'freecam-fabric-1.20.4.jar',
          fileSizeBytes: 128450,
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          modId: 'freecam',
          version: '0.4.2',
          loader: 'fabric',
          verified: true,
          verificationState: 'VERIFIED_EXACT_RELEASE',
          verificationProvider: 'Modrinth',
          projectUrl: 'https://modrinth.com/mod/freecam',
          gameplayPolicy: 'PROHIBITED',
          behaviorCategory: 'PerspectiveExploit',
          policyReason: 'Disallowed in Crystal PvP.',
        },
        {
          name: 'Sodium',
          fileName: 'sodium-fabric-0.5.8.jar',
          fileSizeBytes: 850000,
          sha256: '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff',
          modId: 'sodium',
          version: '0.5.8',
          loader: 'fabric',
          verified: true,
          verificationState: 'VERIFIED_EXACT_RELEASE',
          verificationProvider: 'Modrinth',
          projectUrl: 'https://modrinth.com/mod/sodium',
          gameplayPolicy: 'ALLOWED',
          behaviorCategory: 'PerformanceOptimization',
          policyReason: 'Standard optimization.',
        },
      ],
    },
    {
      publicEvidenceId: 'evi_jvm_01',
      type: 'JvmArguments',
      title: 'JVM Arguments',
      description: 'Active JVM parameters',
      isAvailable: true,
      hasRawContent: true,
      capturedAt: '2026-10-30T10:00:22Z',
      rawContent: '-Xmx4096M -XX:+UseG1GC --accessToken secret_token_xyz --session session_secret_abc',
    },
  ],
  timelineEvents: [
    {
      timestamp: '2026-10-30T09:30:00Z',
      isInferred: false,
      category: 'ProcessExecution',
      source: 'Prefetch',
      description: 'javaw.exe executed from launcher directory.',
      confidence: 'Certain',
    },
  ],
  diagnosticItems: [
    {
      checkName: 'Raw NTFS USN Journal Parser',
      source: 'UsnJournal',
      status: 'AccessDenied',
      reason: 'Direct volume handle read access denied under standard user privileges.',
      recommendation: 'Check Windows event logs or recycle bin.',
    },
  ],
  privacyNotice: 'Scoped Minecraft screenshare forensic collection under explicit player consent.',
};

describe('reportExporter utility', () => {
  it('redactCommandLine scrubs sensitive arguments', () => {
    const raw = 'javaw.exe -Xmx4G --accessToken secret_token_123 --session session_secret_456 --uuid uuid-789 -Dauth.token=auth_sec';
    const redacted = redactCommandLine(raw);

    expect(redacted).not.toContain('secret_token_123');
    expect(redacted).not.toContain('session_secret_456');
    expect(redacted).not.toContain('uuid-789');
    expect(redacted).not.toContain('auth_sec');
    expect(redacted).toContain('--accessToken [REDACTED]');
    expect(redacted).toContain('--session [REDACTED]');
    expect(redacted).toContain('--uuid [REDACTED]');
  });

  it('exportReportToJson generates valid JSON with metadata and redacted secrets', () => {
    const jsonStr = exportReportToJson(sampleReport);
    expect(jsonStr).toBeTruthy();

    const parsed = JSON.parse(jsonStr);
    expect(parsed.exportMetadata).toBeDefined();
    expect(parsed.exportMetadata.exportSchemaVersion).toBe('1.0.0');
    expect(parsed.exportMetadata.reportId).toBe('rep_vitest_exp123');
    expect(parsed.report.publicId).toBe('rep_vitest_exp123');
    expect(parsed.report.appliedGamemode).toBe('Crystal PvP');

    // Secrets redacted
    expect(jsonStr).not.toContain('secret_token_abc');
    expect(jsonStr).not.toContain('secret_token_xyz');
    expect(jsonStr).not.toContain('session_secret_abc');
    expect(jsonStr).toContain('[REDACTED]');
  });

  it('exportReportToMarkdown generates all thirteen sections and verbatim AI guide', () => {
    const md = exportReportToMarkdown(sampleReport);
    expect(md).toBeTruthy();

    // 1. Overview
    expect(md).toContain('# Minecraft Screenshare Forensic Investigation Report');
    expect(md).toContain('## 1. Report Overview');
    expect(md).toContain('`rep_vitest_exp123`');
    expect(md).toContain('Crystal PvP');

    // 2. Scan Completeness
    expect(md).toContain('## 2. Scan Completeness and Limitations');
    expect(md).toContain('Forensic Boundary Notice');

    // 3. AI Analysis Guide
    expect(md).toContain('## 3. AI Analysis Guide');
    expect(md).toContain('Instructions for AI Forensic Reviewer:');
    expect(md).toContain('Directly observed facts.');
    expect(md).toContain('Verified artifact identity.');
    expect(md).toContain('Server-policy violations.');
    expect(md).toContain('Do not assume that an unknown mod is malicious');
    expect(md).toContain('Do not treat a file existing on disk as proof that it executed');

    // 4. Key Findings
    expect(md).toContain('## 4. Key Findings');
    expect(md).toContain('Prohibited Advantage Mod Detected: Freecam');
    expect(md).toContain('**What was observed:**');
    expect(md).toContain('**Supporting evidence:**');
    expect(md).toContain('**Why it may matter:**');
    expect(md).toContain('**Alternative explanations & false positives:**');
    expect(md).toContain('**What it does not prove:**');
    expect(md).toContain('**Additional checks that could clarify it:**');

    // 5. Minecraft Installations & JVM
    expect(md).toContain('## 5. Minecraft Installations and Environment Metadata');
    expect(md).toContain('### Parsed JVM Launch Arguments');

    // 6. Complete Mod Inventory
    expect(md).toContain('## 6. Complete Discovered Mod Inventory');
    expect(md).toContain('freecam-fabric-1.20.4.jar');
    expect(md).toContain('sodium-fabric-0.5.8.jar');

    // 7. Artifact Authenticity Verification
    expect(md).toContain('## 7. Artifact Authenticity Verification');
    expect(md).toContain('VERIFIED_EXACT_RELEASE');

    // 8. Server Policy Compliance
    expect(md).toContain('## 8. Server Policy Compliance');
    expect(md).toContain('PROHIBITED');
    expect(md).toContain('ALLOWED');

    // 9. Process & Runtime
    expect(md).toContain('## 9. Process and Runtime Module Findings');

    // 10. Historical Evidence
    expect(md).toContain('## 10. Log and Historical Evidence');

    // 11. Timeline
    expect(md).toContain('## 11. Evidence Correlation and Timeline');
    expect(md).toContain('Prefetch');

    // 12. Diagnostics
    expect(md).toContain('## 12. Failed, Skipped, or Unavailable Checks');
    expect(md).toContain('Raw NTFS USN Journal Parser');
    expect(md).toContain('AccessDenied');

    // 13. Questions
    expect(md).toContain('## 13. Questions Requiring Further Investigation');
    expect(md).toContain('Prohibited Mods:');

    // 14. Appendix
    expect(md).toContain('## 14. Full Structured Evidence Appendix');
    expect(md).toContain('evi_mod_01');
  });

  it('generateSuggestedFilename formats file name with date and report ID', () => {
    const jsonFilename = generateSuggestedFilename(sampleReport, 'json');
    const mdFilename = generateSuggestedFilename(sampleReport, 'md');

    expect(jsonFilename).toBe('MinecraftForensicReport_2026-10-30_rep_vitest_exp123.json');
    expect(mdFilename).toBe('MinecraftForensicReport_2026-10-30_rep_vitest_exp123.md');
  });

  it('downloadReportFile creates download anchor and clicks it', () => {
    const createObjectURLMock = vi.fn().mockReturnValue('blob:mock-url');
    const revokeObjectURLMock = vi.fn();
    globalThis.URL.createObjectURL = createObjectURLMock;
    globalThis.URL.revokeObjectURL = revokeObjectURLMock;

    const appendChildSpy = vi.spyOn(document.body, 'appendChild');
    const removeChildSpy = vi.spyOn(document.body, 'removeChild');

    downloadReportFile(sampleReport, 'json');

    expect(createObjectURLMock).toHaveBeenCalled();
    expect(appendChildSpy).toHaveBeenCalled();
    expect(removeChildSpy).toHaveBeenCalled();
    expect(revokeObjectURLMock).toHaveBeenCalledWith('blob:mock-url');
  });
});

describe('ExportModal component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders modal with download buttons and preview tabs', () => {
    render(<ExportModal report={sampleReport} isOpen={true} onClose={() => {}} />);

    expect(screen.getByText('Download Forensic Report')).toBeDefined();
    expect(screen.getByText('Full Forensic JSON (.json)')).toBeDefined();
    expect(screen.getByText('AI-Friendly Report (.md)')).toBeDefined();
    expect(screen.getByText('JSON Preview')).toBeDefined();
    expect(screen.getByText('Markdown Preview')).toBeDefined();
  });

  it('switches between JSON and Markdown previews', () => {
    render(<ExportModal report={sampleReport} isOpen={true} onClose={() => {}} />);

    // Click Markdown tab
    const mdTab = screen.getByText('Markdown Preview');
    fireEvent.click(mdTab);

    expect(screen.getByText(/## 3\. AI Analysis Guide/)).toBeDefined();

    // Click JSON tab
    const jsonTab = screen.getByText('JSON Preview');
    fireEvent.click(jsonTab);

    expect(screen.getByText(/"exportSchemaVersion": "1\.0\.0"/)).toBeDefined();
  });

  it('triggers download when download buttons are clicked', () => {
    const createObjectURLMock = vi.fn().mockReturnValue('blob:mock-url');
    const revokeObjectURLMock = vi.fn();
    globalThis.URL.createObjectURL = createObjectURLMock;
    globalThis.URL.revokeObjectURL = revokeObjectURLMock;

    render(<ExportModal report={sampleReport} isOpen={true} onClose={() => {}} />);

    const jsonBtn = screen.getByText('Full Forensic JSON (.json)');
    fireEvent.click(jsonBtn);

    expect(createObjectURLMock).toHaveBeenCalled();

    const mdBtn = screen.getByText('AI-Friendly Report (.md)');
    fireEvent.click(mdBtn);

    expect(createObjectURLMock).toHaveBeenCalledTimes(2);
  });
});
