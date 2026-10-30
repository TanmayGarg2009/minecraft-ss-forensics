import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { SimpleOverviewCard } from '../components/ReportViewer/SimpleOverviewCard';
import { InteractiveFindingsList } from '../components/ReportViewer/InteractiveFindingsList';
import type { ReportDetail } from '../types/report';

const mockReportWithFindings: ReportDetail = {
  publicId: 'mc_experience_test_001',
  schemaVersion: '1.0.0',
  scannerVersion: '1.0.0-rc2',
  createdAt: new Date().toISOString(),
  uploadedAt: new Date().toISOString(),
  scanMode: 'FULL',
  osName: 'Windows 11 Pro',
  osVersion: '10.0.22631',
  osArchitecture: 'x64',
  detectedMinecraftVersions: ['1.20.4'],
  detectedLoaders: ['Fabric 0.15.7'],
  consent: {
    consentGiven: true,
    collectionScopeVersion: '1.0',
    consentTimestamp: new Date().toISOString()
  },
  processingStatus: 'Completed',
  expiresAt: new Date(Date.now() + 7 * 86400000).toISOString(),
  coverage: {
    totalChecks: 40,
    passedChecks: 38,
    flaggedChecks: 2,
    unavailableChecks: 0
  },
  severitySummary: {
    High: 1,
    Low: 1
  },
  findings: [
    {
      ruleId: 'MOD-LOOKALIKE-OPTIFINE',
      title: 'Lookalike Disguised as OptiFine',
      category: 'ModIntegrity',
      severity: 'High',
      confidence: 'High',
      explanation: 'Claims to be OptiFine in filename but has internal mod ID vape.',
      filePath: 'C:\\Users\\User\\.minecraft\\mods\\OptiFine_1.20.4.jar',
      fileSizeBytes: 204800,
      fileSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      evidenceSource: 'ModFolder',
      detectionRuleVersion: '1.0.0',
      limitationsAndFalsePositives: 'User might have renamed another utility mod.',
      observedEvidence: {
        ObservedValue: 'vape',
        ExpectedValue: 'optifine'
      }
    },
    {
      ruleId: 'MOD-DUPLICATE-ID',
      title: 'Duplicate Mod ID Across Separate JARs',
      category: 'ModIntegrity',
      severity: 'Low',
      confidence: 'Certain',
      explanation: 'Found two separate JAR files with mod ID sodium.',
      filePath: 'C:\\Users\\User\\.minecraft\\mods\\sodium-old.jar',
      fileSizeBytes: 512000,
      evidenceSource: 'ModFolder',
      detectionRuleVersion: '1.0.0',
      limitationsAndFalsePositives: 'Often occurs when upgrading mod versions without deleting old JAR.'
    }
  ],
  evidenceItems: [
    {
      publicEvidenceId: 'evi_mod_inventory_01',
      type: 'ModInventory',
      title: 'Mod Inventory',
      description: 'Inventory of mods',
      isAvailable: true,
      capturedAt: new Date().toISOString(),
      hasRawContent: false,
      structuredPayload: [
        {
          name: 'Sodium',
          fileName: 'sodium-fabric-0.5.8.jar',
          sizeBytes: 512000,
          sha256: 'a1b2c3d4e5f6',
          verified: true,
          verificationState: 'VERIFIED_EXACT_RELEASE'
        },
        {
          name: 'Fake OptiFine',
          fileName: 'OptiFine_1.20.4.jar',
          sizeBytes: 204800,
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          verified: false,
          verificationState: 'KNOWN_PROJECT_UNVERIFIED_ARTIFACT'
        }
      ]
    }
  ],
  timelineEvents: [],
  diagnosticItems: [],
  privacyNotice: 'Public link'
};

describe('Redesigned Report Experience', () => {
  it('renders simple overview with the 7 key metrics', () => {
    const handleJump = vi.fn();
    render(
      <SimpleOverviewCard
        report={mockReportWithFindings}
        onOpenDeleteModal={vi.fn()}
        onExportJson={vi.fn()}
        onJumpToFindings={handleJump}
      />
    );

    // Scan status
    expect(screen.getByText('SUSPICIOUS INDICATORS FOUND')).toBeInTheDocument();
    expect(screen.getByText('Scan Completed Successfully')).toBeInTheDocument();

    // 7 Metrics
    expect(screen.getByText('Findings to Review')).toBeInTheDocument();
    expect(screen.getByText('Verified Mods')).toBeInTheDocument();
    expect(screen.getByText('Unverified / Modified')).toBeInTheDocument();
    expect(screen.getByText('Duplicate Files')).toBeInTheDocument();
    expect(screen.getByText('Limited / Inaccessible')).toBeInTheDocument();
    expect(screen.getByText('Game Client')).toBeInTheDocument();

    // Metric counts
    expect(screen.getByText('2')).toBeInTheDocument(); // 2 findings
    expect(screen.getAllByText('1').length).toBeGreaterThanOrEqual(1); // verified mods, unverified, etc.

    // Clicking findings counter triggers jump
    const jumpButton = screen.getByText('Findings to Review').closest('button');
    expect(jumpButton).not.toBeNull();
    fireEvent.click(jumpButton!);
    expect(handleJump).toHaveBeenCalledTimes(1);
  });

  it('renders interactive findings list with plain language and expandable evidence', () => {
    render(<InteractiveFindingsList report={mockReportWithFindings} initialExpandedRuleId="MOD-LOOKALIKE-OPTIFINE" />);

    // Plain language titles
    expect(screen.getByText('Mod Identity Mismatch (Lookalike)')).toBeInTheDocument();
    expect(screen.getByText('Duplicate JAR File')).toBeInTheDocument();

    // Plain language explanations
    expect(screen.getByText(/This file uses a trusted name on the outside, but contains a different mod identity on the inside/i)).toBeInTheDocument();

    // Expandable details: check that evidence drawer is expanded and displays all required sections
    expect(screen.getAllByText(/What Was Observed/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/Why This Matters to Staff/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/What This Evidence Does NOT Establish/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/Possible Legitimate Explanations/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/Supporting Evidence Record/i).length).toBeGreaterThanOrEqual(1);

    // Technical evidence is accessible inside details
    expect(screen.getByText('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBeInTheDocument();
  });

  it('filters interactive findings list by search query and category', () => {
    render(<InteractiveFindingsList report={mockReportWithFindings} />);

    const searchInput = screen.getByPlaceholderText(/Search findings by rule ID/i);
    fireEvent.change(searchInput, { target: { value: 'duplicate' } });

    expect(screen.getByText('Duplicate JAR File')).toBeInTheDocument();
    expect(screen.queryByText('Mod Identity Mismatch (Lookalike)')).not.toBeInTheDocument();
  });
});
