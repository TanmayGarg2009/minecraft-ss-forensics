import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MinecraftEnvSection } from '../components/ReportViewer/MinecraftEnvSection';
import type { ReportDetail } from '../types/report';

const mockReportWithPolicies: ReportDetail = {
  publicId: 'rep_policy_test_123',
  schemaVersion: '1.0.0',
  scannerVersion: '1.0.0-rc2',
  createdAt: '2026-10-30T10:00:00Z',
  uploadedAt: '2026-10-30T10:05:00Z',
  scanMode: 'QUICK',
  osName: 'Windows 11 Pro',
  osVersion: '10.0.22631',
  osArchitecture: 'x64',
  detectedMinecraftVersions: ['1.20.4'],
  detectedLoaders: ['Fabric 0.15.7'],
  appliedPolicyName: 'Crystal PvP Standard Competition Policy',
  appliedPolicyVersion: '1.2.0',
  appliedGamemode: 'Crystal PvP',
  appliedPolicyRulesUrl: 'https://rules.example-pvp.net/crystal-pvp',
  consent: {
    consentGiven: true,
    collectionScopeVersion: '1.0',
    consentTimestamp: '2026-10-30T10:00:00Z'
  },
  processingStatus: 'Completed',
  expiresAt: '2026-11-06T10:00:00Z',
  coverage: {
    totalChecks: 15,
    passedChecks: 13,
    flaggedChecks: 2,
    unavailableChecks: 0
  },
  severitySummary: {
    High: 1,
    Low: 0
  },
  findings: [
    {
      ruleId: 'POLICY-PROHIBITED-MOD',
      title: 'Prohibited Mod Under Crystal PvP Rules: freecam-0.2.1.jar',
      category: 'ModIntegrity',
      severity: 'High',
      confidence: 'Certain',
      explanation: 'Verified as an authentic official release of Freecam, but is expressly PROHIBITED under Crystal PvP rules due to out-of-body perspective advantages.',
      evidenceSource: 'ModFolder',
      detectionRuleVersion: '1.2.0',
      limitationsAndFalsePositives: 'Unmodified official release; prohibited by competitive policy.'
    }
  ],
  evidenceItems: [
    {
      publicEvidenceId: 'evi_mod_inventory_01',
      type: 'ModInventory',
      title: 'Discovered Mod Inventory & Cryptographic Hashes',
      description: 'Inventory of 3 inspected mods',
      capturedAt: '2026-10-30T10:00:00Z',
      isAvailable: true,
      hasRawContent: false,
      structuredPayload: [
        {
          name: 'Sodium',
          fileName: 'sodium-fabric-0.5.8.jar',
          sizeBytes: 512000,
          sha256: 'a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890',
          modId: 'sodium',
          version: '0.5.8',
          loader: 'Fabric',
          verified: true,
          verificationState: 'VERIFIED_EXACT_RELEASE',
          gameplayPolicy: 'ALLOWED',
          behaviorCategory: 'ClientOptimization',
          policyReason: 'Standard open-source client rendering optimization.'
        },
        {
          name: 'Freecam',
          fileName: 'freecam-fabric-0.2.1.jar',
          sizeBytes: 128000,
          sha256: 'f1e2d3c4b5a67890f1e2d3c4b5a67890f1e2d3c4b5a67890f1e2d3c4b5a67890',
          modId: 'freecam',
          version: '0.2.1',
          loader: 'Fabric',
          verified: true,
          verificationState: 'VERIFIED_EXACT_RELEASE',
          gameplayPolicy: 'PROHIBITED',
          behaviorCategory: 'HiddenInformationAdvantages',
          policyReason: 'Out-of-body camera perspective enables looking through obsidian blocks without line of sight.'
        },
        {
          name: 'Clan Custom HUD',
          fileName: 'clan-hud-v1.jar',
          sizeBytes: 45000,
          sha256: '9988776655443322110099887766554433221100998877665544332211009988',
          modId: 'clanhud',
          version: '1.0',
          loader: 'Fabric',
          verified: false,
          verificationState: 'UNKNOWN_OR_UNLISTED',
          gameplayPolicy: 'NEEDS_REVIEW',
          behaviorCategory: 'CosmeticOrHud',
          policyReason: 'Unregistered mod in competitive Crystal PvP. Staff review required to verify absence of macro automation.'
        }
      ]
    }
  ],
  timelineEvents: [],
  diagnosticItems: [],
  privacyNotice: 'Test privacy notice'
};

describe('Mod Policy Engine Frontend Display', () => {
  it('renders active policy banner and both independent badge columns', () => {
    render(<MinecraftEnvSection report={mockReportWithPolicies} />);

    // 1. Policy banner
    expect(screen.getByText(/Active Policy: Crystal PvP/i)).toBeInTheDocument();
    expect(screen.getByText(/Crystal PvP Standard Competition Policy/i)).toBeInTheDocument();

    // 2. Table column headers
    expect(screen.getByText('Artifact Authenticity')).toBeInTheDocument();
    expect(screen.getByText('Gameplay Policy')).toBeInTheDocument();

    // 3. Independent classification for Freecam:
    // It is BOTH "Verified Release" (authenticity) AND "PROHIBITED" (policy)!
    expect(screen.getAllByText('Verified Release')).toHaveLength(2); // Sodium + Freecam
    expect(screen.getByText('PROHIBITED')).toBeInTheDocument(); // Freecam
    expect(screen.getByText('ALLOWED')).toBeInTheDocument(); // Sodium
    expect(screen.getByText('NEEDS REVIEW')).toBeInTheDocument(); // Clan HUD
  });

  it('displays policy reasoning and behavioral category', () => {
    render(<MinecraftEnvSection report={mockReportWithPolicies} />);

    expect(screen.getByText(/HiddenInformationAdvantages/i)).toBeInTheDocument();
    expect(screen.getByText(/looking through obsidian blocks/i)).toBeInTheDocument();
    expect(screen.getByText(/ClientOptimization/i)).toBeInTheDocument();
  });

  it('filters table rows by policy status', () => {
    render(<MinecraftEnvSection report={mockReportWithPolicies} />);

    // Initially all 3 mods are displayed
    expect(screen.getByText('Sodium')).toBeInTheDocument();
    expect(screen.getByText('Freecam')).toBeInTheDocument();
    expect(screen.getByText('Clan Custom HUD')).toBeInTheDocument();

    // Filter to Prohibited only
    const prohibitedFilterBtn = screen.getByRole('button', { name: /^Prohibited$/i });
    fireEvent.click(prohibitedFilterBtn);

    expect(screen.queryByText('Sodium')).not.toBeInTheDocument();
    expect(screen.getByText('Freecam')).toBeInTheDocument();
    expect(screen.queryByText('Clan Custom HUD')).not.toBeInTheDocument();

    // Filter to Allowed only
    const allowedFilterBtn = screen.getByRole('button', { name: /^Allowed$/i });
    fireEvent.click(allowedFilterBtn);

    expect(screen.getByText('Sodium')).toBeInTheDocument();
    expect(screen.queryByText('Freecam')).not.toBeInTheDocument();
    expect(screen.queryByText('Clan Custom HUD')).not.toBeInTheDocument();
  });
});
