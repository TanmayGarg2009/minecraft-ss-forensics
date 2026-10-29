import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { VerdictCard } from '../components/ReportViewer/VerdictCard';
import type { ReportDetail } from '../types/report';

describe('VerdictCard Component', () => {
  const mockReport: ReportDetail = {
    publicId: 'mc_card_test_999',
    schemaVersion: '1.0.0',
    scannerVersion: '1.0.0-rc1',
    createdAt: new Date().toISOString(),
    uploadedAt: new Date().toISOString(),
    scanMode: 'FULL',
    osName: 'Windows 11 Pro',
    osVersion: '10.0.22631',
    osArchitecture: 'X64',
    detectedMinecraftVersions: ['1.8.9'],
    detectedLoaders: ['Forge 11.15.1.2318'],
    consent: {
      consentGiven: true,
      collectionScopeVersion: '1.0.0',
      consentTimestamp: new Date().toISOString(),
    },
    processingStatus: 'Completed',
    expiresAt: new Date(Date.now() + 86400000 * 14).toISOString(),
    privacyNotice: 'Public link',
    severitySummary: { High: 1, Medium: 1 },
    coverage: {
      totalChecks: 38,
      passedChecks: 36,
      flaggedChecks: 2,
      unavailableChecks: 2,
    },
    findings: [
      {
        ruleId: 'MC-DEL-001',
        title: 'Deleted Mod in Temp',
        category: 'FileDeletion',
        severity: 'High',
        confidence: 'High',
        explanation: 'File recorded in NTFS USN journal before scan.',
        evidenceSource: 'UsnJournal',
        detectionRuleVersion: '1.0.0',
        limitationsAndFalsePositives: 'Cannot prove file was loaded.',
        filePath: 'C:\\Users\\User\\AppData\\Local\\Temp\\autoclicker.jar',
      },
      {
        ruleId: 'MC-HIST-002',
        title: 'Historical Autoclicker Execution',
        category: 'ExecutionArtifacts',
        severity: 'Medium',
        confidence: 'Medium',
        explanation: 'Observed in Windows Prefetch.',
        evidenceSource: 'Prefetch',
        detectionRuleVersion: '1.0.0',
        limitationsAndFalsePositives: 'Historical execution only.',
      },
    ],
    evidenceItems: [],
    timelineEvents: [
      {
        timestamp: new Date().toISOString(),
        description: 'autoclicker.jar removed from disk',
        category: 'FileDeletion',
        source: 'UsnJournal',
        confidence: 'High',
        isInferred: false,
      },
    ],
    diagnosticItems: [
      {
        checkName: 'NTFS Change Journal Audit',
        source: 'UsnJournal',
        status: 'Completed',
        reason: 'Successfully audited changes.',
      },
    ],
  };

  it('renders overall verdict status and 6 evidence counters', () => {
    render(<VerdictCard report={mockReport} />);

    expect(screen.getByText(/SUSPICIOUS INDICATORS FOUND/i)).toBeInTheDocument();
    expect(screen.getByText(/High-Conf/i)).toBeInTheDocument();
    expect(screen.getByText(/Other Indicators/i)).toBeInTheDocument();
    expect(screen.getByText(/Historical Artifacts/i)).toBeInTheDocument();
    expect(screen.getByText(/Deleted File Traces/i)).toBeInTheDocument();
    expect(screen.getByText(/Completed Checks/i)).toBeInTheDocument();
    expect(screen.getByText(/Unavailable \/ Skipped/i)).toBeInTheDocument();
  });

  it('renders top investigation highlights and handles inspect click', () => {
    const handleSelectFinding = vi.fn();
    render(<VerdictCard report={mockReport} onSelectFinding={handleSelectFinding} />);

    expect(screen.getByText(/Deleted Mod in Temp/i)).toBeInTheDocument();
    const inspectButtons = screen.getAllByRole('button', { name: /Inspect/i });
    expect(inspectButtons.length).toBeGreaterThanOrEqual(1);

    fireEvent.click(inspectButtons[0]);
    expect(handleSelectFinding).toHaveBeenCalledWith('MC-DEL-001');
  });

  it('toggles evidence distinctions accordion on click', () => {
    render(<VerdictCard report={mockReport} />);

    const toggleButton = screen.getByRole('button', { name: /Evidence Classification & Distinctions/i });
    expect(toggleButton).toBeInTheDocument();

    // Click to expand
    fireEvent.click(toggleButton);
    expect(screen.getByText(/Confirmed Observations/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Suspicious Indicators/i).length).toBeGreaterThanOrEqual(1);
  });
});
