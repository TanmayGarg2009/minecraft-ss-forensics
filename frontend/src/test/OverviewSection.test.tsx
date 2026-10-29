import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { OverviewSection } from '../components/ReportViewer/OverviewSection';
import type { ReportDetail } from '../types/report';

const mockReport: ReportDetail = {
  publicId: 'mc_test1234567890abcdef',
  schemaVersion: '1.0.0',
  scannerVersion: '1.0.0-test',
  createdAt: new Date().toISOString(),
  uploadedAt: new Date().toISOString(),
  scanMode: 'FULL',
  osName: 'Windows 11 Pro',
  osVersion: '10.0.22631',
  osArchitecture: 'x64',
  detectedMinecraftVersions: ['1.8.9'],
  detectedLoaders: ['Forge 11.15.1'],
  consent: {
    consentGiven: true,
    collectionScopeVersion: '1.0',
    consentTimestamp: new Date().toISOString()
  },
  processingStatus: 'Completed',
  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  coverage: {
    totalChecks: 40,
    passedChecks: 38,
    flaggedChecks: 2,
    unavailableChecks: 0
  },
  severitySummary: {
    High: 1,
    Medium: 1
  },
  findings: [
    {
      ruleId: 'TEST-01',
      title: 'Finding 1',
      category: 'Other',
      severity: 'High',
      confidence: 'High',
      explanation: 'Explanation',
      evidenceSource: 'Prefetch',
      detectionRuleVersion: '1.0',
      limitationsAndFalsePositives: 'None'
    }
  ],
  evidenceItems: [],
  timelineEvents: [],
  diagnosticItems: [],
  privacyNotice: 'Bearer link notice'
};

describe('OverviewSection Component', () => {
  it('renders report metadata, OS, scan mode, and privacy notice', () => {
    render(
      <OverviewSection
        report={mockReport}
        onOpenDeleteModal={vi.fn()}
        onExportJson={vi.fn()}
      />
    );

    expect(screen.getByText('FULL SCAN')).toBeInTheDocument();
    expect(screen.getByText(/Windows 11 Pro/i)).toBeInTheDocument();
    expect(screen.getByText(/Bearer-Link Access Model & Privacy Notice/i)).toBeInTheDocument();
  });

  it('renders clean report without misleading "guaranteed clean" claim', () => {
    const cleanReport = {
      ...mockReport,
      findings: [],
      severitySummary: {}
    };

    render(
      <OverviewSection
        report={cleanReport}
        onOpenDeleteModal={vi.fn()}
        onExportJson={vi.fn()}
      />
    );

    expect(screen.getByText(/No forensic indicators flagged across scanned artifacts/i)).toBeInTheDocument();
    expect(screen.getByText(/does not constitute a guaranteed clean badge/i)).toBeInTheDocument();
  });
});
