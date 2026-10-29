import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { DeletedFileInvestigation } from '../components/ReportViewer/DeletedFileInvestigation';
import type { ReportDetail } from '../types/report';

describe('DeletedFileInvestigation Component', () => {
  const mockReport: ReportDetail = {
    publicId: 'mc_del_test_101',
    schemaVersion: '1.0.0',
    scannerVersion: '1.0.0-rc1',
    createdAt: new Date().toISOString(),
    uploadedAt: new Date().toISOString(),
    scanMode: 'FULL',
    osName: 'Windows 11 Pro',
    osVersion: '10.0.22631',
    osArchitecture: 'X64',
    detectedMinecraftVersions: ['1.8.9'],
    detectedLoaders: ['Vanilla'],
    consent: {
      consentGiven: true,
      collectionScopeVersion: '1.0.0',
      consentTimestamp: new Date().toISOString(),
    },
    processingStatus: 'Completed',
    expiresAt: new Date(Date.now() + 86400000 * 14).toISOString(),
    privacyNotice: 'Public link',
    severitySummary: { High: 1 },
    coverage: {
      totalChecks: 30,
      passedChecks: 30,
      flaggedChecks: 1,
      unavailableChecks: 0,
    },
    findings: [
      {
        ruleId: 'MC-DEL-999',
        title: 'Deleted Autoclicker In Temp',
        category: 'FileDeletion',
        severity: 'High',
        confidence: 'High',
        explanation: 'USN Journal records entry for fastclick.jar removed 12 mins before scan.',
        evidenceSource: 'UsnJournal',
        detectionRuleVersion: '1.0.0',
        limitationsAndFalsePositives: 'Cannot prove file was loaded.',
        filePath: 'C:\\Users\\User\\AppData\\Local\\Temp\\fastclick.jar',
      },
    ],
    evidenceItems: [],
    timelineEvents: [
      {
        timestamp: new Date().toISOString(),
        description: 'fastclick.jar unlinked from filesystem',
        category: 'FileDeletion',
        source: 'UsnJournal',
        confidence: 'High',
        isInferred: false,
      },
    ],
    diagnosticItems: [],
  };

  it('renders educational banner explaining the 4 distinct forensic claims', () => {
    render(<DeletedFileInvestigation report={mockReport} />);

    expect(screen.getByText(/Historical & Deleted File Forensic Analysis/i)).toBeInTheDocument();
    expect(screen.getByText(/1\. File Observed/i)).toBeInTheDocument();
    expect(screen.getByText(/2\. Was Executed/i)).toBeInTheDocument();
    expect(screen.getByText(/3\. Loaded into Game/i)).toBeInTheDocument();
    expect(screen.getByText(/4\. Confirmed Cheat/i)).toBeInTheDocument();
  });

  it('renders deleted records and allows searching by filename', () => {
    render(<DeletedFileInvestigation report={mockReport} />);

    expect(screen.getAllByText(/fastclick\.jar/i).length).toBeGreaterThanOrEqual(1);

    const searchInput = screen.getByPlaceholderText(/Search deleted filenames, paths, sources/i);
    fireEvent.change(searchInput, { target: { value: 'nonexistent' } });
    expect(screen.queryAllByText(/fastclick\.jar/i).length).toBe(0);

    fireEvent.change(searchInput, { target: { value: 'fastclick' } });
    expect(screen.getAllByText(/fastclick\.jar/i).length).toBeGreaterThanOrEqual(1);
  });

  it('renders forensic limitations stating what deletion does and does not prove', () => {
    render(<DeletedFileInvestigation report={mockReport} />);

    expect(screen.getByText(/Investigation Rule:/i)).toBeInTheDocument();
    expect(screen.getByText(/A deleted file record alone proves ONLY that a file existed and was removed/i)).toBeInTheDocument();
  });
});
