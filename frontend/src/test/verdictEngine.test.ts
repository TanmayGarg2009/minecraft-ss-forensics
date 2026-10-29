import { describe, it, expect } from 'vitest';
import { evaluateReportVerdict } from '../utils/verdictEngine';
import type { ReportDetail, FindingDetail } from '../types/report';

describe('verdictEngine', () => {
  const baseReport: ReportDetail = {
    publicId: 'mc_test_report_123',
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
    severitySummary: {},
    coverage: {
      totalChecks: 40,
      passedChecks: 38,
      flaggedChecks: 0,
      unavailableChecks: 2,
    },
    findings: [],
    evidenceItems: [],
    timelineEvents: [],
    diagnosticItems: [
      {
        checkName: 'Amcache Hive Parsing',
        source: 'Amcache',
        status: 'Completed',
        reason: 'Clean parsed',
      },
    ],
  };

  it('assigns NO SUSPICIOUS INDICATORS FOUND when findings are empty and coverage is adequate', () => {
    const verdict = evaluateReportVerdict(baseReport);
    expect(verdict.status).toBe('NO SUSPICIOUS INDICATORS FOUND');
    expect(verdict.explanation).toContain('does not constitute an absolute guarantee');
    expect(verdict.counters.highConfidenceFindings).toBe(0);
    expect(verdict.counters.otherSuspiciousIndicators).toBe(0);
  });

  it('assigns INCOMPLETE SCAN when coverage rate is too low or processing status is Failed', () => {
    const lowCoverageReport: ReportDetail = {
      ...baseReport,
      coverage: {
        totalChecks: 40,
        passedChecks: 15,
        flaggedChecks: 0,
        unavailableChecks: 25,
      },
    };

    const verdict = evaluateReportVerdict(lowCoverageReport);
    expect(verdict.status).toBe('INCOMPLETE SCAN');
    expect(verdict.headline).toContain('aborted or suffered significant coverage gaps');
  });

  it('assigns SUSPICIOUS INDICATORS FOUND for medium/high findings without multi-source certainty', () => {
    const suspiciousFinding: FindingDetail = {
      ruleId: 'MC-HIST-001',
      title: 'Historical Executable Run',
      category: 'ExecutionArtifacts',
      severity: 'Medium',
      confidence: 'Medium',
      explanation: 'Found in Prefetch',
      evidenceSource: 'Prefetch',
      detectionRuleVersion: '1.0.0',
      limitationsAndFalsePositives: 'Historical execution trace only.',
    };

    const report: ReportDetail = {
      ...baseReport,
      findings: [suspiciousFinding],
      coverage: {
        ...baseReport.coverage,
        flaggedChecks: 1,
      },
    };

    const verdict = evaluateReportVerdict(report);
    expect(verdict.status).toBe('SUSPICIOUS INDICATORS FOUND');
    expect(verdict.counters.otherSuspiciousIndicators).toBe(1);
  });

  it('assigns STRONG EVIDENCE FOUND when critical findings exist with certain confidence', () => {
    const criticalFinding: FindingDetail = {
      ruleId: 'MC-MEM-001',
      title: 'Memory Injection Detected',
      category: 'ProcessInjection',
      severity: 'Critical',
      confidence: 'Certain',
      explanation: 'Injected dll into javaw.exe',
      evidenceSource: 'ProcessMemory',
      detectionRuleVersion: '1.0.0',
      limitationsAndFalsePositives: 'Unsigned DLL memory mapped into JVM address space.',
    };

    const report: ReportDetail = {
      ...baseReport,
      findings: [criticalFinding],
      coverage: {
        ...baseReport.coverage,
        flaggedChecks: 1,
      },
    };

    const verdict = evaluateReportVerdict(report);
    expect(verdict.status).toBe('STRONG EVIDENCE FOUND');
    expect(verdict.counters.highConfidenceFindings).toBe(1);
    expect(verdict.highlights.length).toBe(1);
    expect(verdict.evidenceDistinctions.confirmedObservations.length).toBeGreaterThanOrEqual(1);
  });
});
