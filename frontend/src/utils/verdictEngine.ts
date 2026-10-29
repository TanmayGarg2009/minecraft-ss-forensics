import type { ReportDetail, FindingDetail } from '../types/report';

export type VerdictStatus =
  | 'NO SUSPICIOUS INDICATORS FOUND'
  | 'SUSPICIOUS INDICATORS FOUND'
  | 'STRONG EVIDENCE FOUND'
  | 'INCONCLUSIVE'
  | 'INCOMPLETE SCAN';

export interface VerdictAnalysis {
  status: VerdictStatus;
  badgeColor: {
    bg: string;
    text: string;
    border: string;
    iconColor: string;
    pulse?: boolean;
  };
  headline: string;
  explanation: string;
  evidenceDistinctions: {
    confirmedObservations: string[];
    suspiciousIndicators: string[];
    corroboratedEvidence: string[];
    inferences: string[];
    unknownOrUnavailable: string[];
  };
  counters: {
    highConfidenceFindings: number;
    otherSuspiciousIndicators: number;
    historicalArtifacts: number;
    deletedFileIndicators: number;
    completedChecks: number;
    failedOrUnavailableChecks: number;
  };
  highlights: FindingDetail[];
  recommendedNextSteps: string[];
  coverageRate: number;
}

export function evaluateReportVerdict(report: ReportDetail): VerdictAnalysis {
  const findings = report.findings || [];
  const diagnostics = report.diagnosticItems || [];
  const timeline = report.timelineEvents || [];
  const evidenceItems = report.evidenceItems || [];
  const coverage = report.coverage || {
    totalChecks: 40,
    passedChecks: 38,
    flaggedChecks: findings.length,
    unavailableChecks: 0,
  };

  const totalChecks = Math.max(1, coverage.totalChecks || (findings.length + diagnostics.length || 40));
  const unavailableChecks = (coverage.unavailableChecks || 0) + 
    diagnostics.filter(d => ['skipped', 'accessdenied', 'unsupported', 'failed'].includes(d.status.toLowerCase())).length;
  const completedChecks = Math.max(0, coverage.passedChecks || (totalChecks - unavailableChecks));
  const coverageRate = Math.min(100, Math.round((completedChecks / totalChecks) * 100));

  // Categorize findings
  const criticalFindings = findings.filter(f => f.severity === 'Critical');
  const highFindings = findings.filter(f => f.severity === 'High');
  const mediumFindings = findings.filter(f => f.severity === 'Medium');

  const highConfidenceFindingsCount = findings.filter(
    f => (f.confidence === 'Certain' || f.confidence === 'High') &&
         (f.severity === 'Critical' || f.severity === 'High')
  ).length;

  const otherSuspiciousIndicatorsCount = findings.filter(
    f => !((f.confidence === 'Certain' || f.confidence === 'High') &&
          (f.severity === 'Critical' || f.severity === 'High'))
  ).length;

  // Historical & Deleted file counters
  const historicalArtifactsCount = findings.filter(
    f => ['Prefetch', 'UsnJournal', 'BamDam', 'Amcache', 'ShimCache', 'EventLogs'].includes(f.evidenceSource) ||
         f.category === 'ExecutionArtifacts' || f.category === 'FileDeletion'
  ).length + evidenceItems.filter(e => e.type === 'WindowsArtifact' || e.type === 'CorrelationResult').length;

  const deletedFileIndicatorsCount = findings.filter(
    f => f.category === 'FileDeletion' || 
         f.evidenceSource === 'UsnJournal' || 
         (f.title && f.title.toLowerCase().includes('delete'))
  ).length + timeline.filter(t => t.category.toLowerCase().includes('delete')).length;

  // Evidence Distinctions
  const confirmedObservations: string[] = [];
  const suspiciousIndicators: string[] = [];
  const corroboratedEvidence: string[] = [];
  const inferences: string[] = [];
  const unknownOrUnavailable: string[] = [];

  // Populate distinctions from data
  findings.forEach(f => {
    if (f.confidence === 'Certain') {
      confirmedObservations.push(`${f.ruleId}: Observed verified artifact via ${f.evidenceSource} (${f.title})`);
    } else if (f.severity === 'Critical' || f.severity === 'High') {
      suspiciousIndicators.push(`${f.ruleId}: ${f.title} (${f.confidence} confidence)`);
    } else {
      suspiciousIndicators.push(`${f.ruleId}: ${f.title}`);
    }
  });

  timeline.forEach(t => {
    if (t.isInferred) {
      inferences.push(`${t.category}: ${t.description} (Inferred time)`);
    } else if (t.correlationGroup) {
      corroboratedEvidence.push(`[${t.correlationGroup}] ${t.description} via ${t.source}`);
    }
  });

  diagnostics.forEach(d => {
    if (['skipped', 'accessdenied', 'unsupported', 'failed'].includes(d.status.toLowerCase())) {
      unknownOrUnavailable.push(`${d.checkName} (${d.status}): ${d.reason}`);
    }
  });

  // Highlights: top 3 findings sorted by severity and confidence
  const severityWeight: Record<string, number> = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };
  const confidenceWeight: Record<string, number> = { Certain: 4, High: 3, Medium: 2, Low: 1 };
  const sortedFindings = [...findings].sort((a, b) => {
    const swA = severityWeight[a.severity] || 0;
    const swB = severityWeight[b.severity] || 0;
    if (swB !== swA) return swB - swA;
    const cwA = confidenceWeight[a.confidence] || 0;
    const cwB = confidenceWeight[b.confidence] || 0;
    return cwB - cwA;
  });
  const highlights = sortedFindings.slice(0, 3);

  // Recommendations for staff
  const recommendedNextSteps: string[] = [];

  // Deterministic Verdict Decision Logic
  let status: VerdictStatus;
  let headline = '';
  let explanation = '';

  const isFailedProcessing = report.processingStatus === 'Failed';
  const hasSevereCoverageGap = coverageRate < 60 || unavailableChecks > 8;

  if (isFailedProcessing || hasSevereCoverageGap) {
    status = 'INCOMPLETE SCAN';
    headline = 'Diagnostic scan was aborted or suffered significant coverage gaps.';
    explanation = `The scanner completed only ${coverageRate}% of targeted checks (${unavailableChecks} checks failed, were skipped, or were denied access). Findings or lack thereof cannot be relied upon without verifying uncollected artifacts.`;
    recommendedNextSteps.push('Review Diagnostics section to inspect skipped or permission-denied subsystems.');
    recommendedNextSteps.push('Verify whether administrator privileges were granted to the scanner.');
  } else if (criticalFindings.length >= 1 || (highFindings.length >= 2 && highConfidenceFindingsCount >= 2)) {
    status = 'STRONG EVIDENCE FOUND';
    headline = `${findings.length} indicators flagged, including high-severity forensic anomalies with multi-artifact agreement.`;
    explanation = `Multiple high-confidence forensic artifacts were identified across independent evidence sources. These records confirm execution or memory injection indicators with minimal likelihood of standard vanilla behavior.`;
    recommendedNextSteps.push('Cross-reference observed execution timestamps with server match / duel records.');
    recommendedNextSteps.push('Check file SHA-256 hashes against known legitimate mod signatures.');
    recommendedNextSteps.push('Inspect the Process & Runtime module list for unsigned library handles.');
  } else if (highFindings.length >= 1 || mediumFindings.length >= 1) {
    status = 'SUSPICIOUS INDICATORS FOUND';
    headline = `${findings.length} suspicious indicator${findings.length === 1 ? '' : 's'} recorded requiring staff evaluation.`;
    explanation = `${findings.length} indicator(s) were observed (such as historical execution logs or deleted temporary files). The evidence establishes activity but does not definitively prove active game interaction without corresponding server audit correlation.`;
    recommendedNextSteps.push('Review the Deleted-File Investigation tab to determine if deleted files were ever loaded into the active Minecraft JVM.');
    recommendedNextSteps.push('Check the Limitations & False Positives note on each finding before taking punitive action.');
  } else if (findings.length > 0) {
    status = 'INCONCLUSIVE';
    headline = `${findings.length} minor or low-confidence indicator(s) found without conclusive corroboration.`;
    explanation = `Observed records (e.g. unsigned third-party helper utilities or benign command-line flags) cannot be linked to malicious modification without additional circumstantial proof.`;
    recommendedNextSteps.push('Manually inspect the player mod folder and game output logs.');
  } else {
    // 0 findings
    if (coverageRate < 80) {
      status = 'INCOMPLETE SCAN';
      headline = 'No suspicious findings recorded, but key diagnostic checks were skipped.';
      explanation = `While zero indicators were flagged, the scan could not inspect several critical areas (${unavailableChecks} unavailable checks). This cannot be treated as proof of absence.`;
      recommendedNextSteps.push('Request a Full Scan if the player previously performed only a Quick Scan.');
    } else {
      status = 'NO SUSPICIOUS INDICATORS FOUND';
      headline = 'Zero forensic anomalies detected across all scanned modules.';
      explanation = `The scan evaluated ${completedChecks} check modules (including active mod signatures, Prefetch records, and process memory metadata) with no matching indicators. Note: this reflects the stated collection scope and does not constitute an absolute guarantee against uninspected methods.`;
      recommendedNextSteps.push('Review game version and loader to verify player was running the inspected installation.');
    }
  }

  // Visual styling for verdict badges
  const badgeColors: Record<VerdictStatus, VerdictAnalysis['badgeColor']> = {
    'STRONG EVIDENCE FOUND': {
      bg: 'bg-red-950/80',
      text: 'text-red-300',
      border: 'border-red-600',
      iconColor: 'text-red-400',
      pulse: true,
    },
    'SUSPICIOUS INDICATORS FOUND': {
      bg: 'bg-amber-950/80',
      text: 'text-amber-300',
      border: 'border-amber-600',
      iconColor: 'text-amber-400',
    },
    'INCONCLUSIVE': {
      bg: 'bg-slate-900',
      text: 'text-slate-300',
      border: 'border-slate-700',
      iconColor: 'text-slate-400',
    },
    'INCOMPLETE SCAN': {
      bg: 'bg-orange-950/80',
      text: 'text-orange-300',
      border: 'border-orange-600',
      iconColor: 'text-orange-400',
    },
    'NO SUSPICIOUS INDICATORS FOUND': {
      bg: 'bg-emerald-950/80',
      text: 'text-emerald-300',
      border: 'border-emerald-600',
      iconColor: 'text-emerald-400',
    },
  };

  return {
    status,
    badgeColor: badgeColors[status],
    headline,
    explanation,
    evidenceDistinctions: {
      confirmedObservations,
      suspiciousIndicators,
      corroboratedEvidence,
      inferences,
      unknownOrUnavailable,
    },
    counters: {
      highConfidenceFindings: highConfidenceFindingsCount,
      otherSuspiciousIndicators: otherSuspiciousIndicatorsCount,
      historicalArtifacts: historicalArtifactsCount,
      deletedFileIndicators: deletedFileIndicatorsCount,
      completedChecks,
      failedOrUnavailableChecks: unavailableChecks,
    },
    highlights,
    recommendedNextSteps,
    coverageRate,
  };
}
