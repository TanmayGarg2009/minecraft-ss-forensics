import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, AlertOctagon, HelpCircle, 
  ArrowRight, CheckCircle2, ChevronDown, ChevronUp, FileSearch, 
  Info
} from 'lucide-react';
import type { ReportDetail } from '../../types/report';
import { evaluateReportVerdict } from '../../utils/verdictEngine';
import { SeverityBadge } from '../UI/Badge';

interface VerdictCardProps {
  report: ReportDetail;
  onSelectFinding?: (ruleId: string) => void;
}

export const VerdictCard: React.FC<VerdictCardProps> = ({ report, onSelectFinding }) => {
  const [showDistinctions, setShowDistinctions] = useState(false);
  const verdict = evaluateReportVerdict(report);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'STRONG EVIDENCE FOUND':
        return <AlertOctagon className="w-6 h-6 text-red-400" />;
      case 'SUSPICIOUS INDICATORS FOUND':
        return <AlertTriangle className="w-6 h-6 text-amber-400" />;
      case 'INCOMPLETE SCAN':
        return <ShieldAlert className="w-6 h-6 text-orange-400" />;
      case 'INCONCLUSIVE':
        return <HelpCircle className="w-6 h-6 text-slate-400" />;
      case 'NO SUSPICIOUS INDICATORS FOUND':
      default:
        return <ShieldCheck className="w-6 h-6 text-emerald-400" />;
    }
  };

  return (
    <div className="bg-slate-900/90 dark:bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
      {/* Primary Verdict Banner */}
      <div className={`p-4 sm:p-5 border-b border-slate-800 ${verdict.badgeColor.bg} transition-colors`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg bg-slate-950/60 border ${verdict.badgeColor.border} shrink-0`}>
              {getStatusIcon(verdict.status)}
            </div>
            <div>
              <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                Investigation Assessment
              </div>
              <div className="flex items-center gap-2 mt-0.5">
                <span className={`text-base sm:text-lg font-black tracking-tight ${verdict.badgeColor.text}`}>
                  {verdict.status}
                </span>
                {verdict.badgeColor.pulse && (
                  <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping inline-block" />
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-center">
            <div className="text-right hidden md:block">
              <div className="text-[11px] text-slate-400 font-medium">Scan Verification</div>
              <div className="text-xs font-mono font-semibold text-emerald-400">
                {verdict.coverageRate}% Checks Validated
              </div>
            </div>
          </div>
        </div>

        {/* Headline & Explanation */}
        <div className="mt-3.5 space-y-1.5">
          <div className="text-xs sm:text-sm font-semibold text-slate-200">
            {verdict.headline}
          </div>
          <p className="text-xs text-slate-300/90 leading-relaxed max-w-4xl">
            {verdict.explanation}
          </p>
        </div>
      </div>

      {/* 6 Metric Evidence Counters Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 divide-x divide-y sm:divide-y-0 divide-slate-800/80 bg-slate-950/60 text-xs">
        <div className="p-3 text-center">
          <div className={`text-lg font-mono font-bold ${verdict.counters.highConfidenceFindings > 0 ? 'text-red-400' : 'text-slate-400'}`}>
            {verdict.counters.highConfidenceFindings}
          </div>
          <div className="text-[10px] text-slate-400 font-medium uppercase tracking-wider mt-0.5">
            High-Conf. Findings
          </div>
        </div>

        <div className="p-3 text-center">
          <div className={`text-lg font-mono font-bold ${verdict.counters.otherSuspiciousIndicators > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
            {verdict.counters.otherSuspiciousIndicators}
          </div>
          <div className="text-[10px] text-slate-400 font-medium uppercase tracking-wider mt-0.5">
            Other Indicators
          </div>
        </div>

        <div className="p-3 text-center">
          <div className="text-lg font-mono font-bold text-indigo-400">
            {verdict.counters.historicalArtifacts}
          </div>
          <div className="text-[10px] text-slate-400 font-medium uppercase tracking-wider mt-0.5">
            Historical Artifacts
          </div>
        </div>

        <div className="p-3 text-center">
          <div className={`text-lg font-mono font-bold ${verdict.counters.deletedFileIndicators > 0 ? 'text-orange-400' : 'text-slate-400'}`}>
            {verdict.counters.deletedFileIndicators}
          </div>
          <div className="text-[10px] text-slate-400 font-medium uppercase tracking-wider mt-0.5">
            Deleted File Traces
          </div>
        </div>

        <div className="p-3 text-center">
          <div className="text-lg font-mono font-bold text-emerald-400">
            {verdict.counters.completedChecks}
          </div>
          <div className="text-[10px] text-slate-400 font-medium uppercase tracking-wider mt-0.5">
            Completed Checks
          </div>
        </div>

        <div className="p-3 text-center">
          <div className={`text-lg font-mono font-bold ${verdict.counters.failedOrUnavailableChecks > 0 ? 'text-slate-300' : 'text-slate-500'}`}>
            {verdict.counters.failedOrUnavailableChecks}
          </div>
          <div className="text-[10px] text-slate-400 font-medium uppercase tracking-wider mt-0.5">
            Unavailable / Skipped
          </div>
        </div>
      </div>

      {/* Investigation Highlights (Top 3) */}
      {verdict.highlights.length > 0 ? (
        <div className="p-4 sm:p-5 border-t border-slate-800 space-y-3 bg-slate-900/40">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-slate-300 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
              <FileSearch className="w-3.5 h-3.5 text-emerald-400" />
              <span>Priority Investigation Highlights</span>
            </span>
            <span className="text-slate-500 text-[11px]">Ranked by severity & corroboration</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {verdict.highlights.map((finding) => (
              <div
                key={finding.ruleId}
                className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 flex flex-col justify-between hover:border-slate-700 transition"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-1 text-[11px]">
                    <span className="font-mono text-emerald-400 font-semibold">{finding.ruleId}</span>
                    <SeverityBadge severity={finding.severity} />
                  </div>
                  <div className="font-bold text-xs text-slate-100 line-clamp-1">{finding.title}</div>
                  <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                    {finding.explanation}
                  </p>
                </div>

                <div className="mt-3 pt-2 border-t border-slate-900 flex items-center justify-between text-[10px]">
                  <span className="font-mono text-slate-400">Src: {finding.evidenceSource}</span>
                  {onSelectFinding && (
                    <button
                      onClick={() => onSelectFinding(finding.ruleId)}
                      className="text-emerald-400 hover:text-emerald-300 font-semibold inline-flex items-center gap-0.5"
                    >
                      <span>Inspect</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="p-4 border-t border-slate-800 bg-slate-900/30 text-xs text-slate-400 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>No priority highlights. All monitored execution artifact and integrity checks returned negative within the collection scope.</span>
        </div>
      )}

      {/* Recommended Next Steps */}
      {verdict.recommendedNextSteps.length > 0 && (
        <div className="px-4 sm:px-5 py-3 border-t border-slate-800/80 bg-slate-950/40 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-start sm:items-center gap-2 text-slate-300">
            <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-bold uppercase tracking-wider shrink-0">
              Staff Next Steps
            </span>
            <span className="text-slate-400 text-[11px] leading-relaxed">
              {verdict.recommendedNextSteps.join(' • ')}
            </span>
          </div>
        </div>
      )}

      {/* Collapsible Evidence Distinctions (Confirmed vs Indicator vs Inference) */}
      <div className="border-t border-slate-800 bg-slate-950/70">
        <button
          onClick={() => setShowDistinctions(!showDistinctions)}
          className="w-full px-4 sm:px-5 py-2.5 flex items-center justify-between text-xs text-slate-400 hover:text-slate-200 transition"
        >
          <span className="font-semibold flex items-center gap-1.5 text-[11px] uppercase tracking-wider">
            <Info className="w-3.5 h-3.5 text-slate-400" />
            <span>Evidence Classification & Distinctions (Confirmed vs. Inferred)</span>
          </span>
          {showDistinctions ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>

        {showDistinctions && (
          <div className="p-4 sm:p-5 pt-1 space-y-3 text-xs border-t border-slate-800/60 divide-y divide-slate-800/60">
            <div className="pt-2">
              <span className="font-semibold text-emerald-400 text-[11px] uppercase tracking-wider block mb-1">
                Confirmed Observations ({verdict.evidenceDistinctions.confirmedObservations.length})
              </span>
              {verdict.evidenceDistinctions.confirmedObservations.length > 0 ? (
                <ul className="list-disc pl-4 space-y-0.5 text-slate-300">
                  {verdict.evidenceDistinctions.confirmedObservations.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-slate-500 italic">No standalone verified binary signatures.</p>
              )}
            </div>

            <div className="pt-2">
              <span className="font-semibold text-amber-400 text-[11px] uppercase tracking-wider block mb-1">
                Suspicious Indicators ({verdict.evidenceDistinctions.suspiciousIndicators.length})
              </span>
              {verdict.evidenceDistinctions.suspiciousIndicators.length > 0 ? (
                <ul className="list-disc pl-4 space-y-0.5 text-slate-300">
                  {verdict.evidenceDistinctions.suspiciousIndicators.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-slate-500 italic">No suspicious indicators recorded.</p>
              )}
            </div>

            <div className="pt-2">
              <span className="font-semibold text-indigo-400 text-[11px] uppercase tracking-wider block mb-1">
                Inferences & Time Approximations ({verdict.evidenceDistinctions.inferences.length})
              </span>
              {verdict.evidenceDistinctions.inferences.length > 0 ? (
                <ul className="list-disc pl-4 space-y-0.5 text-slate-300">
                  {verdict.evidenceDistinctions.inferences.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-slate-500 italic">No inferred timestamps; all times directly recorded.</p>
              )}
            </div>

            <div className="pt-2">
              <span className="font-semibold text-slate-400 text-[11px] uppercase tracking-wider block mb-1">
                Unavailable or Skipped Scope ({verdict.evidenceDistinctions.unknownOrUnavailable.length})
              </span>
              {verdict.evidenceDistinctions.unknownOrUnavailable.length > 0 ? (
                <ul className="list-disc pl-4 space-y-0.5 text-slate-400">
                  {verdict.evidenceDistinctions.unknownOrUnavailable.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-slate-500 italic">All requested scan checks completed successfully.</p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
