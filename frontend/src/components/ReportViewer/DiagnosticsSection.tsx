import React from 'react';
import { ShieldCheck, AlertCircle, XCircle, Slash, HelpCircle, CheckCircle } from 'lucide-react';
import type { DiagnosticItemDetail } from '../../types/report';

interface DiagnosticsSectionProps {
  diagnostics: DiagnosticItemDetail[];
}

export const DiagnosticsSection: React.FC<DiagnosticsSectionProps> = ({ diagnostics }) => {
  const getStatusBadge = (status: string) => {
    const s = status.toLowerCase();
    if (s === 'completed') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-950 text-emerald-300 border border-emerald-800">
          <CheckCircle className="w-3 h-3 text-emerald-400" />
          Completed
        </span>
      );
    }
    if (s === 'skipped') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700">
          <Slash className="w-3 h-3 text-slate-400" />
          Skipped
        </span>
      );
    }
    if (s === 'accessdenied') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-950 text-amber-300 border border-amber-800">
          <AlertCircle className="w-3 h-3 text-amber-400" />
          Access Denied
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-950 text-red-300 border border-red-800">
        <XCircle className="w-3 h-3 text-red-400" />
        {status}
      </span>
    );
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden space-y-0">
      <div className="p-4 sm:p-5 border-b border-slate-800">
        <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>Scanner Collection Diagnostics & Check Coverage</span>
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Audit trail of completed checks, permission hurdles, skipped modules, and system limitations
        </p>
      </div>

      {diagnostics.length === 0 ? (
        <div className="p-8 text-center text-slate-500 text-xs">
          No diagnostic items were recorded for this scan.
        </div>
      ) : (
        <div className="divide-y divide-slate-800/80">
          {diagnostics.map((diag, idx) => (
            <div key={idx} className="p-4 sm:p-5 hover:bg-slate-850/40 transition space-y-2">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <div className="font-semibold text-xs sm:text-sm text-slate-200">
                    {diag.checkName}
                  </div>
                  <span className="text-xs text-slate-500 font-mono hidden sm:inline">
                    [{diag.source}]
                  </span>
                </div>
                <div>{getStatusBadge(diag.status)}</div>
              </div>

              <div className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
                <span className="text-slate-400 font-medium">Outcome: </span>
                {diag.reason}
              </div>

              {diag.recommendation && (
                <div className="text-[11px] text-amber-300/90 flex items-start gap-1.5 pt-1">
                  <HelpCircle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                  <span>Recommendation for Staff: {diag.recommendation}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
