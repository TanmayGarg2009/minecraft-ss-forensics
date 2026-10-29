import React, { useState, useMemo } from 'react';
import { 
  ShieldCheck, AlertCircle, XCircle, Slash, HelpCircle, 
  CheckCircle, AlertTriangle, Search, 
  Info, Lock
} from 'lucide-react';
import type { DiagnosticItemDetail } from '../../types/report';

interface DiagnosticsSectionProps {
  diagnostics: DiagnosticItemDetail[];
}

export const DiagnosticsSection: React.FC<DiagnosticsSectionProps> = ({ diagnostics }) => {
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ISSUES_ONLY' | 'COMPLETED'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Status breakdown counters
  const counts = useMemo(() => {
    let completed = 0;
    let limitations = 0;
    let failed = 0;
    let accessDenied = 0;
    let skipped = 0;
    let unsupported = 0;

    diagnostics.forEach(d => {
      const s = d.status.toLowerCase();
      if (s === 'completed') completed++;
      else if (s.includes('limit')) limitations++;
      else if (s === 'accessdenied' || s.includes('denied') || s.includes('permission')) accessDenied++;
      else if (s === 'failed' || s === 'error') failed++;
      else if (s === 'skipped') skipped++;
      else if (s.includes('unsupported') || s.includes('unavail')) unsupported++;
      else limitations++;
    });

    return {
      completed,
      limitations,
      failed,
      accessDenied,
      skipped,
      unsupported,
      totalIssues: limitations + failed + accessDenied + skipped + unsupported,
      total: diagnostics.length
    };
  }, [diagnostics]);

  // Filtered list
  const filteredDiagnostics = useMemo(() => {
    return diagnostics.filter(d => {
      const s = d.status.toLowerCase();
      const isCompleted = s === 'completed';

      if (statusFilter === 'COMPLETED' && !isCompleted) return false;
      if (statusFilter === 'ISSUES_ONLY' && isCompleted) return false;

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchName = d.checkName.toLowerCase().includes(q);
        const matchSource = d.source.toLowerCase().includes(q);
        const matchReason = d.reason.toLowerCase().includes(q);
        const matchRec = d.recommendation?.toLowerCase().includes(q);
        if (!matchName && !matchSource && !matchReason && !matchRec) return false;
      }

      return true;
    });
  }, [diagnostics, statusFilter, searchQuery]);

  const getStatusBadge = (status: string) => {
    const s = status.toLowerCase();
    if (s === 'completed') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">
          <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
          Completed
        </span>
      );
    }
    if (s.includes('limit')) {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950 text-amber-300 border border-amber-800">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          Completed with Limitations
        </span>
      );
    }
    if (s === 'accessdenied' || s.includes('denied') || s.includes('permission')) {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-950 text-red-300 border border-red-800">
          <Lock className="w-3.5 h-3.5 text-red-400" />
          Permission Denied
        </span>
      );
    }
    if (s === 'skipped') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-300 border border-slate-700">
          <Slash className="w-3.5 h-3.5 text-slate-400" />
          Skipped
        </span>
      );
    }
    if (s.includes('unsupported') || s.includes('unavail')) {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
          <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
          Unsupported / Unavailable
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-950 text-red-300 border border-red-800">
        <XCircle className="w-3.5 h-3.5 text-red-400" />
        Failed ({status})
      </span>
    );
  };

  const getLimitationMeaning = (status: string) => {
    const s = status.toLowerCase();

    if (s === 'completed') {
      return 'Check executed successfully with full diagnostic depth.';
    }
    if (s.includes('denied') || s.includes('permission')) {
      return 'Staff Limitation: Non-elevated scan execution prevented access to low-level Windows APIs or system volumes. Cannot confirm absence of artifacts in protected directories.';
    }
    if (s.includes('unsupported') || s.includes('unavail')) {
      return 'Staff Limitation: Target platform or Windows edition lacks this artifact feature (e.g., BAM unavailable on legacy builds, or NTFS Journal disabled).';
    }
    if (s === 'skipped') {
      return 'Staff Limitation: Skipped due to scan mode configuration (Quick Scan) or prerequisite check failure.';
    }
    return 'Staff Limitation: Partial or failed collection means conclusions cannot be drawn regarding this specific vector.';
  };

  return (
    <div className="space-y-4">
      {/* 1. Header & Statistical Breakdown Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Scanner Collection Diagnostics & Check Coverage</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Transparent audit trail of executed checks, operational hurdles, skipped modules, and investigation limitations
            </p>
          </div>

          <div className="text-xs font-mono text-slate-400 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
            Total Checks: <span className="font-bold text-slate-200">{counts.total}</span>
          </div>
        </div>

        {/* Breakdown Metric Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 pt-2 border-t border-slate-800/80">
          <div className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-800/40 text-center">
            <span className="text-[10px] uppercase font-mono text-emerald-400 block font-semibold">Completed</span>
            <span className="text-lg font-bold text-emerald-300 font-mono">{counts.completed}</span>
          </div>

          <div className="p-2.5 rounded-lg bg-amber-950/20 border border-amber-800/40 text-center">
            <span className="text-[10px] uppercase font-mono text-amber-400 block font-semibold">Limitations</span>
            <span className="text-lg font-bold text-amber-300 font-mono">{counts.limitations}</span>
          </div>

          <div className="p-2.5 rounded-lg bg-red-950/20 border border-red-800/40 text-center">
            <span className="text-[10px] uppercase font-mono text-red-400 block font-semibold">Permission Denied</span>
            <span className="text-lg font-bold text-red-300 font-mono">{counts.accessDenied}</span>
          </div>

          <div className="p-2.5 rounded-lg bg-rose-950/20 border border-rose-800/40 text-center">
            <span className="text-[10px] uppercase font-mono text-rose-400 block font-semibold">Failed</span>
            <span className="text-lg font-bold text-rose-300 font-mono">{counts.failed}</span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
            <span className="text-[10px] uppercase font-mono text-slate-400 block font-semibold">Skipped</span>
            <span className="text-lg font-bold text-slate-300 font-mono">{counts.skipped}</span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
            <span className="text-[10px] uppercase font-mono text-slate-400 block font-semibold">Unsupported</span>
            <span className="text-lg font-bold text-slate-300 font-mono">{counts.unsupported}</span>
          </div>
        </div>

        {/* Filter and Search Bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2 border-t border-slate-800/80">
          <div className="inline-flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs w-full sm:w-auto">
            <button
              onClick={() => setStatusFilter('ALL')}
              className={`px-3 py-1 rounded-md font-medium transition ${
                statusFilter === 'ALL' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All Checks ({diagnostics.length})
            </button>
            <button
              onClick={() => setStatusFilter('ISSUES_ONLY')}
              className={`px-3 py-1 rounded-md font-medium transition flex items-center gap-1.5 ${
                statusFilter === 'ISSUES_ONLY' ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <span>Limitations & Hurdles</span>
              <span className="px-1 rounded-full text-[10px] font-mono bg-amber-900/60 text-amber-200">
                {counts.totalIssues}
              </span>
            </button>
            <button
              onClick={() => setStatusFilter('COMPLETED')}
              className={`px-3 py-1 rounded-md font-medium transition ${
                statusFilter === 'COMPLETED' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Completed ({counts.completed})
            </button>
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search checks, sources, reasons..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition"
            />
          </div>
        </div>
      </div>

      {/* 2. Educational Forensic Note */}
      <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl flex items-start gap-3 text-xs text-slate-300">
        <Info className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <span className="font-semibold text-slate-200">Anti-Cheat Staff Rule: </span>
          <span className="text-slate-400">
            A scan report is only as authoritative as its collection coverage. When critical forensic sources (e.g. NTFS USN Journal, Amcache, or Process Memory) report <strong className="text-amber-300">Access Denied</strong> or <strong className="text-red-300">Failed</strong>, the player cannot be declared clean solely on the absence of findings.
          </span>
        </div>
      </div>

      {/* 3. Diagnostic Cards List */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {filteredDiagnostics.length === 0 ? (
          <div className="p-12 text-center space-y-2">
            <ShieldCheck className="w-8 h-8 text-slate-600 mx-auto" />
            <div className="text-xs font-semibold text-slate-400">No diagnostic items matched your filter.</div>
            <button
              onClick={() => { setStatusFilter('ALL'); setSearchQuery(''); }}
              className="text-xs text-emerald-400 hover:underline inline-block mt-1"
            >
              Reset filters
            </button>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {filteredDiagnostics.map((diag, idx) => {
              const limitationNotice = getLimitationMeaning(diag.status);
              const isIssue = diag.status.toLowerCase() !== 'completed';

              return (
                <div 
                  key={idx} 
                  className={`p-4 sm:p-5 hover:bg-slate-850/40 transition space-y-3 ${
                    isIssue ? 'bg-slate-950/30' : ''
                  }`}
                >
                  {/* Title & Status */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <div className="font-bold text-xs sm:text-sm text-slate-100 flex items-center gap-2">
                        {isIssue ? (
                          <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
                        ) : (
                          <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                        )}
                        <span>{diag.checkName}</span>
                      </div>
                      <span className="text-[11px] text-slate-500 font-mono hidden sm:inline px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800">
                        Source: {diag.source}
                      </span>
                    </div>

                    <div>{getStatusBadge(diag.status)}</div>
                  </div>

                  {/* Outcome Description */}
                  <div className="text-xs text-slate-300 leading-relaxed bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
                    <span className="text-slate-400 font-semibold">Outcome / Collector Log: </span>
                    <span>{diag.reason}</span>
                  </div>

                  {/* What it means for staff & recommendation */}
                  {isIssue && (
                    <div className="p-3 bg-amber-950/20 border border-amber-800/40 rounded-lg space-y-2 text-xs">
                      <div className="text-amber-300/95 leading-relaxed">
                        <strong className="text-amber-200">Investigation Impact: </strong>
                        <span>{limitationNotice}</span>
                      </div>

                      {diag.recommendation && (
                        <div className="text-[11px] text-emerald-300 flex items-start gap-1.5 pt-1 border-t border-amber-800/30">
                          <HelpCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                          <span><strong className="text-emerald-200">Staff Recommendation:</strong> {diag.recommendation}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
