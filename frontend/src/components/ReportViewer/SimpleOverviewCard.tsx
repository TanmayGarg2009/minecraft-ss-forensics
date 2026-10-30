import React from 'react';
import { 
  AlertCircle, CheckCircle2, Copy, Check, Printer, Trash2, Download
} from 'lucide-react';
import type { ReportDetail } from '../../types/report';
import { extractReportOverviewMetrics } from '../../utils/forensicLanguage';

interface SimpleOverviewCardProps {
  report: ReportDetail;
  onOpenDeleteModal: () => void;
  onExportJson: () => void;
  onJumpToFindings: () => void;
}

export const SimpleOverviewCard: React.FC<SimpleOverviewCardProps> = ({
  report,
  onOpenDeleteModal,
  onExportJson,
  onJumpToFindings,
}) => {
  const [copied, setCopied] = React.useState(false);
  const metrics = extractReportOverviewMetrics(report);

  const handleCopyLink = () => {
    navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'STRONG EVIDENCE FOUND':
        return {
          bg: 'bg-rose-950/60',
          border: 'border-rose-800/80',
          text: 'text-rose-300',
          dot: 'bg-rose-500'
        };
      case 'SUSPICIOUS INDICATORS FOUND':
        return {
          bg: 'bg-amber-950/60',
          border: 'border-amber-800/80',
          text: 'text-amber-300',
          dot: 'bg-amber-500'
        };
      case 'INCOMPLETE SCAN':
      case 'INCONCLUSIVE':
        return {
          bg: 'bg-sky-950/60',
          border: 'border-sky-800/80',
          text: 'text-sky-300',
          dot: 'bg-sky-500'
        };
      default:
        return {
          bg: 'bg-emerald-950/60',
          border: 'border-emerald-800/80',
          text: 'text-emerald-300',
          dot: 'bg-emerald-500'
        };
    }
  };

  const statusColors = getStatusColor(metrics.overallStatus);

  return (
    <div className="space-y-4">
      {/* 1. Top Meta Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex flex-wrap items-center gap-2">
          <span className="px-2.5 py-0.5 rounded text-xs font-semibold uppercase tracking-wider bg-slate-800 text-slate-300 border border-slate-700">
            Mode: {report.scanMode}
          </span>
          <span className="px-2.5 py-0.5 rounded text-xs font-mono bg-slate-950 text-slate-300 border border-slate-800">
            Report ID: {report.publicId}
          </span>
          <span className="text-xs text-slate-400">
            Uploaded: {new Date(report.uploadedAt).toLocaleDateString()}
          </span>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 self-start sm:self-auto no-print">
          <button
            onClick={handleCopyLink}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm transition"
            title="Copy public link to share with staff"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-200" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Link Copied!' : 'Copy Share Link'}</span>
          </button>

          <button
            onClick={() => window.print()}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
            title="Print or Save PDF"
          >
            <Printer className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">Print</span>
          </button>

          <button
            onClick={onExportJson}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
            title="Export full JSON payload"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">JSON</span>
          </button>

          <button
            onClick={onOpenDeleteModal}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-red-950/60 text-slate-300 hover:text-red-400 border border-slate-700 hover:border-red-800 transition"
            title="Player-controlled deletion with private key"
          >
            <Trash2 className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">Delete</span>
          </button>
        </div>
      </div>

      {/* 2. Primary Status & High-Level Verdict Card */}
      <div className={`rounded-xl border p-5 shadow-sm space-y-4 ${statusColors.bg} ${statusColors.border}`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className={`w-3 h-3 rounded-full animate-pulse ${statusColors.dot}`} />
              <h1 className={`text-lg sm:text-xl font-bold tracking-tight ${statusColors.text}`}>
                {metrics.overallStatus}
              </h1>
            </div>
            <p className="text-xs sm:text-sm text-slate-300 max-w-3xl leading-relaxed">
              {metrics.summaryExplanation}
            </p>
          </div>

          <div className="shrink-0 flex items-center gap-2">
            <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold ${
              metrics.isCompleted 
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' 
                : 'bg-slate-800 text-slate-300 border border-slate-700'
            }`}>
              {metrics.isCompleted ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <AlertCircle className="w-3.5 h-3.5 text-amber-400" />}
              <span>{metrics.completionLabel}</span>
            </span>
          </div>
        </div>

        {/* 3. Seven High-Level Metrics Summary Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 pt-2 border-t border-slate-800/80">
          {/* 1. Findings Requiring Review */}
          <button
            onClick={onJumpToFindings}
            className="text-left p-3 rounded-lg bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition"
          >
            <span className="text-[11px] font-medium text-slate-400 block truncate">Findings to Review</span>
            <span className={`text-xl font-bold font-mono ${metrics.findingsForReviewCount > 0 ? 'text-amber-400' : 'text-slate-200'}`}>
              {metrics.findingsForReviewCount}
            </span>
          </button>

          {/* 2. Verified Mods */}
          <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
            <span className="text-[11px] font-medium text-slate-400 block truncate">Verified Mods</span>
            <span className="text-xl font-bold font-mono text-emerald-400">
              {metrics.verifiedModsCount}
            </span>
          </div>

          {/* 3. Unverified / Modified */}
          <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
            <span className="text-[11px] font-medium text-slate-400 block truncate">Unverified / Modified</span>
            <span className={`text-xl font-bold font-mono ${metrics.unverifiedOrModifiedCount > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
              {metrics.unverifiedOrModifiedCount}
            </span>
          </div>

          {/* 4. Duplicate Files */}
          <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
            <span className="text-[11px] font-medium text-slate-400 block truncate">Duplicate Files</span>
            <span className={`text-xl font-bold font-mono ${metrics.duplicateFilesCount > 0 ? 'text-indigo-400' : 'text-slate-400'}`}>
              {metrics.duplicateFilesCount}
            </span>
          </div>

          {/* 5. Scan Errors / Unavailable */}
          <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
            <span className="text-[11px] font-medium text-slate-400 block truncate">Limited / Inaccessible</span>
            <span className={`text-xl font-bold font-mono ${metrics.scanErrorsOrUnavailableCount > 0 ? 'text-sky-400' : 'text-slate-400'}`}>
              {metrics.scanErrorsOrUnavailableCount}
            </span>
          </div>

          {/* 6. Minecraft Versions */}
          <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800">
            <span className="text-[11px] font-medium text-slate-400 block truncate">Game Client</span>
            <span className="text-xs font-semibold text-slate-200 block truncate mt-1">
              {report.detectedMinecraftVersions?.join(', ') || 'Vanilla / Standard'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
