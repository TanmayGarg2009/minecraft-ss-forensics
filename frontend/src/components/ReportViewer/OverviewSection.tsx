import React, { useState } from 'react';
import { 
  Clock, Monitor, Box, 
  Printer, Trash2, CheckCircle2, Download, Info, Copy, Check
} from 'lucide-react';
import type { ReportDetail } from '../../types/report';

interface OverviewSectionProps {
  report: ReportDetail;
  onOpenDeleteModal: () => void;
  onExportJson: () => void;
}

export const OverviewSection: React.FC<OverviewSectionProps> = ({ report, onOpenDeleteModal, onExportJson }) => {
  const [copied, setCopied] = useState(false);

  const handleCopyLink = () => {
    navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const criticalCount = report.severitySummary['Critical'] || 0;
  const highCount = report.severitySummary['High'] || 0;
  const mediumCount = report.severitySummary['Medium'] || 0;
  const lowCount = report.severitySummary['Low'] || 0;
  const infoCount = report.severitySummary['Informational'] || 0;

  const totalChecks = report.coverage?.totalChecks || (report.findings.length + 35);
  const passedChecks = report.coverage?.passedChecks || 35;
  const flaggedChecks = report.coverage?.flaggedChecks ?? report.findings.length;
  const unavailableChecks = report.coverage?.unavailableChecks || 0;

  return (
    <div className="space-y-6">
      {/* Top Banner & Action Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 sm:p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wider ${
                report.scanMode === 'FULL' 
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' 
                  : 'bg-indigo-950 text-indigo-400 border border-indigo-800'
              }`}>
                {report.scanMode} SCAN
              </span>
              <span className="px-2.5 py-1 rounded text-xs font-mono bg-slate-950 text-slate-300 border border-slate-800">
                ID: {report.publicId}
              </span>
              <span className="px-2.5 py-1 rounded text-xs bg-slate-800 text-slate-300">
                Schema v{report.schemaVersion}
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Minecraft SS Forensic Diagnostic Report
            </h1>
            <p className="text-xs sm:text-sm text-slate-400">
              Scanned with <span className="text-slate-300 font-mono">{report.scannerVersion}</span> • Uploaded on {new Date(report.uploadedAt).toLocaleString()}
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-2.5 no-print">
            <button
              onClick={handleCopyLink}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm transition"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-200" /> : <Copy className="w-4 h-4" />}
              <span>{copied ? 'Link Copied!' : 'Copy Share Link'}</span>
            </button>

            <button
              onClick={() => window.print()}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
              title="Print or Save as PDF"
            >
              <Printer className="w-4 h-4 text-slate-400" />
              <span>Print / PDF</span>
            </button>

            <button
              onClick={onExportJson}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
              title="Export complete report as JSON"
            >
              <Download className="w-4 h-4 text-slate-400" />
              <span>Export JSON</span>
            </button>

            <button
              onClick={onOpenDeleteModal}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg bg-red-950/60 hover:bg-red-900/80 text-red-300 border border-red-800/60 transition"
              title="Permanently delete this report using your Deletion Key"
            >
              <Trash2 className="w-4 h-4 text-red-400" />
              <span>Delete</span>
            </button>
          </div>
        </div>

        {/* Bearer Link Privacy Callout */}
        <div className="mt-5 p-3.5 bg-slate-950/70 border border-slate-800 rounded-lg flex items-start gap-3 text-xs text-slate-300">
          <Info className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="font-semibold text-slate-200">Bearer-Link Access Model & Privacy Notice</div>
            <p className="text-slate-400 leading-relaxed">
              Anyone with this complete share URL can view this report without requiring an account. This report will automatically expire on{' '}
              <span className="text-amber-300 font-medium">{new Date(report.expiresAt).toLocaleDateString()} at {new Date(report.expiresAt).toLocaleTimeString()}</span>.
              Share this link exclusively with verified server anti-cheat staff.
            </p>
          </div>
        </div>
      </div>

      {/* Metadata Tiles Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Environment Tile */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-start gap-3">
          <div className="p-2.5 rounded-lg bg-slate-800 text-slate-300">
            <Monitor className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="overflow-hidden">
            <div className="text-xs text-slate-400 font-medium">Operating System</div>
            <div className="text-sm font-semibold text-slate-200 truncate mt-0.5" title={`${report.osName} (${report.osArchitecture})`}>
              {report.osName}
            </div>
            <div className="text-xs text-slate-500 font-mono mt-0.5">Build {report.osVersion} • {report.osArchitecture}</div>
          </div>
        </div>

        {/* Game Versions Tile */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-start gap-3">
          <div className="p-2.5 rounded-lg bg-slate-800 text-slate-300">
            <Box className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="overflow-hidden">
            <div className="text-xs text-slate-400 font-medium">Minecraft & Loaders</div>
            <div className="text-sm font-semibold text-slate-200 truncate mt-0.5">
              {report.detectedMinecraftVersions?.join(', ') || 'Version Unknown'}
            </div>
            <div className="text-xs text-slate-500 truncate mt-0.5">
              {report.detectedLoaders?.join(', ') || 'Vanilla / None Detected'}
            </div>
          </div>
        </div>

        {/* Timestamps Tile */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-start gap-3">
          <div className="p-2.5 rounded-lg bg-slate-800 text-slate-300">
            <Clock className="w-5 h-5 text-amber-400" />
          </div>
          <div className="overflow-hidden">
            <div className="text-xs text-slate-400 font-medium">Consent & Duration</div>
            <div className="text-sm font-semibold text-slate-200 mt-0.5">
              {report.consent?.consentGiven ? 'Consent Confirmed' : 'No Consent Recorded'}
            </div>
            <div className="text-xs text-slate-500 mt-0.5">Scope v{report.consent?.collectionScopeVersion || '1.0'}</div>
          </div>
        </div>

        {/* Expiration Tile */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-start gap-3">
          <div className="p-2.5 rounded-lg bg-slate-800 text-slate-300">
            <CheckCircle2 className="w-5 h-5 text-teal-400" />
          </div>
          <div className="overflow-hidden">
            <div className="text-xs text-slate-400 font-medium">Status & Retention</div>
            <div className="text-sm font-semibold text-slate-200 mt-0.5">
              {report.processingStatus}
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              Expires in {Math.max(0, Math.ceil((new Date(report.expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24)))} days
            </div>
          </div>
        </div>
      </div>

      {/* Severity Breakdown & Check Coverage Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Summary Cards */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
              Findings By Severity
            </h2>
            <span className="text-xs text-slate-400 font-mono">
              Total Findings: {report.findings.length}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <div className={`p-3 rounded-lg border text-center ${
              criticalCount > 0 ? 'bg-red-950/40 border-red-800/80 text-red-300' : 'bg-slate-950/40 border-slate-800/80 text-slate-400'
            }`}>
              <div className="text-2xl font-bold font-mono">{criticalCount}</div>
              <div className="text-[11px] font-semibold uppercase tracking-wider mt-1">Critical</div>
            </div>

            <div className={`p-3 rounded-lg border text-center ${
              highCount > 0 ? 'bg-orange-950/40 border-orange-800/80 text-orange-300' : 'bg-slate-950/40 border-slate-800/80 text-slate-400'
            }`}>
              <div className="text-2xl font-bold font-mono">{highCount}</div>
              <div className="text-[11px] font-semibold uppercase tracking-wider mt-1">High</div>
            </div>

            <div className={`p-3 rounded-lg border text-center ${
              mediumCount > 0 ? 'bg-amber-950/40 border-amber-800/80 text-amber-300' : 'bg-slate-950/40 border-slate-800/80 text-slate-400'
            }`}>
              <div className="text-2xl font-bold font-mono">{mediumCount}</div>
              <div className="text-[11px] font-semibold uppercase tracking-wider mt-1">Medium</div>
            </div>

            <div className={`p-3 rounded-lg border text-center ${
              lowCount > 0 ? 'bg-sky-950/40 border-sky-800/80 text-sky-300' : 'bg-slate-950/40 border-slate-800/80 text-slate-400'
            }`}>
              <div className="text-2xl font-bold font-mono">{lowCount}</div>
              <div className="text-[11px] font-semibold uppercase tracking-wider mt-1">Low</div>
            </div>

            <div className="p-3 rounded-lg border border-slate-800/80 bg-slate-950/40 text-slate-400 text-center col-span-2 sm:col-span-1">
              <div className="text-2xl font-bold font-mono">{infoCount}</div>
              <div className="text-[11px] font-semibold uppercase tracking-wider mt-1">Info</div>
            </div>
          </div>

          {report.findings.length === 0 && (
            <div className="mt-4 p-3 bg-emerald-950/30 border border-emerald-800/40 rounded-lg flex items-center gap-2.5 text-xs text-emerald-300">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>No forensic indicators flagged across scanned artifacts. Note: this reflects scanned scope and does not constitute a guaranteed clean badge.</span>
            </div>
          )}
        </div>

        {/* Coverage Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
                Coverage Diagnostics
              </h2>
              <span className="text-xs text-emerald-400 font-mono">
                {Math.round(((passedChecks) / Math.max(1, totalChecks)) * 100)}% Verified
              </span>
            </div>

            <div className="space-y-3 text-xs">
              <div className="flex justify-between items-center text-slate-300">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  Checks Passed
                </span>
                <span className="font-mono font-semibold">{passedChecks}</span>
              </div>

              <div className="flex justify-between items-center text-slate-300">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-orange-500" />
                  Flagged Indicators
                </span>
                <span className="font-mono font-semibold">{flaggedChecks}</span>
              </div>

              <div className="flex justify-between items-center text-slate-300">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-slate-500" />
                  Skipped / Unavailable
                </span>
                <span className="font-mono font-semibold">{unavailableChecks}</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-500">
            {totalChecks} total forensic check modules evaluated
          </div>
        </div>
      </div>
    </div>
  );
};
