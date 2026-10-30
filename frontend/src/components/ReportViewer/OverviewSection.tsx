import React, { useState } from 'react';
import { 
  Clock, Monitor, Box, 
  Printer, Trash2, CheckCircle2, Download, Info, Copy, Check, FileJson,
  ShieldCheck, ChevronDown, ChevronUp, Layers
} from 'lucide-react';
import type { ReportDetail } from '../../types/report';
import { VerdictCard } from './VerdictCard';
import { SimpleOverviewCard } from './SimpleOverviewCard';
import { InteractiveFindingsList } from './InteractiveFindingsList';
import { MinecraftEnvSection } from './MinecraftEnvSection';
import { ProcessRuntimeSection } from './ProcessRuntimeSection';
import { HistoricalEvidenceSection } from './HistoricalEvidenceSection';
import { TimelineSection } from './TimelineSection';
import { DiagnosticsSection } from './DiagnosticsSection';

interface OverviewSectionProps {
  report: ReportDetail;
  onOpenDeleteModal: () => void;
  onExportJson: () => void;
  onSelectFinding?: (ruleId: string) => void;
  onInspectRawJson?: () => void;
}

export const OverviewSection: React.FC<OverviewSectionProps> = ({ 
  report, 
  onOpenDeleteModal, 
  onExportJson, 
  onSelectFinding,
  onInspectRawJson 
}) => {
  const [copied, setCopied] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [advancedTab, setAdvancedTab] = useState<'mods' | 'process' | 'historical' | 'timeline' | 'diagnostics'>('mods');

  const handleCopyLink = () => {
    navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const findingsRef = React.useRef<HTMLDivElement>(null);
  const scrollToFindings = () => {
    findingsRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="space-y-6">
      {/* 1. Header Toolbar with Metadata & Actions */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5 shadow-sm space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider ${
                report.scanMode === 'FULL' 
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' 
                  : 'bg-indigo-950 text-indigo-400 border border-indigo-800'
              }`}>
                {report.scanMode} SCAN
              </span>
              <span className="px-2 py-0.5 rounded text-xs font-mono bg-slate-950 text-slate-300 border border-slate-800">
                ID: {report.publicId}
              </span>
              <span className="px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-400 font-mono">
                Schema v{report.schemaVersion}
              </span>
            </div>

            <h1 className="text-lg sm:text-xl font-bold text-white tracking-tight">
              Minecraft SS Forensic Diagnostic Report
            </h1>
            <p className="text-xs text-slate-400">
              Scanned with <span className="text-slate-300 font-mono">{report.scannerVersion}</span> • Uploaded on {new Date(report.uploadedAt).toLocaleString()}
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-2 no-print">
            <button
              onClick={handleCopyLink}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm transition"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-200" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Link Copied!' : 'Copy Share Link'}</span>
            </button>

            <button
              onClick={() => window.print()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
              title="Print or Save as PDF"
            >
              <Printer className="w-3.5 h-3.5 text-slate-400" />
              <span>Print / PDF</span>
            </button>

            <button
              onClick={onExportJson}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-sky-950/80 hover:bg-sky-900/80 text-sky-300 border border-sky-800 transition"
              title="Download full forensic report (.json or .md) for AI or offline analysis"
            >
              <Download className="w-3.5 h-3.5 text-sky-400" />
              <span>Download Report</span>
            </button>

            {onInspectRawJson && (
              <button
                onClick={onInspectRawJson}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                title="Inspect raw JSON syntax-highlighted"
              >
                <FileJson className="w-3.5 h-3.5 text-slate-400" />
                <span>Raw JSON</span>
              </button>
            )}

            <button
              onClick={onOpenDeleteModal}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-red-950/60 hover:bg-red-900/80 text-red-300 border border-red-800/60 transition"
              title="Permanently delete this report using your secret Deletion Key"
            >
              <Trash2 className="w-3.5 h-3.5 text-red-400" />
              <span>Delete</span>
            </button>
          </div>
        </div>

        {/* Compact Metadata Chips */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-slate-800/80 text-xs">
          <div className="flex items-center gap-2 text-slate-300">
            <Monitor className="w-4 h-4 text-indigo-400 shrink-0" />
            <div className="truncate">
              <span className="text-slate-500 font-mono text-[10px] block">PLATFORM</span>
              <span className="font-semibold">{report.osName}</span> <span className="text-slate-500 font-mono">({report.osArchitecture})</span>
            </div>
          </div>

          <div className="flex items-center gap-2 text-slate-300">
            <Box className="w-4 h-4 text-emerald-400 shrink-0" />
            <div className="truncate">
              <span className="text-slate-500 font-mono text-[10px] block">MINECRAFT &amp; CLIENT</span>
              <span className="font-semibold">{report.detectedMinecraftVersions?.join(', ') || 'Version Unknown'}</span>
            </div>
          </div>

          <div className="flex items-center gap-2 text-slate-300">
            <Clock className="w-4 h-4 text-amber-400 shrink-0" />
            <div className="truncate">
              <span className="text-slate-500 font-mono text-[10px] block">CONSENT TIMESTAMP</span>
              <span className="font-semibold">{report.consent?.consentGiven ? 'Player Consented' : 'No Consent'}</span>
            </div>
          </div>

          <div className="flex items-center gap-2 text-slate-300">
            <ShieldCheck className="w-4 h-4 text-teal-400 shrink-0" />
            <div className="truncate">
              <span className="text-slate-500 font-mono text-[10px] block">RETENTION EXPIRATION</span>
              <span className="font-semibold">Expires in {Math.max(0, Math.ceil((new Date(report.expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24)))} days</span>
            </div>
          </div>
        </div>

        {/* Compact Privacy Notice Callout */}
        <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg flex items-start gap-2.5 text-xs text-slate-300">
          <Info className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <div className="space-y-0.5">
            <span className="font-bold text-slate-200">Bearer-Link Access Model &amp; Privacy Notice: </span>
            <span className="text-slate-400">
              Anyone with this complete report URL can view this forensic report without creating an account. This report will automatically expire on{' '}
              <strong className="text-amber-300">{new Date(report.expiresAt).toLocaleDateString()} at {new Date(report.expiresAt).toLocaleTimeString()}</strong>.
              Share this link exclusively with verified server anti-cheat staff.
            </span>
          </div>
        </div>
      </div>

      {/* 2. Simple High-Level Overview Card (Section 1.A) */}
      <SimpleOverviewCard
        report={report}
        onOpenDeleteModal={onOpenDeleteModal}
        onExportJson={onExportJson}
        onJumpToFindings={scrollToFindings}
      />

      {/* 3. Findings Section (Section 1.B, 1.C, 1.D: Simple, Clickable, Expandable Evidence) */}
      <div ref={findingsRef}>
        <InteractiveFindingsList report={report} />
      </div>

      {/* 4. Primary Investigation Verdict Card (Corroborated Distinctions) */}
      <VerdictCard report={report} onSelectFinding={onSelectFinding} />

      {/* 5. Negative finding guarantee note for clean reports */}
      {report.findings.length === 0 && (
        <div className="p-3.5 bg-emerald-950/20 border border-emerald-800/40 rounded-xl flex items-center gap-2.5 text-xs text-emerald-300">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>No forensic indicators flagged across scanned artifacts. Note: this reflects the scope of checks completed and does not constitute a guaranteed clean badge.</span>
        </div>
      )}

      {/* 6. Expandable Advanced Evidence & Inventories (Section 1.F) */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <button
          onClick={() => setShowAdvanced(prev => !prev)}
          className="w-full p-4 flex items-center justify-between text-left hover:bg-slate-850/50 transition focus:outline-none"
        >
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-indigo-400" />
            <h3 className="text-sm font-bold text-slate-100">
              Advanced Forensic Inventories &amp; Diagnostics
            </h3>
            <span className="px-2 py-0.5 rounded text-[11px] bg-slate-800 text-slate-400 font-mono">
              Optional Technical Depth
            </span>
          </div>

          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>{showAdvanced ? 'Collapse Advanced Details' : 'Expand Advanced Details'}</span>
            {showAdvanced ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </button>

        {showAdvanced && (
          <div className="p-4 sm:p-5 border-t border-slate-800 bg-slate-950/40 space-y-4">
            {/* Sub-tabs for advanced inspection */}
            <div className="flex flex-wrap items-center gap-1.5 border-b border-slate-800 pb-2 text-xs">
              <button
                onClick={() => setAdvancedTab('mods')}
                className={`px-3 py-1.5 rounded-lg font-medium transition ${
                  advancedTab === 'mods' ? 'bg-slate-800 text-white border border-slate-700' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Full Mod Inventory
              </button>
              <button
                onClick={() => setAdvancedTab('process')}
                className={`px-3 py-1.5 rounded-lg font-medium transition ${
                  advancedTab === 'process' ? 'bg-slate-800 text-white border border-slate-700' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Process &amp; Modules
              </button>
              <button
                onClick={() => setAdvancedTab('historical')}
                className={`px-3 py-1.5 rounded-lg font-medium transition ${
                  advancedTab === 'historical' ? 'bg-slate-800 text-white border border-slate-700' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Historical &amp; Deletions
              </button>
              <button
                onClick={() => setAdvancedTab('timeline')}
                className={`px-3 py-1.5 rounded-lg font-medium transition ${
                  advancedTab === 'timeline' ? 'bg-slate-800 text-white border border-slate-700' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Timeline
              </button>
              <button
                onClick={() => setAdvancedTab('diagnostics')}
                className={`px-3 py-1.5 rounded-lg font-medium transition ${
                  advancedTab === 'diagnostics' ? 'bg-slate-800 text-white border border-slate-700' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Diagnostics
              </button>
            </div>

            {/* Sub-panel Content */}
            <div className="pt-2">
              {advancedTab === 'mods' && <MinecraftEnvSection report={report} />}
              {advancedTab === 'process' && <ProcessRuntimeSection report={report} />}
              {advancedTab === 'historical' && <HistoricalEvidenceSection report={report} />}
              {advancedTab === 'timeline' && <TimelineSection events={report.timelineEvents} />}
              {advancedTab === 'diagnostics' && <DiagnosticsSection diagnostics={report.diagnosticItems} />}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
