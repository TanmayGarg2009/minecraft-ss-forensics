import React, { useState } from 'react';
import { Database, Copy, Check } from 'lucide-react';
import type { ReportDetail } from '../../types/report';

interface HistoricalEvidenceSectionProps {
  report: ReportDetail;
}

export const HistoricalEvidenceSection: React.FC<HistoricalEvidenceSectionProps> = ({ report }) => {
  const [selectedEvidence, setSelectedEvidence] = useState<string | null>(
    report.evidenceItems[0]?.publicEvidenceId || null
  );
  const [copied, setCopied] = useState(false);

  const activeItem = report.evidenceItems.find(e => e.publicEvidenceId === selectedEvidence);

  const copyContent = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Evidence Items Navigation and Detail Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left List */}
        <div className="space-y-3">
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <Database className="w-3.5 h-3.5 text-emerald-400" />
            <span>Forensic Artifact Collections ({report.evidenceItems.length})</span>
          </div>

          <div className="space-y-2">
            {report.evidenceItems.map((item) => {
              const isSelected = item.publicEvidenceId === selectedEvidence;

              return (
                <div
                  key={item.publicEvidenceId}
                  onClick={() => setSelectedEvidence(item.publicEvidenceId)}
                  className={`p-3.5 rounded-xl border text-left cursor-pointer transition ${
                    isSelected
                      ? 'bg-slate-800/90 border-emerald-500/80 shadow-sm'
                      : 'bg-slate-900 border-slate-800 hover:bg-slate-850 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] mb-1">
                    <span className="font-mono text-emerald-400 font-semibold">{item.publicEvidenceId}</span>
                    <span className="px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                      {item.type}
                    </span>
                  </div>
                  <div className="font-semibold text-xs text-slate-200 line-clamp-1">
                    {item.title}
                  </div>
                  <div className="text-[11px] text-slate-400 line-clamp-2 mt-1">
                    {item.description}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Detail Pane */}
        <div className="lg:col-span-2">
          {activeItem ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-emerald-400 font-semibold">{activeItem.publicEvidenceId}</span>
                    <span className="text-slate-500">•</span>
                    <span className="text-xs text-slate-400 font-medium">{activeItem.type}</span>
                  </div>
                  <h3 className="text-sm font-bold text-slate-100 mt-0.5">{activeItem.title}</h3>
                </div>

                {activeItem.rawContent && (
                  <button
                    onClick={() => copyContent(activeItem.rawContent!)}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition self-start sm:self-auto"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy Raw Text'}</span>
                  </button>
                )}
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">
                {activeItem.description}
              </p>

              {activeItem.sha256Hash && (
                <div className="text-xs bg-slate-950 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between gap-2">
                  <span className="text-slate-500">Integrity Hash:</span>
                  <span className="font-mono text-slate-300 text-[11px] truncate">{activeItem.sha256Hash}</span>
                </div>
              )}

              {/* Raw Content View */}
              {activeItem.rawContent && (
                <div className="space-y-1.5">
                  <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                    Raw Artifact Contents
                  </div>
                  <pre className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-96">
                    {activeItem.rawContent}
                  </pre>
                </div>
              )}

              {/* Structured Payload View */}
              {activeItem.structuredPayload && (
                <div className="space-y-1.5">
                  <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                    Parsed Structured Records
                  </div>
                  <pre className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-indigo-300 overflow-x-auto max-h-96">
                    {JSON.stringify(activeItem.structuredPayload, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-500 text-xs">
              Select an artifact collection from the left panel to inspect detailed forensic logs.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
