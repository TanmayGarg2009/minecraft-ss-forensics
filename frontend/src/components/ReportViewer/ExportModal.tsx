import React, { useState } from 'react';
import { Download, Copy, Check, X, FileJson, Printer } from 'lucide-react';
import type { ReportDetail } from '../../types/report';

interface ExportModalProps {
  report: ReportDetail;
  isOpen: boolean;
  onClose: () => void;
}

export const ExportModal: React.FC<ExportModalProps> = ({ report, isOpen, onClose }) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const jsonString = JSON.stringify(report, null, 2);

  const handleDownload = () => {
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `minecraft-ss-report-${report.publicId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative space-y-4 max-h-[90vh] flex flex-col">
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-slate-500 hover:text-slate-200"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-emerald-950/70 border border-emerald-800/80 text-emerald-400">
            <FileJson className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-100">Export Forensic Report Data</h3>
            <p className="text-xs text-slate-400">Standardized Schema v{report.schemaVersion} Export</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 no-print">
          <button
            onClick={handleDownload}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white transition"
          >
            <Download className="w-4 h-4" />
            <span>Download .json file</span>
          </button>

          <button
            onClick={handleCopy}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            <span>{copied ? 'Copied to Clipboard' : 'Copy JSON'}</span>
          </button>

          <button
            onClick={() => {
              onClose();
              window.print();
            }}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            <Printer className="w-4 h-4 text-slate-400" />
            <span>Print Report View</span>
          </button>
        </div>

        {/* JSON Preview */}
        <div className="flex-1 overflow-hidden flex flex-col pt-2">
          <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1">
            Raw JSON Preview
          </div>
          <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-emerald-300 overflow-y-auto flex-1 max-h-72">
            {jsonString}
          </pre>
        </div>
      </div>
    </div>
  );
};
