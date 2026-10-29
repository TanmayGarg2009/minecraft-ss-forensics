import React, { useState } from 'react';
import { FileJson, Copy, Check, Download, X, Search } from 'lucide-react';
import type { ReportDetail } from '../../types/report';

interface RawDataModalProps {
  report: ReportDetail;
  isOpen: boolean;
  onClose: () => void;
}

export const RawDataModal: React.FC<RawDataModalProps> = ({ report, isOpen, onClose }) => {
  const [copied, setCopied] = useState(false);
  const [search, setSearch] = useState('');

  if (!isOpen) return null;

  const rawJson = JSON.stringify(report, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(rawJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([rawJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${report.publicId}-raw.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full p-5 sm:p-6 shadow-2xl flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-emerald-950 border border-emerald-800 text-emerald-400">
              <FileJson className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100">Raw Diagnostic Report (JSON)</h3>
              <p className="text-[11px] text-slate-400">Schema v{report.schemaVersion} • Public ID: {report.publicId}</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>

            <button
              onClick={handleDownload}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white transition"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download</span>
            </button>

            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white p-1 ml-2"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Search bar inside JSON */}
        <div className="my-3 relative">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Filter lines in raw payload..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
          />
        </div>

        {/* Syntax-colored JSON container */}
        <div className="flex-1 overflow-auto bg-slate-950 border border-slate-800/80 rounded-xl p-4 font-mono text-xs text-emerald-300/90 leading-relaxed max-h-[60vh]">
          <pre className="whitespace-pre-wrap">
            {search.trim()
              ? rawJson
                  .split('\n')
                  .filter(line => line.toLowerCase().includes(search.toLowerCase()))
                  .join('\n')
              : rawJson}
          </pre>
        </div>
      </div>
    </div>
  );
};
