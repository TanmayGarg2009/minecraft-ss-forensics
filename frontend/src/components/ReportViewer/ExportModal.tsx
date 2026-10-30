import React, { useState, useMemo } from 'react';
import { Download, Copy, Check, X, FileJson, FileText, Printer, Sparkles, AlertCircle } from 'lucide-react';
import type { ReportDetail } from '../../types/report';
import { 
  exportReportToJson, 
  exportReportToMarkdown, 
  downloadReportFile, 
  generateSuggestedFilename 
} from '../../utils/reportExporter';

interface ExportModalProps {
  report: ReportDetail;
  isOpen: boolean;
  onClose: () => void;
}

export const ExportModal: React.FC<ExportModalProps> = ({ report, isOpen, onClose }) => {
  const [activeTab, setActiveTab] = useState<'json' | 'md'>('json');
  const [copied, setCopied] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const jsonString = useMemo(() => {
    try {
      return exportReportToJson(report);
    } catch (e: any) {
      return `// Error generating JSON export: ${e.message}`;
    }
  }, [report]);

  const mdString = useMemo(() => {
    try {
      return exportReportToMarkdown(report);
    } catch (e: any) {
      return `<!-- Error generating Markdown export: ${e.message} -->`;
    }
  }, [report]);

  if (!isOpen) return null;

  const handleDownload = (format: 'json' | 'md') => {
    try {
      setErrorMsg(null);
      downloadReportFile(report, format);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to download report file.');
    }
  };

  const handleCopyCurrent = () => {
    try {
      const textToCopy = activeTab === 'json' ? jsonString : mdString;
      navigator.clipboard.writeText(textToCopy);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err: any) {
      setErrorMsg('Failed to copy to clipboard.');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full p-6 shadow-2xl relative space-y-4 max-h-[90vh] flex flex-col">
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-slate-500 hover:text-slate-200 transition"
          aria-label="Close export modal"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-sky-950/70 border border-sky-800/80 text-sky-400">
            <Download className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-100">Download Forensic Report</h3>
            <p className="text-xs text-slate-400">
              Portable, self-contained offline reports for human review or second-stage AI analysis
            </p>
          </div>
        </div>

        {errorMsg && (
          <div className="flex items-center gap-2 p-3 bg-red-950/80 border border-red-800 rounded-lg text-xs text-red-200">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Download Buttons Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 no-print">
          <button
            onClick={() => handleDownload('json')}
            className="flex items-center justify-between p-3 rounded-xl bg-slate-800/90 hover:bg-slate-700/90 border border-slate-700 text-left transition group"
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-emerald-950 text-emerald-400 border border-emerald-800">
                <FileJson className="w-5 h-5" />
              </div>
              <div>
                <div className="text-xs font-bold text-slate-200 group-hover:text-emerald-300">
                  Full Forensic JSON (.json)
                </div>
                <div className="text-[11px] text-slate-400">
                  Complete structured data, hashes &amp; diagnostics
                </div>
              </div>
            </div>
            <Download className="w-4 h-4 text-slate-400 group-hover:text-emerald-400 shrink-0 ml-2" />
          </button>

          <button
            onClick={() => handleDownload('md')}
            className="flex items-center justify-between p-3 rounded-xl bg-slate-800/90 hover:bg-slate-700/90 border border-slate-700 text-left transition group"
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-indigo-950 text-indigo-400 border border-indigo-800">
                <Sparkles className="w-5 h-5" />
              </div>
              <div>
                <div className="text-xs font-bold text-slate-200 group-hover:text-indigo-300">
                  AI-Friendly Report (.md)
                </div>
                <div className="text-[11px] text-slate-400">
                  13-section analysis with AI Analysis Guide
                </div>
              </div>
            </div>
            <Download className="w-4 h-4 text-slate-400 group-hover:text-indigo-400 shrink-0 ml-2" />
          </button>
        </div>

        {/* Secondary Actions & Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => setActiveTab('json')}
              className={`inline-flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded-md transition ${
                activeTab === 'json'
                  ? 'bg-slate-800 text-emerald-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileJson className="w-3.5 h-3.5" />
              <span>JSON Preview</span>
            </button>
            <button
              onClick={() => setActiveTab('md')}
              className={`inline-flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded-md transition ${
                activeTab === 'md'
                  ? 'bg-slate-800 text-indigo-400 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Markdown Preview</span>
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyCurrent}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied!' : `Copy ${activeTab === 'json' ? 'JSON' : 'Markdown'}`}</span>
            </button>

            <button
              onClick={() => {
                onClose();
                window.print();
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
            >
              <Printer className="w-3.5 h-3.5 text-slate-400" />
              <span>Print</span>
            </button>
          </div>
        </div>

        {/* Content Preview */}
        <div className="flex-1 overflow-hidden flex flex-col pt-1">
          <div className="flex items-center justify-between text-[11px] text-slate-400 mb-1">
            <span className="font-mono text-slate-500">
              {generateSuggestedFilename(report, activeTab)}
            </span>
            <span className="text-slate-500">
              {activeTab === 'json' ? `${jsonString.length.toLocaleString()} chars` : `${mdString.length.toLocaleString()} chars`}
            </span>
          </div>
          <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-emerald-300 overflow-y-auto flex-1 max-h-64 leading-relaxed select-text">
            {activeTab === 'json' ? jsonString : mdString}
          </pre>
        </div>
      </div>
    </div>
  );
};
