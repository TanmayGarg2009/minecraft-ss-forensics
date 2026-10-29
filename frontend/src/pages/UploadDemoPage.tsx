import React, { useState } from 'react';
import { 
  UploadCloud, Sparkles, AlertTriangle, CheckCircle2, 
  Copy, Check, ArrowRight, ShieldAlert, Code 
} from 'lucide-react';
import { SYNTHETIC_PRESETS } from '../services/syntheticPresets';
import { submitReport } from '../services/api';
import type { SubmitReportResponse } from '../types/report';

interface UploadDemoPageProps {
  onOpenReport: (publicId: string) => void;
}

export const UploadDemoPage: React.FC<UploadDemoPageProps> = ({ onOpenReport }) => {
  const [selectedPresetId, setSelectedPresetId] = useState(SYNTHETIC_PRESETS[1].id);
  const [jsonContent, setJsonContent] = useState(
    JSON.stringify(SYNTHETIC_PRESETS[1].payload, null, 2)
  );
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<SubmitReportResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const handleSelectPreset = (preset: typeof SYNTHETIC_PRESETS[0]) => {
    setSelectedPresetId(preset.id);
    setJsonContent(JSON.stringify(preset.payload, null, 2));
    setResponse(null);
    setError(null);
  };

  const handleCopy = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResponse(null);

    let parsedPayload: any;
    try {
      parsedPayload = JSON.parse(jsonContent);
    } catch (err: any) {
      setError(`Invalid JSON syntax: ${err.message}`);
      setLoading(false);
      return;
    }

    try {
      const res = await submitReport(parsedPayload);
      setResponse(res);
    } catch (err: any) {
      setError(err.message || 'Report submission failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Page Header */}
      <div className="space-y-2">
        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Stage 1 Ingestion Simulator & Test Laboratory</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          Submit Forensic Reports to Live Backend
        </h1>
        <p className="text-sm text-slate-400 max-w-2xl leading-relaxed">
          Test the end-to-end report pipeline. Choose a realistic synthetic forensic preset or paste custom JSON from a future Stage 2 scanner to ingest and generate a shareable viewer link.
        </p>
      </div>

      {/* Preset Cards Selector */}
      <div className="space-y-3">
        <div className="text-xs font-bold text-slate-400 uppercase tracking-wider">
          Choose a Realistic Synthetic Scenario
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {SYNTHETIC_PRESETS.map((preset) => {
            const isSelected = preset.id === selectedPresetId;
            return (
              <div
                key={preset.id}
                onClick={() => handleSelectPreset(preset)}
                className={`p-4 rounded-xl border text-left cursor-pointer transition ${
                  isSelected
                    ? 'bg-slate-800/90 border-emerald-500 shadow-md ring-1 ring-emerald-500'
                    : 'bg-slate-900 border-slate-800 hover:bg-slate-850 hover:border-slate-700'
                }`}
              >
                <div className="font-bold text-sm text-slate-100 flex items-center justify-between">
                  <span>{preset.name}</span>
                  {isSelected && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                </div>
                <div className="text-xs text-slate-400 mt-1 leading-relaxed">
                  {preset.subtitle}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Ingestion Form & JSON Editor */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 items-start">
        {/* Editor (3 cols) */}
        <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-slate-300 flex items-center gap-1.5 uppercase tracking-wider text-[11px]">
              <Code className="w-3.5 h-3.5 text-emerald-400" />
              <span>Report Submission Payload (JSON)</span>
            </span>
            <span className="text-slate-500 font-mono">Schema 1.0.0</span>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <textarea
              rows={16}
              value={jsonContent}
              onChange={(e) => setJsonContent(e.target.value)}
              className="w-full p-3.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-emerald-300 placeholder-slate-600 focus:outline-none focus:border-emerald-500 leading-relaxed resize-y"
            />

            {error && (
              <div className="p-3 bg-red-950/50 border border-red-800/60 rounded-lg text-xs text-red-300 flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span className="leading-relaxed">{error}</span>
              </div>
            )}

            <div className="flex items-center justify-between pt-2">
              <span className="text-xs text-slate-500">
                Payload validated against strict server schemas
              </span>

              <button
                type="submit"
                disabled={loading}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-md transition disabled:opacity-50"
              >
                <UploadCloud className="w-4 h-4" />
                <span>{loading ? 'Submitting Report...' : 'Ingest to Backend API'}</span>
              </button>
            </div>
          </form>
        </div>

        {/* Live Response Panel (2 cols) */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Backend API Ingestion Response</span>
            </h2>

            {response ? (
              <div className="space-y-4">
                <div className="p-3 bg-emerald-950/40 border border-emerald-800/60 rounded-lg text-xs text-emerald-300 space-y-1">
                  <div className="font-semibold">{response.message}</div>
                  <div className="text-[11px] text-emerald-400/80">
                    Ingested {response.findingsCount} findings • Status: {response.processingStatus}
                  </div>
                </div>

                {/* Generated Public ID */}
                <div className="space-y-1 text-xs">
                  <div className="text-slate-400 font-semibold">Generated Public ID:</div>
                  <div className="p-2 bg-slate-950 rounded border border-slate-800 font-mono text-emerald-400 flex items-center justify-between">
                    <span>{response.publicId}</span>
                    <button
                      onClick={() => handleCopy(response.publicId, 'id')}
                      className="text-slate-500 hover:text-white"
                      title="Copy Public ID"
                    >
                      {copiedField === 'id' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                {/* Shareable Bearer URL */}
                <div className="space-y-1 text-xs">
                  <div className="text-slate-400 font-semibold">Shareable Public URL:</div>
                  <div className="p-2 bg-slate-950 rounded border border-slate-800 font-mono text-slate-200 text-[11px] break-all flex items-center justify-between gap-2">
                    <span>{response.shareUrl}</span>
                    <button
                      onClick={() => handleCopy(response.shareUrl, 'share')}
                      className="text-slate-500 hover:text-white shrink-0"
                      title="Copy URL"
                    >
                      {copiedField === 'share' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                {/* Secret Deletion Key Callout */}
                <div className="p-3 bg-amber-950/30 border border-amber-800/60 rounded-lg space-y-2 text-xs">
                  <div className="flex items-center gap-1.5 text-amber-300 font-bold">
                    <ShieldAlert className="w-4 h-4 text-amber-400" />
                    <span>Secret Deletion Key (Save Now!)</span>
                  </div>
                  <p className="text-amber-200/80 text-[11px] leading-relaxed">
                    This key is only returned once. It is stored exclusively as an HMAC-SHA256 hash in the database and will never be shown again.
                  </p>
                  <div className="p-2 bg-slate-950 rounded border border-amber-800/50 font-mono text-amber-300 text-[11px] break-all flex items-center justify-between gap-2">
                    <span>{response.deletionKey}</span>
                    <button
                      onClick={() => handleCopy(response.deletionKey, 'del')}
                      className="text-amber-400 hover:text-white shrink-0"
                      title="Copy Deletion Key"
                    >
                      {copiedField === 'del' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                {/* Open in Viewer Button */}
                <button
                  onClick={() => onOpenReport(response.publicId)}
                  className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-md transition"
                >
                  <span>Open Report in Viewer</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <div className="text-center py-12 text-slate-500 text-xs space-y-2">
                <UploadCloud className="w-8 h-8 text-slate-700 mx-auto" />
                <p>Submit a payload to view generated bearer links and cryptographic keys.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
