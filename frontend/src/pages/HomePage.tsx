import React, { useState } from 'react';
import { 
  Shield, ArrowRight, 
  Lock, Eye, Sparkles, Terminal 
} from 'lucide-react';
import { SYNTHETIC_PRESETS } from '../services/syntheticPresets';
import { submitReport } from '../services/api';

interface HomePageProps {
  onOpenReport: (publicId: string) => void;
  onNavigateIngest: () => void;
}

export const HomePage: React.FC<HomePageProps> = ({ onOpenReport, onNavigateIngest }) => {
  const [reportInput, setReportInput] = useState('');
  const [loadingPreset, setLoadingPreset] = useState<string | null>(null);

  const handleOpenId = (e: React.FormEvent) => {
    e.preventDefault();
    if (reportInput.trim()) {
      onOpenReport(reportInput.trim());
    }
  };

  const handleQuickLaunchPreset = async (preset: typeof SYNTHETIC_PRESETS[0]) => {
    setLoadingPreset(preset.id);
    try {
      const res = await submitReport(preset.payload);
      onOpenReport(res.publicId);
    } catch (err: any) {
      alert(`Error submitting preset: ${err.message}`);
    } finally {
      setLoadingPreset(null);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-12">
      {/* Hero Section */}
      <div className="text-center max-w-3xl mx-auto space-y-4">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">
          <Shield className="w-3.5 h-3.5" />
          <span>Stage 1: Production-Grade Ingestion & Web Report Viewer</span>
        </div>

        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight leading-tight">
          Minecraft Screenshare <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-teal-300">
            Forensic Investigation Platform
          </span>
        </h1>

        <p className="text-sm sm:text-base text-slate-400 max-w-2xl mx-auto leading-relaxed">
          Fast, consent-driven diagnostic reporting for Minecraft anti-cheat and server staff. View comprehensive execution artifacts, process memory metadata, and NTFS journal traces via unguessable bearer links.
        </p>

        {/* Quick Report ID Lookup */}
        <div className="pt-4 max-w-md mx-auto">
          <form onSubmit={handleOpenId} className="flex gap-2">
            <input
              type="text"
              placeholder="Paste Report ID (e.g. mc_...)"
              value={reportInput}
              onChange={(e) => setReportInput(e.target.value)}
              className="flex-1 px-4 py-2.5 text-xs bg-slate-900 border border-slate-800 rounded-xl font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
            <button
              type="submit"
              className="px-5 py-2.5 text-xs font-bold rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white transition shrink-0"
            >
              View Report
            </button>
          </form>
        </div>
      </div>

      {/* Quick Launch Realistic Presets */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-emerald-400" />
              <span>Explore Realistic Synthetic Investigations</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Instantly ingest and render pre-configured forensic scenarios in the live report viewer
            </p>
          </div>

          <button
            onClick={onNavigateIngest}
            className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1"
          >
            <span>Custom JSON Lab</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {SYNTHETIC_PRESETS.map((preset) => {
            const isLoading = loadingPreset === preset.id;

            return (
              <div
                key={preset.id}
                className="bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition flex flex-col justify-between space-y-4"
              >
                <div className="space-y-2">
                  <div className="text-sm font-bold text-slate-100">{preset.name}</div>
                  <p className="text-xs text-slate-400 leading-relaxed">{preset.subtitle}</p>
                </div>

                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
                  <span className="text-[11px] font-mono text-slate-500">
                    {preset.payload.findings.length} Finding{preset.payload.findings.length === 1 ? '' : 's'}
                  </span>

                  <button
                    onClick={() => handleQuickLaunchPreset(preset)}
                    disabled={isLoading}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 transition disabled:opacity-50"
                  >
                    <span>{isLoading ? 'Ingesting...' : 'Launch Report'}</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Feature Highlights Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-4">
        <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-5 space-y-2">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center">
            <Lock className="w-4 h-4" />
          </div>
          <div className="font-bold text-sm text-slate-200">Unguessable Bearer Links</div>
          <p className="text-xs text-slate-400 leading-relaxed">
            144 bits of cryptographic entropy per public URL. No sequential report IDs, no login walls, and automatic configurable retention expiration.
          </p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-5 space-y-2">
          <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 flex items-center justify-center">
            <Eye className="w-4 h-4" />
          </div>
          <div className="font-bold text-sm text-slate-200">Transparent Anti-Slop Analysis</div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Distinguishes observations from indicators. Shows potential false positives alongside findings and explicitly avoids misleading "cheat probability" scores.
          </p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-5 space-y-2">
          <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 flex items-center justify-center">
            <Terminal className="w-4 h-4" />
          </div>
          <div className="font-bold text-sm text-slate-200">Clean Stage 2 Agent Contract</div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Fully documented REST OpenAPI contract ready for the Windows native scanner executable in Stage 2 with zero changes to the backend.
          </p>
        </div>
      </div>
    </div>
  );
};
