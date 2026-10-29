import React, { useEffect, useState } from 'react';
import { Shield, UploadCloud, ExternalLink } from 'lucide-react';
import { fetchHealth } from '../../services/api';

interface NavbarProps {
  currentPublicId?: string;
  onNavigateHome: () => void;
  onNavigateIngest: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onNavigateHome, onNavigateIngest }) => {
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [lookupId, setLookupId] = useState('');

  useEffect(() => {
    fetchHealth()
      .then(res => setHealthy(res.status === 'Healthy'))
      .catch(() => setHealthy(false));
  }, []);

  const handleLookup = (e: React.FormEvent) => {
    e.preventDefault();
    if (lookupId.trim()) {
      window.location.hash = `#/report/${lookupId.trim()}`;
      setLookupId('');
    }
  };

  return (
    <header className="sticky top-0 z-40 bg-slate-900/90 backdrop-blur border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3 cursor-pointer" onClick={onNavigateHome}>
          <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="font-bold text-slate-100 flex items-center gap-2 text-sm sm:text-base">
              Minecraft SS Forensics
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                Stage 1
              </span>
            </div>
            <div className="text-xs text-slate-400 hidden sm:block">Open-Source Screenshare Forensic Reporting</div>
          </div>
        </div>

        {/* Quick lookup form */}
        <form onSubmit={handleLookup} className="hidden md:flex items-center gap-2">
          <input
            type="text"
            placeholder="Report ID (e.g. mc_...)"
            value={lookupId}
            onChange={(e) => setLookupId(e.target.value)}
            className="px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-md text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-44 font-mono"
          />
          <button
            type="submit"
            className="px-2.5 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md font-medium transition"
          >
            Open
          </button>
        </form>

        {/* Navigation links & status */}
        <div className="flex items-center gap-3 sm:gap-4">
          <button
            onClick={onNavigateIngest}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 transition"
          >
            <UploadCloud className="w-4 h-4" />
            <span>Ingest & Demo</span>
          </button>

          <a
            href="http://localhost:5000/swagger"
            target="_blank"
            rel="noreferrer"
            className="hidden sm:flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 transition"
          >
            <span>OpenAPI Spec</span>
            <ExternalLink className="w-3 h-3" />
          </a>

          {/* Health indicator */}
          <div className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-slate-950 border border-slate-800">
            <span
              className={`w-2 h-2 rounded-full ${
                healthy === null ? 'bg-amber-400 animate-pulse' : healthy ? 'bg-emerald-400' : 'bg-red-400'
              }`}
            />
            <span className="text-slate-400 font-mono text-[11px] hidden sm:inline">
              API: {healthy === null ? 'Checking...' : healthy ? 'Online' : 'Offline'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};
