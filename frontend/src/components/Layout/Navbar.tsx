import React, { useEffect, useState } from 'react';
import { Shield, UploadCloud, ExternalLink, Sun, Moon, Search } from 'lucide-react';
import { fetchHealth } from '../../services/api';
import { useTheme } from '../../context/ThemeContext';

interface NavbarProps {
  currentPublicId?: string;
  onNavigateHome: () => void;
  onNavigateIngest: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onNavigateHome, onNavigateIngest }) => {
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [lookupId, setLookupId] = useState('');
  const { theme, toggleTheme } = useTheme();

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
    <header className="sticky top-0 z-40 bg-slate-900/90 backdrop-blur border-b border-slate-800 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Brand */}
        <div 
          className="flex items-center gap-3 cursor-pointer select-none group" 
          onClick={onNavigateHome}
        >
          <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 group-hover:border-emerald-500 transition">
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
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
            <input
              type="text"
              placeholder="Report ID (mc_...)"
              value={lookupId}
              onChange={(e) => setLookupId(e.target.value)}
              className="pl-7 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-md text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-44 font-mono transition"
            />
          </div>
          <button
            type="submit"
            className="px-2.5 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md font-medium transition"
          >
            Open
          </button>
        </form>

        {/* Navigation links, theme toggle & status */}
        <div className="flex items-center gap-2 sm:gap-3">
          <button
            onClick={onNavigateIngest}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 transition shadow-sm"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span>Ingest & Demo</span>
          </button>

          <a
            href="http://localhost:5000/swagger"
            target="_blank"
            rel="noreferrer"
            className="hidden lg:flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 transition px-2 py-1"
          >
            <span>OpenAPI Spec</span>
            <ExternalLink className="w-3 h-3" />
          </a>

          {/* Theme Toggle Button */}
          <button
            onClick={toggleTheme}
            className="p-1.5 text-slate-400 hover:text-slate-100 bg-slate-950 hover:bg-slate-800 rounded-md border border-slate-800 transition"
            title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
            aria-label="Toggle color theme"
          >
            {theme === 'dark' ? (
              <Sun className="w-4 h-4 text-amber-400" />
            ) : (
              <Moon className="w-4 h-4 text-indigo-400" />
            )}
          </button>

          {/* Backend API Health indicator */}
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
