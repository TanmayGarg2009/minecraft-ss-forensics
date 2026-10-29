import React, { useState, useMemo } from 'react';
import { 
  Box, CheckCircle2, Copy, Check, FileCheck, Layers, 
  Terminal, Search, HelpCircle 
} from 'lucide-react';
import type { ReportDetail } from '../../types/report';

interface MinecraftEnvSectionProps {
  report: ReportDetail;
}

export const MinecraftEnvSection: React.FC<MinecraftEnvSectionProps> = ({ report }) => {
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [copiedJvm, setCopiedJvm] = useState(false);
  const [searchMod, setSearchMod] = useState('');
  const [filterVerified, setFilterVerified] = useState<'ALL' | 'VERIFIED' | 'CUSTOM'>('ALL');

  // Look for mod inventory in evidence items
  const modInventoryEvidence = report.evidenceItems.find(
    e => e.type === 'ModInventory' || e.publicEvidenceId.includes('mod')
  );

  const jvmEvidence = report.evidenceItems.find(
    e => e.type === 'JvmArguments' || e.publicEvidenceId.includes('jvm')
  );

  const rawJvm = jvmEvidence?.rawContent || '-Xmx4096M -XX:+UseG1GC -Dminecraft.applet.TargetDirectory=...';

  const mods: any[] = Array.isArray(modInventoryEvidence?.structuredPayload)
    ? modInventoryEvidence.structuredPayload
    : [];

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const copyJvm = () => {
    navigator.clipboard.writeText(rawJvm);
    setCopiedJvm(true);
    setTimeout(() => setCopiedJvm(false), 2000);
  };

  // Parse JVM arguments into categories
  const parsedJvmArgs = useMemo(() => {
    const tokens = rawJvm.split(/\s+/).filter(Boolean);
    const memoryFlags: string[] = [];
    const gcFlags: string[] = [];
    const systemProps: string[] = [];
    const otherFlags: string[] = [];

    tokens.forEach(tok => {
      if (tok.startsWith('-Xmx') || tok.startsWith('-Xms') || tok.startsWith('-Xss')) {
        memoryFlags.push(tok);
      } else if (tok.startsWith('-XX:+Use') || tok.startsWith('-XX:G1') || tok.startsWith('-XX:+Unlock')) {
        gcFlags.push(tok);
      } else if (tok.startsWith('-D')) {
        systemProps.push(tok);
      } else {
        otherFlags.push(tok);
      }
    });

    return { memoryFlags, gcFlags, systemProps, otherFlags };
  }, [rawJvm]);

  // Filtered mods
  const filteredMods = useMemo(() => {
    return mods.filter(m => {
      if (filterVerified === 'VERIFIED' && !m.verified) return false;
      if (filterVerified === 'CUSTOM' && m.verified) return false;
      if (searchMod.trim()) {
        const q = searchMod.toLowerCase();
        const matchName = m.name?.toLowerCase().includes(q);
        const matchHash = m.sha256?.toLowerCase().includes(q);
        if (!matchName && !matchHash) return false;
      }
      return true;
    });
  }, [mods, searchMod, filterVerified]);

  return (
    <div className="space-y-6">
      {/* 1. Header Cards for Loaders and Versions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Versions Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3 shadow-sm">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-200">
            <Box className="w-4 h-4 text-emerald-400" />
            <span>Detected Minecraft Game Versions</span>
          </div>

          <div className="flex flex-wrap gap-2">
            {report.detectedMinecraftVersions?.length > 0 ? (
              report.detectedMinecraftVersions.map((ver, idx) => (
                <span
                  key={idx}
                  className="px-3 py-1 rounded-lg text-xs font-mono font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800"
                >
                  Minecraft {ver}
                </span>
              ))
            ) : (
              <span className="text-xs text-slate-500 italic">No specific game version reported</span>
            )}
          </div>
        </div>

        {/* Loaders Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3 shadow-sm">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-200">
            <Layers className="w-4 h-4 text-indigo-400" />
            <span>Active Mod Loaders & Clients</span>
          </div>

          <div className="flex flex-wrap gap-2">
            {report.detectedLoaders?.length > 0 ? (
              report.detectedLoaders.map((loader, idx) => (
                <span
                  key={idx}
                  className="px-3 py-1 rounded-lg text-xs font-medium bg-slate-950 text-slate-200 border border-slate-800"
                >
                  {loader}
                </span>
              ))
            ) : (
              <span className="text-xs text-slate-500 italic">Vanilla environment or unknown client</span>
            )}
          </div>
        </div>
      </div>

      {/* 2. JVM Launch Arguments Categorized Inspector */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="space-y-0.5">
            <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span>Parsed JVM Launch Arguments (javaw.exe)</span>
            </div>
            <p className="text-xs text-slate-400">
              Command-line flags passed to the Java runtime at game launch
            </p>
          </div>

          <button
            onClick={copyJvm}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition self-start sm:self-auto"
          >
            {copiedJvm ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedJvm ? 'Copied' : 'Copy All Flags'}</span>
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-2">
            <div className="font-bold text-slate-300 uppercase tracking-wider text-[11px]">
              Memory Allocation Flags
            </div>
            <div className="space-y-1">
              {parsedJvmArgs.memoryFlags.length > 0 ? (
                parsedJvmArgs.memoryFlags.map((flag, i) => (
                  <span key={i} className="inline-block px-2 py-0.5 mr-1 mb-1 font-mono text-[11px] rounded bg-slate-900 text-emerald-300 border border-slate-850">
                    {flag}
                  </span>
                ))
              ) : (
                <span className="text-slate-500 italic text-[11px]">Default JVM Memory Limits</span>
              )}
            </div>
          </div>

          <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-2">
            <div className="font-bold text-slate-300 uppercase tracking-wider text-[11px]">
              Garbage Collector Flags
            </div>
            <div className="space-y-1">
              {parsedJvmArgs.gcFlags.length > 0 ? (
                parsedJvmArgs.gcFlags.map((flag, i) => (
                  <span key={i} className="inline-block px-2 py-0.5 mr-1 mb-1 font-mono text-[11px] rounded bg-slate-900 text-indigo-300 border border-slate-850">
                    {flag}
                  </span>
                ))
              ) : (
                <span className="text-slate-500 italic text-[11px]">Standard GC Configuration</span>
              )}
            </div>
          </div>

          <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-2">
            <div className="font-bold text-slate-300 uppercase tracking-wider text-[11px]">
              System Properties & Targets
            </div>
            <div className="space-y-1 overflow-x-auto max-h-32">
              {parsedJvmArgs.systemProps.map((flag, i) => (
                <div key={i} className="font-mono text-[10px] text-slate-400 truncate bg-slate-900 p-1 rounded">
                  {flag}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 3. Installed Mod & JAR Inventory Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 sm:p-5 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <FileCheck className="w-4 h-4 text-emerald-400" />
              <span>Installed Mod & JAR Inventories</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Collected JAR files found in .minecraft/mods or loader directories
            </p>
          </div>

          {/* Search & Filter */}
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
              <input
                type="text"
                placeholder="Search mods..."
                value={searchMod}
                onChange={(e) => setSearchMod(e.target.value)}
                className="pl-8 pr-3 py-1 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div className="inline-flex rounded-lg bg-slate-950 p-0.5 border border-slate-800 text-xs">
              <button
                onClick={() => setFilterVerified('ALL')}
                className={`px-2 py-0.5 rounded font-medium ${filterVerified === 'ALL' ? 'bg-slate-800 text-white' : 'text-slate-400'}`}
              >
                All ({mods.length})
              </button>
              <button
                onClick={() => setFilterVerified('VERIFIED')}
                className={`px-2 py-0.5 rounded font-medium ${filterVerified === 'VERIFIED' ? 'bg-slate-800 text-white' : 'text-slate-400'}`}
              >
                Verified
              </button>
              <button
                onClick={() => setFilterVerified('CUSTOM')}
                className={`px-2 py-0.5 rounded font-medium ${filterVerified === 'CUSTOM' ? 'bg-slate-800 text-white' : 'text-slate-400'}`}
              >
                Custom
              </button>
            </div>
          </div>
        </div>

        {filteredMods.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs">
            {mods.length === 0 ? 'No specific mod inventory records attached to this scan mode.' : 'No mods matched search filters.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                  <th className="py-2.5 px-4">File Name</th>
                  <th className="py-2.5 px-4">Size</th>
                  <th className="py-2.5 px-4">SHA-256 Digest</th>
                  <th className="py-2.5 px-4 text-right">Signature Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredMods.map((mod, idx) => (
                  <tr key={idx} className="hover:bg-slate-850/50 transition">
                    <td className="py-2.5 px-4 font-semibold text-slate-200">
                      {mod.name || 'Unknown JAR'}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                      {mod.sizeBytes ? `${(mod.sizeBytes / 1024).toFixed(1)} KB` : 'N/A'}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">
                      {mod.sha256 ? (
                        <div className="flex items-center gap-2">
                          <span className="truncate max-w-[220px] sm:max-w-xs">{mod.sha256}</span>
                          <button
                            onClick={() => copyHash(mod.sha256)}
                            className="text-slate-400 hover:text-white shrink-0"
                            title="Copy SHA-256"
                          >
                            {copiedHash === mod.sha256 ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      ) : (
                        <span className="text-slate-600">No Hash</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      {mod.verified ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-sans px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                          <CheckCircle2 className="w-3 h-3" />
                          Signature Verified
                        </span>
                      ) : (
                        <span className="text-[11px] font-sans px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                          Unsigned / Custom
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="p-3 bg-slate-950/60 border-t border-slate-800 text-[11px] text-slate-500 flex items-center gap-1.5">
          <HelpCircle className="w-3.5 h-3.5 text-slate-500 shrink-0" />
          <span>Note for staff: Unsigned custom mods are common in Minecraft (custom texture packs, personal HUDs). An unsigned mod does not inherently indicate malicious intent.</span>
        </div>
      </div>
    </div>
  );
};
