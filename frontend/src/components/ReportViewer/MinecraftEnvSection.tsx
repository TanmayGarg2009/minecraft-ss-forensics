import React, { useState } from 'react';
import { Box, CheckCircle2, Copy, Check, FileCheck, Layers } from 'lucide-react';
import type { ReportDetail } from '../../types/report';

interface MinecraftEnvSectionProps {
  report: ReportDetail;
}

export const MinecraftEnvSection: React.FC<MinecraftEnvSectionProps> = ({ report }) => {
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Look for mod inventory in evidence items
  const modInventoryEvidence = report.evidenceItems.find(
    e => e.type === 'ModInventory' || e.publicEvidenceId.includes('mod')
  );

  const mods: any[] = Array.isArray(modInventoryEvidence?.structuredPayload)
    ? modInventoryEvidence.structuredPayload
    : [];

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Cards for Loaders and Versions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Versions Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-200">
            <Box className="w-4 h-4 text-emerald-400" />
            <span>Detected Minecraft Versions</span>
          </div>

          <div className="flex flex-wrap gap-2">
            {report.detectedMinecraftVersions?.length > 0 ? (
              report.detectedMinecraftVersions.map((ver, idx) => (
                <span
                  key={idx}
                  className="px-3 py-1 rounded-lg text-xs font-mono font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-800"
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
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
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

      {/* Mod and JAR Inventory Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <FileCheck className="w-4 h-4 text-emerald-400" />
              <span>Installed Mod & JAR Inventories</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Collected JAR files found in .minecraft/mods or loader directories
            </p>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {mods.length} file{mods.length === 1 ? '' : 's'} recorded
          </span>
        </div>

        {mods.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs">
            No specific mod inventory records attached to this scan mode.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                  <th className="py-3 px-4">File Name</th>
                  <th className="py-3 px-4">Size</th>
                  <th className="py-3 px-4">SHA-256 Digest</th>
                  <th className="py-3 px-4 text-right">Integrity Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {mods.map((mod, idx) => (
                  <tr key={idx} className="hover:bg-slate-850/50 transition">
                    <td className="py-3 px-4 font-semibold text-slate-200">
                      {mod.name || 'Unknown JAR'}
                    </td>
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      {mod.sizeBytes ? `${(mod.sizeBytes / 1024).toFixed(1)} KB` : 'N/A'}
                    </td>
                    <td className="py-3 px-4 text-slate-300">
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
                    <td className="py-3 px-4 text-right">
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
      </div>
    </div>
  );
};
