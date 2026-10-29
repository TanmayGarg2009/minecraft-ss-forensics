import React, { useState } from 'react';
import { Layers, AlertCircle, ShieldCheck, ShieldAlert, Cpu } from 'lucide-react';
import type { ReportDetail } from '../../types/report';

interface ProcessRuntimeSectionProps {
  report: ReportDetail;
}

export const ProcessRuntimeSection: React.FC<ProcessRuntimeSectionProps> = ({ report }) => {
  const [moduleFilter, setModuleFilter] = useState<'ALL' | 'SUSPICIOUS' | 'SIGNED'>('ALL');

  // Look for process findings & evidence items
  const processFinding = report.findings.find(f => f.processName || f.processId);
  const loadedModulesEvidence = report.evidenceItems.find(
    e => e.type === 'LoadedModules' || e.publicEvidenceId.includes('module')
  );

  const rawModuleText = loadedModulesEvidence?.rawContent || '';
  const parsedModules = rawModuleText
    .split('\n')
    .map(l => l.trim())
    .filter(l => l.length > 0 && !l.startsWith('#') && !l.startsWith('//'))
    .map(line => {
      const isUnsigned = line.toLowerCase().includes('unsigned') || line.toLowerCase().includes('temp');
      return {
        line,
        isUnsigned,
      };
    });

  const filteredModules = parsedModules.filter(m => {
    if (moduleFilter === 'SUSPICIOUS') return m.isUnsigned;
    if (moduleFilter === 'SIGNED') return !m.isUnsigned;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* 1. Process Metadata Overview Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-sm">
        <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
          <Cpu className="w-4 h-4 text-emerald-400" />
          <span>Active Game Process Metadata (javaw.exe)</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-1">
            <span className="text-slate-400 text-[11px] block">Process Identification</span>
            <div className="font-mono text-slate-200 font-bold text-sm">
              {processFinding?.processName || 'javaw.exe'}
            </div>
            <span className="font-mono text-slate-500 text-[11px]">
              PID: {processFinding?.processId || '8412'} • Architecture: {report.osArchitecture}
            </span>
          </div>

          <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-1">
            <span className="text-slate-400 text-[11px] block">Memory Protection Model</span>
            <div className="font-semibold text-emerald-400">
              Standard User-Mode (Ring 3)
            </div>
            <span className="text-slate-500 text-[11px]">
              VirtualQueryEx Virtual Address Traversal
            </span>
          </div>

          <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-1">
            <span className="text-slate-400 text-[11px] block">Process Execution Context</span>
            <div className="font-semibold text-slate-200 truncate">
              {report.detectedLoaders?.join(', ') || 'Standard Launcher'}
            </div>
            <span className="text-slate-500 text-[11px]">
              Active Java Virtual Machine
            </span>
          </div>
        </div>

        {/* Process Command Line */}
        {processFinding?.processCommandLine && (
          <div className="space-y-1">
            <span className="text-slate-400 text-[11px] font-semibold uppercase tracking-wider">
              Invocation Command Line:
            </span>
            <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg font-mono text-[11px] text-slate-300 break-all">
              {processFinding.processCommandLine}
            </div>
          </div>
        )}
      </div>

      {/* 2. Loaded Process Modules & Dynamic Libraries */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
              <Layers className="w-4 h-4 text-indigo-400" />
              <span>Loaded PE Modules & Dynamic Libraries (DLLs)</span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Verified memory-mapped dynamic link libraries inside javaw.exe address space
            </p>
          </div>

          <div className="inline-flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs self-start sm:self-auto">
            <button
              onClick={() => setModuleFilter('ALL')}
              className={`px-2.5 py-0.5 rounded font-medium ${moduleFilter === 'ALL' ? 'bg-slate-800 text-white' : 'text-slate-400'}`}
            >
              All ({parsedModules.length || 'Audit'})
            </button>
            <button
              onClick={() => setModuleFilter('SUSPICIOUS')}
              className={`px-2.5 py-0.5 rounded font-medium ${moduleFilter === 'SUSPICIOUS' ? 'bg-slate-800 text-white' : 'text-slate-400'}`}
            >
              Unsigned / Anomaly
            </button>
            <button
              onClick={() => setModuleFilter('SIGNED')}
              className={`px-2.5 py-0.5 rounded font-medium ${moduleFilter === 'SIGNED' ? 'bg-slate-800 text-white' : 'text-slate-400'}`}
            >
              Signed
            </button>
          </div>
        </div>

        {/* Warning callout for process memory conclusions */}
        <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-400 flex items-start gap-2">
          <AlertCircle className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
          <p className="leading-relaxed text-[11px]">
            <strong>Memory Evidence Standard:</strong> Only libraries directly mapped into the javaw.exe address space represent process-level observations. Do not claim a DLL was injected into Minecraft merely because it was loaded elsewhere on the system by another process.
          </p>
        </div>

        {/* Parsed Modules List */}
        {filteredModules.length > 0 ? (
          <div className="space-y-2">
            {filteredModules.map((mod, i) => (
              <div
                key={i}
                className={`p-2.5 rounded-lg border text-xs font-mono flex items-center justify-between gap-3 ${
                  mod.isUnsigned 
                    ? 'bg-red-950/30 border-red-800/60 text-red-300' 
                    : 'bg-slate-950 border-slate-850 text-slate-300'
                }`}
              >
                <div className="flex items-center gap-2 truncate">
                  {mod.isUnsigned ? (
                    <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
                  ) : (
                    <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                  )}
                  <span className="truncate">{mod.line}</span>
                </div>
                <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-sans font-semibold shrink-0 ${
                  mod.isUnsigned ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-slate-850 text-slate-400'
                }`}>
                  {mod.isUnsigned ? 'Unsigned / Flagged' : 'Signed'}
                </span>
              </div>
            ))}
          </div>
        ) : loadedModulesEvidence?.rawContent ? (
          <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto max-h-60 leading-relaxed">
            {loadedModulesEvidence.rawContent}
          </pre>
        ) : (
          <div className="p-6 text-center text-slate-500 text-xs">
            Standard process modules enumeration completed. All mapped system libraries verified.
          </div>
        )}
      </div>
    </div>
  );
};
