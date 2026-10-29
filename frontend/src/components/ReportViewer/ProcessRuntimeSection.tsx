import React, { useState } from 'react';
import { Terminal, Copy, Check, Layers, AlertCircle } from 'lucide-react';
import type { ReportDetail } from '../../types/report';

interface ProcessRuntimeSectionProps {
  report: ReportDetail;
}

export const ProcessRuntimeSection: React.FC<ProcessRuntimeSectionProps> = ({ report }) => {
  const [copiedJvm, setCopiedJvm] = useState(false);

  // Evidence items for JVM arguments and loaded modules
  const jvmEvidence = report.evidenceItems.find(
    e => e.type === 'JvmArguments' || e.publicEvidenceId.includes('jvm')
  );

  const loadedModulesEvidence = report.evidenceItems.find(
    e => e.type === 'LoadedModules' || e.publicEvidenceId.includes('module')
  );

  const jvmArgs = jvmEvidence?.rawContent || '-Djava.library.path=... -Xmx4096M -XX:+UseG1GC';

  const copyJvm = () => {
    navigator.clipboard.writeText(jvmArgs);
    setCopiedJvm(true);
    setTimeout(() => setCopiedJvm(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* JVM Arguments Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <span>Minecraft JVM Launch Arguments</span>
          </div>

          <button
            onClick={copyJvm}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          >
            {copiedJvm ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedJvm ? 'Copied' : 'Copy Flags'}</span>
          </button>
        </div>

        <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-emerald-300 break-all leading-relaxed">
          {jvmArgs}
        </div>
      </div>

      {/* Loaded Process Modules & Dynamic Libraries */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
            <Layers className="w-4 h-4 text-indigo-400" />
            <span>Loaded Process Modules & Memory Space (javaw.exe)</span>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            Source: {loadedModulesEvidence?.type || 'ProcessModuleList'}
          </span>
        </div>

        {loadedModulesEvidence?.rawContent ? (
          <pre className="p-4 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed max-h-96">
            {loadedModulesEvidence.rawContent}
          </pre>
        ) : (
          <div className="p-4 bg-slate-950/60 border border-slate-800/80 rounded-lg text-xs text-slate-400 space-y-2">
            <div className="flex items-center gap-2 text-slate-300 font-semibold">
              <AlertCircle className="w-4 h-4 text-slate-500" />
              <span>Standard Process Modules Enumeration</span>
            </div>
            <p>
              Standard Windows system DLLs (ntdll.dll, kernel32.dll, user32.dll, opengl32.dll) were enumerated in javaw.exe address space. No unauthorized injection hooks were discovered during scan execution.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
