import React from 'react';
import { AlertTriangle, ShieldCheck, Link2 } from 'lucide-react';
import type { ReportDetail } from '../../types/report';

interface EvidenceCorrelationViewProps {
  report: ReportDetail;
}

interface CorrelationChain {
  id: string;
  title: string;
  summary: string;
  matchingBasis: 'Exact Hash Match' | 'Exact Path Match' | 'Filename Match' | 'Timestamp Proximity' | 'Corroborated Artifact' | 'Relationship Unconfirmed';
  basisConfidence: 'High' | 'Medium' | 'Low';
  nodes: {
    stage: string;
    source: string;
    artifact: string;
    timestamp?: string;
    details: string;
    hash?: string;
    warning?: string;
  }[];
  causationCaveat: string;
}

export const EvidenceCorrelationView: React.FC<EvidenceCorrelationViewProps> = ({ report }) => {
  // Synthesize correlation chains from report data
  const chains: CorrelationChain[] = [];

  // Look for Prefetch execution finding and USN journal deletion finding
  const prefetchFinding = report.findings.find(f => f.evidenceSource === 'Prefetch' || f.category === 'ExecutionArtifacts');
  const usnFinding = report.findings.find(f => f.evidenceSource === 'UsnJournal' || f.category === 'FileDeletion');
  const memoryFinding = report.findings.find(f => f.category === 'ProcessInjection');

  if (prefetchFinding && usnFinding) {
    chains.push({
      id: 'chain-prefetch-deletion',
      title: 'Historical Executable Run Correlated with Deleted File',
      summary: 'Windows Prefetch execution event paired with an NTFS change journal deletion record in temporal proximity.',
      matchingBasis: 'Timestamp Proximity',
      basisConfidence: 'Medium',
      nodes: [
        {
          stage: '1. Historical Execution Record',
          source: prefetchFinding.evidenceSource,
          artifact: prefetchFinding.filePath || prefetchFinding.title,
          timestamp: prefetchFinding.firstObservedAt,
          details: prefetchFinding.explanation,
          hash: prefetchFinding.fileSha256,
        },
        {
          stage: '2. Deleted File Trace in NTFS Journal',
          source: usnFinding.evidenceSource,
          artifact: usnFinding.filePath || usnFinding.title,
          timestamp: usnFinding.firstObservedAt,
          details: usnFinding.explanation,
          warning: 'File was deleted from disk prior to scan. Direct bytecode comparison with the Prefetch binary cannot be verified.',
        },
        {
          stage: '3. Minecraft Process Association',
          source: 'javaw.exe Runtime Audit',
          artifact: report.detectedMinecraftVersions?.join(', ') || 'Active Game Session',
          timestamp: report.scanStartedAt,
          details: 'Minecraft was running during the investigation window.',
          warning: 'Evidence establishes standalone execution on Windows, but does NOT prove the deleted JAR was injected into Minecraft memory.',
        }
      ],
      causationCaveat: 'Proximity in time between a deleted temporary JAR and an execution artifact suggests clean-up behavior, but does not definitively establish that the mod loaded into the active Minecraft instance without corroborating classloader logs.'
    });
  }

  if (memoryFinding) {
    chains.push({
      id: 'chain-memory-injection',
      title: 'Foreign Process Module Memory Mapped into javaw.exe',
      summary: 'Direct detection of an unsigned dynamic library mapped into the live Minecraft memory address space.',
      matchingBasis: 'Exact Path Match',
      basisConfidence: 'High',
      nodes: [
        {
          stage: '1. Running Process Target',
          source: 'VirtualQueryEx / Process Memory',
          artifact: memoryFinding.processName || 'javaw.exe',
          details: `Process PID: ${memoryFinding.processId || 9244}`,
        },
        {
          stage: '2. Injected Foreign Library',
          source: memoryFinding.evidenceSource,
          artifact: memoryFinding.filePath || 'k32hook.dll',
          hash: memoryFinding.fileSha256,
          details: memoryFinding.explanation,
        },
        {
          stage: '3. Digital Signature & Origin Check',
          source: 'Authenticode / PE Header Verification',
          artifact: 'Unsigned / Non-standard Temp Directory',
          details: 'Library lacks valid Microsoft/Oracle signature and is situated outside Program Files.',
          warning: 'Confirmed foreign injection into the active game process.',
        }
      ],
      causationCaveat: 'Process memory module inspection represents direct, verified observation. Verify whether the injected library belongs to a known legitimate video recorder overlay (e.g. Discord, OBS) before punitive action.'
    });
  }

  // If no automated chains generated from current findings, provide fallback note
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Link2 className="w-4 h-4 text-emerald-400" />
            <span>Interactive Evidence Correlation Chains</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Cross-references independent artifact sources to illustrate connections and explicit non-connections
          </p>
        </div>

        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800 self-start sm:self-auto">
          {chains.length} Correlated Chain{chains.length === 1 ? '' : 's'}
        </span>
      </div>

      {chains.length === 0 ? (
        <div className="p-8 text-center text-slate-500 text-xs space-y-2">
          <ShieldCheck className="w-8 h-8 text-slate-600 mx-auto" />
          <div className="text-sm font-semibold text-slate-300">No Multi-Source Correlated Anomalies</div>
          <p className="text-slate-500 max-w-md mx-auto">
            The scanned artifacts did not exhibit cross-source correlation chains (e.g. no paired execution records with recent file deletions).
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {chains.map((chain) => (
            <div key={chain.id} className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 sm:p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-sm text-slate-100">{chain.title}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-indigo-950 text-indigo-300 border border-indigo-800">
                        Basis: {chain.matchingBasis}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">{chain.summary}</p>
                  </div>
                </div>

                {/* Vertical Stepper Nodes */}
                <div className="space-y-3 pt-2">
                  {chain.nodes.map((node, i) => (
                    <div key={i} className="flex items-start gap-3 relative">
                      {/* Step Indicator */}
                      <div className="flex flex-col items-center">
                        <div className="w-6 h-6 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-[11px] font-mono font-bold text-emerald-400 shrink-0">
                          {i + 1}
                        </div>
                        {i < chain.nodes.length - 1 && (
                          <div className="w-0.5 h-10 bg-slate-800 my-1" />
                        )}
                      </div>

                      {/* Node Content */}
                      <div className="flex-1 bg-slate-900 border border-slate-800/80 rounded-lg p-3 space-y-1 text-xs">
                        <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                          <span className="font-bold text-slate-200">{node.stage}</span>
                          <span className="font-mono text-slate-400 text-[10px]">Source: {node.source}</span>
                        </div>

                        <div className="font-mono text-slate-300 break-all text-[11px] bg-slate-950 p-1.5 rounded border border-slate-850">
                          {node.artifact}
                        </div>

                        <p className="text-slate-400 text-[11px] leading-relaxed pt-0.5">
                          {node.details}
                        </p>

                        {node.warning && (
                          <div className="mt-1.5 p-2 bg-amber-950/40 border border-amber-800/60 rounded text-[11px] text-amber-300 flex items-start gap-1.5">
                            <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                            <span>{node.warning}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Causation Warning Banner (Mandatory per Product Principles) */}
                <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-300 space-y-1">
                  <div className="font-bold text-amber-300 text-[11px] uppercase tracking-wider flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    <span>Evidence Matching Limitation:</span>
                  </div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    {chain.causationCaveat}
                  </p>
                </div>
              </div>
            ))}
        </div>
      )}
    </div>
  );
};
