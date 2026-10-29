import React, { useState } from 'react';
import { 
  Trash2, FileCode, AlertTriangle, ShieldCheck, 
  Copy, Check, Search, CheckCircle2 
} from 'lucide-react';
import type { ReportDetail } from '../../types/report';

interface DeletedFileInvestigationProps {
  report: ReportDetail;
}

interface DeletedFileItem {
  id: string;
  fileName: string;
  originalPath: string;
  source: string;
  eventType: 'Deleted' | 'Truncated' | 'Overwritten' | 'Renamed' | 'Created';
  timestamp?: string;
  timestampReliability: 'Confirmed Record' | 'Estimated Proximity' | 'Uncertain';
  relatedProcess?: string;
  confidence: 'High' | 'Medium' | 'Low';
  details: string;
  limitations: string;
  isConfirmedLoadedInMinecraft: boolean;
  isConfirmedCheatSignature: boolean;
}

export const DeletedFileInvestigation: React.FC<DeletedFileInvestigationProps> = ({ report }) => {
  const [search, setSearch] = useState('');
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(id);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Extract deleted file records from findings and evidence
  const deletedRecords: DeletedFileItem[] = [];

  report.findings.forEach((f, idx) => {
    if (f.category === 'FileDeletion' || f.evidenceSource === 'UsnJournal' || f.title.toLowerCase().includes('delete')) {
      const fileName = f.filePath ? f.filePath.split(/[\\/]/).pop() || f.title : f.title;
      deletedRecords.push({
        id: `finding-del-${idx}`,
        fileName,
        originalPath: f.filePath || 'Unknown directory',
        source: f.evidenceSource,
        eventType: 'Deleted',
        timestamp: f.firstObservedAt,
        timestampReliability: 'Confirmed Record',
        relatedProcess: f.processName || 'javaw.exe session',
        confidence: f.confidence === 'Certain' || f.confidence === 'High' ? 'High' : 'Medium',
        details: f.explanation,
        limitations: f.limitationsAndFalsePositives || 'File was deleted prior to scan. SHA-256 cannot be computed from deleted USN records alone.',
        isConfirmedLoadedInMinecraft: false,
        isConfirmedCheatSignature: false,
      });
    }
  });

  // Also extract from timeline events tagged with deletion
  report.timelineEvents.forEach((t, idx) => {
    if (t.category.toLowerCase().includes('delete') || t.description.toLowerCase().includes('delete')) {
      if (!deletedRecords.some(r => r.timestamp === t.timestamp)) {
        deletedRecords.push({
          id: `timeline-del-${idx}`,
          fileName: t.description.split(' ')[0] || 'Deleted Artifact',
          originalPath: 'Identified in timeline log',
          source: t.source,
          eventType: 'Deleted',
          timestamp: t.timestamp,
          timestampReliability: t.isInferred ? 'Estimated Proximity' : 'Confirmed Record',
          confidence: 'Medium',
          details: t.description,
          limitations: 'NTFS Change Journal or registry log recorded deletion. File body not available for decompilation.',
          isConfirmedLoadedInMinecraft: false,
          isConfirmedCheatSignature: false,
        });
      }
    }
  });

  // Filtered items
  const filtered = deletedRecords.filter(item => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return item.fileName.toLowerCase().includes(q) || item.originalPath.toLowerCase().includes(q) || item.source.toLowerCase().includes(q);
  });

  return (
    <div className="space-y-6">
      {/* Educational Banner: The 4 Distinct Forensic Claims */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
        <div className="flex items-center gap-2">
          <Trash2 className="w-5 h-5 text-orange-400" />
          <h2 className="text-sm font-bold text-slate-100">
            Historical & Deleted File Forensic Analysis
          </h2>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          Minecraft screenshare investigations frequently encounter deleted files in NTFS USN Journals or temp folders. To prevent wrongful bans, staff must strictly distinguish between these four independent claims:
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-1 text-xs">
          <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-1">
            <div className="font-bold text-slate-200 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <span>1. File Observed</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Record exists in NTFS journal or registry that a file was created or deleted.
            </p>
          </div>

          <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-1">
            <div className="font-bold text-slate-200 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-sky-400" />
              <span>2. Was Executed</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Prefetch, BAM, or Shimcache proves the program executed on the computer.
            </p>
          </div>

          <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-1">
            <div className="font-bold text-slate-200 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              <span>3. Loaded into Game</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Classloader logs or DLL handles prove the code hooked Minecraft memory.
            </p>
          </div>

          <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-1">
            <div className="font-bold text-slate-200 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-red-400" />
              <span>4. Confirmed Cheat</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Hash matches a verified cheat client or bytecode analysis confirms unfair advantage.
            </p>
          </div>
        </div>

        <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs text-amber-300/90 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <p>
            <strong>Investigation Rule:</strong> A deleted file record alone proves ONLY that a file existed and was removed. It does not prove it was injected into Minecraft or used during competitive play.
          </p>
        </div>
      </div>

      {/* Search and Records List */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search deleted filenames, paths, sources..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <span className="text-xs text-slate-400 font-mono">
            {filtered.length} Deleted Artifact Indicator{filtered.length === 1 ? '' : 's'}
          </span>
        </div>

        {filtered.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs space-y-2">
            <CheckCircle2 className="w-8 h-8 text-slate-600 mx-auto" />
            <div className="text-sm font-semibold text-slate-300">No Deleted File Indicators Detected</div>
            <p className="text-slate-500">
              The scan examined NTFS change journal records and found no suspicious file deletion activity in the monitored time window.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {filtered.map((item) => {
              const isExpanded = selectedEventId === item.id;

              return (
                <div
                  key={item.id}
                  className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden hover:border-slate-700 transition shadow-sm"
                >
                  <div
                    onClick={() => setSelectedEventId(isExpanded ? null : item.id)}
                    className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer select-none bg-slate-950/60 hover:bg-slate-900/60"
                  >
                    <div className="flex items-start sm:items-center gap-3">
                      <span className="p-2 rounded-lg bg-orange-950/60 border border-orange-800/80 text-orange-400 shrink-0">
                        <Trash2 className="w-4 h-4" />
                      </span>
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-xs font-bold text-slate-100">{item.fileName}</span>
                          <span className="text-slate-500">•</span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-red-950 text-red-300 border border-red-800">
                            {item.eventType}
                          </span>
                          <span className="text-slate-500">•</span>
                          <span className="text-xs text-slate-400 font-mono">Source: {item.source}</span>
                        </div>
                        <div className="text-xs text-slate-400 truncate max-w-xl font-mono mt-0.5">
                          {item.originalPath}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 self-end sm:self-auto text-xs font-mono text-slate-400">
                      {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : 'Recent Window'}
                    </div>
                  </div>

                  {/* Expanded Forensic Breakdown */}
                  {isExpanded && (
                    <div className="p-4 sm:p-5 pt-0 space-y-4 border-t border-slate-800/80 text-xs">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4">
                        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3 space-y-2">
                          <div className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                            <FileCode className="w-3.5 h-3.5 text-indigo-400" />
                            <span>Observed Location & Path</span>
                          </div>
                          <div className="p-2 bg-slate-950 rounded border border-slate-850 font-mono text-slate-300 break-all flex items-center justify-between gap-2">
                            <span>{item.originalPath}</span>
                            <button
                              onClick={() => handleCopy(item.originalPath, item.id)}
                              className="text-slate-400 hover:text-white shrink-0"
                            >
                              {copiedText === item.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                            </button>
                          </div>
                          <div className="flex justify-between text-slate-400 text-[11px]">
                            <span>Timestamp Reliability:</span>
                            <span className="font-semibold text-slate-200">{item.timestampReliability}</span>
                          </div>
                        </div>

                        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3 space-y-2">
                          <div className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                            <span>Corroboration Boundaries</span>
                          </div>
                          <div className="space-y-1 text-[11px]">
                            <div className="flex justify-between text-slate-400">
                              <span>Loaded into Minecraft:</span>
                              <span className="text-amber-400 font-semibold">Unconfirmed (No hook log)</span>
                            </div>
                            <div className="flex justify-between text-slate-400">
                              <span>Cheat Signature Matched:</span>
                              <span className="text-amber-400 font-semibold">Unconfirmed (File deleted)</span>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Explanation */}
                      <div className="space-y-1">
                        <span className="font-bold text-slate-300 text-[11px] uppercase tracking-wider">
                          Artifact Findings Details:
                        </span>
                        <p className="p-3 bg-slate-900 rounded-lg border border-slate-850 text-slate-300 leading-relaxed">
                          {item.details}
                        </p>
                      </div>

                      {/* Explicit Limitation Box */}
                      <div className="p-3 bg-amber-950/30 border border-amber-800/60 rounded-lg text-amber-200 space-y-1">
                        <div className="font-bold text-amber-300 text-[11px] uppercase tracking-wider flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                          <span>Forensic Limitation & Staff Directive:</span>
                        </div>
                        <p className="text-[11px] text-amber-200/90 leading-relaxed">
                          {item.limitations}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
