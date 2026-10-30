import React, { useState, useMemo } from 'react';
import { 
  ChevronDown, ChevronUp, Copy, Check, AlertTriangle, 
  ShieldAlert, HelpCircle, Eye, Info, Search
} from 'lucide-react';
import type { ReportDetail } from '../../types/report';
import { SeverityBadge, ConfidenceBadge } from '../UI/Badge';
import { formatFindingForPresentation } from '../../utils/forensicLanguage';

interface InteractiveFindingsListProps {
  report: ReportDetail;
  initialExpandedRuleId?: string;
}

export const InteractiveFindingsList: React.FC<InteractiveFindingsListProps> = ({
  report,
  initialExpandedRuleId,
}) => {
  const findings = report.findings || [];
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedGroup, setSelectedGroup] = useState('ALL');
  const [expandedItems, setExpandedItems] = useState<Record<string, boolean>>(() => {
    const init: Record<string, boolean> = {};
    if (initialExpandedRuleId) {
      init[initialExpandedRuleId] = true;
    } else if (findings.length <= 3) {
      // Auto-expand first few findings for fast staff scanning
      findings.forEach(f => { init[f.ruleId] = true; });
    }
    return init;
  });
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const toggleExpand = (ruleId: string) => {
    setExpandedItems(prev => ({ ...prev, [ruleId]: !prev[ruleId] }));
  };

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Pre-process findings with plain-language presentations
  const findingsWithPresentation = useMemo(() => {
    return findings.map(f => ({
      raw: f,
      presentation: formatFindingForPresentation(f),
    }));
  }, [findings]);

  // Filtered findings
  const filteredFindings = useMemo(() => {
    return findingsWithPresentation.filter(({ raw, presentation }) => {
      // Severity filter
      if (selectedSeverity !== 'ALL' && raw.severity !== selectedSeverity) {
        return false;
      }

      // Group filter
      if (selectedGroup === 'MODS' && raw.category !== 'ModIntegrity') return false;
      if (selectedGroup === 'PROCESS' && raw.category !== 'ProcessInjection') return false;
      if (selectedGroup === 'HISTORICAL' && !['ExecutionArtifacts', 'FileDeletion'].includes(raw.category)) return false;

      // Search filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchTitle = presentation.simpleTitle.toLowerCase().includes(q) || raw.title.toLowerCase().includes(q);
        const matchExpl = presentation.simpleExplanation.toLowerCase().includes(q) || raw.explanation.toLowerCase().includes(q);
        const matchRule = raw.ruleId.toLowerCase().includes(q);
        const matchFile = (raw.filePath || '').toLowerCase().includes(q);
        const matchHash = (raw.fileSha256 || '').toLowerCase().includes(q);

        if (!matchTitle && !matchExpl && !matchRule && !matchFile && !matchHash) {
          return false;
        }
      }

      return true;
    });
  }, [findingsWithPresentation, selectedSeverity, selectedGroup, searchQuery]);

  return (
    <div className="space-y-4">
      {/* 1. Header & Controls Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-sm">
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Forensic Findings &amp; Observations
            </h2>
            <span className="px-2 py-0.5 rounded-full text-xs font-mono font-semibold bg-slate-800 text-slate-300">
              {filteredFindings.length} of {findings.length}
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Click any item to inspect the underlying technical evidence, official reference data, and caveats.
          </p>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search Input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search findings by rule ID, title, or file..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-52 sm:w-64"
            />
          </div>

          {/* Group Filter */}
          <select
            value={selectedGroup}
            onChange={(e) => setSelectedGroup(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Categories</option>
            <option value="MODS">Mods &amp; Integrity</option>
            <option value="PROCESS">Process &amp; Memory</option>
            <option value="HISTORICAL">Historical &amp; Deletions</option>
          </select>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Informational">Informational</option>
          </select>
        </div>
      </div>

      {/* 2. Empty State */}
      {findings.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center space-y-3 shadow-sm">
          <div className="w-12 h-12 rounded-full bg-emerald-950/60 border border-emerald-800 flex items-center justify-center mx-auto text-emerald-400">
            <Check className="w-6 h-6" />
          </div>
          <h3 className="text-base font-bold text-slate-100">No Suspicious Indicators Flagged</h3>
          <p className="text-xs text-slate-400 max-w-lg mx-auto leading-relaxed">
            The scanner did not find any modified mod artifacts, lookalikes, suspicious injected DLLs, or abnormal session records in the inspected locations.
          </p>
          <div className="p-3 bg-slate-950/80 border border-slate-850 rounded-lg text-[11px] text-slate-500 max-w-md mx-auto">
            Forensic Standard: An empty findings list indicates no evidence was found within the scanned scope. It does not guarantee the player never modified their game at earlier uninspected times.
          </div>
        </div>
      ) : filteredFindings.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400 text-xs">
          No findings matched your search and filter criteria.
        </div>
      ) : (
        /* 3. Findings Accordion List */
        <div className="space-y-3">
          {filteredFindings.map(({ raw, presentation }, idx) => {
            const isExpanded = !!expandedItems[raw.ruleId];
            const severityColor = raw.severity === 'Critical' || raw.severity === 'High' 
              ? 'border-amber-900/40 hover:border-amber-700/60' 
              : 'border-slate-800 hover:border-slate-700';

            return (
              <div
                key={raw.ruleId || idx}
                className={`bg-slate-900 border rounded-xl overflow-hidden transition shadow-sm ${severityColor}`}
              >
                {/* Clickable Header Bar */}
                <div
                  onClick={() => toggleExpand(raw.ruleId)}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleExpand(raw.ruleId); } }}
                  tabIndex={0}
                  role="button"
                  aria-expanded={isExpanded}
                  className="p-4 cursor-pointer hover:bg-slate-850/50 transition flex flex-col sm:flex-row sm:items-center justify-between gap-3 focus:outline-none focus:ring-1 focus:ring-emerald-500"
                >
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={raw.severity} />
                      <ConfidenceBadge confidence={raw.confidence} />
                      <span className="text-[11px] font-mono text-slate-400 font-semibold">
                        {raw.ruleId}
                      </span>
                      {presentation.identifier && (
                        <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-950 text-slate-300 border border-slate-800 truncate max-w-xs">
                          {presentation.identifier}
                        </span>
                      )}
                    </div>

                    <div className="text-sm font-bold text-slate-100 flex items-center gap-2">
                      <span>{presentation.simpleTitle}</span>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed">
                      {presentation.simpleExplanation}
                    </p>
                  </div>

                  {/* Right side expand indicator */}
                  <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
                    <span className="text-xs font-semibold text-emerald-400 group-hover:text-emerald-300">
                      {isExpanded ? 'Hide Details' : 'Inspect Evidence'}
                    </span>
                    <div className="w-7 h-7 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-400">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </div>
                  </div>
                </div>

                {/* Expanded Evidence Detail Drawer */}
                {isExpanded && (
                  <div className="p-4 sm:p-5 bg-slate-950/70 border-t border-slate-800 space-y-4 text-xs">
                    {/* 1. What was observed & Why it matters */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="p-3.5 bg-slate-900 border border-slate-800 rounded-lg space-y-1.5">
                        <div className="font-bold text-slate-200 flex items-center gap-1.5 text-xs">
                          <Eye className="w-3.5 h-3.5 text-indigo-400" />
                          <span>What Was Observed</span>
                        </div>
                        <p className="text-slate-300 text-xs leading-relaxed">
                          {presentation.whatWasObserved}
                        </p>
                      </div>

                      <div className="p-3.5 bg-slate-900 border border-slate-800 rounded-lg space-y-1.5">
                        <div className="font-bold text-slate-200 flex items-center gap-1.5 text-xs">
                          <Info className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Why This Matters to Staff</span>
                        </div>
                        <p className="text-slate-300 text-xs leading-relaxed">
                          {presentation.whyItMatters}
                        </p>
                      </div>
                    </div>

                    {/* 2. Concrete Evidence Supporting It (File path, size, hash) */}
                    <div className="p-3.5 bg-slate-900 border border-slate-800 rounded-lg space-y-2.5">
                      <div className="font-bold text-slate-200 text-xs flex items-center justify-between">
                        <span>Supporting Evidence Record</span>
                        <span className="text-[11px] text-slate-400 font-mono">Source: {raw.evidenceSource}</span>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono">
                        {raw.filePath && (
                          <div className="col-span-full bg-slate-950 p-2 rounded border border-slate-850 flex items-center justify-between gap-2">
                            <span className="text-slate-400 shrink-0">Path:</span>
                            <span className="text-slate-200 truncate">{raw.filePath}</span>
                            <button
                              onClick={() => copyText(raw.filePath!, `path-${raw.ruleId}`)}
                              className="text-slate-400 hover:text-white shrink-0 ml-1"
                              title="Copy file path"
                            >
                              {copiedKey === `path-${raw.ruleId}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>
                        )}

                        {raw.fileSha256 && (
                          <div className="col-span-full bg-slate-950 p-2 rounded border border-slate-850 flex items-center justify-between gap-2">
                            <span className="text-slate-400 shrink-0">SHA-256:</span>
                            <span className="text-slate-200 truncate">{raw.fileSha256}</span>
                            <button
                              onClick={() => copyText(raw.fileSha256!, `hash-${raw.ruleId}`)}
                              className="text-slate-400 hover:text-white shrink-0 ml-1"
                              title="Copy SHA-256 hash"
                            >
                              {copiedKey === `hash-${raw.ruleId}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>
                        )}

                        {raw.fileSizeBytes !== undefined && (
                          <div className="bg-slate-950 p-2 rounded border border-slate-850 flex items-center justify-between">
                            <span className="text-slate-400">File Size:</span>
                            <span className="text-slate-200">
                              {(raw.fileSizeBytes / 1024).toFixed(1)} KB ({raw.fileSizeBytes.toLocaleString()} bytes)
                            </span>
                          </div>
                        )}

                        {raw.fileModifiedTime && (
                          <div className="bg-slate-950 p-2 rounded border border-slate-850 flex items-center justify-between">
                            <span className="text-slate-400">Modified:</span>
                            <span className="text-slate-200">
                              {new Date(raw.fileModifiedTime).toLocaleString()}
                            </span>
                          </div>
                        )}

                        {raw.processCommandLine && (
                          <div className="col-span-full bg-slate-950 p-2 rounded border border-slate-850">
                            <span className="text-slate-400 block mb-1">Command Line:</span>
                            <div className="text-slate-300 break-all text-[10px] leading-relaxed">
                              {raw.processCommandLine}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* 3. What the evidence does NOT establish (Anti-Slop Guardrail) */}
                    <div className="p-3.5 bg-amber-950/30 border border-amber-900/50 rounded-lg space-y-1.5">
                      <div className="font-bold text-amber-300 text-xs flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                        <span>What This Evidence Does NOT Establish (Forensic Caveats)</span>
                      </div>
                      <p className="text-amber-200/90 text-xs leading-relaxed">
                        {presentation.whatItDoesNotEstablish}
                      </p>
                    </div>

                    {/* 4. Possible Legitimate Explanations */}
                    <div className="p-3.5 bg-slate-900 border border-slate-800 rounded-lg space-y-2">
                      <div className="font-bold text-slate-200 text-xs flex items-center gap-1.5">
                        <HelpCircle className="w-3.5 h-3.5 text-indigo-400" />
                        <span>Possible Legitimate Explanations</span>
                      </div>
                      <ul className="list-disc list-inside space-y-1 text-slate-300 text-xs">
                        {presentation.possibleLegitimateExplanations.map((expl, i) => (
                          <li key={i}>{expl}</li>
                        ))}
                      </ul>
                    </div>

                    {/* 5. Limitations & Confidence Callout */}
                    <div className="p-3 bg-slate-900/80 border border-slate-850 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] text-slate-400">
                      <div>
                        <strong>Detection Rule Version:</strong> <span className="font-mono text-slate-300">{raw.detectionRuleVersion || '1.0.0'}</span> • <strong>Confidence:</strong> <span className="text-slate-300">{raw.confidence}</span>
                      </div>
                      <div className="text-slate-500 italic">
                        {raw.limitationsAndFalsePositives || 'Review in context with other timeline events.'}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
