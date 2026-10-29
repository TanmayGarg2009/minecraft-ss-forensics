import React, { useState, useMemo } from 'react';
import { 
  Search, ChevronDown, ChevronUp, Copy, Check, 
  AlertTriangle, FileCode, Cpu, ShieldAlert, 
  HelpCircle, Eye, Terminal, Activity
} from 'lucide-react';
import type { FindingDetail } from '../../types/report';
import { SeverityBadge, ConfidenceBadge } from '../UI/Badge';

interface FindingsSectionProps {
  findings: FindingDetail[];
  initialExpandedRuleId?: string;
}

const severityWeight: Record<string, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Informational: 1,
};

type FilterTab = 
  | 'ALL' 
  | 'CURRENT_STATE' 
  | 'HISTORICAL' 
  | 'DELETED_FILES' 
  | 'PROCESS_MODULES' 
  | 'MODS_JARS' 
  | 'WINDOWS_EXEC' 
  | 'HIGH_CONFIDENCE' 
  | 'LOW_CONFIDENCE';

export const FindingsSection: React.FC<FindingsSectionProps> = ({ findings, initialExpandedRuleId }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState<FilterTab>('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState<'severity-desc' | 'severity-asc' | 'rule' | 'time'>('severity-desc');
  const [expandedRules, setExpandedRules] = useState<Record<string, boolean>>(() => {
    const init: Record<string, boolean> = {};
    if (initialExpandedRuleId) {
      init[initialExpandedRuleId] = true;
    } else {
      findings.forEach(f => { init[f.ruleId] = true; });
    }
    return init;
  });
  const [showRawJson, setShowRawJson] = useState<Record<string, boolean>>({});
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const categories = useMemo(() => {
    const set = new Set<string>();
    findings.forEach(f => set.add(f.category));
    return Array.from(set);
  }, [findings]);

  const toggleExpand = (ruleId: string) => {
    setExpandedRules(prev => ({ ...prev, [ruleId]: !prev[ruleId] }));
  };

  const toggleRawJson = (ruleId: string) => {
    setShowRawJson(prev => ({ ...prev, [ruleId]: !prev[ruleId] }));
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Filter tabs definition
  const filterTabs: { id: FilterTab; label: string; count: number }[] = [
    { id: 'ALL', label: 'All Findings', count: findings.length },
    { 
      id: 'HIGH_CONFIDENCE', 
      label: 'High Confidence', 
      count: findings.filter(f => f.confidence === 'Certain' || f.confidence === 'High').length 
    },
    { 
      id: 'DELETED_FILES', 
      label: 'Deleted / Renamed', 
      count: findings.filter(f => f.category === 'FileDeletion' || f.evidenceSource === 'UsnJournal' || f.title.toLowerCase().includes('delete')).length 
    },
    { 
      id: 'WINDOWS_EXEC', 
      label: 'Execution Artifacts', 
      count: findings.filter(f => f.category === 'ExecutionArtifacts' || ['Prefetch', 'BamDam', 'Amcache', 'ShimCache'].includes(f.evidenceSource)).length 
    },
    { 
      id: 'PROCESS_MODULES', 
      label: 'Process & Memory', 
      count: findings.filter(f => f.category === 'ProcessInjection' || f.evidenceSource === 'ProcessMemoryMetadata').length 
    },
    { 
      id: 'MODS_JARS', 
      label: 'Mods & Integrity', 
      count: findings.filter(f => f.category === 'ModIntegrity' || f.evidenceSource === 'ModFolder').length 
    },
    { 
      id: 'HISTORICAL', 
      label: 'Historical Traces', 
      count: findings.filter(f => ['Prefetch', 'UsnJournal', 'BamDam', 'EventLogs'].includes(f.evidenceSource)).length 
    },
    { 
      id: 'LOW_CONFIDENCE', 
      label: 'Low / Inconclusive', 
      count: findings.filter(f => f.confidence === 'Low' || f.confidence === 'Medium').length 
    },
  ];

  const filteredAndSortedFindings = useMemo(() => {
    return findings
      .filter(f => {
        // Tab filter
        if (activeTab === 'HIGH_CONFIDENCE' && !(f.confidence === 'Certain' || f.confidence === 'High')) return false;
        if (activeTab === 'LOW_CONFIDENCE' && !(f.confidence === 'Low' || f.confidence === 'Medium')) return false;
        if (activeTab === 'DELETED_FILES' && !(f.category === 'FileDeletion' || f.evidenceSource === 'UsnJournal' || f.title.toLowerCase().includes('delete'))) return false;
        if (activeTab === 'WINDOWS_EXEC' && !(f.category === 'ExecutionArtifacts' || ['Prefetch', 'BamDam', 'Amcache', 'ShimCache'].includes(f.evidenceSource))) return false;
        if (activeTab === 'PROCESS_MODULES' && !(f.category === 'ProcessInjection' || f.evidenceSource === 'ProcessMemoryMetadata')) return false;
        if (activeTab === 'MODS_JARS' && !(f.category === 'ModIntegrity' || f.evidenceSource === 'ModFolder')) return false;
        if (activeTab === 'HISTORICAL' && !['Prefetch', 'UsnJournal', 'BamDam', 'EventLogs'].includes(f.evidenceSource)) return false;

        // Dropdown filters
        if (categoryFilter !== 'ALL' && f.category !== categoryFilter) return false;
        if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;

        // Search Query
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchTitle = f.title.toLowerCase().includes(q);
          const matchRule = f.ruleId.toLowerCase().includes(q);
          const matchExp = f.explanation.toLowerCase().includes(q);
          const matchPath = f.filePath?.toLowerCase().includes(q) ?? false;
          const matchProc = f.processName?.toLowerCase().includes(q) ?? false;
          if (!matchTitle && !matchRule && !matchExp && !matchPath && !matchProc) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'severity-desc') {
          return (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0);
        }
        if (sortBy === 'severity-asc') {
          return (severityWeight[a.severity] || 0) - (severityWeight[b.severity] || 0);
        }
        if (sortBy === 'rule') {
          return a.ruleId.localeCompare(b.ruleId);
        }
        if (sortBy === 'time') {
          const timeA = a.firstObservedAt ? new Date(a.firstObservedAt).getTime() : 0;
          const timeB = b.firstObservedAt ? new Date(b.firstObservedAt).getTime() : 0;
          return timeB - timeA;
        }
        return 0;
      });
  }, [findings, activeTab, categoryFilter, severityFilter, searchQuery, sortBy]);

  return (
    <div className="space-y-4">
      {/* Search and Filters Toolbar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3 shadow-sm">
        <div className="flex flex-col sm:flex-row gap-3">
          {/* Search Box */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search findings by rule ID, title, file path, process..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition"
            />
          </div>

          {/* Severity Dropdown */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Informational">Informational</option>
          </select>

          {/* Category Dropdown */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Categories</option>
            {categories.map(cat => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>

          {/* Sort Selector */}
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as any)}
            className="px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="severity-desc">Sort: Severity (High to Low)</option>
            <option value="severity-asc">Sort: Severity (Low to High)</option>
            <option value="rule">Sort: Rule ID</option>
            <option value="time">Sort: Timestamp</option>
          </select>
        </div>

        {/* Quick Filter Pill Chips */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 pt-1 text-[11px] no-print">
          {filterTabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-2.5 py-1 rounded-md font-medium whitespace-nowrap transition flex items-center gap-1.5 ${
                  isActive
                    ? 'bg-emerald-600 text-white font-semibold'
                    : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800 hover:bg-slate-850'
                }`}
              >
                <span>{tab.label}</span>
                <span className={`px-1 rounded-full text-[10px] font-mono ${
                  isActive ? 'bg-emerald-800 text-white' : 'bg-slate-850 text-slate-500'
                }`}>
                  {tab.count}
                </span>
              </button>
            );
          })}
        </div>

        <div className="flex items-center justify-between text-xs text-slate-500 pt-1 border-t border-slate-800/60">
          <span>
            Showing <strong className="text-slate-300">{filteredAndSortedFindings.length}</strong> of{' '}
            <strong className="text-slate-300">{findings.length}</strong> findings
          </span>
          {(searchQuery || categoryFilter !== 'ALL' || severityFilter !== 'ALL' || activeTab !== 'ALL') && (
            <button
              onClick={() => {
                setSearchQuery('');
                setCategoryFilter('ALL');
                setSeverityFilter('ALL');
                setActiveTab('ALL');
              }}
              className="text-emerald-400 hover:underline"
            >
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* Findings List */}
      {filteredAndSortedFindings.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400 space-y-2">
          <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto" />
          <div className="text-sm font-semibold text-slate-300">No findings matched your filter criteria</div>
          <p className="text-xs text-slate-500">Broaden your search terms or switch to "All Findings".</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredAndSortedFindings.map((finding) => {
            const isExpanded = expandedRules[finding.ruleId] ?? true;
            const isRawOpen = showRawJson[finding.ruleId] ?? false;

            return (
              <div
                key={finding.ruleId}
                id={`finding-${finding.ruleId}`}
                className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden transition hover:border-slate-700 shadow-sm"
              >
                {/* Header Row */}
                <div
                  onClick={() => toggleExpand(finding.ruleId)}
                  className="p-3.5 sm:p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer bg-slate-900/80 hover:bg-slate-850 select-none"
                >
                  <div className="flex items-start sm:items-center gap-3">
                    <SeverityBadge severity={finding.severity} />
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-bold text-emerald-400">
                          {finding.ruleId}
                        </span>
                        <span className="text-slate-600 text-xs">•</span>
                        <span className="text-xs text-slate-400 font-medium">
                          {finding.category}
                        </span>
                        <span className="text-slate-600 text-xs">•</span>
                        <ConfidenceBadge confidence={finding.confidence} />
                      </div>
                      <h3 className="text-sm font-bold text-slate-100 mt-1">
                        {finding.title}
                      </h3>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 self-end sm:self-auto">
                    <span className="text-xs text-slate-500 font-mono hidden md:inline">
                      Source: {finding.evidenceSource}
                    </span>
                    <button className="text-slate-400 hover:text-slate-200 p-1">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* 8-Part Structured Investigation View */}
                {isExpanded && (
                  <div className="p-4 sm:p-5 pt-0 space-y-4 border-t border-slate-800/60 text-xs">
                    {/* 1. What was observed & 2. Why it matters */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-4">
                      <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-1.5">
                        <div className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                          <Eye className="w-3.5 h-3.5 text-emerald-400" />
                          <span>1. What Was Observed</span>
                        </div>
                        <p className="text-slate-300 leading-relaxed text-[11px]">
                          {finding.explanation}
                        </p>
                      </div>

                      <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-1.5">
                        <div className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                          <Activity className="w-3.5 h-3.5 text-indigo-400" />
                          <span>2. Forensic Significance</span>
                        </div>
                        <p className="text-slate-300 leading-relaxed text-[11px]">
                          Indicator of {finding.category.toLowerCase()} identified through {finding.evidenceSource} audit records. Confidence rated as {finding.confidence}.
                        </p>
                      </div>
                    </div>

                    {/* 3. What it does NOT prove & 7. Potential False Positives (Prominent Callout) */}
                    <div className="p-3.5 bg-amber-950/30 border border-amber-800/60 rounded-lg space-y-1.5 text-amber-200">
                      <div className="font-bold text-amber-300 text-[11px] uppercase tracking-wider flex items-center gap-1.5">
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                        <span>3. Limitations & Potential False Positives:</span>
                      </div>
                      <p className="text-amber-200/90 leading-relaxed text-[11px]">
                        {finding.limitationsAndFalsePositives || 'This record proves artifact presence or execution; it does not confirm in-game combat modification or server duel impact without corroborating game log timestamps.'}
                      </p>
                    </div>

                    {/* 4. Source & Collection Method + 5. Related Events + 6. File & Process Metadata */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      {/* File Metadata */}
                      {finding.filePath && (
                        <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-2">
                          <div className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                            <FileCode className="w-3.5 h-3.5 text-indigo-400" />
                            <span>File System Metadata</span>
                          </div>

                          <div className="space-y-1 text-[11px]">
                            <div className="text-slate-400">Path:</div>
                            <div className="font-mono text-slate-200 break-all bg-slate-900 p-1.5 rounded flex items-center justify-between gap-2 border border-slate-850">
                              <span>{finding.filePath}</span>
                              <button
                                onClick={() => copyToClipboard(finding.filePath!, `path-${finding.ruleId}`)}
                                className="text-slate-400 hover:text-white shrink-0"
                                title="Copy Path"
                              >
                                {copiedText === `path-${finding.ruleId}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                              </button>
                            </div>
                          </div>

                          {finding.fileSha256 && (
                            <div className="space-y-1 text-[11px]">
                              <div className="text-slate-400">SHA-256 Digest:</div>
                              <div className="font-mono text-[10px] text-slate-300 break-all bg-slate-900 p-1.5 rounded flex items-center justify-between gap-2 border border-slate-850">
                                <span>{finding.fileSha256}</span>
                                <button
                                  onClick={() => copyToClipboard(finding.fileSha256!, `hash-${finding.ruleId}`)}
                                  className="text-slate-400 hover:text-white shrink-0"
                                  title="Copy Hash"
                                >
                                  {copiedText === `hash-${finding.ruleId}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                                </button>
                              </div>
                            </div>
                          )}

                          {finding.fileSizeBytes && (
                            <div className="flex justify-between text-slate-400 text-[11px] pt-1">
                              <span>File Size:</span>
                              <span className="font-mono text-slate-200">
                                {(finding.fileSizeBytes / 1024).toFixed(1)} KB ({finding.fileSizeBytes.toLocaleString()} bytes)
                              </span>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Process & Provenance */}
                      <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-2">
                        <div className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                          <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                          <span>4. Provenance & 5. Timeline Anchors</span>
                        </div>

                        {finding.processName && (
                          <div className="flex justify-between text-slate-400 text-[11px]">
                            <span>Process:</span>
                            <span className="font-mono text-slate-200">
                              {finding.processName} {finding.processId ? `(PID ${finding.processId})` : ''}
                            </span>
                          </div>
                        )}

                        <div className="flex justify-between text-slate-400 text-[11px]">
                          <span>Collection Source:</span>
                          <span className="font-semibold text-slate-200">{finding.evidenceSource}</span>
                        </div>

                        <div className="flex justify-between text-slate-400 text-[11px]">
                          <span>Rule Engine Version:</span>
                          <span className="font-mono text-slate-200">{finding.detectionRuleVersion}</span>
                        </div>

                        {finding.firstObservedAt && (
                          <div className="flex justify-between text-slate-400 text-[11px] pt-1 border-t border-slate-900">
                            <span>First Observed:</span>
                            <span className="font-mono text-slate-300">
                              {new Date(finding.firstObservedAt).toLocaleTimeString()} ({new Date(finding.firstObservedAt).toLocaleDateString()})
                            </span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* 8. Recommended Manual Verification Steps */}
                    <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-[11px] text-slate-300 space-y-1">
                      <div className="font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                        <HelpCircle className="w-3.5 h-3.5 text-emerald-400" />
                        <span>8. Recommended Staff Verification:</span>
                      </div>
                      <p className="text-slate-400 leading-relaxed">
                        Verify if player executed or downloaded this file outside gaming sessions. Compare timestamp with server duel replay logs. Do not ban on filename alone.
                      </p>
                    </div>

                    {/* Optional Technical Details Accordion (Raw JSON) */}
                    {finding.observedEvidence && (
                      <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950">
                        <button
                          onClick={() => toggleRawJson(finding.ruleId)}
                          className="w-full p-2.5 px-3 flex items-center justify-between text-[11px] text-slate-400 hover:text-slate-200 bg-slate-950 hover:bg-slate-900/60 transition"
                        >
                          <span className="font-mono flex items-center gap-1.5">
                            <Terminal className="w-3 h-3 text-emerald-400" />
                            <span>Technical Details & Raw Observed Attributes</span>
                          </span>
                          <span className="text-slate-500">
                            {isRawOpen ? 'Hide JSON' : 'Expand JSON'}
                          </span>
                        </button>

                        {isRawOpen && (
                          <pre className="p-3 border-t border-slate-850 text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-60">
                            {JSON.stringify(finding.observedEvidence, null, 2)}
                          </pre>
                        )}
                      </div>
                    )}
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
