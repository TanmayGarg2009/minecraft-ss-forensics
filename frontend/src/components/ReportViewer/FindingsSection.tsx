import React, { useState, useMemo } from 'react';
import { 
  Search, ChevronDown, ChevronUp, Copy, Check, 
  AlertTriangle, FileCode, Cpu, ShieldAlert, Hash 
} from 'lucide-react';
import type { FindingDetail } from '../../types/report';
import { SeverityBadge, ConfidenceBadge } from '../UI/Badge';

interface FindingsSectionProps {
  findings: FindingDetail[];
}

const severityWeight: Record<string, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Informational: 1,
};

export const FindingsSection: React.FC<FindingsSectionProps> = ({ findings }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [confidenceFilter, setConfidenceFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState<'severity-desc' | 'severity-asc' | 'rule' | 'time'>('severity-desc');
  const [expandedRules, setExpandedRules] = useState<Record<string, boolean>>({});
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const categories = useMemo(() => {
    const set = new Set<string>();
    findings.forEach(f => set.add(f.category));
    return Array.from(set);
  }, [findings]);

  const toggleExpand = (ruleId: string) => {
    setExpandedRules(prev => ({ ...prev, [ruleId]: !prev[ruleId] }));
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const filteredAndSortedFindings = useMemo(() => {
    return findings
      .filter(f => {
        if (categoryFilter !== 'ALL' && f.category !== categoryFilter) return false;
        if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
        if (confidenceFilter !== 'ALL' && f.confidence !== confidenceFilter) return false;
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
  }, [findings, categoryFilter, severityFilter, confidenceFilter, searchQuery, sortBy]);

  return (
    <div className="space-y-4">
      {/* Search and Filters Toolbar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex flex-col sm:flex-row gap-3">
          {/* Search Box */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              placeholder="Search findings by rule ID, title, file path, process..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition"
            />
          </div>

          {/* Severity Filter */}
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

          {/* Category Filter */}
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

        <div className="flex items-center justify-between text-xs text-slate-500 pt-1">
          <span>
            Showing <strong className="text-slate-300">{filteredAndSortedFindings.length}</strong> of{' '}
            <strong className="text-slate-300">{findings.length}</strong> findings
          </span>
          {(searchQuery || categoryFilter !== 'ALL' || severityFilter !== 'ALL') && (
            <button
              onClick={() => {
                setSearchQuery('');
                setCategoryFilter('ALL');
                setSeverityFilter('ALL');
                setConfidenceFilter('ALL');
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
          <div className="text-sm font-semibold text-slate-300">No findings matched your criteria</div>
          <p className="text-xs text-slate-500">Try broadening your search term or clearing filters.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredAndSortedFindings.map((finding) => {
            const isExpanded = expandedRules[finding.ruleId] ?? true;

            return (
              <div
                key={finding.ruleId}
                className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden transition-all hover:border-slate-700 shadow-sm"
              >
                {/* Header Bar */}
                <div
                  onClick={() => toggleExpand(finding.ruleId)}
                  className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer bg-slate-900/60 hover:bg-slate-850 select-none"
                >
                  <div className="flex items-start sm:items-center gap-3">
                    <SeverityBadge severity={finding.severity} />
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-emerald-400">
                          {finding.ruleId}
                        </span>
                        <span className="text-slate-500 text-xs">•</span>
                        <span className="text-xs text-slate-400 font-medium">
                          {finding.category}
                        </span>
                        <span className="text-slate-500 text-xs">•</span>
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

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="p-4 sm:p-5 pt-0 space-y-4 border-t border-slate-800/60">
                    {/* Explanation */}
                    <div className="space-y-1.5 pt-4">
                      <div className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                        Forensic Explanation & Assessment
                      </div>
                      <p className="text-xs sm:text-sm text-slate-200 leading-relaxed bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
                        {finding.explanation}
                      </p>
                    </div>

                    {/* False Positives & Limitations Callout (Mandatory per Product Vision) */}
                    {finding.limitationsAndFalsePositives && (
                      <div className="p-3.5 bg-amber-950/30 border border-amber-800/50 rounded-lg flex items-start gap-3 text-xs text-amber-200">
                        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                        <div className="space-y-1">
                          <span className="font-semibold text-amber-300">
                            Limitations & Potential False Positives:
                          </span>
                          <p className="text-amber-200/90 leading-relaxed">
                            {finding.limitationsAndFalsePositives}
                          </p>
                        </div>
                      </div>
                    )}

                    {/* Technical Metadata Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                      {/* File Metadata */}
                      {finding.filePath && (
                        <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-3 space-y-2">
                          <div className="flex items-center gap-2 text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                            <FileCode className="w-3.5 h-3.5 text-indigo-400" />
                            <span>File System Metadata</span>
                          </div>

                          <div className="space-y-1">
                            <div className="text-slate-400">Path:</div>
                            <div className="font-mono text-slate-200 break-all bg-slate-900 p-1.5 rounded flex items-center justify-between gap-2">
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
                            <div className="space-y-1">
                              <div className="text-slate-400">SHA-256 Hash:</div>
                              <div className="font-mono text-[11px] text-slate-300 break-all bg-slate-900 p-1.5 rounded flex items-center justify-between gap-2">
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
                            <div className="flex justify-between text-slate-400 pt-1">
                              <span>Size:</span>
                              <span className="font-mono text-slate-200">
                                {(finding.fileSizeBytes / 1024).toFixed(1)} KB ({finding.fileSizeBytes.toLocaleString()} bytes)
                              </span>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Process & Rule Provenance */}
                      <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-3 space-y-2">
                        <div className="flex items-center gap-2 text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                          <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Process & Rule Provenance</span>
                        </div>

                        {finding.processName && (
                          <div className="flex justify-between text-slate-400">
                            <span>Process:</span>
                            <span className="font-mono text-slate-200">
                              {finding.processName} {finding.processId ? `(PID: ${finding.processId})` : ''}
                            </span>
                          </div>
                        )}

                        <div className="flex justify-between text-slate-400">
                          <span>Evidence Source:</span>
                          <span className="font-semibold text-slate-200">{finding.evidenceSource}</span>
                        </div>

                        <div className="flex justify-between text-slate-400">
                          <span>Rule Version:</span>
                          <span className="font-mono text-slate-200">{finding.detectionRuleVersion}</span>
                        </div>

                        {finding.firstObservedAt && (
                          <div className="flex justify-between text-slate-400 pt-1 border-t border-slate-900">
                            <span>First Observed:</span>
                            <span className="font-mono text-slate-300">
                              {new Date(finding.firstObservedAt).toLocaleTimeString()}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Observed Evidence Structured Payload */}
                    {finding.observedEvidence && (
                      <div className="space-y-1.5">
                        <div className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                          <Hash className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Observed Raw Evidence Attributes</span>
                        </div>
                        <pre className="p-3 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto">
                          {JSON.stringify(finding.observedEvidence, null, 2)}
                        </pre>
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
