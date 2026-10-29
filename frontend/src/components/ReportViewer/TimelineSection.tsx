import React, { useState, useMemo } from 'react';
import { 
  Clock, Tag, ArrowUpDown, Search, Calendar,
  Info, RotateCcw
} from 'lucide-react';
import type { TimelineEventDetail } from '../../types/report';
import { ConfidenceBadge } from '../UI/Badge';

interface TimelineSectionProps {
  events: TimelineEventDetail[];
  initialCorrelationGroup?: string;
}

export const TimelineSection: React.FC<TimelineSectionProps> = ({ 
  events,
  initialCorrelationGroup 
}) => {
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  const [filterInferred, setFilterInferred] = useState<'ALL' | 'OBSERVED' | 'INFERRED'>('ALL');
  const [selectedSource, setSelectedSource] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedCorrelation, setSelectedCorrelation] = useState<string | null>(initialCorrelationGroup || null);
  const [searchQuery, setSearchQuery] = useState('');

  // Extract unique sources and categories for filter dropdowns
  const sources = useMemo(() => {
    const s = new Set<string>();
    events.forEach(e => {
      if (e.source) s.add(e.source);
    });
    return Array.from(s).sort();
  }, [events]);

  const categories = useMemo(() => {
    const c = new Set<string>();
    events.forEach(e => {
      if (e.category) c.add(e.category);
    });
    return Array.from(c).sort();
  }, [events]);

  const correlationGroups = useMemo(() => {
    const g = new Set<string>();
    events.forEach(e => {
      if (e.correlationGroup) g.add(e.correlationGroup);
    });
    return Array.from(g).sort();
  }, [events]);

  // Filtering and sorting
  const filteredEvents = useMemo(() => {
    return events
      .filter(e => {
        if (filterInferred === 'OBSERVED' && e.isInferred) return false;
        if (filterInferred === 'INFERRED' && !e.isInferred) return false;
        if (selectedSource !== 'ALL' && e.source !== selectedSource) return false;
        if (selectedCategory !== 'ALL' && e.category !== selectedCategory) return false;
        if (selectedCorrelation && e.correlationGroup !== selectedCorrelation) return false;
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchDesc = e.description.toLowerCase().includes(q);
          const matchSource = e.source.toLowerCase().includes(q);
          const matchCat = e.category.toLowerCase().includes(q);
          const matchGroup = e.correlationGroup?.toLowerCase().includes(q);
          if (!matchDesc && !matchSource && !matchCat && !matchGroup) return false;
        }
        return true;
      })
      .sort((a, b) => {
        const timeA = new Date(a.timestamp).getTime();
        const timeB = new Date(b.timestamp).getTime();
        return sortOrder === 'asc' ? timeA - timeB : timeB - timeA;
      });
  }, [events, filterInferred, selectedSource, selectedCategory, selectedCorrelation, searchQuery, sortOrder]);

  const resetFilters = () => {
    setFilterInferred('ALL');
    setSelectedSource('ALL');
    setSelectedCategory('ALL');
    setSelectedCorrelation(null);
    setSearchQuery('');
  };

  const hasActiveFilters = filterInferred !== 'ALL' || selectedSource !== 'ALL' || selectedCategory !== 'ALL' || selectedCorrelation !== null || searchQuery !== '';

  return (
    <div className="space-y-4">
      {/* 1. Header & Global Filters */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Clock className="w-4 h-4 text-emerald-400" />
              <span>Chronological Forensic Timeline</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Sequence of observed Windows artifacts, game log timestamps, process memory events, and filesystem mutations
            </p>
          </div>

          {/* Quick Count & Sort Direction Toggle */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSortOrder(prev => prev === 'asc' ? 'desc' : 'asc')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-medium text-slate-300 hover:text-white hover:border-slate-700 transition"
              title="Toggle chronological sorting"
            >
              <ArrowUpDown className="w-3.5 h-3.5 text-emerald-400" />
              <span>{sortOrder === 'asc' ? 'Oldest First (Asc)' : 'Newest First (Desc)'}</span>
            </button>
          </div>
        </div>

        {/* Filter Controls Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 pt-2 border-t border-slate-800/80">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search timeline events..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition"
            />
          </div>

          {/* Source Dropdown */}
          <select
            value={selectedSource}
            onChange={(e) => setSelectedSource(e.target.value)}
            className="px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Forensic Sources ({sources.length})</option>
            {sources.map(src => (
              <option key={src} value={src}>{src}</option>
            ))}
          </select>

          {/* Category Dropdown */}
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Event Categories ({categories.length})</option>
            {categories.map(cat => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>

          {/* Inferred vs Observed Toggle */}
          <div className="inline-flex rounded-lg bg-slate-950 p-0.5 border border-slate-800 text-xs">
            <button
              onClick={() => setFilterInferred('ALL')}
              className={`flex-1 py-1 rounded-md font-medium transition text-center ${
                filterInferred === 'ALL' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All ({events.length})
            </button>
            <button
              onClick={() => setFilterInferred('OBSERVED')}
              className={`flex-1 py-1 rounded-md font-medium transition text-center ${
                filterInferred === 'OBSERVED' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Observed
            </button>
            <button
              onClick={() => setFilterInferred('INFERRED')}
              className={`flex-1 py-1 rounded-md font-medium transition text-center ${
                filterInferred === 'INFERRED' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Inferred
            </button>
          </div>
        </div>

        {/* Correlation Group Pills & Active Filter Bar */}
        {(correlationGroups.length > 0 || hasActiveFilters) && (
          <div className="flex flex-wrap items-center gap-2 pt-2 text-xs border-t border-slate-800/80">
            {correlationGroups.length > 0 && (
              <div className="flex items-center gap-1.5 mr-2">
                <span className="text-slate-500 text-[11px] flex items-center gap-1">
                  <Tag className="w-3 h-3 text-indigo-400" />
                  Correlated Groups:
                </span>
                {correlationGroups.map(grp => {
                  const isSelected = selectedCorrelation === grp;
                  return (
                    <button
                      key={grp}
                      onClick={() => setSelectedCorrelation(isSelected ? null : grp)}
                      className={`px-2 py-0.5 rounded text-[11px] font-mono border transition ${
                        isSelected
                          ? 'bg-indigo-900 text-indigo-200 border-indigo-600 font-bold'
                          : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200 hover:border-slate-700'
                      }`}
                    >
                      {grp}
                    </button>
                  );
                })}
              </div>
            )}

            {hasActiveFilters && (
              <button
                onClick={resetFilters}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] text-amber-400 hover:text-amber-300 bg-amber-950/40 border border-amber-900 transition ml-auto"
              >
                <RotateCcw className="w-3 h-3" />
                <span>Reset Filters</span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* 2. Educational Forensic Callout: Observed vs Inferred */}
      <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl flex items-start gap-3 text-xs text-slate-300">
        <Info className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <span className="font-semibold text-slate-200">Timestamp Interpretation Rule: </span>
          <span className="text-slate-400">
            Events marked <strong className="text-emerald-300">Observed Record</strong> are recorded with strict hardware/system clock stamps from Prefetch header, BAM last execution, or journal write time. Events marked <strong className="text-amber-300">Inferred Timestamp</strong> are estimated based on relative log line offsets, sequence order, or heuristic windows; slight variance is possible.
          </span>
        </div>
      </div>

      {/* 3. Chronological Vertical Timeline View */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 sm:p-6 shadow-sm">
        {filteredEvents.length === 0 ? (
          <div className="p-12 text-center space-y-2">
            <Clock className="w-8 h-8 text-slate-600 mx-auto" />
            <div className="text-xs font-semibold text-slate-400">No timeline events match the active criteria.</div>
            {hasActiveFilters && (
              <button
                onClick={resetFilters}
                className="text-xs text-emerald-400 hover:underline inline-block mt-1"
              >
                Clear all filters
              </button>
            )}
          </div>
        ) : (
          <div className="relative pl-6 sm:pl-8 border-l-2 border-slate-800 space-y-6 my-2">
            {filteredEvents.map((ev, idx) => {
              const date = new Date(ev.timestamp);
              const formattedTime = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
              const formattedDate = date.toLocaleDateString();

              return (
                <div key={idx} className="relative group">
                  {/* Timeline Node Bullet */}
                  <div className={`absolute -left-[31px] sm:-left-[39px] top-1.5 w-4 h-4 rounded-full border-2 bg-slate-950 flex items-center justify-center transition group-hover:scale-110 ${
                    ev.isInferred 
                      ? 'border-amber-400 text-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.3)]' 
                      : 'border-emerald-400 text-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.3)]'
                  }`}>
                    <div className={`w-1.5 h-1.5 rounded-full ${ev.isInferred ? 'bg-amber-400' : 'bg-emerald-400'}`} />
                  </div>

                  {/* Event Card */}
                  <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-4 transition group-hover:border-slate-700 space-y-2 shadow-sm">
                    {/* Card Header */}
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-slate-100 font-semibold text-xs sm:text-sm">{formattedTime}</span>
                        <span className="text-slate-500 font-mono text-[11px] flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {formattedDate}
                        </span>

                        {ev.isInferred ? (
                          <span 
                            className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-amber-950/80 text-amber-300 border border-amber-800"
                            title="Inferred timestamp based on relative log or filesystem sequence"
                          >
                            Inferred
                          </span>
                        ) : (
                          <span 
                            className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-emerald-950/80 text-emerald-300 border border-emerald-800"
                            title="Observed timestamp logged directly in forensic artifact"
                          >
                            Observed Record
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <ConfidenceBadge confidence={ev.confidence} />
                        {ev.correlationGroup && (
                          <button
                            onClick={() => setSelectedCorrelation(ev.correlationGroup!)}
                            className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-950 text-indigo-300 border border-indigo-800 hover:bg-indigo-900 hover:border-indigo-600 transition flex items-center gap-1"
                            title={`Filter to correlation group: ${ev.correlationGroup}`}
                          >
                            <Tag className="w-2.5 h-2.5" />
                            {ev.correlationGroup}
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Description */}
                    <div className="text-xs sm:text-sm font-medium text-slate-200 leading-relaxed">
                      {ev.description}
                    </div>

                    {/* Footer Details */}
                    <div className="text-[11px] text-slate-400 flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-900 font-mono">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500">Category:</span>
                        <span className="text-slate-300 font-sans">{ev.category}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500">Forensic Source:</span>
                        <span className="text-emerald-400">{ev.source}</span>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
