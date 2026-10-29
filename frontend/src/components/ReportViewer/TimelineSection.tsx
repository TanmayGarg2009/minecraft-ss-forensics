import React, { useState } from 'react';
import { Clock, Tag } from 'lucide-react';
import type { TimelineEventDetail } from '../../types/report';
import { ConfidenceBadge } from '../UI/Badge';

interface TimelineSectionProps {
  events: TimelineEventDetail[];
}

export const TimelineSection: React.FC<TimelineSectionProps> = ({ events }) => {
  const [filterInferred, setFilterInferred] = useState<'ALL' | 'OBSERVED' | 'INFERRED'>('ALL');

  const filteredEvents = events.filter(e => {
    if (filterInferred === 'OBSERVED') return !e.isInferred;
    if (filterInferred === 'INFERRED') return e.isInferred;
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Filter Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Clock className="w-4 h-4 text-emerald-400" />
            <span>Chronological Forensic Timeline</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Cross-correlated events ordered chronologically from earliest to latest
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">View:</span>
          <div className="inline-flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs">
            <button
              onClick={() => setFilterInferred('ALL')}
              className={`px-2.5 py-1 rounded font-medium transition ${
                filterInferred === 'ALL' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All ({events.length})
            </button>
            <button
              onClick={() => setFilterInferred('OBSERVED')}
              className={`px-2.5 py-1 rounded font-medium transition ${
                filterInferred === 'OBSERVED' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Observed
            </button>
            <button
              onClick={() => setFilterInferred('INFERRED')}
              className={`px-2.5 py-1 rounded font-medium transition ${
                filterInferred === 'INFERRED' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Inferred Times
            </button>
          </div>
        </div>
      </div>

      {/* Vertical Timeline */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 sm:p-6">
        {filteredEvents.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs">
            No timeline events matched the filter.
          </div>
        ) : (
          <div className="relative pl-6 sm:pl-8 border-l border-slate-800 space-y-8 my-2">
            {filteredEvents.map((ev, idx) => {
              const date = new Date(ev.timestamp);
              const formattedTime = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
              const formattedDate = date.toLocaleDateString();

              return (
                <div key={idx} className="relative group">
                  {/* Timeline Node Dot */}
                  <div className={`absolute -left-[31px] sm:-left-[39px] top-1.5 w-4 h-4 rounded-full border-2 bg-slate-950 flex items-center justify-center ${
                    ev.isInferred 
                      ? 'border-amber-400 text-amber-400' 
                      : 'border-emerald-400 text-emerald-400'
                  }`}>
                    <div className={`w-1.5 h-1.5 rounded-full ${ev.isInferred ? 'bg-amber-400' : 'bg-emerald-400'}`} />
                  </div>

                  {/* Event Content */}
                  <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-4 transition group-hover:border-slate-700 space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-slate-200 font-semibold">{formattedTime}</span>
                        <span className="text-slate-500 font-mono text-[11px]">{formattedDate}</span>

                        {ev.isInferred ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-amber-950 text-amber-300 border border-amber-800/80">
                            Inferred Timestamp
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-slate-800 text-slate-300">
                            Observed Record
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <ConfidenceBadge confidence={ev.confidence} />
                        {ev.correlationGroup && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-950 text-indigo-300 border border-indigo-800 flex items-center gap-1">
                            <Tag className="w-2.5 h-2.5" />
                            {ev.correlationGroup}
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="text-xs sm:text-sm font-semibold text-slate-100">
                      {ev.description}
                    </div>

                    <div className="text-[11px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-900">
                      <span>Category: <strong className="text-slate-300">{ev.category}</strong></span>
                      <span className="font-mono text-slate-500">Source: {ev.source}</span>
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
