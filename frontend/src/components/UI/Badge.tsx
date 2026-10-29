import React from 'react';
import type { Severity, ConfidenceLevel } from '../../types/report';

interface SeverityBadgeProps {
  severity: Severity | string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const norm = severity.toLowerCase();
  let color = 'bg-slate-800 text-slate-300 border-slate-700';

  if (norm === 'critical') {
    color = 'bg-red-950/80 text-red-300 border-red-700/80 animate-pulse';
  } else if (norm === 'high') {
    color = 'bg-orange-950/70 text-orange-300 border-orange-700/70';
  } else if (norm === 'medium') {
    color = 'bg-amber-950/60 text-amber-300 border-amber-700/60';
  } else if (norm === 'low') {
    color = 'bg-sky-950/60 text-sky-300 border-sky-700/60';
  } else if (norm === 'informational') {
    color = 'bg-slate-800 text-slate-300 border-slate-600';
  }

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider border ${color}`}>
      {severity}
    </span>
  );
};

interface ConfidenceBadgeProps {
  confidence: ConfidenceLevel | string;
}

export const ConfidenceBadge: React.FC<ConfidenceBadgeProps> = ({ confidence }) => {
  const norm = confidence.toLowerCase();
  let color = 'bg-slate-800 text-slate-300 border-slate-700';

  if (norm === 'certain') {
    color = 'bg-emerald-950/70 text-emerald-300 border-emerald-700/70';
  } else if (norm === 'high') {
    color = 'bg-teal-950/60 text-teal-300 border-teal-700/60';
  } else if (norm === 'medium') {
    color = 'bg-indigo-950/60 text-indigo-300 border-indigo-700/60';
  } else if (norm === 'low') {
    color = 'bg-slate-800/80 text-slate-400 border-slate-700';
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${color}`}>
      Confidence: {confidence}
    </span>
  );
};
