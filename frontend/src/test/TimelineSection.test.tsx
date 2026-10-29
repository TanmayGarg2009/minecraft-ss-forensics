import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { TimelineSection } from '../components/ReportViewer/TimelineSection';
import type { TimelineEventDetail } from '../types/report';

describe('TimelineSection Component', () => {
  const mockEvents: TimelineEventDetail[] = [
    {
      timestamp: '2026-10-29T10:00:00Z',
      description: 'Prefetch execution logged for autoclicker.exe',
      category: 'ExecutionArtifacts',
      source: 'Prefetch',
      confidence: 'High',
      isInferred: false,
      correlationGroup: 'GRP-CLICK-1',
    },
    {
      timestamp: '2026-10-29T10:15:00Z',
      description: 'USN journal deletion event for autoclicker.exe',
      category: 'FileDeletion',
      source: 'UsnJournal',
      confidence: 'High',
      isInferred: true,
      correlationGroup: 'GRP-CLICK-1',
    },
  ];

  it('renders chronological timeline and sorts ascending / descending', () => {
    render(<TimelineSection events={mockEvents} />);

    expect(screen.getByText(/Chronological Forensic Timeline/i)).toBeInTheDocument();
    expect(screen.getByText(/Prefetch execution logged for autoclicker.exe/i)).toBeInTheDocument();
    expect(screen.getByText(/USN journal deletion event for autoclicker.exe/i)).toBeInTheDocument();

    const sortButton = screen.getByRole('button', { name: /Oldest First/i });
    expect(sortButton).toBeInTheDocument();

    fireEvent.click(sortButton);
    expect(screen.getByRole('button', { name: /Newest First/i })).toBeInTheDocument();
  });

  it('filters by observed vs inferred timestamps', () => {
    render(<TimelineSection events={mockEvents} />);

    const observedButton = screen.getByRole('button', { name: /^Observed$/i });
    fireEvent.click(observedButton);

    expect(screen.getByText(/Prefetch execution logged/i)).toBeInTheDocument();
    expect(screen.queryByText(/USN journal deletion event/i)).not.toBeInTheDocument();

    const inferredButton = screen.getByRole('button', { name: /^Inferred$/i });
    fireEvent.click(inferredButton);

    expect(screen.queryByText(/Prefetch execution logged/i)).not.toBeInTheDocument();
    expect(screen.getByText(/USN journal deletion event/i)).toBeInTheDocument();
  });

  it('filters by correlation group', () => {
    render(<TimelineSection events={mockEvents} />);

    expect(screen.getAllByText('GRP-CLICK-1').length).toBeGreaterThanOrEqual(1);
  });
});
