import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { DiagnosticsSection } from '../components/ReportViewer/DiagnosticsSection';
import type { DiagnosticItemDetail } from '../types/report';

describe('DiagnosticsSection Component', () => {
  const mockDiagnostics: DiagnosticItemDetail[] = [
    {
      checkName: 'NTFS Journal Scanner',
      source: 'UsnJournal',
      status: 'Completed',
      reason: 'Enumerated 1,240 records cleanly.',
    },
    {
      checkName: 'Kernel Memory Driver Inspection',
      source: 'Driver',
      status: 'AccessDenied',
      reason: 'Administrator elevation was not granted.',
      recommendation: 'Request player execute scanner as Administrator to audit low-level drivers.',
    },
    {
      checkName: 'BAM / DAM Activity Monitor',
      source: 'BamDam',
      status: 'CompletedWithLimitations',
      reason: 'Registry permissions partially restricted on subkey.',
    },
  ];

  it('renders check coverage summary and diagnostic cards', () => {
    render(<DiagnosticsSection diagnostics={mockDiagnostics} />);

    expect(screen.getByText(/Scanner Collection Diagnostics & Check Coverage/i)).toBeInTheDocument();
    expect(screen.getByText(/NTFS Journal Scanner/i)).toBeInTheDocument();
    expect(screen.getByText(/Kernel Memory Driver Inspection/i)).toBeInTheDocument();
    expect(screen.getByText(/BAM \/ DAM Activity Monitor/i)).toBeInTheDocument();
  });

  it('filters by issues and hurdles only', () => {
    render(<DiagnosticsSection diagnostics={mockDiagnostics} />);

    const issuesButton = screen.getByRole('button', { name: /Limitations & Hurdles/i });
    fireEvent.click(issuesButton);

    expect(screen.queryByText(/NTFS Journal Scanner/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Kernel Memory Driver Inspection/i)).toBeInTheDocument();
    expect(screen.getByText(/BAM \/ DAM Activity Monitor/i)).toBeInTheDocument();
  });

  it('renders staff recommendations and investigation limitations', () => {
    render(<DiagnosticsSection diagnostics={mockDiagnostics} />);

    expect(screen.getByText(/Request player execute scanner as Administrator/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Investigation Impact:/i).length).toBeGreaterThanOrEqual(1);
  });
});
