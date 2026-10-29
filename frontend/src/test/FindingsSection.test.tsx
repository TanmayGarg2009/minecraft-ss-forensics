import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { FindingsSection } from '../components/ReportViewer/FindingsSection';
import type { FindingDetail } from '../types/report';

const mockFindings: FindingDetail[] = [
  {
    ruleId: 'MC-MOD-001',
    title: 'Autoclicker Binary Execution',
    category: 'ExecutionArtifacts',
    severity: 'High',
    confidence: 'High',
    explanation: 'Executed 12 minutes prior to investigation.',
    filePath: 'C:\\Users\\User\\Downloads\\clicker.exe',
    fileSizeBytes: 412000,
    evidenceSource: 'Prefetch',
    detectionRuleVersion: '1.0.0',
    limitationsAndFalsePositives: 'Could be testing tool.'
  },
  {
    ruleId: 'NTFS-USN-002',
    title: 'Deleted Mod in Temp',
    category: 'FileDeletion',
    severity: 'Medium',
    confidence: 'Medium',
    explanation: 'Deleted 3 minutes prior.',
    filePath: 'C:\\Users\\User\\AppData\\Local\\Temp\\mod.jar',
    fileSizeBytes: 200000,
    evidenceSource: 'UsnJournal',
    detectionRuleVersion: '1.0.0',
    limitationsAndFalsePositives: 'User might clean old jars.'
  }
];

describe('FindingsSection Component', () => {
  it('renders all findings initially', () => {
    render(<FindingsSection findings={mockFindings} />);
    expect(screen.getByText('Autoclicker Binary Execution')).toBeInTheDocument();
    expect(screen.getByText('Deleted Mod in Temp')).toBeInTheDocument();
  });

  it('filters findings by search query', () => {
    render(<FindingsSection findings={mockFindings} />);
    const searchInput = screen.getByPlaceholderText(/Search findings by rule ID/i);
    fireEvent.change(searchInput, { target: { value: 'clicker' } });

    expect(screen.getByText('Autoclicker Binary Execution')).toBeInTheDocument();
    expect(screen.queryByText('Deleted Mod in Temp')).not.toBeInTheDocument();
  });

  it('filters findings by category dropdown', () => {
    render(<FindingsSection findings={mockFindings} />);
    const selects = screen.getAllByRole('combobox');
    const catSelect = selects[1]; // category select
    fireEvent.change(catSelect, { target: { value: 'FileDeletion' } });

    expect(screen.getByText('Deleted Mod in Temp')).toBeInTheDocument();
    expect(screen.queryByText('Autoclicker Binary Execution')).not.toBeInTheDocument();
  });

  it('renders false-positive limitations prominently', () => {
    render(<FindingsSection findings={mockFindings} />);
    const callouts = screen.getAllByText(/Limitations & Potential False Positives:/i);
    expect(callouts.length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/Could be testing tool./i)).toBeInTheDocument();
  });
});
