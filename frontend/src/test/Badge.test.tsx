import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SeverityBadge, ConfidenceBadge } from '../components/UI/Badge';

describe('Badge Components', () => {
  it('renders critical severity with pulse animation styling', () => {
    render(<SeverityBadge severity="Critical" />);
    const badge = screen.getByText('Critical');
    expect(badge).toBeInTheDocument();
    expect(badge.className).toContain('text-red-300');
  });

  it('renders confidence badge properly', () => {
    render(<ConfidenceBadge confidence="Certain" />);
    expect(screen.getByText('Confidence: Certain')).toBeInTheDocument();
  });
});
