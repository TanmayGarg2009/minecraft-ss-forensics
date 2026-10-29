import type { ReportDetail, EvidenceSummary, SubmitReportResponse } from '../types/report';

const API_BASE = '/api/v1';

export class ApiError extends Error {
  status: number;
  errors?: any[];

  constructor(message: string, status: number, errors?: any[]) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.errors = errors;
  }
}

export async function fetchReport(publicId: string): Promise<ReportDetail> {
  const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(publicId)}`, {
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!res.ok) {
    if (res.status === 404) {
      throw new ApiError('Report not found or has expired. Reports expire automatically after their retention window.', 404);
    }
    const errData = await res.json().catch(() => ({}));
    throw new ApiError(errData.message || 'Failed to fetch report', res.status);
  }

  return res.json();
}

export async function fetchEvidence(publicId: string, evidenceId: string): Promise<EvidenceSummary> {
  const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(publicId)}/evidence/${encodeURIComponent(evidenceId)}`);
  if (!res.ok) {
    throw new ApiError('Evidence not found or unauthorized.', res.status);
  }
  return res.json();
}

export async function submitReport(payload: any): Promise<SubmitReportResponse> {
  const res = await fetch(`${API_BASE}/reports`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new ApiError(data.message || 'Report ingestion failed.', res.status, data.errors);
  }

  return data;
}

export async function deleteReport(publicId: string, deletionKey: string): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(publicId)}`, {
    method: 'DELETE',
    headers: {
      'Content-Type': 'application/json',
      'X-Deletion-Key': deletionKey,
    },
    body: JSON.stringify({ deletionKey }),
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new ApiError(data.message || 'Report deletion failed.', res.status);
  }

  return data;
}

export async function fetchHealth(): Promise<{ status: string; uptime: string; database: string }> {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}
