/**
 * Typed API client for SecureScan backend.
 * Conforms strictly to docs/api_contracts.md.
 */
import {
  Repository,
  Audit,
  Finding,
  ControlResult,
  ScannerRun,
  AuditEvent,
  RemediationAction,
  SecurityCoverageResponse
} from '../types/contracts';
import * as mockData from './mockData';

const BASE_URL = '/api/v1';

// Session management
export function getSessionId(): string {
  let sessionId = localStorage.getItem('securescan_session_id');
  if (!sessionId) {
    sessionId = crypto.randomUUID();
    localStorage.setItem('securescan_session_id', sessionId);
  }
  return sessionId;
}

const getHeaders = (): HeadersInit => ({
  'Content-Type': 'application/json',
  'X-Session-ID': getSessionId()
});

// Mode toggle: fallback to mock data if backend unavailable
const USE_MOCK = false;

export async function fetchHealth(): Promise<{ status: string; version: string; as_of_date: string }> {
  if (USE_MOCK) return { status: 'OK', version: '1.0.0', as_of_date: '2026-11-14' };
  const res = await fetch(`${BASE_URL}/health`);
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

export async function submitRepository(githubUrl: string, branch = 'main'): Promise<Repository> {
  if (USE_MOCK) return mockData.mockRepository;
  const res = await fetch(`${BASE_URL}/repositories`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ github_url: githubUrl, branch })
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error?.message || 'Failed to import repository');
  }
  return res.json();
}

export async function startAudit(repositoryId: string, scopes = ['SECURITY', 'DPDP']): Promise<{ audit_id: string; status: string }> {
  if (USE_MOCK) return { audit_id: mockData.mockAudit.id, status: 'QUEUED' };
  const res = await fetch(`${BASE_URL}/audits`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ repository_id: repositoryId, scopes })
  });
  if (!res.ok) throw new Error('Failed to start audit');
  return res.json();
}

export async function getAudit(auditId: string): Promise<Audit> {
  if (USE_MOCK) return mockData.mockAudit;
  const res = await fetch(`${BASE_URL}/audits/${auditId}`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to get audit');
  return res.json();
}

export async function getAuditEvents(auditId: string): Promise<AuditEvent[]> {
  if (USE_MOCK) return mockData.mockAuditEvents;
  const res = await fetch(`${BASE_URL}/audits/${auditId}/events`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to get audit events');
  return res.json();
}

export async function getScannerRuns(auditId: string): Promise<ScannerRun[]> {
  if (USE_MOCK) return mockData.mockScannerRuns;
  const res = await fetch(`${BASE_URL}/audits/${auditId}/scanner-runs`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to get scanner runs');
  return res.json();
}

export async function getFindings(auditId: string): Promise<{ items: Finding[]; total: number }> {
  if (USE_MOCK) return { items: mockData.mockFindings, total: mockData.mockFindings.length };
  const res = await fetch(`${BASE_URL}/audits/${auditId}/security/findings`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to get findings');
  return res.json();
}

export async function getControlResults(auditId: string, domain = 'SECURITY'): Promise<ControlResult[]> {
  if (USE_MOCK) return mockData.mockControlResults.filter(c => c.domain === domain);
  const endpoint = domain === 'DPDP' ? `${BASE_URL}/audits/${auditId}/dpdp/controls` : `${BASE_URL}/audits/${auditId}/security/coverage`;
  const res = await fetch(endpoint, { headers: getHeaders() });
  if (!res.ok) throw new Error(`Failed to get ${domain} controls`);
  const data = await res.json();
  return data.controls || data;
}

export async function getSecurityCoverage(auditId: string): Promise<SecurityCoverageResponse> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/security/coverage`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to get security coverage');
  return res.json();
}

export async function getRemediations(auditId: string): Promise<RemediationAction[]> {
  if (USE_MOCK) return mockData.mockRemediations;
  const res = await fetch(`${BASE_URL}/audits/${auditId}/remediations`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to get remediations');
  return res.json();
}

export async function getLegalExposure(auditId: string): Promise<{ items: any[]; mandatory_disclaimer: string }> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/legal-exposure`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to get legal exposure');
  return res.json();
}

export async function submitDpdpProfile(auditId: string, answers: Record<string, boolean | null>): Promise<any> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/dpdp/profile`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(answers)
  });
  if (!res.ok) throw new Error('Failed to submit DPDP profile');
  return res.json();
}

export async function getDataFlows(auditId: string): Promise<any[]> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/dpdp/data-flows`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to get data flows');
  return res.json();
}

export async function createReport(auditId: string, format: 'pdf' | 'json'): Promise<{ report_id: string; status: string; format: string }> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/reports`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ format })
  });
  if (!res.ok) throw new Error('Failed to create report');
  return res.json();
}

export async function explainFinding(findingId: string, includeRiskContext = true): Promise<any> {
  const res = await fetch(`${BASE_URL}/findings/${findingId}/explain`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ include_risk_context: includeRiskContext })
  });
  if (!res.ok) throw new Error('Failed to explain finding');
  return res.json();
}


