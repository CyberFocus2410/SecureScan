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
  SecurityCoverageResponse,
  Target,
  TargetVerification,
  ScanScope,
  RiskIntelligenceData,
  CompareResult,
  AuditListItem,
  DPDPReadinessReport,
  AttackSurfaceData
} from '../types/contracts';
import * as mockData from './mockData';

const RAW_BASE = (import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || '')
  .replace(/\/api\/v1\/?$/, '')
  .replace(/\/+$/, '');
const BASE_URL = `${RAW_BASE}/api/v1`;

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

export async function uploadRepositoryArchive(file: File, projectName?: string): Promise<Repository> {
  if (USE_MOCK) return mockData.mockRepository;
  const formData = new FormData();
  formData.append('file', file);
  if (projectName) formData.append('project_name', projectName);

  const res = await fetch(`${BASE_URL}/repositories/upload`, {
    method: 'POST',
    headers: { 'X-Session-ID': getSessionId() },
    body: formData
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || err.detail || 'Failed to upload repository archive');
  }
  return res.json();
}

export async function uploadRepositoryFolder(files: File[], projectName?: string): Promise<Repository> {
  if (USE_MOCK) return mockData.mockRepository;
  const formData = new FormData();
  if (projectName) formData.append('project_name', projectName);

  for (const file of files) {
    const relPath = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
    formData.append('files', file);
    formData.append('relative_paths', relPath);
  }

  const res = await fetch(`${BASE_URL}/repositories/upload`, {
    method: 'POST',
    headers: { 'X-Session-ID': getSessionId() },
    body: formData
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || err.detail || 'Failed to upload repository folder');
  }
  return res.json();
}

export async function startAudit(
  repositoryId: string,
  scopes = ['SECURITY', 'DPDP'],
  commitSha?: string,
  targetId?: string
): Promise<{ audit_id: string; status: string }> {
  if (USE_MOCK) return { audit_id: mockData.mockAudit.id, status: 'QUEUED' };
  const res = await fetch(`${BASE_URL}/audits`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({
      repository_id: repositoryId,
      scopes,
      commit_sha: commitSha,
      target_id: targetId
    })
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

export interface ToolDiagnosticItem {
  category: string;
  primary_tool: string;
  primary_installed: boolean;
  primary_version: string | null;
  fallback_tool: string;
  fallback_available: boolean;
  active_engine: string;
  status: 'PASS' | 'FALLBACK_ACTIVE' | 'FAIL';
  details: string;
}

export interface ToolHealthResponse {
  status: 'HEALTHY' | 'DEGRADED';
  total_areas: number;
  primary_count: number;
  fallback_count: number;
  failed_count: number;
  sandbox: {
    active_engine: string;
    environment: string;
    fail_closed_enforced: boolean;
  };
  tools: ToolDiagnosticItem[];
}

export async function fetchToolHealth(): Promise<ToolHealthResponse> {
  const res = await fetch(`${BASE_URL}/admin/tools`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error('Tool diagnostics check failed');
  return res.json();
}

export async function createTarget(url: string, targetType = 'WEBSITE', name?: string): Promise<Target> {
  const res = await fetch(`${BASE_URL}/targets`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ url, target_type: targetType, name }),
  });
  if (!res.ok) throw new Error('Failed to create target');
  return res.json();
}

export async function listTargets(): Promise<Target[]> {
  const res = await fetch(`${BASE_URL}/targets`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to list targets');
  return res.json();
}

export async function requestVerificationChallenge(targetId: string, method = 'DNS_TXT'): Promise<TargetVerification> {
  const res = await fetch(`${BASE_URL}/targets/${targetId}/challenges`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ method }),
  });
  if (!res.ok) throw new Error('Failed to request verification challenge');
  return res.json();
}

export async function verifyTarget(targetId: string, verificationId?: string, proof?: Record<string, unknown>): Promise<{ verified: boolean; message: string }> {
  const res = await fetch(`${BASE_URL}/targets/${targetId}/verify`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ verification_id: verificationId, proof }),
  });
  if (!res.ok) throw new Error('Failed to verify target');
  return res.json();
}

export async function configureTargetScope(
  targetId: string,
  scope: { allowed_hosts?: string[]; allowed_paths?: string[]; excluded_paths?: string[]; max_rps?: number; max_crawl_depth?: number }
): Promise<ScanScope> {
  const res = await fetch(`${BASE_URL}/targets/${targetId}/scope`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(scope),
  });
  if (!res.ok) throw new Error('Failed to configure target scope');
  return res.json();
}

export async function recordConsent(targetId: string, userId: string, termsVersion = '2.0'): Promise<any> {
  const res = await fetch(`${BASE_URL}/targets/${targetId}/consent`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ user_id: userId, terms_version: termsVersion }),
  });
  if (!res.ok) throw new Error('Failed to record consent');
  return res.json();
}

export async function listAudits(): Promise<AuditListItem[]> {
  const res = await fetch(`${BASE_URL}/audits`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to list audits');
  return res.json();
}

export async function cancelAudit(auditId: string): Promise<{ audit_id: string; status: string; message: string }> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/cancel`, {
    method: 'POST',
    headers: getHeaders()
  });
  if (!res.ok) throw new Error('Failed to cancel audit');
  return res.json();
}

export async function getRiskIntelligence(auditId: string): Promise<RiskIntelligenceData> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/risk-intelligence`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to fetch risk intelligence');
  return res.json();
}

export async function getAttackSurface(auditId: string): Promise<AttackSurfaceData> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/attack-surface`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to fetch attack surface');
  return res.json();
}

export async function compareAudits(auditId: string, baseAuditId: string): Promise<CompareResult> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/compare?base_audit_id=${baseAuditId}`, {
    headers: getHeaders()
  });
  if (!res.ok) throw new Error('Failed to compare audits');
  return res.json();
}

export async function getFindingDetail(findingId: string): Promise<Finding> {
  const res = await fetch(`${BASE_URL}/findings/${findingId}`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to get finding detail');
  return res.json();
}

export async function createFindingFixPr(findingId: string): Promise<{ status: string; branch_name: string; pr_number?: number; pr_url?: string; is_draft: boolean; message: string }> {
  const res = await fetch(`${BASE_URL}/findings/${findingId}/create-pr`, {
    method: 'POST',
    headers: getHeaders()
  });
  if (!res.ok) throw new Error('Failed to create remediation PR');
  return res.json();
}

export async function getDpdpReadiness(auditId: string): Promise<DPDPReadinessReport> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/dpdp/readiness`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to get DPDP readiness report');
  return res.json();
}

export async function getSarifReport(auditId: string): Promise<string> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/sarif`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to export SARIF report');
  return res.text();
}

export async function getMarkdownReport(auditId: string): Promise<string> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/markdown`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to export Markdown report');
  return res.text();
}

export async function getFixPack(auditId: string, format = 'json'): Promise<any> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/fix-pack?format=${format}`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to export Fix Pack');
  return format === 'json' ? res.json() : res.text();
}

export async function getSbomCycloneDx(auditId: string): Promise<any> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/sbom/cyclonedx`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to export CycloneDX SBOM');
  return res.json();
}

export async function getSbomSpdx(auditId: string): Promise<any> {
  const res = await fetch(`${BASE_URL}/audits/${auditId}/sbom/spdx`, { headers: getHeaders() });
  if (!res.ok) throw new Error('Failed to export SPDX SBOM');
  return res.json();
}



