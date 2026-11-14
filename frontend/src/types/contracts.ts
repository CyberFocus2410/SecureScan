/**
 * Frozen API and domain contracts.
 * Generated from docs/api_contracts.md and backend Pydantic v2 schemas.
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Confidence = 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW' | 'EXPERIMENTAL';

export type ControlState =
  | 'PASS_EVIDENCED'
  | 'FAIL_EVIDENCED'
  | 'POTENTIAL_GAP'
  | 'NOT_VERIFIED'
  | 'NOT_APPLICABLE'
  | 'ERROR';

export type EvidenceTier =
  | 'E1_SOURCE_CODE'
  | 'E2_CONFIG_MANIFEST'
  | 'E3_SUPPLIED_DOCS'
  | 'E4_ORG_ATTESTATION'
  | 'E5_RUNTIME_TEST';

export type AuditStatus =
  | 'QUEUED'
  | 'IMPORTING'
  | 'SCANNING'
  | 'NORMALIZING'
  | 'SECURITY_MAPPING'
  | 'DPDP_MAPPING'
  | 'REPORT_READY'
  | 'COMPLETED'
  | 'PARTIAL'
  | 'FAILED';

export type EffectiveDateStatus = 'IN_FORCE' | 'UPCOMING' | 'NOT_DETERMINED';

export interface Evidence {
  id: string;
  audit_id: string;
  finding_id?: string | null;
  control_result_id?: string | null;
  tier: EvidenceTier;
  path: string;
  start_line?: number | null;
  end_line?: number | null;
  redacted_excerpt: string;
  raw_data?: Record<string, unknown>;
  provenance: string;
}

export interface FindingRemediation {
  technical_fix: string;
  validation_steps: string;
}

export interface Finding {
  id: string;
  audit_id: string;
  fingerprint: string;
  scanner_name: string;
  scanner_version: string;
  rule_id: string;
  title: string;
  description: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  file_path: string;
  start_line: number;
  end_line: number;
  cwe_ids: string[];
  owasp_refs: string[];
  evidence?: Evidence | null;
  remediation?: FindingRemediation | null;
  redacted_snippet?: string | null;
}

export interface StatutoryRef {
  source_doc: string;
  clause: string;
  source_url?: string | null;
  schedule_item?: number | null;
  statutory_ceiling?: string | null;
  mandatory_caveat: string;
}

export interface ControlResult {
  id: string;
  audit_id: string;
  control_id: string;
  domain: 'SECURITY' | 'DPDP';
  title: string;
  state: ControlState;
  readiness_label?: string | null;
  effective_date_status: EffectiveDateStatus;
  effective_date?: string | null;
  rationale: string;
  evidence_tier?: EvidenceTier | null;
  statutory_ref?: StatutoryRef | null;
  evidence_items?: Evidence[];
}

export interface ScannerRun {
  id: string;
  audit_id: string;
  scanner: string;
  version: string;
  status: string;
  duration_ms: number;
  findings_count: number;
  error_code?: string | null;
}

export interface Repository {
  id: string;
  github_owner: string;
  github_repo: string;
  canonical_url: string;
  default_branch: string;
  last_commit_sha?: string | null;
  detected_languages: string[];
  detected_frameworks: string[];
}

export interface AuditEvent {
  timestamp: string;
  stage: string;
  state: string;
  message: string;
}

export interface Audit {
  id: string;
  repository_id: string;
  commit_sha?: string | null;
  scopes: ('SECURITY' | 'DPDP')[];
  status: AuditStatus;
  current_stage: string;
  created_at: string;
  completed_at?: string | null;
  coverage?: {
    security?: Record<string, number>;
    dpdp?: Record<string, number>;
  };
}

export interface RemediationAction {
  id: string;
  audit_id: string;
  priority: 'P0' | 'P1' | 'P2';
  action_type: 'ENGINEERING' | 'DOCUMENTATION' | 'ORGANIZATIONAL';
  target_id: string;
  title: string;
  steps: string[];
  validation_method: string;
}

export interface SecurityCoverageSummary {
  total_controls: number;
  applicable_controls: number;
  evidenced_controls: number;
  coverage_ratio: number;
  denominator: number;
  evidenced_pass: number;
  evidenced_fail: number;
  potential_gap: number;
  not_verified: number;
  not_applicable: number;
  error: number;
}

export interface SecurityCoverageResponse {
  summary: SecurityCoverageSummary;
  controls: ControlResult[];
}

export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

