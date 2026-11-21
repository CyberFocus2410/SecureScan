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
  engine?: string | null;
  tool?: string | null;
  verified_state?: 'CONFIRMED' | 'SUSPECTED' | 'NOT_VERIFIED' | 'FALSE_POSITIVE' | null;
  priority?: 'P0' | 'P1' | 'P2' | 'P3' | null;
  signals?: string[] | null;
  standards?: Record<string, unknown> | null;
  plain_title?: string | null;
  plain_summary?: string | null;
  why_it_matters?: string | null;
  how_to_fix?: string | null;
  how_to_verify_fix?: string | null;
  fix_effort?: string | null;
  fix_prompt?: string | null;
  related_finding_ids?: string[] | null;
  attack_chain_id?: string | null;
  status?: string | null;
  request_evidence?: string | null;
  response_evidence?: string | null;
}

export interface Target {
  id: string;
  session_id: string;
  name?: string | null;
  target_type: 'WEBSITE' | 'API' | 'REPOSITORY' | 'IP_CIDR' | 'CLOUD_ASSET' | string;
  url: string;
  verified: boolean;
  verified_at?: string | null;
  created_at: string;
}

export interface TargetVerification {
  id: string;
  target_id: string;
  verification_method: 'DNS_TXT' | 'WELL_KNOWN_FILE' | 'META_TAG' | 'REPO_TOKEN' | string;
  token: string;
  status: 'PENDING' | 'VERIFIED' | 'FAILED' | 'EXPIRED' | string;
  proof_details?: Record<string, unknown> | null;
  expires_at?: string | null;
  created_at: string;
}

export interface ScanScope {
  id: string;
  target_id: string;
  allowed_hosts: string[];
  allowed_paths: string[];
  excluded_paths: string[];
  max_rps: number;
  max_crawl_depth: number;
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

export interface SecondaryScores {
  security_score: number;
  privacy_score: number;
  infrastructure_score: number;
  supply_chain_score: number;
  dpdp_readiness_score: number;
  overall_rating: string;
  hard_cap_applied: boolean;
  hard_cap_reasons: string[];
  methodology: string;
}

export interface AttackChain {
  chain_id: string;
  title: string;
  severity: string;
  narrative_story: string;
  traversal_steps: string[];
  linked_finding_rules: string[];
  linked_finding_ids: string[];
  remediation_strategy: string;
}

export interface RiskIntelligenceData {
  audit_id: string;
  priority_counts: {
    P0: number;
    P1: number;
    P2: number;
    P3: number;
  };
  severity_counts: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
  };
  scores: SecondaryScores;
  attack_chains: AttackChain[];
  findings_count: number;
  confirmed_exploitable_count: number;
}

export interface FindingComparison {
  id: string;
  rule_id: string;
  title: string;
  severity: string;
  priority: string;
  file_path: string;
}

export interface CompareResult {
  current_audit_id: string;
  base_audit_id: string;
  summary: {
    fixed_count: number;
    new_count: number;
    unchanged_count: number;
    regressed_count: number;
    score_deltas: {
      security_score_delta: number;
      privacy_score_delta: number;
      infrastructure_score_delta: number;
      supply_chain_score_delta: number;
    };
  };
  fixed_findings: FindingComparison[];
  new_findings: FindingComparison[];
  unchanged_findings: FindingComparison[];
  regressed_findings: FindingComparison[];
  base_scores: {
    security_score: number;
    overall_rating: string;
  };
  current_scores: {
    security_score: number;
    overall_rating: string;
  };
}

export interface AuditListItem {
  id: string;
  repository_id: string;
  target_url: string;
  commit_sha?: string | null;
  scopes: string[];
  status: AuditStatus;
  current_stage: string;
  findings_count: number;
  created_at?: string | null;
  completed_at?: string | null;
}

export interface DPDPReadinessReport {
  readiness_score: number;
  raw_score: number;
  hard_cap_applied: boolean;
  hard_cap_reason?: string | null;
  as_of_date: string;
  categories: Array<{
    category_id: string;
    title: string;
    status: string;
    controls_count: number;
    implemented_count: number;
  }>;
  evaluated_controls: Array<{
    control_id: string;
    title: string;
    status: string;
    category: string;
    effective_date_status: string;
    evidence_summary: string;
    remediation: string;
    act_section?: string;
    rules_ref?: string;
    applies_to?: string;
  }>;
  action_plan: Array<{
    control_id: string;
    title: string;
    status: string;
    category: string;
    statutory_deadline: string;
    remediation: string;
  }>;
  statutory_penalties: Array<{
    schedule_item: number;
    breach_description: string;
    related_act_section: string;
    statutory_ceiling_inr: string;
    mandatory_caveat: string;
    linked_controls: string[];
  }>;
}

