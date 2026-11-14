import {
  Repository,
  Audit,
  Finding,
  ControlResult,
  ScannerRun,
  AuditEvent,
  RemediationAction
} from '../types/contracts';

export const mockRepository: Repository = {
  id: '7f8b9e6a-1234-4a5b-bcde-9876543210ab',
  github_owner: 'vulnerable-org',
  github_repo: 'vulnerable-python-api',
  canonical_url: 'https://github.com/vulnerable-org/vulnerable-python-api',
  default_branch: 'main',
  last_commit_sha: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e',
  detected_languages: ['Python'],
  detected_frameworks: ['FastAPI']
};

export const mockAudit: Audit = {
  id: '9a8b7c6d-5e4f-3a2b-1c0d-e9f8a7b6c5d4',
  repository_id: mockRepository.id,
  commit_sha: mockRepository.last_commit_sha,
  scopes: ['SECURITY', 'DPDP'],
  status: 'COMPLETED',
  current_stage: 'REPORT_READY',
  created_at: '2026-11-14T12:00:00Z',
  completed_at: '2026-11-14T12:02:15Z',
  coverage: {
    security: {
      tested: 14,
      applicable: 22,
      potential_gap: 6,
      not_verified: 2,
      not_applicable: 10
    },
    dpdp: {
      evidence_supports: 4,
      potential_gap: 8,
      needs_documents: 4,
      not_applicable: 2
    }
  }
};

export const mockScannerRuns: ScannerRun[] = [
  {
    id: 'run-1',
    audit_id: mockAudit.id,
    scanner: 'gitleaks',
    version: '8.21.2',
    status: 'COMPLETED',
    duration_ms: 1150,
    findings_count: 1
  },
  {
    id: 'run-2',
    audit_id: mockAudit.id,
    scanner: 'semgrep',
    version: '1.102.0',
    status: 'COMPLETED',
    duration_ms: 3420,
    findings_count: 2
  },
  {
    id: 'run-3',
    audit_id: mockAudit.id,
    scanner: 'osv-scanner',
    version: '1.9.2',
    status: 'COMPLETED',
    duration_ms: 2890,
    findings_count: 1
  }
];

export const mockFindings: Finding[] = [
  {
    id: 'finding-1',
    audit_id: mockAudit.id,
    fingerprint: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    scanner_name: 'gitleaks',
    scanner_version: '8.21.2',
    rule_id: 'aws-access-token',
    title: 'Hardcoded AWS Access Key ID exposed in repository',
    description: 'Found raw AWS credentials committed to settings file.',
    category: 'secrets',
    severity: 'CRITICAL',
    confidence: 'CONFIRMED',
    file_path: 'backend/config/settings.py',
    start_line: 42,
    end_line: 42,
    cwe_ids: ['CWE-798'],
    owasp_refs: ['A07:2025'],
    redacted_snippet: "AWS_ACCESS_KEY_ID = '[REDACTED:aws-access-key]'",
    remediation: {
      technical_fix: "Rotate credentials in AWS IAM immediately and load via environment variables.",
      validation_steps: "Run Gitleaks on the worktree to ensure secret is not present."
    }
  },
  {
    id: 'finding-2',
    audit_id: mockAudit.id,
    fingerprint: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3ee3b0c44298fc1c149afbf4c8',
    scanner_name: 'semgrep',
    scanner_version: '1.102.0',
    rule_id: 'python.fastapi.security.sql-injection',
    title: 'Unescaped SQL query construction with user-controlled input',
    description: 'Direct string concatenation in database query allows SQL injection.',
    category: 'injection',
    severity: 'HIGH',
    confidence: 'CONFIRMED',
    file_path: 'backend/api/users.py',
    start_line: 88,
    end_line: 89,
    cwe_ids: ['CWE-89'],
    owasp_refs: ['A05:2025'],
    redacted_snippet: "query = f\"SELECT * FROM users WHERE email = '{user_email}'\"",
    remediation: {
      technical_fix: "Use parameterized queries via SQLAlchemy text(:email) or ORM filter.",
      validation_steps: "Inject single quotes in query parameter tests; verify query execution fails safely."
    }
  }
];

export const mockControlResults: ControlResult[] = [
  {
    id: 'cr-1',
    audit_id: mockAudit.id,
    control_id: 'SEC-005',
    domain: 'SECURITY',
    title: 'API rate limiting on sensitive routes',
    state: 'POTENTIAL_GAP',
    rationale: 'No rate limiting middleware detected in application code. Gateway/reverse-proxy rate limits unverified.',
    evidence_tier: 'E1_SOURCE_CODE',
    effective_date_status: 'IN_FORCE'
  },
  {
    id: 'cr-2',
    audit_id: mockAudit.id,
    control_id: 'DPDP-006',
    domain: 'DPDP',
    title: 'Reasonable security safeguards against data breaches',
    state: 'POTENTIAL_GAP',
    readiness_label: 'Potential gap',
    effective_date_status: 'UPCOMING',
    effective_date: '2027-05-13',
    rationale: 'Exposed secrets and SQL injection findings indicate vulnerabilities in safeguards protecting personal data.',
    statutory_ref: {
      source_doc: 'Digital Personal Data Protection Act, 2023',
      clause: 'Section 8(5)',
      schedule_item: 1,
      statutory_ceiling: 'Up to ₹250 crore',
      mandatory_caveat: 'Potential legal category; applicability and liability not determined.'
    }
  }
];

export const mockAuditEvents: AuditEvent[] = [
  { timestamp: '2026-11-14T12:00:01Z', stage: 'IMPORTING', state: 'DONE', message: 'Cloned worktree and pinned SHA a1b2c3d4' },
  { timestamp: '2026-11-14T12:00:10Z', stage: 'SCANNING', state: 'DONE', message: 'Executed Semgrep and Gitleaks in sandbox' },
  { timestamp: '2026-11-14T12:01:00Z', stage: 'NORMALIZING', state: 'DONE', message: 'Normalized findings and verified redaction' }
];

export const mockRemediations: RemediationAction[] = [
  {
    id: 'rem-1',
    audit_id: mockAudit.id,
    priority: 'P0',
    action_type: 'ENGINEERING',
    target_id: 'SEC-001',
    title: 'Revoke and rotate AWS credentials',
    steps: [
      'Revoke exposed AWS access key in AWS IAM console.',
      'Deploy replacement key into secure secrets vault.'
    ],
    validation_method: 'Rescan with Gitleaks.'
  }
];

