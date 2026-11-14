# SecureScan AI — Frozen API & Domain Contracts

- **Status:** Frozen at Milestone 0 (M0)
- **Version:** 1.0.0
- **Base URL:** `/api/v1`
- **Governing Rule:** Rules.md §G rule 4 & 11: *"Freeze shared contracts at M0; do not change the finding schema, statuses, or API shapes without an ADR entry and product owner approval."*

---

## 1. Core Enumerations

```typescript
// Finding Severity
export enum Severity {
  CRITICAL = "CRITICAL",
  HIGH = "HIGH",
  MEDIUM = "MEDIUM",
  LOW = "LOW",
  INFO = "INFO"
}

// Finding & Rule Confidence
export enum Confidence {
  CONFIRMED = "CONFIRMED",       // Deterministic proof (e.g. valid AST sink or live lockfile CVE)
  HIGH = "HIGH",                 // Strong static pattern match
  MEDIUM = "MEDIUM",             // Heuristic match requiring human context
  LOW = "LOW",                   // Weak indicator or potential false positive
  EXPERIMENTAL = "EXPERIMENTAL"  // Prototype or informational check
}

// Control Result States (Mandatory 6 states - Architecture §3, Rules.md §C)
export enum ControlState {
  PASS_EVIDENCED = "PASS_EVIDENCED",   // Meaningful code/config evidence proves compliance
  FAIL_EVIDENCED = "FAIL_EVIDENCED",   // Concrete evidence of vulnerability or violation
  POTENTIAL_GAP = "POTENTIAL_GAP",     // Static indicator suggests absence, but deployment unverified
  NOT_VERIFIED = "NOT_VERIFIED",       // Cannot evaluate (no lockfile, unsupported framework, no doc)
  NOT_APPLICABLE = "NOT_APPLICABLE",   // Control is formally outside the project's declared scope
  ERROR = "ERROR"                      // Scanner crashed or execution encountered unrecoverable error
}

// Evidence Tiers (FRD v1.1)
export enum EvidenceTier {
  E1_SOURCE_CODE = "E1_SOURCE_CODE",           // Static source code AST / regex
  E2_CONFIG_MANIFEST = "E2_CONFIG_MANIFEST",   // Lockfiles, Dockerfiles, compose, gateway config
  E3_SUPPLIED_DOCS = "E3_SUPPLIED_DOCS",       // Privacy notices, uploaded policies
  E4_ORG_ATTESTATION = "E4_ORG_ATTESTATION",   // Completed questionnaire answers
  E5_RUNTIME_TEST = "E5_RUNTIME_TEST"          // Out of MVP (reserved)
}

// Audit Stages & Lifecycle Statuses
export enum AuditStatus {
  QUEUED = "QUEUED",
  IMPORTING = "IMPORTING",
  SCANNING = "SCANNING",
  NORMALIZING = "NORMALIZING",
  SECURITY_MAPPING = "SECURITY_MAPPING",
  DPDP_MAPPING = "DPDP_MAPPING",
  REPORT_READY = "REPORT_READY",
  COMPLETED = "COMPLETED",
  PARTIAL = "PARTIAL",     // >=1 scanner/check failed, but results remain viewable
  FAILED = "FAILED"        // Critical pipeline failure (e.g. clone rejected)
}

// DPDP Phased Commencement Status
export enum EffectiveDateStatus {
  IN_FORCE = "IN_FORCE",
  UPCOMING = "UPCOMING",
  NOT_DETERMINED = "NOT_DETERMINED"
}
```

---

## 2. Frozen Domain Schemas (Pydantic v2 Models)

### 2.1 Evidence Schema
```json
{
  "$id": "Evidence",
  "type": "object",
  "properties": {
    "id": { "type": "string", "format": "uuid" },
    "audit_id": { "type": "string", "format": "uuid" },
    "finding_id": { "type": ["string", "null"], "format": "uuid" },
    "control_result_id": { "type": ["string", "null"], "format": "uuid" },
    "tier": { "type": "string", "enum": ["E1_SOURCE_CODE", "E2_CONFIG_MANIFEST", "E3_SUPPLIED_DOCS", "E4_ORG_ATTESTATION", "E5_RUNTIME_TEST"] },
    "path": { "type": "string" },
    "start_line": { "type": ["integer", "null"] },
    "end_line": { "type": ["integer", "null"] },
    "redacted_excerpt": { "type": "string", "description": "Snippet with literals replaced by [REDACTED:<type>]" },
    "raw_data": { "type": "object", "description": "Arbitrary scanner metadata, strictly scrubbed of secrets" },
    "provenance": { "type": "string", "description": "Scanner name, rule id, version tag" }
  },
  "required": ["id", "audit_id", "tier", "path", "redacted_excerpt", "provenance"]
}
```

### 2.2 Finding Schema
```json
{
  "$id": "Finding",
  "type": "object",
  "properties": {
    "id": { "type": "string", "format": "uuid" },
    "audit_id": { "type": "string", "format": "uuid" },
    "fingerprint": { "type": "string", "description": "SHA-256 hash of rule_id + canonical path + context" },
    "scanner_name": { "type": "string", "enum": ["semgrep", "gitleaks", "osv-scanner", "bandit", "custom"] },
    "scanner_version": { "type": "string" },
    "rule_id": { "type": "string" },
    "title": { "type": "string" },
    "description": { "type": "string" },
    "category": { "type": "string", "description": "secrets, injection, auth, api, misconfig, dependency, data_exposure" },
    "severity": { "type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] },
    "confidence": { "type": "string", "enum": ["CONFIRMED", "HIGH", "MEDIUM", "LOW", "EXPERIMENTAL"] },
    "file_path": { "type": "string" },
    "start_line": { "type": "integer" },
    "end_line": { "type": "integer" },
    "cwe_ids": { "type": "array", "items": { "type": "string" } },
    "owasp_refs": { "type": "array", "items": { "type": "string" }, "description": "e.g. ['A05:2025', 'API4:2023']" },
    "evidence": { "$ref": "#/definitions/Evidence" },
    "remediation": {
      "type": "object",
      "properties": {
        "technical_fix": { "type": "string" },
        "validation_steps": { "type": "string" }
      },
      "required": ["technical_fix", "validation_steps"]
    }
  },
  "required": ["id", "audit_id", "fingerprint", "scanner_name", "rule_id", "title", "severity", "confidence", "file_path", "start_line", "end_line"]
}
```

### 2.3 ControlResult Schema
```json
{
  "$id": "ControlResult",
  "type": "object",
  "properties": {
    "id": { "type": "string", "format": "uuid" },
    "audit_id": { "type": "string", "format": "uuid" },
    "control_id": { "type": "string", "description": "e.g. SEC-005 or DPDP-006" },
    "domain": { "type": "string", "enum": ["SECURITY", "DPDP"] },
    "title": { "type": "string" },
    "state": { "type": "string", "enum": ["PASS_EVIDENCED", "FAIL_EVIDENCED", "POTENTIAL_GAP", "NOT_VERIFIED", "NOT_APPLICABLE", "ERROR"] },
    "readiness_label": { "type": ["string", "null"], "description": "For DPDP: Evidence supports / Potential gap / Needs documents / Not applicable / Requires legal review" },
    "effective_date_status": { "type": "string", "enum": ["IN_FORCE", "UPCOMING", "NOT_DETERMINED"] },
    "effective_date": { "type": ["string", "null"], "format": "date" },
    "rationale": { "type": "string" },
    "evidence_tier": { "type": "string", "enum": ["E1_SOURCE_CODE", "E2_CONFIG_MANIFEST", "E3_SUPPLIED_DOCS", "E4_ORG_ATTESTATION", "E5_RUNTIME_TEST"] },
    "evidence_items": { "type": "array", "items": { "$ref": "#/definitions/Evidence" } },
    "statutory_ref": {
      "type": ["object", "null"],
      "properties": {
        "source_doc": { "type": "string" },
        "clause": { "type": "string" },
        "source_url": { "type": "string" },
        "schedule_item": { "type": ["integer", "null"] },
        "statutory_ceiling": { "type": ["string", "null"] },
        "mandatory_caveat": { "type": "string" }
      }
    }
  },
  "required": ["id", "audit_id", "control_id", "domain", "state", "rationale"]
}
```

---

## 3. Standardized Error Response Model

Every error returned by the API follows this uniform JSON schema:

```json
{
  "$id": "ErrorResponse",
  "type": "object",
  "properties": {
    "error": {
      "type": "object",
      "properties": {
        "code": { "type": "string" },
        "message": { "type": "string" },
        "details": { "type": ["object", "array", "null"] }
      },
      "required": ["code", "message"]
    }
  },
  "required": ["error"]
}
```

### Complete List of Typed Error Codes

| HTTP Status | Error Code | Description / Trigger Condition |
|---|---|---|
| `400` | `ERR_INVALID_REPO_URL` | Submitted URL does not match `https://github.com/{owner}/{repo}` format. |
| `400` | `ERR_UNSUPPORTED_PROTOCOL` | Scheme is not HTTPS, or path contains encoded tricks/IP literals. |
| `400` | `ERR_INVALID_BRANCH` | Requested branch contains directory traversal or invalid git ref characters. |
| `403` | `ERR_UNAUTHORIZED_SESSION` | Access attempted on audit or report with mismatched session capability ID. |
| `404` | `ERR_REPO_NOT_FOUND` | Repository does not exist or is private/inaccessible on GitHub. |
| `404` | `ERR_AUDIT_NOT_FOUND` | Requested audit ID does not exist in the active session. |
| `404` | `ERR_REPORT_NOT_FOUND` | Requested report ID does not exist or has expired. |
| `409` | `ERR_DUPLICATE_ACTIVE_AUDIT` | An identical audit (repo + SHA + scopes) is already running for this session. |
| `413` | `ERR_REPO_TOO_LARGE` | Repository exceeds size limit (50MB) or file count limit (2000 files). |
| `422` | `ERR_VALIDATION_ERROR` | Request body failed Pydantic schema validation. |
| `429` | `ERR_QUOTA_EXCEEDED` | Session rate limit or concurrent scan quota exceeded. |
| `504` | `ERR_CLONE_TIMEOUT` | Git clone or shallow fetch exceeded the 30-second cap. |
| `500` | `ERR_SCANNER_EXECUTION_FAILED` | Internal runner error invoking a scanner container. |
| `500` | `ERR_POLICY_LOAD_FAILED` | Policy YAML corrupted or failed schema verification. |
| `500` | `ERR_REPORT_GENERATION_FAILED`| WeasyPrint failed to compile PDF report artifact. |
| `503` | `ERR_AI_PROVIDER_UNAVAILABLE` | LLM API timeout or quota exhausted (triggers deterministic fallback). |

---

## 4. Audit Pipeline State Machine

```text
                  ┌──────────────┐
                  │    QUEUED    │
                  └──────┬───────┘
                         │ (Worker picks up)
                         ▼
                  ┌──────────────┐
       ┌──────────┤  IMPORTING   ├──────────┐
       │ (Clone   └──────┬───────┘ (Clone   │
       │  Failed)        │ (Fetch OK)      │  Timeout)
       │                 ▼                 │
       │          ┌──────────────┐         │
       │          │   SCANNING   │         │
       │          └──────┬───────┘         │
       │                 │ (Scanners done) │
       │                 ▼                 │
       │          ┌──────────────┐         │
       │          │ NORMALIZING  │         │
       │          └──────┬───────┘         │
       │                 │                 │
       │                 ▼                 │
       │          ┌──────────────┐         │
       │          │  SEC_MAPPING │         │
       │          └──────┬───────┘         │
       │                 │                 │
       │                 ▼                 │
       │          ┌──────────────┐         │
       │          │ DPDP_MAPPING │         │
       │          └──────┬───────┘         │
       │                 │                 │
       │                 ▼                 │
       │          ┌──────────────┐         │
       │          │ REPORT_READY │         │
       │          └──────┬───────┘         │
       │                 │                 │
       ▼                 ▼                 ▼
 ┌───────────┐    ┌─────────────┐    ┌───────────┐
 │  FAILED   │    │  COMPLETED  │    │  PARTIAL  │
 └───────────┘    └─────────────┘    └───────────┘
```

- **Partial State Guarantee:** If any individual scanner (e.g. Bandit or Semgrep) times out or exits non-zero, the pipeline transitions to `PARTIAL`, never `FAILED`. Findings from completed scanners are preserved and displayed, and affected controls are marked `ERROR` or `NOT_VERIFIED`.

---

## 5. API Endpoint Specifications

### 5.1 Repository Management

#### `POST /api/v1/repositories`
- **Headers:** `X-Session-ID: <uuid>` (optional, auto-generated if omitted)
- **Request:**
  ```json
  {
    "github_url": "https://github.com/vulnerable-org/sample-api",
    "branch": "main"
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "id": "7f8b9e6a-1234-4a5b-bcde-9876543210ab",
    "github_owner": "vulnerable-org",
    "github_repo": "sample-api",
    "canonical_url": "https://github.com/vulnerable-org/sample-api",
    "default_branch": "main"
  }
  ```

#### `GET /api/v1/repositories/{id}`
- **Response (200 OK):**
  ```json
  {
    "id": "7f8b9e6a-1234-4a5b-bcde-9876543210ab",
    "github_owner": "vulnerable-org",
    "github_repo": "sample-api",
    "canonical_url": "https://github.com/vulnerable-org/sample-api",
    "default_branch": "main",
    "last_commit_sha": "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e",
    "detected_languages": ["Python"],
    "detected_frameworks": ["FastAPI"]
  }
  ```

---

### 5.2 Audits & Execution

#### `POST /api/v1/audits`
- **Request:**
  ```json
  {
    "repository_id": "7f8b9e6a-1234-4a5b-bcde-9876543210ab",
    "scopes": ["SECURITY", "DPDP"],
    "commit_sha": "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e"
  }
  ```
- **Response (202 Accepted):**
  ```json
  {
    "audit_id": "9a8b7c6d-5e4f-3a2b-1c0d-e9f8a7b6c5d4",
    "status": "QUEUED",
    "created_at": "2026-11-14T12:00:00Z",
    "poll_url": "/api/v1/audits/9a8b7c6d-5e4f-3a2b-1c0d-e9f8a7b6c5d4"
  }
  ```

#### `GET /api/v1/audits/{id}`
- **Response (200 OK):**
  ```json
  {
    "id": "9a8b7c6d-5e4f-3a2b-1c0d-e9f8a7b6c5d4",
    "repository_id": "7f8b9e6a-1234-4a5b-bcde-9876543210ab",
    "commit_sha": "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e",
    "scopes": ["SECURITY", "DPDP"],
    "status": "COMPLETED",
    "current_stage": "REPORT_READY",
    "created_at": "2026-11-14T12:00:00Z",
    "completed_at": "2026-11-14T12:02:15Z",
    "coverage": {
      "security": { "evidenced": 14, "applicable": 22, "potential_gap": 6, "not_verified": 2, "not_applicable": 10 },
      "dpdp": { "evidence_supports": 4, "potential_gap": 8, "needs_documents": 4, "not_applicable": 2 }
    }
  }
  ```

#### `GET /api/v1/audits/{id}/events`
- **Response (200 OK):**
  ```json
  [
    { "timestamp": "2026-11-14T12:00:01Z", "stage": "IMPORTING", "state": "IN_PROGRESS", "message": "Cloning repository shallow worktree..." },
    { "timestamp": "2026-11-14T12:00:05Z", "stage": "IMPORTING", "state": "DONE", "message": "Pinned commit SHA a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e" },
    { "timestamp": "2026-11-14T12:00:06Z", "stage": "SCANNING", "state": "IN_PROGRESS", "message": "Executing Semgrep and Gitleaks in sandbox containers..." }
  ]
  ```

#### `GET /api/v1/audits/{id}/scanner-runs`
- **Response (200 OK):**
  ```json
  [
    {
      "scanner": "semgrep",
      "version": "1.102.0",
      "status": "COMPLETED",
      "duration_ms": 3420,
      "findings_count": 5,
      "error_code": null
    },
    {
      "scanner": "gitleaks",
      "version": "8.21.2",
      "status": "COMPLETED",
      "duration_ms": 1150,
      "findings_count": 1,
      "error_code": null
    },
    {
      "scanner": "osv-scanner",
      "version": "1.9.2",
      "status": "COMPLETED",
      "duration_ms": 2890,
      "findings_count": 2,
      "error_code": null
    }
  ]
  ```

---

### 5.3 Security Audit Results

#### `GET /api/v1/audits/{id}/security/findings`
- **Query Params:** `severity`, `category`, `scanner`, `file_path`, `page=1`, `page_size=50`
- **Response (200 OK):**
  ```json
  {
    "items": [
      {
        "id": "11112222-3333-4444-5555-666677778888",
        "audit_id": "9a8b7c6d-5e4f-3a2b-1c0d-e9f8a7b6c5d4",
        "fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "scanner_name": "gitleaks",
        "scanner_version": "8.21.2",
        "rule_id": "aws-access-token",
        "title": "AWS Access Key ID exposed in repository",
        "category": "secrets",
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "file_path": "backend/config/settings.py",
        "start_line": 42,
        "end_line": 42,
        "cwe_ids": ["CWE-798"],
        "owasp_refs": ["A07:2025"],
        "redacted_snippet": "AWS_ACCESS_KEY_ID = '[REDACTED:aws-token]'"
      }
    ],
    "total": 1,
    "page": 1,
    "page_size": 50
  }
  ```

#### `GET /api/v1/findings/{id}`
- **Response (200 OK):**
  Full `Finding` object including detailed `Evidence` and `Remediation` instructions.

#### `GET /api/v1/audits/{id}/security/coverage`
- **Response (200 OK):**
  ```json
  {
    "summary": {
      "total_controls": 32,
      "evidenced_pass": 14,
      "evidenced_fail": 6,
      "potential_gap": 8,
      "not_verified": 2,
      "not_applicable": 2
    },
    "controls": [
      {
        "control_id": "SEC-005",
        "title": "API rate limiting on sensitive routes",
        "state": "POTENTIAL_GAP",
        "rationale": "No rate limiter middleware detected in application code. Deployment/gateway throttling unverified.",
        "owasp_refs": ["API4:2023", "API6:2023"]
      }
    ]
  }
  ```

---

### 5.4 DPDP Compliance & Legal Exposure

#### `GET /api/v1/audits/{id}/dpdp/controls`
- **Response (200 OK):**
  ```json
  {
    "as_of_date": "2026-11-14",
    "disclaimer": "Readiness assessment. Not a compliance determination or legal advice.",
    "controls": [
      {
        "control_id": "DPDP-006",
        "title": "Reasonable security safeguards against data breaches",
        "readiness_label": "Potential gap",
        "effective_date_status": "UPCOMING",
        "effective_date": "2027-05-13",
        "legal_source": {
          "act_section": "Section 8(5)",
          "rules_ref": "Rule 6",
          "gazette_id": "G.S.R. 843(E)"
        },
        "penalty_reference": {
          "schedule_item": 1,
          "statutory_ceiling": "Up to ₹250 crore",
          "caveat": "Potential legal category; applicability and liability not determined."
        }
      }
    ]
  }
  ```

#### `POST /api/v1/audits/{id}/dpdp/profile`
- **Request:**
  ```json
  {
    "processes_children_data": false,
    "significant_data_fiduciary_designated": false,
    "third_party_processors_engaged": true,
    "privacy_notice_url": "https://sample-api.org/privacy"
  }
  ```
- **Response (202 Accepted):** Refreshes DPDP evaluation job and returns updated status.

#### `GET /api/v1/audits/{id}/dpdp/data-flows`
- **Response (200 OK):**
  ```json
  [
    {
      "model_name": "User",
      "file_path": "backend/models/user.py",
      "inferred_fields": ["email", "phone_number", "date_of_birth"],
      "purpose": "Unknown (requires organizational questionnaire)",
      "processor": "Unknown"
    }
  ]
  ```

#### `GET /api/v1/audits/{id}/legal-exposure`
- **Response (200 OK):**
  ```json
  {
    "disclaimer": "Potential legal category; applicability and liability not determined.",
    "categories": [
      {
        "schedule_item": 1,
        "related_act_section": "Section 8(5)",
        "statutory_ceiling_inr": "₹250 crore",
        "linked_controls": ["DPDP-006"],
        "caveat": "Potential legal category; applicability and liability not determined."
      }
    ]
  }
  ```

#### `GET /api/v1/audits/{id}/remediations`
- **Response (200 OK):**
  ```json
  [
    {
      "priority": "P0",
      "type": "ENGINEERING",
      "target_id": "SEC-001",
      "title": "Revoke and rotate exposed credentials",
      "steps": [
        "Immediately revoke AWS access token in AWS IAM console.",
        "Store replacement secret in environment variables or KMS."
      ],
      "validation_method": "Run Gitleaks on worktree to ensure secret is eliminated."
    }
  ]
  ```

---

### 5.5 Reports & AI Explanations

#### `POST /api/v1/audits/{id}/reports`
- **Request:** `{ "format": "pdf" }` or `{ "format": "json" }`
- **Response (202 Accepted):**
  ```json
  {
    "report_id": "44445555-6666-7777-8888-99990000aaaa",
    "status": "PROCESSING",
    "format": "pdf"
  }
  ```

#### `GET /api/v1/reports/{id}`
- **Response (200 OK):** Returns status (`PROCESSING`, `COMPLETED`, `FAILED`).

#### `GET /api/v1/reports/{id}/download`
- **Headers:** `X-Session-ID: <uuid>`
- **Response (200 OK):** Binary file stream (`application/pdf` or `application/json`) with `Content-Disposition: attachment; filename="securescan_audit_report_<commit_sha>.pdf"`.

#### `POST /api/v1/findings/{id}/explain`
- **Request:** `{ "include_risk_context": true }`
- **Response (200 OK):**
  ```json
  {
    "finding_id": "11112222-3333-4444-5555-666677778888",
    "ai_generated": true,
    "root_cause": "Hardcoded AWS secret key assigned directly to configuration variable.",
    "recommended_technical_fix": "Use os.environ.get('AWS_ACCESS_KEY_ID') or pydantic-settings BaseSettings.",
    "validation_steps": "Run pytest tests/test_config.py ensuring settings load from environment.",
    "limitations": "AI explanation does not certify absence of other exposed secrets."
  }
  ```

#### `GET /api/v1/health`
- **Response (200 OK):**
  ```json
  {
    "status": "OK",
    "version": "1.0.0",
    "as_of_date": "2026-11-14",
    "services": {
      "database": "CONNECTED",
      "redis": "CONNECTED"
    }
  }
  ```

