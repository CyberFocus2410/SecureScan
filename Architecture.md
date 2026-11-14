# SecureScan AI — Architecture

Version 1.1 · Status: Proposed (pending ADR approval — see decision.md)

## 1. Architectural style

**Modular monolith** for the control/API plane + **isolated asynchronous scanner workers**. No microservice fan-out in MVP.

```text
React + Vite + TypeScript + Tailwind
                |
             REST API  (/api/v1)
                |
      FastAPI control plane
    /           |            \
PostgreSQL   Redis / RQ    Report service
                |
       isolated scan worker  (no network, read-only, non-root)
     /      |       |       \
 Semgrep Gitleaks  OSV     custom checks
                |
      normalized finding store
            /       \
 OWASP mapping    DPDP evidence engine
            \       /
 evidence + remediation + versioned legal refs
                |
        dashboard and PDF/JSON
```

## 2. Trust zones

| Zone | Contains | Trust | Network |
|---|---|---|---|
| **Z1 Public edge** | React app, API gateway | Untrusted input | Internet |
| **Z2 Control plane** | FastAPI, Postgres, Redis, report service | Trusted | Internal only |
| **Z3 Importer** | GitHub fetch (bounded, pinned SHA) | Semi-trusted | github.com allowlist only |
| **Z4 Scan sandbox** | Semgrep, Gitleaks, custom rules, Bandit | **Untrusted data** | **None** |
| **Z5 Advisory resolver** | OSV lookup | Trusted, restricted | OSV hosts only; never sees repo code beyond package coordinates |
| **Z6 AI gateway** | Provider client | Trusted | Provider only; receives redacted context only |

Rule: data flows Z1→Z2→Z3→Z4→Z2. Z4 returns results through a read-only output channel; it holds no credentials.

## 3. Component responsibilities

| Component | Responsibility | Must not |
|---|---|---|
| `github_import` | Validate URL, resolve branch → SHA, bounded checkout, no submodules/LFS | Follow redirects off-host; run hooks |
| `audit` | Orchestrate stages, state machine, coverage | Mark a failed scanner as pass |
| Scanner adapters | `supports/prepare/execute/parse/normalize/metadata` | Expose raw commands to client |
| `normalization` | Unified finding, fingerprint, dedupe, CWE (if grounded) | Merge findings without matching location/context |
| `security_controls` | Evaluate SEC-001…032, evidence tiers, result states | Report "confirmed absent" without deployment scope |
| `owasp_mappings` | Versioned many-to-many mapping | Invent ASVS IDs |
| `dpdp_controls` | Applicability, predicates, readiness labels | Output binary compliance verdict |
| `dpdp/commencement` | Compute effective status from `as_of_date` | Hard-code "in force/upcoming" |
| `penalties` | Schedule reference + caveat | Sum, predict or quantify |
| `reporting` | HTML→PDF, JSON | Include raw secrets |
| `ai_explain` | Redacted, schema-validated explanation | Change severity/legal mapping |
| `core/limits` | Quotas, size/time caps | — |

## 4. Audit pipeline

```text
QUEUED → IMPORTING → SCANNING → NORMALIZING → SECURITY_MAPPING → DPDP_MAPPING → REPORT_READY → COMPLETED
                                  (any stage)  → PARTIAL | FAILED
```

1. **Import (Z3):** parse URL → resolve SHA → bounded shallow checkout → canonicalize paths → purge symlinks escaping root.
2. **Discovery:** language/framework detection, route/model/serializer/config inventory (safe, static).
3. **Scan (Z4):** run applicable adapters in parallel with per-tool timeouts; each emits a `scanner_run` row.
4. **Advisory (Z5):** OSV lookup from extracted package coordinates only.
5. **Normalize:** fingerprint, dedupe, redact, attach provenance.
6. **Security mapping:** evaluate SEC controls → `control_results` + OWASP mappings.
7. **DPDP mapping:** applicability → predicates → readiness + effective date + penalty reference.
8. **Remediation:** deterministic remediation actions (technical / document / organizational).
9. **Report:** PDF + JSON on demand.
10. **Cleanup:** purge worktree.

**Partial-failure rule:** any adapter failure ⇒ audit `PARTIAL`, affected controls `NOT_VERIFIED`/`ERROR`, UI shows coverage gap. Results from successful stages remain viewable.

## 5. Sandbox specification (NFR-03)

- Disposable container per scan; **non-root**; read-only repo mount; writable tmpfs for scratch only.
- `--cap-drop=ALL`, `no-new-privileges`, seccomp default, no privileged mode, **no Docker socket**.
- CPU/memory/PIDs/disk/time limits; `network=none`.
- Rules/binaries baked into a pinned image; no runtime downloads.
- Output limited to structured JSON on a mounted output path; terminal escape sequences stripped.
- Worker hosting must satisfy the above; if not available, fall back to local Docker Compose demo only (decision D-05).

## 6. Data architecture

PostgreSQL + JSONB for scanner-native evidence and questionnaires.

```text
repositories 1─N audits 1─N scanner_runs
                   │ 1─N findings ──N─ evidence
                   │ 1─N control_results ──N─ evidence
                   │ 1─1 dpdp_profiles
                   │ 1─N remediation_actions
                   │ 1─N report_artifacts
                   └ 1─N audit_events
control_catalogue ─< control_results
control_catalogue ─< owasp_mappings (many-to-many)
legal_sources ─< penalty_categories
```

| Table | Key columns |
|---|---|
| `repositories` | id, github_owner, github_repo, canonical_url (unique), default_branch |
| `audits` | id, repository_id, session_id, commit_sha, scope, status, coverage_json |
| `scanner_runs` | id, audit_id, scanner, version, status, counters, error_code |
| `findings` | id, audit_id, fingerprint, rule_id, scanner_run_id, category, severity, confidence, file_path, start/end_line, status |
| `evidence` | id, audit_id, finding_id?, control_result_id?, kind, path, line_range, **redacted_excerpt**, data_json, provenance |
| `control_catalogue` | id, domain, version, label, source_uri, source_ref, applicability_json, effective_at (immutable once used) |
| `control_results` | id, audit_id, control_id, result, rationale, evidence_level, evaluated_at |
| `owasp_mappings` | internal_control_id, standard, standard_version, external_ref, rationale |
| `dpdp_profiles` | id, audit_id, questionnaire_json |
| `legal_sources` | id, doc_name, clause_ref, source_url, gazette_id, version, effective_at, reviewed_at |
| `penalty_categories` | id, schedule_item, related_act_section, ceiling_inr, legal_source_id, caveat |
| `remediation_actions` | id, audit_id, finding_id/control_id, priority, action_type, steps, validation_method |
| `report_artifacts` | id, audit_id, format, status, safe_storage_key, expires_at |
| `audit_events` | id, audit_id, stage, state, message, timestamp |
| `ai_explanations` (optional) | model/version, redacted_input_fingerprint, response fields, caveat |

**Integrity rules:** raw provenance fields are never overwritten by AI output · no raw secrets in any column · catalogue rows immutable after use (new version instead).

## 7. Policy-as-data

Legal and control logic lives in versioned YAML under `policies/`, loaded at runtime and snapshot-versioned into each audit:

`security_controls.yaml` · `owasp_mappings.yaml` · `dpdp_controls.yaml` · `dpdp_commencement.yaml` · `penalty_schedule.yaml`

Updating law/dates should not require a code deploy (NFR-10).

## 8. Technology stack

| Layer | Choice |
|---|---|
| Frontend | React, TypeScript, Vite, Tailwind, TanStack Query, React Router, optional Recharts |
| Backend | Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy, Alembic |
| Data/queue | PostgreSQL, Redis + RQ |
| Scanners | Semgrep, Gitleaks, OSV-Scanner, Bandit (conditional) + custom Python rules |
| AI | Provider abstraction (Gemini or Claude), validated output, optional |
| Reports | HTML-to-PDF + JSON |
| Orchestration | Docker Compose (local); hardened sandbox required for internet-facing scans |

## 9. Cross-cutting design

| Concern | Approach |
|---|---|
| Redaction | At parser boundary before any persistence/log/AI; snapshot tests |
| Idempotency | Dedupe active audits per (session, repo, SHA, scope) |
| Observability | `audit_events` ordered stream; structured logs without payloads |
| AuthZ | Session capability IDs; middleware checks on every resource |
| Config | Env-driven limits (`core/limits.py`) |
| Versioning | Scanner + rule-pack + catalogue + schema versions stored per audit |
| Error model | Typed error codes; no stack traces to client |

## 10. Directory structure

```text
securescan-ai/
  frontend/src/{app,pages/{Home,AuditProgress,Security,DPDP,Finding,Report},components,services/api.ts,hooks,types,tests}
  backend/app/{main.py,core,api/v1,models,schemas,services,scanners,dpdp,workers,reporting/templates,tests/{unit,integration,fixtures,security}}
  backend/migrations/
  policies/*.yaml
  fixtures/{vulnerable-python-api,vulnerable-node-api,clean-api}/
  infrastructure/{compose.yaml,docker/}
  docs/{architecture,api_contracts,threat_model,legal_sources}/
```

## 11. Deployment views

| Env | Shape |
|---|---|
| Local / demo | Docker Compose: web, api, worker, postgres, redis; sandbox container per scan |
| Hosted (later) | API + Postgres + Redis managed; scanner workers on an isolated host/VM pool with `network=none` containers |

## 12. Architecture risks

| Risk | Response |
|---|---|
| No safe hosting for workers | Demo locally; document constraint (D-05) |
| Policy drift | Versioned YAML + commencement tests |
| Adapter schema drift | Pin tool versions; contract tests on fixtures |
| Custom-rule false positives | Confidence labels; fixture precision review |
