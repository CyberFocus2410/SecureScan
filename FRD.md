# SecureScan AI — Functional Requirements Document (FRD)

Version 1.1 · As-of 14 Nov 2026 · Companion to PRD.md

Evidence tiers: **E1** source code · **E2** config/manifest · **E3** supplied docs · **E4** org attestation · **E5** authorized runtime test.
Evidence class in checks: **S** static · **D** dependency/config · **R** runtime (optional) · **O** organizational/doc.

---

## 1. Functional overview

| Area | Requirement ID range |
|---|---|
| Repository import | FR-IMP-* |
| Audit orchestration | FR-AUD-* |
| Scanning & normalization | FR-SCN-* |
| Security controls & OWASP | FR-SEC-* |
| DPDP engine | FR-DPD-* |
| Penalty reference | PEN-* |
| AI explanations | FR-AI-* |
| Reporting | FR-RPT-* |
| Session & access | FR-ACC-* |

## 2. Repository import (FR-IMP)

- **FR-IMP-01** Accept only `https://github.com/{owner}/{repo}` (+ validated branch). Strip `.git`. Reject query/fragment abuse, other protocols/hosts, redirects to private IPs, `file://`.
- **FR-IMP-02** Pin and record **commit SHA** at import; all scans run on that SHA.
- **FR-IMP-03** Enforce caps: repo size, file count, per-file bytes, clone time. No submodules; no LFS dereference by default.
- **FR-IMP-04** Path canonicalization; symlinks never followed outside the worktree.
- **FR-IMP-05** Detect languages/frameworks; **FastAPI, Flask, Django, Express, Next.js (best effort)**. Unsupported frameworks are never labelled clean.
- **FR-IMP-06** Unsupported/oversized/invalid repo → structured 4xx with reason code.

## 3. Security check catalogue (FR-SEC)

| ID | Check | Method | MVP |
|---|---|---|---|
| SEC-001 | Hardcoded API keys, tokens, passwords, private keys | Gitleaks; redacted; optional bounded history | P0 S |
| SEC-002 | Secrets in frontend env/public assets | Client prefixes, bundled configs, committed env; distinguish publishable IDs | P0 S |
| SEC-003 | DB connection strings in client/public config | Pattern + framework-path | P0 S |
| SEC-004 | API returns excessive fields (passwords, tokens, national IDs, private profile) | Serializer/DTO analysis; auth context needed | P0 S potential |
| SEC-005 | Endpoints possibly missing rate limiting | Route discovery + middleware/gateway + endpoint classification | P0 S potential |
| SEC-006 | Login/reset/OTP lacking brute-force protection | Endpoint discovery; limiter/lockout markers | P0 S potential |
| SEC-007 | Missing route auth / public admin routes | Middleware/decorator patterns | P0 S potential |
| SEC-008 | BOLA/IDOR | Identifier access + ownership guard | P1 S potential |
| SEC-009 | Broken function-level authorization | Role checks, service-layer guards | P1 S potential |
| SEC-010 | Mass assignment | Object-to-model update patterns | P1 S |
| SEC-011 | SQL/NoSQL injection | Semgrep + unsafe query construction | P0 S |
| SEC-012 | OS command injection | Semgrep; subprocess/shell sinks | P0 S |
| SEC-013 | XSS / unsafe HTML | Semgrep framework rules | P0 S |
| SEC-014 | Path traversal | Semgrep + path handling | P1 S |
| SEC-015 | SSRF | Semgrep + server-side request sinks | P1 S |
| SEC-016 | Insecure JWT/session | Semgrep + auth config | P1 S |
| SEC-017 | Weak password hashing | Semgrep, crypto APIs | P1 S |
| SEC-018 | TLS validation disabled | Semgrep + config | P0 S |
| SEC-019 | Weak crypto, bad RNG, hardcoded keys | Semgrep/Bandit | P1 S |
| SEC-020 | CORS wildcard with credentials | Framework/deploy config | P0 D |
| SEC-021 | Debug mode, verbose errors, insecure defaults | Settings/error middleware | P0 D |
| SEC-022 | Missing security headers/cookie flags | Framework/proxy config | P1 D potential |
| SEC-023 | Known vulnerable dependencies | OSV-Scanner on lockfiles | P0 D |
| SEC-024 | CI workflow permission / source integrity | Workflow & manifest rules | P1 D |
| SEC-025 | Unsafe deserialization, upload validation, file writes | Semgrep/custom | P1 S |
| SEC-026 | Personal data in logs/exceptions | Logger sinks + field heuristics | P1 S potential |
| SEC-027 | Audit-trail gaps for sensitive events | Route + config + policy | P1 S/O potential |
| SEC-028 | Insecure backups / public storage config | Terraform/YAML | P1 D |
| SEC-029 | Excessive data extraction, pagination, resource use | Pagination/limit patterns | P1 S potential |
| SEC-030 | Missing CSRF on cookie-auth state-changing routes | Framework + auth-aware config | P1 S potential |
| SEC-031 | Missing input schema validation | Request models/validators | P1 S potential |
| SEC-032 | API inventory vs OpenAPI, stale endpoints | Route inventory diff | P2 S |

**OWASP mapping (FR-SEC-10):** many-to-many; store `external_ref`, `standard_version`, `rationale`. Examples: SEC-005 → API4:2023 / API6:2023; SEC-004 → API3:2023; SEC-008 → API1:2023; SEC-011 → A05:2025. ASVS IDs only from the official machine-readable catalogue; never invented. Taxonomies are not evidence of pass/fail.

### Conservative rule behaviour

| Topic | Rule |
|---|---|
| Rate limiting | Classify sensitive routes (login/OTP/reset/search/export). No limiter in source or included gateway config → `POTENTIAL_GAP`, **never** confirmed failure without deployment scope |
| Key exposure | Credential-like syntax in tracked frontend/public file → finding; if apparently fake, show confidence; always redact |
| DB / data exposure | Trace route → query/model → response serializer; flag *potential excessive exposure* only if sensitive fields are in output schema; auth context labelled unverified if unprovable |
| Personal data inference | Infer probable categories from forms/models; purpose and processor "unknown"; never treat all collection as unlawful |
| Privacy notice | Missing file alone → `NOT_VERIFIED`. Supplied notice failing a concrete content requirement → `POTENTIAL_GAP` or stronger only after deterministic review |

## 4. Scanner integration (FR-SCN)

**Adapter interface:** `supports(repo)`, `prepare(context)`, `execute(sandbox)`, `parse(output)`, `normalize(findings)`, `metadata()`.

| Tool | Scope | Output contract |
|---|---|---|
| Semgrep | SAST Python/JS/TS with pinned rule pack | JSON: rule, file, line, severity, metadata |
| Gitleaks | Worktree; history only if explicitly included | Redacted immediately; no literal stored |
| OSV-Scanner | Supported lockfiles/manifests | Advisory ID, package, version, affected range |
| Bandit | Python-only, optional | JSON: confidence, test ID |
| Custom Python rules | Routes, middleware, CORS, debug, auth, DTO leakage, retention hints | Normalized evidence, conservative status |

- **FR-SCN-01** Safe repo discovery separate from scanners; online advisory lookup separate from offline inspection.
- **FR-SCN-02** One normalized finding object; dedupe only when source **and** location/context match; retain all contributing scanner refs; include CWE only when grounded.
- **FR-SCN-03** Scanner output is untrusted: sanitize terminals, paths, logs.
- **FR-SCN-04** No recognized lockfile → `NOT_VERIFIED`, not "zero CVEs".
- **FR-SCN-05** Scanner crash/timeout → run status `FAILED/TIMEOUT`, audit `PARTIAL`, coverage shows the gap.
- **FR-SCN-06** Pin scanner and rule-pack versions; record with every audit.

## 5. DPDP engine (FR-DPD)

### Control catalogue

| ID | Topic (source basis) | Evidence | Treatment |
|---|---|---|---|
| DPDP-001 | Scope, roles, applicability (Act §§3–4) | Personal-data models, questionnaire | Manual applicability |
| DPDP-002 | Privacy notice, itemized data, purposes (Act §5, Rule 3) | Forms, notice text/URL | Gap only if supplied notice lacks detail; else Not verified |
| DPDP-003 | Consent / lawful basis, records (Act §§4, 6–7) | Consent UX/API, logs | Conditional; consent not assumed for all processing |
| DPDP-004 | Withdrawal mechanism (Act §6, Rule 3) | Settings UI + handler | Potential gap + manual UX review |
| DPDP-005 | Purpose limitation, minimization (Act §§4–8) | Field inventory, destinations | Potential gap; needs purpose |
| DPDP-006 | Reasonable security safeguards (Act §8(5), Rule 6) | Encryption, masking, ACL, monitoring, backups | Technical signals + docs; not a legal conclusion |
| DPDP-007 | Breach notification (Act §8(6), Rule 7) | Incident runbook, escalation owner | Mostly documentary |
| DPDP-008 | Erasure / storage limitation (Act §8(7)–(8), Rule 8) | Delete API, retention jobs | Conditional; legal-retention exceptions |
| DPDP-009 | Accuracy, correction (Act §§8, 12) | Edit endpoints | Code + docs |
| DPDP-010 | Data-principal rights & grievance (Act §§11–13, Rules 13–14) | Request mechanisms, support | Beyond code |
| DPDP-011 | Children's data (Act §9, Rule 10) | Age/guardian flows, ads/tracking | Ask applicability; exemptions |
| DPDP-012 | Persons with disabilities / guardians (Rule 11) | Guardian workflow | Conditional/manual |
| DPDP-013 | Significant Data Fiduciary (Act §10) | Classification, DPO, audits | Only if formally applicable |
| DPDP-014 | Processor contracts, third-party sharing (Act §8, Rule 6) | SDKs, subprocessors, contracts | Document evidence |
| DPDP-015 | Cross-border processing (Act §16) | Hosting/processor inventory | Legal review |
| DPDP-016 | Logs, monitoring, incident, retention | Logging config, policies | Verify Rule 6 conditions |
| DPDP-017 | Contact/grievance channels | Website notice | Source + docs |
| DPDP-018 | Personal-data exposure in API/frontend | Link SEC-002/003/004/026 → DPDP-006 | Cross-link; don't declare breach |

### Evaluation algorithm (FR-DPD-10)

1. Load pinned Act/Rules catalogue + commencement map.
2. Evaluate applicability questionnaire (personal data, geography, purpose, children, roles, SDF, consent/other basis, third parties, retention). **No answer = unknown.**
3. Extract candidate personal-data assets and routes from repo.
4. Collect optional notice/policy/questionnaire (never scraped from unrelated domains).
5. Evaluate each control with deterministic predicates and evidence state.
6. Attach `legal_source_ref, effective_date, as_of_date, applicability_status, result_status, uncertainty, remediation`.
7. Map only plausibly relevant penalty categories; never total or expected fine.
8. Flag human review for governance/contract/designation obligations.

**Readiness labels:** evidence supports · potential gap · needs documents · not applicable · requires legal review. **Effective-date label** (computed from `as_of_date`): *In force* · *Upcoming (date)* · *Not yet determined*.

**Example:** profile API returns email, phone, DOB to any authenticated user → Security flags potential excessive exposure; DPDP links it to safeguards/purpose-limitation readiness. Neither engine proves a breach or a ₹250 crore fine.

## 6. Penalty reference engine (PEN)

| Item | Breach type | Ceiling (Act Schedule) |
|---|---|---|
| 1 | Failure of reasonable security safeguards, §8(5) | Up to ₹250 crore |
| 2 | Failure to notify Board/affected principals of breach, §8(6) | Up to ₹200 crore |
| 3 | Additional obligations for children, §9 | Up to ₹200 crore |
| 4 | Significant Data Fiduciary obligations, §10 | Up to ₹150 crore |
| 5 | Breach of data-principal duties, §15 | Up to ₹10,000 |
| 6 | Breach of voluntary undertaking, §32 | Up to the amount applicable to the underlying breach |
| 7 | Other breaches of Act/Rules | Up to ₹50 crore |

- **PEN-01** Never emit "expected fine = ₹X", "fine will be imposed", or add ceilings.
- **PEN-02** Code finding maps only to a *possible* obligation + Schedule category, if applicable and effective.
- **PEN-03** Unresolved applicability/commencement → "Not established / upcoming", not "violation".
- **PEN-04** No number without verifiable official reference + caveat.
- **PEN-05** Separate *engineering priority*, *legal exposure reference*, *legal determination required*.
- **PEN-06** Human reviewer may correct applicability and attach evidence; recorded in audit trail.
- **Mandatory caveat text:** "Potential legal category; applicability and liability not determined."

## 7. AI explanations (FR-AI)

- **FR-AI-01** Optional, on-demand, never required for a complete report; deterministic remediation text always exists.
- **FR-AI-02** Pipeline: normalized finding → minimal redacted context + rule evidence → typed prompt with untrusted-source delimiters → provider → **schema-validated** response.
- **FR-AI-03** Output fields: `root_cause, risk_context, code_evidence_ref, recommended_technical_fix, recommended_document_or_process_action, validation_steps, unanswered_questions, limitations`.
- **FR-AI-04** Never invent ASVS IDs or DPDP clauses; never expose secrets; source comments are not instructions; no auto file writes; never instruct testing a third-party live endpoint without authorization.
- **FR-AI-05** AI cannot change severity, status or legal mapping; original evidence preserved in separate fields.
- **FR-AI-06** Provider down → deterministic fallback.

*Future (not MVP):* patch generation → disposable worktree → rescan → states `PATCH_APPLIED / STATIC_FINDING_CLEARED / TESTS_PASSED / INCONCLUSIVE / FAILED`. A vanished finding never means "secure".

## 8. Reporting (FR-RPT)

**Calculations**
- Severity distribution: confirmed and potential reported separately.
- **Coverage ratio** = controls with meaningful executed evidence ÷ controls applicable to declared scope; unknown/untested separate; denominator described.
- Security status = findings + coverage (no blanket Pass/Fail).
- DPDP readiness = per-control decisions, no % compliance unless clearly qualified.
- Penalties = one-to-many reference display, no aggregation.
- Citations: source title, clause, URL, version, accessed/reviewed date, commencement status.
- Optional "risk indicator" must be transparent and non-certifying.

**PDF mandatory sections:** cover (repo/commit/time) · executive summary · methodology & exclusions · tool versions & scope · security finding table · per-finding proof & fix · OWASP coverage matrix · DPDP control matrix · applicability & effective dates · legal appendix with penalty ceilings & disclaimer · prioritized remediation plan · evidence gaps & next steps.
**JSON:** machine-readable equivalent, no raw credentials, safe filenames.

## 9. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-01 Safety | API server never executes repo scripts or user-supplied commands |
| NFR-02 Input limits | GitHub HTTPS allowlist; size/file/clone/scan time caps; no submodules/LFS |
| NFR-03 Isolation | Unprivileged disposable worker; read-only code; no privileged containers; no Docker socket; dropped capabilities; CPU/mem/disk/time limits; **no network during untrusted inspection**; advisory lookup in separate restricted trusted stage |
| NFR-04 Privacy | Store redacted snippets only; no secrets to third-party AI |
| NFR-05 Integrity | Record SHA, scanner/rule versions, evidence origin, timestamp, sources, import status |
| NFR-06 Availability | Async jobs, bounded queue, per-session quotas, partial results viewable |
| NFR-07 Performance | Demo-size repo target: a few minutes; no guarantee |
| NFR-08 Accessibility | Keyboard nav; status text for critical findings |
| NFR-09 AI trust | Deterministic output canonical |
| NFR-10 Legal updateability | Catalogue + dates versioned, updateable without code change |
| NFR-11 Export | PDF + JSON, safe filenames, no credentials |
| NFR-12 Retention | Purge worktrees after completion/failure; configurable report retention |

## 10. Access & session (FR-ACC)

- Anonymous **session-scoped** capability IDs (opaque UUIDs); cross-session access → 403/404; reports expire.
- Per-session quotas and rate limits; bounded concurrency; dedupe active audits (reuse ID or 409).

## 11. API contract

Base `/api/v1`. Long-running calls return `202 Accepted` + resource link. Typed error codes. Internal scanner commands never exposed. Lists paginated; evidence redacted and session-scoped.

| Method | Path | Purpose |
|---|---|---|
| POST | `/repositories` | `{github_url, branch?}` → repo_id + metadata |
| GET | `/repositories/{id}` | Details + last commit |
| POST | `/audits` | `{repository_id, scopes:[security,dpdp], commit_sha?}` → queued |
| GET | `/audits/{id}` | Stage, status, progress, coverage |
| GET | `/audits/{id}/events` | Ordered progress events |
| GET | `/audits/{id}/scanner-runs` | Per-tool status/version |
| GET | `/audits/{id}/security/findings` | Filters: severity, type, tool, file, page |
| GET | `/findings/{id}` | Redacted evidence, OWASP, remediation |
| GET | `/audits/{id}/security/coverage` | Control-level matrix |
| GET | `/audits/{id}/dpdp/controls` | Readiness matrix |
| POST | `/audits/{id}/dpdp/profile` | Questionnaire → refreshed assessment job |
| GET | `/audits/{id}/dpdp/data-flows` | Possible personal-data flows + uncertainty |
| GET | `/audits/{id}/legal-exposure` | Schedule category, ceiling, caveats |
| GET | `/audits/{id}/remediations` | Prioritized plan |
| POST | `/audits/{id}/reports` | `{format: pdf|json}` → report_id |
| GET | `/reports/{id}` | Report status |
| GET | `/reports/{id}/download` | Session-scoped download |
| POST | `/findings/{id}/explain` | Optional AI explanation job |
| GET | `/health` | Readiness |

**Errors:** 422 invalid input · 403/404 unauthorized session · 409 duplicate active audit · 429 quota · structured 4xx unsupported repo · scanner crash → `PARTIAL`, never empty Pass.
**Audit states:** `QUEUED → IMPORTING → SCANNING → NORMALIZING → SECURITY_MAPPING → DPDP_MAPPING → REPORT_READY → COMPLETED | PARTIAL | FAILED`.

## 12. Acceptance test matrix

| ID | Scenario | Expected |
|---|---|---|
| AT-01 | Valid public Python/JS repo | Correct SHA + language inventory |
| AT-02 | `file://`, private IP, non-GitHub, malformed | Rejected before fetch |
| AT-03 | Repo contains known secret | Redacted finding; literal absent everywhere |
| AT-04 | SQL injection fixture | Rule evidence with real file/line |
| AT-05 | No visible limiter, gateway unspecified | POTENTIAL_GAP / NOT_VERIFIED, never confirmed absent |
| AT-06 | Public DTO includes sensitive field | Potential exposure with serializer context |
| AT-07 | Lockfile with known vulnerable version | Advisory finding or explained lookup failure |
| AT-08 | Scanner crash | Partial status, explicit unavailable coverage |
| AT-09 | No privacy notice file | NOT_VERIFIED unless supplied elsewhere |
| AT-10 | Supplied notice lacks required details | Traceable potential gap at correct operative date |
| AT-11 | Child-processing question unanswered | Conditional applicability, not violation |
| AT-12 | DPDP obligation dated 2027 | "Upcoming" as of 2026-11-14 |
| AT-13 | DPDP Schedule Item 1 | "Up to ₹250 crore", not expected fine |
| AT-14 | Multiple DPDP gaps | No summed fine |
| AT-15 | Cross-session report access | Denied |
| AT-16 | Source prompt-injection payload | Ignored as instruction; evidence retained safely |
| AT-17 | Report generation | PDF + JSON contain scope, limitations, legal refs |
| AT-18 | Clean repo / unsupported check | No fabricated vuln; honest coverage |
| AT-19 | Oversized / malicious symlink repo | Rejected or contained |
| AT-20 | Combined security + DPDP | Both tabs from same pinned commit |

## 13. Threat model

| Threat | Mitigation | Verification |
|---|---|---|
| URL-based SSRF / unsafe clone | Strict github.com HTTPS parse; no arbitrary redirects | Negative URL tests |
| Malicious repo, symlinks, hooks | No execution; non-root sandbox; no network; canonicalization; no submodules | Malicious fixtures |
| Resource exhaustion | File/byte/time/CPU/memory quotas | Oversized fixture |
| Credential leakage | Redact at ingest; no literals in UI/AI/report/log | Snapshot redaction tests |
| Prompt injection | Untrusted delimiters; fixed system prompt; schema validation | Adversarial fixture |
| Queue abuse | Quotas, bounded concurrency, dedupe | Parallel stress test |
| Unauthorized report access | Session capability IDs, middleware, expiry | Cross-session tests |
| Legal hallucination | Deterministic versioned citations | Citation/date unit tests |
| False positives | Confidence labels; suppression needs rationale | Fixture precision review |
| Advisory network abuse | Trusted resolver, host restrictions, timeouts, isolated | Outbound request audit |
