# SecureScan 2.0 — Task Breakdown & Implementation Roadmap (Steps 2–16)

- **Document Version:** 2.0
- **Parent Plan:** `prompt2_0.md`
- **Companion Architecture Document:** `docs/adr-002-securescan-2.md`
- **Governance:** `rules.md` + Section 1 Approved Amendments

---

## Roadmap Overview

```
Step 1: Read, Audit & ADR-002 (Current Step - No feature code)
  │
  ├─ Phase I: Foundations & Sandbox (Steps 2–3)
  │    Step 2: Sandbox Abstraction, tool-doctor, Worker Fixes, Pinned Tool Image
  │    Step 3: Unified Finding Engine, Target Ownership & Consent System
  │
  ├─ Phase II: Deep Static & Infrastructure (Steps 4–6)
  │    Step 4: Multi-Language SAST, TruffleHog Secrets, SCA & SBOM Export
  │    Step 5: IaC, Docker, CI/CD & Cloud Configuration Analyzers
  │    Step 6: Database Security & ORM/Migration Analyzers
  │
  ├─ Phase III: Dynamic & Active Security (Steps 7–9)
  │    Step 7: DAST Engine, Web Crawl & Lab Benchmark (Juice Shop / DVWA)
  │    Step 8: API Security Engine & OWASP API Top 10 Conformance
  │    Step 9: Authenticated Access-Control & Multi-User BOLA Matrix
  │
  ├─ Phase IV: Compliance, AI & Reporting (Steps 10–13)
  │    Step 10: India DPDP Privacy Engine & Statutory Penalty Ceilings
  │    Step 11: AI / LLM Application Security (OWASP LLM Top 10)
  │    Step 12: Risk Intelligence, AI Security Analyst & Fix Pack Generator
  │    Step 13: Professional Multi-Format Reports (HTML, PDF, MD, JSON, SARIF)
  │
  └─ Phase V: Frontend, CI & Release (Steps 14–16)
       Step 14: Frontend Upgrade & Navigation (Zero Regressions)
       Step 15: Continuous Security, Scheduled Re-scans & CI Gate CLI
       Step 16: Security Hardening, Verification & Production Release
```

---

## Detailed Step Breakdowns

### Step 2 — Make the Tools Actually Work (Foundation)
- **Goal:** Implement the 3-tier sandbox backend abstraction (`docker`, `bubblewrap`, `subprocess-dev`), build the `securescan doctor` CLI and diagnostics endpoint, bake reproducible tool images, and fix the RQ worker.
- **Files Modified/Created:**
  - `backend/app/sandbox/base.py` (Sandbox interface)
  - `backend/app/sandbox/docker.py` (Rootless Docker sandbox)
  - `backend/app/sandbox/bubblewrap.py` (Linux namespace bwrap/nsjail sandbox)
  - `backend/app/sandbox/subprocess_dev.py` (Dev fallback with production fail-closed check)
  - `backend/app/cli/doctor.py` (`securescan doctor` CLI)
  - `backend/app/api/v1/admin.py` (`GET /api/v1/admin/tools` diagnostics)
  - `tools.lock` (Pinned scanner versions + SHA256)
  - `infrastructure/docker/static-worker.Dockerfile`
  - `backend/migrations/versions/xxxx_add_tool_runs.py` (Additive table `tool_runs`)
  - `backend/app/core/config.py` (Dynamic `AS_OF_DATE` defaulting to `date.today()`)
- **Tests Added:**
  - `backend/tests/unit/test_sandbox_backends.py` (Unit tests for all 3 sandbox engines + fail-closed production check)
  - `backend/tests/unit/test_tool_doctor.py` (Verification of self-tests and fallback selection)
- **Gate:** Real output of `securescan doctor` pasted, showing all tools PASS or verified fallback, full real-worker audit of fixtures, all 85 existing tests passing.

---

### Step 3 — Unified Finding Engine, Targets & Ownership/Consent
- **Goal:** Additive database models for targets, cryptographic ownership verification, immutable consent logging, safe-mode boundaries, and unified finding normalization with deduplication and correlation.
- **Files Modified/Created:**
  - `backend/app/models/models.py` (Additive models: `TargetModel`, `TargetVerificationModel`, `ScanScopeModel`, `ConsentRecordModel`, `TestAccountModel`)
  - `backend/migrations/versions/xxxx_targets_and_scopes.py`
  - `backend/app/services/ownership.py` (DNS TXT, well-known, meta tag, repo token verifiers)
  - `backend/app/core/safe_fetch.py` (Anti-SSRF IP pinning and blocklist)
  - `backend/app/services/normalization.py` (Correlation engine: CWE + endpoint/file deduplication)
  - `backend/app/schemas/target.py`, `backend/app/schemas/scope.py`
- **Tests Added:**
  - `backend/tests/security/test_ownership_verification.py` (Active scan rejection without verification)
  - `backend/tests/security/test_ssrf_egress_guard.py` (Blocking loopback, private IPs, metadata IP, `.gov.in`, `.nic.in`)
  - `backend/tests/unit/test_finding_correlation.py` (Multi-signal merging of duplicate findings)
  - `backend/tests/unit/test_migrations_reversible.py` (Additive migration up and down test)
- **Gate:** Tests proving unverified targets are rejected, SSRF protection blocks restricted networks, duplicate findings merge with multi-signal evidence, migrations apply cleanly.

---

### Step 4 — Multi-Language SAST, Secrets, SCA & SBOM Export
- **Goal:** Expand Semgrep rules, add TruffleHog secrets detection with git history, multi-package SCA (OSV + Trivy), and CycloneDX 1.6 / SPDX 2.3 SBOM generation.
- **Files Modified/Created:**
  - `backend/app/scanners/semgrep.py` (Expanded rules for Python, JS/TS, Go, Java)
  - `backend/app/scanners/trufflehog.py` (TruffleHog scanner adapter with git history support)
  - `backend/app/scanners/trivy.py` (Trivy SCA adapter)
  - `backend/app/services/sbom.py` (CycloneDX + SPDX generator)
  - `backend/app/api/v1/sbom.py` (SBOM download endpoints)
  - `backend/app/models/models.py` (Additive `SbomComponentModel`)
- **Tests Added:**
  - `backend/tests/unit/test_trufflehog_adapter.py`
  - `backend/tests/unit/test_sbom_export.py` (CycloneDX schema validation)
  - `backend/tests/security/test_git_history_secret_redaction.py` (Deleted secret detection without raw literal leakage)
- **Gate:** Fixtures confirm new detectors; deleted git secret found and redacted; SBOM validates against official CycloneDX JSON schema; zero secret literals persist.

---

### Step 5 — Infrastructure, Docker, CI/CD & Cloud Configuration
- **Goal:** Static security analysis of Dockerfiles, docker-compose, Kubernetes manifests, Terraform/CloudFormation IaC, and GitHub Actions workflows.
- **Files Modified/Created:**
  - `backend/app/scanners/checkov.py` (IaC and Dockerfile scanner)
  - `backend/app/scanners/hadolint.py` (Dockerfile linter)
  - `backend/app/scanners/zizmor.py` (GitHub Actions workflow auditor)
  - `backend/app/rules/ci_cd_rules.py` (Action unpinned, `pull_request_target`, secret injection checks)
  - `fixtures/insecure-iac/` (Terraform, K8s, Dockerfile, workflow fixtures)
- **Tests Added:**
  - `backend/tests/integration/test_iac_scanner.py`
  - `backend/tests/integration/test_github_actions_audit.py`
- **Gate:** Insecure fixtures produce correct P0-P2 findings with remediation; clean fixtures produce explicit `PASS_EVIDENCED` entries.

---

### Step 6 — Database Security Module
- **Goal:** Static inspection of database models, SQL migrations, Prisma/Supabase/Firebase rules, plus safe non-destructive runtime database port and admin interface exposure probes.
- **Files Modified/Created:**
  - `backend/app/scanners/database_static.py` (Model/migration PII column and encryption auditor)
  - `backend/app/scanners/database_runtime.py` (Safe port and admin UI exposure scanner)
  - `backend/app/rules/database_rules.py`
- **Tests Added:**
  - `backend/tests/integration/test_db_static_audit.py` (Plaintext PII, unhashed password detection)
  - `backend/tests/integration/test_db_runtime_exposure.py` (Verification that no data dump/extraction occurs)
- **Gate:** Static and runtime DB test cases pass; proof that no raw database records are ever extracted or persisted.

---

### Step 7 — DAST Engine & Web Testing (Lab Benchmark)
- **Goal:** Build `dast-worker` container with ZAP, Nuclei, Katana, sslyze, ffuf, and Playwright; execute scoped passive recon, crawling, TLS testing, and non-destructive active probes against verified targets.
- **Files Modified/Created:**
  - `infrastructure/docker/dast-worker.Dockerfile`
  - `backend/app/dast/crawler.py` (Katana + Playwright SPA crawler)
  - `backend/app/dast/tls_scanner.py` (sslyze / testssl.sh integration)
  - `backend/app/dast/zap_adapter.py` (OWASP ZAP baseline & API scanner)
  - `backend/app/dast/nuclei_adapter.py` (Nuclei with non-intrusive tag filter)
  - `backend/app/dast/pipeline.py` (Full active scanning orchestrator)
  - `docs/lab_benchmark.md`
- **Tests Added:**
  - `backend/tests/dast/test_dast_pipeline.py`
  - `backend/tests/dast/test_egress_containment.py`
- **Gate:** Lab benchmark against OWASP Juice Shop / DVWA on isolated network detects >= 80% of documented benchmark vulnerabilities with zero off-scope requests.

---

### Step 8 — API Security Engine (OWASP API Top 10)
- **Goal:** Endpoint discovery (OpenAPI/Swagger, Postman, source routes, crawl), API inventory generation, and Schemathesis contract conformance checking.
- **Files Modified/Created:**
  - `backend/app/api_security/inventory.py` (Endpoint inventory model)
  - `backend/app/api_security/schemathesis_runner.py` (Read-only property testing)
  - `backend/app/api_security/rules.py` (BOLA, shadow API, excessive data exposure checks)
  - `backend/app/api/v1/inventory.py` (Endpoints for inventory JSON/CSV export)
- **Tests Added:**
  - `backend/tests/integration/test_api_security_engine.py`
- **Gate:** crAPI / API fixtures detect BOLA, shadow endpoints, and excessive field exposures; inventory export functions in JSON and CSV.

---

### Step 9 — Authentication & Authorisation Testing (Multi-Account Matrix)
- **Goal:** Authenticated scanning mode with multi-user role support (Anon vs User A vs User B vs Admin) verifying horizontal and vertical privilege boundaries.
- **Files Modified/Created:**
  - `backend/app/authz/matrix_runner.py` (Access-control test harness)
  - `backend/app/authz/recipes.py` (Login recipes: form, bearer, cookie, OAuth token paste)
  - `backend/app/authz/crypto.py` (AES-GCM encryption for stored test credentials)
- **Tests Added:**
  - `backend/tests/integration/test_authz_matrix.py` (Seeded IDOR and unauthorized admin route detected)
  - `backend/tests/security/test_credential_memory_purge.py` (Proof that test credentials never leak into DB or logs)
- **Gate:** Two-user fixture detects horizontal privilege escalation; credential absence verified across database and logs.

---

### Step 10 — India DPDP Privacy & Compliance Engine
- **Goal:** Re-verify legal catalogue against official Gazettes (G.S.R. 843(E), G.S.R. 846(E)), implement 10 DPDP categories, dynamic phased commencement logic, and statutory penalty ceilings.
- **Files Modified/Created:**
  - `policies/dpdp_controls.yaml` (Updated with Gazette verification stamps)
  - `policies/dpdp_commencement.yaml` (Verified phased dates)
  - `policies/penalty_schedule.yaml` (Schedule items with mandatory caveat)
  - `docs/legal_sources.md` (Updated audit trail)
  - `backend/app/dpdp/evaluator.py` (10-category evaluation engine)
  - `backend/app/dpdp/pii_detector.py` (Indian identifier checksums: Aadhaar, PAN, GSTIN, UPI, IFSC)
  - `backend/app/api/v1/dpdp.py`
- **Tests Added:**
  - `backend/tests/integration/test_dpdp_categories.py`
  - `backend/tests/security/test_dpdp_non_compliance_language.py` (Repo-wide assertion that "compliant/non-compliant" is never emitted)
  - `backend/tests/unit/test_indian_pii_validation.py`
- **Gate:** DPDP category tests pass across three distinct `as_of_date` milestones; zero occurrences of binary compliance verdicts; legal review checklist ready.

---

### Step 11 — AI / LLM Application Security (OWASP LLM Top 10)
- **Goal:** Static discovery of LLM integrations (OpenAI, Gemini, Anthropic, LangChain, vector DBs), prompt-injection sink detection, and sensitive data leakage analysis.
- **Files Modified/Created:**
  - `backend/app/rules/ai_rules.py` (Semgrep & AST checks for OWASP LLM Top 10)
  - `backend/app/services/ai_security.py`
  - `fixtures/vulnerable-ai-app/`
- **Tests Added:**
  - `backend/tests/integration/test_ai_security_scanner.py`
- **Gate:** Seeded AI fixture detects system prompt leakage and unsanitized LLM output reaching HTML/eval sinks; clean apps pass.

---

### Step 12 — Risk Intelligence, AI Security Analyst & Fix Pack Generator
- **Goal:** Dimensional risk scoring (Security, Privacy, Infrastructure, Supply Chain, DPDP 0–100 with printed methodology), attack chain synthesis, optional AI analyst, and machine/human Fix Pack generator.
- **Files Modified/Created:**
  - `backend/app/services/risk_scoring.py` (Dominant worst-case scoring algorithm)
  - `backend/app/services/attack_chains.py` (High-level vulnerability chaining)
  - `backend/app/services/fixpack.py` (`fixpack.md` and `fixpack.json` generator)
  - `backend/app/services/ai_explain.py` (Grounded patch suggestions with fallback)
  - `backend/app/api/v1/fixpack.py`
- **Tests Added:**
  - `backend/tests/unit/test_risk_scoring_methodology.py` (Critical P0 caps overall score)
  - `backend/tests/unit/test_fixpack_generation.py` (Validation that Fix Pack contains no secrets/PII)
- **Gate:** Deterministic fallback works 100% without AI; prompt-injection tests pass; Fix Pack format conforms strictly to §8.5.

---

### Step 13 — Professional Multi-Format Reports
- **Goal:** Implement Executive and Technical report exports in HTML, PDF (ReportLab), Markdown, JSON, SARIF 2.1.0, and CycloneDX SBOM.
- **Files Modified/Created:**
  - `backend/app/reporting/sarif_export.py` (OASIS SARIF 2.1.0 standard)
  - `backend/app/reporting/markdown_export.py`
  - `backend/app/reporting/pdf_export.py` (Updated with 2.0 sections, disclaimers, Fix Pack reference)
  - `backend/app/reporting/collector.py`
  - `backend/app/api/v1/reports.py`
- **Tests Added:**
  - `backend/tests/integration/test_sarif_export.py`
  - `backend/tests/integration/test_report_plain_language.py` (Grade 8-10 readability checks)
- **Gate:** PDF, SARIF, JSON, and MD export cleanly with mandatory running header/footer disclaimers and zero raw secret literals.

---

### Step 14 — Frontend Upgrade & Navigation (Zero Regressions)
- **Goal:** Update React frontend with New Scan wizard, live timeline, Results dashboard, API Inventory, Access-Control Matrix, SBOM view, Report Center, and Admin Tool Health page. Wire `FindingDetailPage.tsx` to real API.
- **Files Modified/Created:**
  - `frontend/src/pages/Finding/FindingDetailPage.tsx` (Migrate from `mockData` to `fetchFinding` API)
  - `frontend/src/pages/Admin/ToolHealthPage.tsx`
  - `frontend/src/pages/Inventory/ApiInventoryPage.tsx`
  - `frontend/src/pages/Sbom/SbomPage.tsx`
  - `frontend/src/components/FixPackModal.tsx`
  - `frontend/src/services/api.ts`
  - `frontend/src/types/contracts.ts`
- **Tests Added:**
  - Frontend type checks (`tsc --noEmit`) and Vite production bundle build verification.
- **Gate:** `npm run build` passes; finding detail uses real backend data; mobile PWA responsiveness maintained.

---

### Step 15 — Continuous Security & CI/CD Gate CLI
- **Goal:** Scheduled re-scans, scan-to-scan differential comparison, CI gate CLI (`securescan ci --fail-on P0`), and HMAC-signed webhook notifications.
- **Files Modified/Created:**
  - `backend/app/cli/ci.py` (`securescan ci` command)
  - `backend/app/services/comparison.py` (Scan differential logic)
  - `backend/app/services/webhooks.py` (HMAC-SHA256 signed webhook dispatcher)
- **Tests Added:**
  - `backend/tests/unit/test_scan_comparison.py`
  - `backend/tests/unit/test_ci_cli.py`
- **Gate:** CI gate fails when P0 is introduced and passes on clean scans; webhook HMAC signatures verify correctly.

---

### Step 16 — Hardening, Evidence & Production Release
- **Goal:** Comprehensive regression testing across all 85+ unit, integration, and security tests; self-security audit; production deployment guide updates; Indian legal review checklist.
- **Files Modified/Created:**
  - `DEPLOYMENT.md`
  - `README.md`
  - `docs/LEGAL_REVIEW_CHECKLIST.md`
  - `docs/lab_benchmark.md`
- **Tests Added:**
  - Full automated regression test suite.
- **Gate:** 100% test pass rate, clean security audit of SecureScan itself, complete release checklist with evidence attached.
