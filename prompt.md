# SecureScan AI — Build Prompts for Antigravity

How to use: paste **one prompt at a time**, in order. Do not start the next prompt until the current one's **Gate** is passed and you reply `APPROVED: <step>`. Never paste several steps together.

Project files already in the workspace: `PRD.md`, `FRD.md`, `Architecture.md`, `Design.md`, `rules.md`, `decision.md`, `memory.md`, `SUMMARY.md`.

---

## 0. Master system prompt (set once as the workspace / agent rules)

```text
You are the implementation agent for SecureScan AI, built in Google Antigravity.

SOURCE OF TRUTH (read before every task, in this order):
rules.md → memory.md → decision.md → PRD.md → FRD.md → Architecture.md → Design.md.
If documents conflict, rules.md wins, then FRD.md. Never silently resolve a conflict: list it and ask.

OPERATING RULES
1. Work on ONE milestone/step at a time. Do not build ahead.
2. Do not write code until I reply "APPROVED: Step 1" to your ADR/task breakdown.
3. Never execute cloned-repository install/build/test scripts, hooks or workflows. Never run real-world pentests.
4. Scanners run only in the sandbox from Architecture.md §5 (non-root, read-only repo, no network, caps dropped, limits).
5. Unknown is never Pass. Failed/skipped/unsupported checks = NOT_VERIFIED / ERROR / PARTIAL.
6. Never print, store, log, export or send to AI a raw secret. Redact at the parser boundary.
7. Never invent findings, line numbers, ASVS IDs, DPDP clauses, dates or penalty numbers. Legal data comes only from policies/*.yaml.
8. Never output a binary DPDP verdict, a predicted fine, or a sum of penalty ceilings.
9. Effective-date status is computed from as_of_date, never hard-coded.
10. Pin all dependency, scanner and rule-pack versions; record them with every audit.
11. Freeze shared contracts at M0; do not change the finding schema, statuses or API shapes without an ADR entry and my approval.
12. Every step must end with: (a) files changed, (b) tests added and their results (actual output, not claims), (c) exit-criteria checklist with evidence, (d) known gaps, (e) updates to memory.md and decision.md.
13. If a task fails or is incomplete, say so explicitly. Do not mark it done.
14. If something is ambiguous or unsafe, STOP and ask. Do not guess.

OUTPUT STYLE: concise, structured, evidence-based. Show command output for tests. No marketing language.
```

---

## Step 1 — Read, challenge, plan (NO CODE)

```text
TASK: Step 1 — Review and plan. Do NOT write application code.

1. Read all 8 project docs. Summarize in <=15 lines what we are building and what is tested.
2. List any conflicts, ambiguities or missing details across the docs (including source-doc issues in memory.md §8).
3. Verify current stable versions and compatibility of: Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy, Alembic, PostgreSQL, Redis, RQ, Node, React, Vite, Tailwind, TanStack Query, Semgrep, Gitleaks, OSV-Scanner, Bandit, and the chosen HTML-to-PDF tool. Propose exact pinned versions with source links.
4. Check the open decisions O-1..O-6 in decision.md. For each, restate the default and recommend accept/change. Ask me only what you truly need.
5. Produce a task breakdown for M0..M6: for each milestone list tasks, files, tests (AT-xx), exit criteria, risks, estimated effort, and which tasks can run in parallel.
6. Produce the frozen contract proposal (documentation only): normalized Finding schema, ControlResult schema, Evidence schema, audit state machine, error code list, and API request/response shapes for all /api/v1 endpoints.
7. Produce a threat-model checklist mapped to tests.

DELIVERABLES (files in docs/): docs/adr-001-stack-and-versions.md, docs/task_breakdown.md, docs/api_contracts.md, docs/threat_model.md.
Update decision.md (status changes) and memory.md.

GATE: Stop. Wait for "APPROVED: Step 1". No code until then.
```

---

## Step 2 — M0: Repo skeleton, contracts, safety harness

```text
TASK: M0 — Contracts + safety (target ~3h). Scope ONLY this.

BUILD
1. Create the repo layout from Architecture.md §10 (empty modules with docstrings are fine).
2. Backend: FastAPI app with GET /api/v1/health; core/config.py, core/limits.py (env-driven caps), core/db.py; typed error model with the error-code list from docs/api_contracts.md.
3. Pydantic v2 schemas for Finding, Evidence, ControlResult, ScannerRun, Audit, RemediationAction, ErrorResponse. Enums: ControlResult state (6 states), severity, confidence, audit stage/status, evidence tier E1–E5.
4. Alembic baseline + initial migration for all tables in Architecture.md §6.
5. Docker Compose: postgres, redis, api, worker (placeholder), web (placeholder). Pin image versions.
6. Redaction utility (core/security.py): redact(secret_match) -> placeholder, plus a "no raw secret" assertion helper for tests.
7. Frontend skeleton: Vite + React + TS + Tailwind + React Router + TanStack Query; typed api.ts generated from/matching the frozen contract; mock fixtures for every endpoint so UI can proceed in parallel.
8. Policy loader: load and schema-validate policies/*.yaml (empty valid stubs ok).
9. CI-style script: lint, type-check, unit tests.

TESTS: health endpoint; schema validation (valid + invalid); enum completeness; redaction unit tests; policy loader rejects malformed YAML; migration applies cleanly on empty DB.

EXIT CRITERIA: `docker compose up` brings up services; /health returns OK; all M0 tests pass; contracts documented and frozen; no scanner or import code yet.

GATE: Provide the report (files, test output, checklist, gaps). Stop. Wait for "APPROVED: M0".
```

---

## Step 3 — M1: Safe GitHub import + async jobs

```text
TASK: M1 — Import + jobs (target ~4h). Depends on approved M0.

BUILD
1. services/github_import.py:
   - Strict parser: only https://github.com/{owner}/{repo}; strip .git; reject query/fragment, other hosts/protocols, file://, IPs, userinfo, encoded tricks, redirects off github.com.
   - Branch validation; resolve branch -> commit SHA; record SHA.
   - Bounded shallow checkout/archive fetch with caps: total bytes, file count, per-file bytes, clone timeout. No submodules, no LFS dereference.
   - Path canonicalization; remove or refuse symlinks escaping root; no git hooks executed.
   - Language/framework detection (FastAPI, Flask, Django, Express, Next.js best effort).
2. API: POST /repositories, GET /repositories/{id}, POST /audits (202), GET /audits/{id}, GET /audits/{id}/events.
3. Redis/RQ queue: bounded concurrency, per-session quotas (429), dedupe of active audits (reuse id or 409).
4. Anonymous session-scoped capability IDs and middleware (403/404 on cross-session).
5. Audit state machine: QUEUED -> IMPORTING (stop here for M1) with audit_events written; worktree purge on success/failure.
6. Fixtures: fixtures/malicious-symlink, fixtures/oversized (generated, not committed as huge blobs), plus small valid Python and Node repos.

TESTS: AT-01 (valid repo, correct SHA + language inventory); AT-02 (file://, private IP, non-GitHub, malformed -> rejected BEFORE any fetch, assert no network call); AT-19 (symlink/oversized contained); quota and dedupe tests; cross-session negative test (part of AT-15); worktree purge test.

EXIT CRITERIA: AT-01, AT-02, AT-19 (import portion) pass with shown output; no repo code executed (prove with a test that a repo containing hooks/scripts leaves no side effects).

GATE: Report + evidence. Stop. Wait for "APPROVED: M1".
```

---

## Step 4 — M2: Sandboxed scanners + normalization

```text
TASK: M2 — Core scanners (target ~8h). Depends on approved M1.

BUILD
1. Sandbox runner: disposable container per scan; non-root; read-only repo mount; tmpfs scratch; --cap-drop=ALL, no-new-privileges, no Docker socket, network=none, CPU/mem/PIDs/time limits; pinned image with tools and rule packs baked in (no runtime downloads). Strip terminal escapes from output.
2. Adapter base class: supports/prepare/execute/parse/normalize/metadata (scanners/base.py).
3. Adapters: Semgrep (pinned rule pack, Python/JS/TS), Gitleaks (worktree only; history only if explicitly enabled and bounded), OSV-Scanner (lockfile parsing offline in sandbox; advisory lookup in the separate trusted resolver stage with host allowlist + timeout), Bandit (conditional Python, may be deferred per scope-cut order).
4. Redaction at parse time for Gitleaks/Semgrep secret-like output; the literal must never reach the DB/log.
5. Normalization: single Finding object; fingerprinting; dedupe ONLY when source and location/context match; keep all contributing scanner refs; CWE only when grounded; evidence rows with provenance.
6. Scanner-run tracking: status, version, duration, counters, error_code. Any failure => audit PARTIAL and affected controls NOT_VERIFIED/ERROR.
7. No recognized lockfile => NOT_VERIFIED, never "0 CVEs".
8. API: GET /audits/{id}/scanner-runs, GET /audits/{id}/security/findings (filters + pagination), GET /findings/{id}.
9. Fixtures: vulnerable-python-api and vulnerable-node-api with known secret (fake), SQL injection, command injection, vulnerable lockfile entry, debug mode, CORS wildcard; clean-api.

TESTS: AT-03 (secret redacted; grep the DB dump, logs, API responses and exports for the literal -> must be absent); AT-04 (SQLi with real file/line); AT-07 (known vulnerable dependency or explained lookup failure); AT-08 (kill a scanner -> PARTIAL, not Pass); sandbox tests (no network, non-root, read-only, resource limit enforced); adapter contract tests per tool with pinned output samples.

EXIT CRITERIA: AT-03, AT-04, AT-07, AT-08 pass with evidence. Every finding has real origin + locator + redacted detail.

GATE: Report + evidence. Stop. Wait for "APPROVED: M2".
```

---

## Step 5 — M3: Security controls, OWASP mapping, Security UI

```text
TASK: M3 — Security UI + OWASP mapping (target ~5h). Depends on approved M2. Frontend may start earlier against M0 mocks, but integrate only now.

BUILD
1. policies/security_controls.yaml (SEC-001..032 with evidence class, MVP priority, method) and policies/owasp_mappings.yaml (many-to-many, rationale, standard_version). Load ASVS IDs ONLY from the official machine-readable catalogue; never hand-type IDs. Validate with schema tests.
2. services/security_controls.py: evaluate controls into the 6 result states with evidence tiers and rationale.
3. Custom rules (scanners/custom.py) for FastAPI + Express first (D-12): route discovery, middleware/decorators, rate-limit markers (SEC-005/006), auth markers (SEC-007), CORS (SEC-020), debug (SEC-021), DTO/serializer sensitive-field exposure (SEC-004), DB/credential exposure in client config (SEC-002/003). Conservative semantics per FRD §3:
   - no limiter found => POTENTIAL_GAP, never confirmed failure
   - exposure flagged only when the sensitive field appears in the output schema; auth context labelled unverified
   - unsupported framework => NOT_VERIFIED, never clean
4. Coverage calculation: evidenced / applicable (+ N/A and unknown separately), denominator exposed in API.
5. Deterministic remediation text per control and per finding (technical + validation steps).
6. API: GET /audits/{id}/security/coverage, GET /audits/{id}/remediations.
7. Frontend (per Design.md): Landing, Repository profile, Audit progress (engine cards), Security tab (coverage strip, severity distribution with confirmed vs potential, filters, table, coverage matrix), Finding detail with redacted EvidenceBlock, OWASP chips. Status = icon + text + color. Accessibility per Design.md §10.

TESTS: AT-05, AT-06, AT-18; mapping tests (every SEC id has >=1 mapping or an explicit "none" rationale); UI tests for the six states, partial banner, empty-clean copy ("No findings from checks that ran. N controls could not be verified."); keyboard-navigation test.

EXIT CRITERIA: AT-05, AT-06, AT-18 pass; Security tab works end-to-end against the vulnerable fixture without hand-entered data.

GATE: Report + screenshots of each screen/state. Stop. Wait for "APPROVED: M3".
```

---

## Step 6 — M4: DPDP engine, legal catalogue, penalty reference

```text
TASK: M4 — DPDP controls + legal references (target ~7h). Depends on approved M1 and the evidence model. Legal catalogue authoring may be done earlier.

BUILD
1. policies/dpdp_controls.yaml (DPDP-001..018), policies/dpdp_commencement.yaml, policies/penalty_schedule.yaml. Every entry has a legal_source (document, clause, URL, gazette id, version, reviewed_at). Use only the provided FRD/memory data and primary sources: DPDP Act 2023 + Schedule, G.S.R. 843(E), G.S.R. 846(E). If anything cannot be verified, mark it "needs legal review" — do NOT fill from memory.
2. dpdp/commencement.py: compute In force / Upcoming(date) / Not yet determined from as_of_date. Test with fixed dates (2026-11-14 and 2027-05-14).
   Expected as of 2026-11-14: Rule 4, §6(9), §27(1)(d) = In force; Rules 3, 5-16, 22, 23 and Act §§3-5, most of §6, §§7-17 = Upcoming 13 May 2027.
3. dpdp/applicability.py: questionnaire handling; unanswered = Unknown.
4. dpdp/evidence.py + data-flow extraction: candidate personal-data fields/routes from models/forms; purpose and processor stay "unknown".
5. services/dpdp_controls.py: deterministic predicates; readiness labels (evidence supports / potential gap / needs documents / not applicable / requires legal review) + separate effective-date field; link SEC-002/003/004/026 to DPDP-006 via DPDP-018 without declaring a breach.
6. services/penalties.py: map only plausibly relevant Schedule categories; show ceiling + mandatory caveat "Potential legal category; applicability and liability not determined."; NEVER sum, predict, or say "fine". Separate engineering priority / legal exposure reference / legal determination required (PEN-05). Human reviewer override + audit-trail (PEN-06).
7. API: GET /audits/{id}/dpdp/controls, POST /audits/{id}/dpdp/profile (202, refreshes assessment), GET /audits/{id}/dpdp/data-flows, GET /audits/{id}/legal-exposure.
8. Frontend: DPDP tab (persistent disclaimer, applicability panel, questionnaire, control matrix with effective-date chips, penalty reference drawer with fixed template).

TESTS: AT-09, AT-10, AT-11, AT-12, AT-13, AT-14; commencement tests with fixed as_of_date; test that no response/template contains the strings "expected fine", "will be fined", "non-compliant", "DPDP compliant" or any aggregated amount; citation completeness test (every displayed legal item has a source).

EXIT CRITERIA: AT-09..AT-14 pass; DPDP tab populated from the same pinned commit as Security.

GATE: Report + evidence. Flag items requiring legal review. Stop. Wait for "APPROVED: M4".
```

---

## Step 7 — M5: Reports + optional AI explanations

```text
TASK: M5 — Reports + AI (target ~5h). Depends on approved M2–M4.

BUILD
1. reporting/: HTML templates -> PDF (pinned tool) and JSON export. Mandatory PDF sections per Design.md §12 / FRD §8: cover (repo, SHA, time, tool versions), executive summary (counts + coverage, no grade), methodology and exclusions, finding table, per-finding proof and fix, OWASP matrix, DPDP matrix with effective dates, legal appendix with ceilings + disclaimer, prioritized remediation plan, evidence gaps. Header on every page: "Developer-assistance report — not a security certificate or legal opinion."
2. Report worker; POST /audits/{id}/reports, GET /reports/{id}, GET /reports/{id}/download (session-scoped, safe filenames, expiry).
3. services/ai_explain.py (optional, P1): provider abstraction; minimal redacted context; untrusted-source delimiters; fixed system prompt; JSON-schema validated output with fields root_cause, risk_context, code_evidence_ref, recommended_technical_fix, recommended_document_or_process_action, validation_steps, unanswered_questions, limitations. AI cannot change severity/status/legal mapping; originals preserved. Fallback to deterministic text. POST /findings/{id}/explain (job). UI panel collapsed by default, labelled AI-generated.

TESTS: AT-16 (source prompt-injection payload ignored, evidence retained); AT-17 (PDF + JSON contain scope, limitations, legal refs, versions); AT-20 (both audits same SHA); AI output schema-rejection tests; secret-literal absence scan across PDF text and JSON; AI-provider-down fallback test.

EXIT CRITERIA: AT-16, AT-17, AT-20 pass; reports are complete with AI disabled.

GATE: Report + sample PDF/JSON. Stop. Wait for "APPROVED: M5".
```

---

## Step 8 — M6: Hardening, full regression, demo

```text
TASK: M6 — Hardening + demo (target ~4h). Depends on all previous approvals.

DO
1. Run the full AT-01..AT-20 matrix; produce a results table with pass/fail and evidence. Fix failures; list anything still failing honestly.
2. Security review against the threat model (FRD §13): negative URL tests, malicious fixtures, resource exhaustion, redaction snapshot scan, prompt injection, queue stress (parallel scans), cross-session access (AT-15), outbound-request audit of the advisory resolver.
3. Fail-safe checks: kill each scanner/service mid-run; confirm PARTIAL results, no false Pass, partial results still viewable.
4. Accessibility pass (keyboard, focus, aria-live, reduced motion, non-color status).
5. Copy audit: grep UI/report strings against Design.md §11 do/don't list.
6. Pin and record versions; produce docs/legal_sources.md listing each source with reviewed_at and a "legal review pending" banner if not reviewed.
7. Demo: scripted 3-minute flow from Design.md §13 on fixtures, plus a backup recording/screenshots and a seeded fallback dataset generated by a REAL scan (not hand-written).
8. README: setup, run, test, limitations, safety notes, how to update policies/*.yaml and as_of_date.
9. Final update of memory.md, decision.md (set accepted/superseded), and a release checklist (legal review, Gazette re-verification, versions).

EXIT CRITERIA (Definition of Done, PRD §16): a user can enter a GitHub URL; a safe scan returns genuine findings with coverage; rate-limit / key / DB-exposure checks show honest states; OWASP mappings are version-qualified; DPDP separates evidence, unknown and upcoming; penalties are ceilings with caveats; the report has concrete remediation and source references.

GATE: Final report. Stop.
```

---

## Reusable prompts

**Resume after a break**
```text
Read rules.md, memory.md and decision.md. Tell me: the current step, what is done with evidence, what is incomplete, and the next action. Do not write code until I confirm.
```

**Rejected / failed step**
```text
The previous step did not pass: <reason>. Do not start new work. Reproduce the failure, show the failing output, explain the root cause, propose a minimal fix, wait for my OK, then re-run the tests and show the actual output.
```

**Contract change request**
```text
I want to change <contract>. Do not edit code. Write an ADR entry in decision.md with impact on schemas, API, UI, tests and docs, then wait for approval.
```

**Scope-cut mode (running late)**
```text
We are behind schedule. Apply scope cuts strictly in this order: animated UI -> AI chat -> dependency upgrade advice -> Bandit -> extended custom rules -> optional document upload. NEVER cut: isolation, redaction, genuine scanner evidence, honest coverage, DPDP commencement, penalty caveats. Show me what you propose to cut and its effect before doing it.
```

**Legal-wording audit**
```text
Search the whole repo (UI strings, templates, YAML, API responses, report output) for: "expected fine", "will be fined", "you are fined", "non-compliant", "DPDP compliant", "100% secure", "secure", "0 vulnerabilities", and any summed rupee amount. List every hit with file/line and propose compliant wording. Do not auto-edit.
```

**Redaction audit**
```text
Create a test secret in a fixture. Run a full audit and report. Search the DB dump, logs, API responses, JSON export, PDF text and AI prompts for the literal. Show the commands and results. Any hit is a blocker.
```

---

## Step gate checklist (copy into each approval)

- [ ] Tests ran; actual output shown (not summarized claims)
- [ ] Exit criteria met with evidence
- [ ] No rule in rules.md violated
- [ ] No raw secrets anywhere; honesty states respected
- [ ] Versions pinned and recorded
- [ ] memory.md and decision.md updated
- [ ] Known gaps listed explicitly

Reply format to approve: `APPROVED: <Step/M#>` — anything else means "continue working on the current step".
