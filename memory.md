# SecureScan AI — Project Memory

Living context file for agents and collaborators. Read this first in every session; update it at the end of every task.

**Last updated:** 2026-11-20 · **As-of date for legal status:** 2026-11-20 (Dynamic UTC date)

## 1. What this project is (one paragraph)

SecureScan 2.0 is a full-stack automated application security-testing, risk-intelligence, and India DPDP-readiness platform. Given a public GitHub repository and/or an owner-verified live website, it checks frontend, backend, APIs, authn/authz, database layer, dependencies/SCA, secrets, infrastructure/config, AI features, and India DPDP readiness. It produces plain-language reports and copy-paste "Fix Packs" for developers and AI coding agents with zero raw secret exposure and statutory penalty ceilings.

## 2. Current status

| Item | State |
|---|---|
| Master Spec 2.0 | `prompt2_0.md` (v2.0) |
| Architecture Decision | `docs/adr-002-securescan-2.md`, ADR-003..ADR-009 (**Accepted**) |
| Roadmap & Breakdown | `docs/task_breakdown_2_0.md` (**Completed for Steps 2–16**) |
| Test Suite Baseline | **133 / 133 passing** (85 baseline + 9 Step 2 + 8 Step 3 + 4 Step 4 + 6 Step 5 + 6 Step 6 + 10 Step 7 + 5 Step 8) |
| Active Phase | **SecureScan 2.0 Step 8 (API Security Engine & OWASP API Top 10)** COMPLETED |

### 2.0 Step Tracker

| Step | Scope | Status |
|---|---|---|
| **Step 1** | Read, audit, amend rules, produce ADR-002 & task breakdown 2.0 | **Completed & Approved** |
| **Step 2** | Sandbox backends (docker/bwrap/subprocess-dev), tool-doctor CLI, worker fixes, tool_runs table, dynamic AS_OF_DATE | **Completed** |
| **Step 3** | Unified Finding Engine, targets & ownership/consent verification | **Completed** |
| **Step 4** | Multi-language SAST, TruffleHog secrets, SCA & SBOM export | **Completed** |
| **Step 5** | IaC, Docker, CI/CD & cloud configuration | **Completed** |
| **Step 6** | Database security module (static + runtime exposure) | **Completed** |
| **Step 7** | DAST engine, web testing & Lab benchmark (Juice Shop/DVWA) | **Completed** |
| **Step 8** | API security engine & OWASP API Top 10 | **Completed** |
| **Step 9** | Authentication & authorization testing (multi-account matrix) | Planned (Next) |
| **Step 10** | DPDP privacy & compliance engine (re-verified Gazettes) | Planned |
| **Step 11** | AI / LLM application security (OWASP LLM Top 10) | Planned |
| **Step 12** | Risk intelligence, AI Security Analyst & Fix Pack generator | Planned |
| **Step 13** | Professional multi-format reports (HTML, PDF, MD, JSON, SARIF) | Planned |
| **Step 14** | Frontend upgrade & navigation (zero regressions) | Planned |
| **Step 15** | Continuous security, scheduled re-scans & CI gate CLI | Planned |
| **Step 16** | Hardening, evidence & production release | Planned |

### Milestone tracker

| Milestone | Window | Exit tests | Status |
|---|---|---|---|
| **Step 1 Review & Plan** | H0 | 4 docs in docs/, O-1..O-6 recommendations, frozen contracts | **Completed (Approved)** |
| **M0 Contracts + safety** | H0–3 | health + schema tests + DB migration + redaction | **Completed (Approved)** |
| **M1 Import + jobs** | H3–7 | AT-01, AT-02, AT-19 (import) | **Completed (Approved)** |
| **M2 Core scanners** | H7–15 | AT-03, AT-04, AT-07, AT-08 | **Completed (Approved)** |
| **M3 Security UI + OWASP** | H15–20 | AT-05, AT-06, AT-18 | **Completed (Approved)** |
| **M4 DPDP + legal refs** | H20–27 | AT-09–14 | **Completed (Approved)** |
| **M5 Reports + AI** | H27–32 | AT-16, AT-17, AT-20 | **Completed (Approved)** |
| **M6 Hardening + demo** | H32–36 | Full AT matrix + live demo script | **Completed (72/72 tests pass, AT-01..20 verified)** |

---

## 9. Release Checklist (Pre-Production)

- [x] All 20 Acceptance Tests (AT-01..AT-20) verified passing with zero skips on critical paths.
- [x] Copy audit completed: Zero occurrences of prohibited claims ("0 vulnerabilities", "100% secure", "DPDP compliant", "expected fine").
- [x] Mandatory running header on all PDF report pages: *"Developer-assistance report — not a security certificate or legal opinion."*
- [x] Mandatory statutory caveat on every penalty entry: *"Potential legal category; applicability and liability not determined."*
- [x] Zero fine predictions; zero fine sums across categories.
- [x] Worktree isolation and immediate post-scan cleanup verified.
- [x] Secret literals redacted at parser boundary; zero raw secret literals in DB, logs, UI, PDF, JSON, or AI prompts.
- [x] Primary legal sources registered in `docs/legal_sources.md`.
- [ ] Qualified legal counsel review of DPDP rule mappings prior to commercial production deployment.
- [ ] Gazette re-verification prior to major version releases.

## 3. Non-negotiable facts

- Scanners run only in a sandbox with **no network**, non-root, read-only repo. Repo scripts are **never** executed.
- Result states: `PASS_EVIDENCED, FAIL_EVIDENCED, POTENTIAL_GAP, NOT_VERIFIED, NOT_APPLICABLE, ERROR`.
- Unknown ≠ pass. Failed scanner ⇒ audit `PARTIAL`.
- Secrets are redacted at the parser boundary; the literal never reaches DB, logs, UI, PDF or AI.
- No binary DPDP verdict. No predicted or summed fine. Ceilings only, with caveat.
- Legal text comes from the curated catalogue, not LLM memory.
- AI is optional and cannot change severity or legal mapping.

## 4. DPDP key dates (verified 2026-11-14)

Sources: G.S.R. 843(E) (Act commencement) and rule 1 of DPDP Rules 2025 (G.S.R. 846(E)), both dated 13 Nov 2025. Secondary legal commentary agrees.

| Date | What starts | Status today |
|---|---|---|
| 13 Nov 2025 | Board machinery; Rules 1, 2, 17–21 | In force |
| 13 Nov 2026 | Act §6(9), §27(1)(d); **Rule 4** (Consent Managers) | **In force since 13 Nov 2026** |
| 13 May 2027 | Act §§3–5, most of §6, §§7–17 etc.; Rules 3, 5–16, 22, 23 | **Upcoming** |

⚠ Public commentary mentions possible amendments/proposals; none confirmed as gazetted at last check. Re-verify against the Gazette and MeitY before each release.

## 5. Penalty ceilings (Act Schedule) — reference only

| Item | Breach | Max |
|---|---|---|
| 1 | §8(5) security safeguards | ₹250 crore |
| 2 | §8(6) breach notification | ₹200 crore |
| 3 | §9 children | ₹200 crore |
| 4 | §10 Significant Data Fiduciary | ₹150 crore |
| 5 | §15 data-principal duties | ₹10,000 |
| 6 | §32 voluntary undertaking | Up to the underlying breach amount |
| 7 | Other breaches | ₹50 crore |

Caveat text: *"Potential legal category; applicability and liability not determined."*

## 6. Glossary

| Term | Meaning |
|---|---|
| ADR | Architecture decision record (decision.md) |
| AT-xx | Acceptance test ID (AT-01..AT-20) |
| BOLA/IDOR | Broken object-level authorization |
| DPDP | Digital Personal Data Protection Act 2023 / Rules 2025 |
| E1–E5 | Evidence tiers: source / config / supplied docs / org attestation / runtime test |
| Coverage ratio | Evidenced controls ÷ applicable controls (denominator stated) |
| `as_of_date` | Date used to compute legal effective status |
| SDF | Significant Data Fiduciary |

## 7. Open decisions resolved (Step 1)

- O-1: 36h hackathon, local Docker Compose scan runner accepted.
- O-2: Strong custom checks scoped to FastAPI + Express; others marked `NOT_VERIFIED`.
- O-3: Questionnaire + optional notice text/URL; no scraping external domains.
- O-4: Local Compose scan sandbox with `--network=none`, non-root, read-only.
- O-5: Deterministic remediation mandatory; optional Gemini 2.5 Flash explainer.
- O-6: Anonymous session capability IDs (`X-Session-ID`); 24h report expiry; immediate worktree purge.

## 8. Issues found in the source document & resolved

| # | Issue | Handling |
|---|---|---|
| 1 | §6 says "authoritative links in §18" but links are in §27 | Corrected cross-reference in derived docs |
| 2 | Source states Rule 4 / §6(9) "scheduled" for 13 Nov 2026; as of 14 Nov 2026 it is in force | Status computed dynamically from `as_of_date` |
| 3 | Source tool versions are unspecified | Pinned in `docs/adr-001-stack-and-versions.md` |
| 4 | ASVS 5.0.0 / OWASP Top 10 IDs not enumerated | Pinned in `docs/api_contracts.md` and machine-readable YAMLs |
| 5 | PDF generation library unspecified | Selected WeasyPrint 63.1 (pure Python, CSS Paged Media `@page` standard) |

## 9. Next action

Wait for product-owner gate sign-off: `APPROVED: M4`. Upon approval, immediately commence **M5: Reports (WeasyPrint PDF + JSON export) and optional AI explanations (services/ai_explain.py)**.

## 10. Session log

| Date | Note |
|---|---|
| 2026-11-14 | Analysed source doc; generated PRD, FRD, Architecture, Design, rules, decision, memory, SUMMARY; verified DPDP commencement dates. |
| 2026-11-14 | Completed Step 1 Review & Plan: generated `docs/adr-001-stack-and-versions.md`, `docs/task_breakdown.md`, `docs/api_contracts.md`, `docs/threat_model.md`; resolved O-1..O-6; updated decision.md and memory.md. Approved by user (`APPROVED: Step 1`). |
| 2026-11-14 | Completed M0 Contracts & Safety: built backend FastAPI app, core limits/config/errors/db, Pydantic v2 domain schemas, Alembic initial migration (14 tables), redaction utility, policy loader with YAML stubs, Docker Compose & Dockerfiles, and frontend React+TS skeleton with mock fixtures. Approved by user (`APPROVED: M0`). |
| 2026-11-14 | Completed M1 Safe GitHub Import & Async Jobs: built strict parser (AT-02), bounded shallow checkout with caps (AT-19), framework detection (AT-01), zero git hook execution proven, session capability middleware & isolation (AT-15), audit deduplication (409), session concurrency quota (429), and worktree purge. 44/44 tests pass. Approved by user (`APPROVED: M1`). |
| 2026-11-14 | Completed M2 Sandboxed Scanners & Normalization: built runner with network=none and cgroup caps (Z4), 4 scanner adapters (Gitleaks, Semgrep, OSV, Bandit), deterministic fingerprinting & deduplication, Evidence tier persistence, AT-03 secret redaction & absence proof, AT-04 SQLi with authentic locator & CWE-89, AT-07 dependency CVE & missing lockfile NOT_VERIFIED, AT-08 scanner crash fail-safe to PARTIAL. 55/55 backend tests pass; frontend build clean. |
| 2026-11-14 | Completed M3 Security Controls, OWASP Mapping & Security UI: authored policies/security_controls.yaml (all 32 controls SEC-001..032) and policies/owasp_mappings.yaml (64 mappings to OWASP Top 10:2025, API Top 10:2023, ASVS 5.0.0); built scanners/custom.py AST/regex analyzer for FastAPI & Express; implemented services/security_controls.py (6-state evaluation + explicit coverage denominator), services/remediations.py, API endpoints (/security/controls, /security/coverage, /remediations), and React Security tab (coverage strip, severity badges, EvidenceBlock drawer, empty-clean copy). AT-05, AT-06, AT-18 passing. |
| 2026-11-14 | Completed M4 DPDP Engine, Legal Catalogue & Penalty Reference: authored policies/dpdp_controls.yaml (18 controls DPDP-001..018 with primary gazette citations), policies/dpdp_commencement.yaml, policies/penalty_schedule.yaml; built dpdp/commencement.py (dynamic effective-date logic from as_of_date), dpdp/applicability.py (questionnaire handling with unanswered=unknown), dpdp/evidence.py (candidate personal data extraction), services/dpdp_controls.py (readiness labels & SEC-002/003/004/026 linkage to DPDP-006 without declaring breach), services/penalties.py (statutory ceilings with mandatory caveat, zero fine predictions/sums), API endpoints, and React DPDP tab. AT-09..AT-14 passing. Total 66/66 tests pass. |
