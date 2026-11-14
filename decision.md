# SecureScan AI — Decision Log (ADRs)

Format: **Status** (Proposed / Accepted / Superseded) · **Context** · **Decision** · **Consequences**.

---

## D-01 — Modular monolith + isolated scan workers
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Context:** 36-hour build, 3 collaborators; need clear boundaries without microservice overhead.
- **Decision:** One FastAPI control plane (modular), async RQ workers for scanning, sandboxed per scan.
- **Consequences:** Fast to build; worker isolation preserves safety. Scaling later means splitting workers, not rewriting.

## D-02 — Static-first, source-based auditing; no repo code execution
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Context:** Untrusted public repos; install hooks and tests are an RCE vector.
- **Decision:** Only read-only static scanners run. No build/install/test. Runtime testing is out of MVP.
- **Consequences:** Many checks can only reach `POTENTIAL_GAP` / `NOT_VERIFIED`. Accepted and surfaced honestly.

## D-03 — Six-state control result model
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Decision:** `PASS_EVIDENCED, FAIL_EVIDENCED, POTENTIAL_GAP, NOT_VERIFIED, NOT_APPLICABLE, ERROR`.
- **Consequences:** Prevents false-clean output; UI/report must render all six. No binary Pass/Fail.

## D-04 — Scanner set: Semgrep + Gitleaks + OSV-Scanner (+ custom rules; Bandit conditional)
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Context:** Need broad coverage with transparent, pinned tooling.
- **Decision:** Semgrep (SAST), Gitleaks (secrets), OSV-Scanner (dependencies), custom Python rules for API/CORS/debug/DTO exposure, Bandit optional.
- **Consequences:** Custom rules are the main source of false positives → confidence labels and fixture precision review.

## D-05 — Where scan workers run
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Context:** Safe hosting needs `network=none`, non-root, resource caps — not all hosts allow it.
- **Decision:** Demo locally via Docker Compose; do not expose internet-facing scanning unless the sandbox spec in Architecture §5 is met.
- **Consequences:** Hosted cloud deployment deferred to post-hackathon; local demo operates with full isolation guarantees.

## D-06 — Policy-as-data (YAML) for controls, mappings, dates, penalties
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Decision:** `policies/*.yaml`, versioned and snapshotted per audit.
- **Consequences:** Law changes need no code deploy; requires schema validation + tests.

## D-07 — Effective-date status computed, not hard-coded
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Context:** Commencement is phased (verified 14 Nov 2026 against G.S.R. 843(E) / rule 1): 13 Nov 2025 → 13 Nov 2026 (§6(9), §27(1)(d), Rule 4) → 13 May 2027 (most duties). **Rule 4 became operative the day before this document's as-of date**, so a static "upcoming" label would already be wrong.
- **Decision:** Derive *In force / Upcoming / Not yet determined* dynamically from `as_of_date` + commencement map.
- **Consequences:** Labels stay correct over time; AT-12 tested with a fixed as-of date.

## D-08 — No binary DPDP verdict; penalty ceilings only
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Decision:** Readiness labels + effective-date label; show Schedule ceiling with caveat; never predict or sum (PEN-01…06).
- **Consequences:** Less "punchy" demo, much safer legally. Requires legal review before release.

## D-09 — Legal citations from curated catalogue, not LLM
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Decision:** All clause refs, dates and amounts come from `legal_sources` / `penalty_categories`.
- **Consequences:** Needs manual catalogue authoring; eliminates legal hallucination.

## D-10 — AI is optional, grounded, on-demand
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Decision:** Provider abstraction (Gemini or Claude), redacted minimal context, schema-validated output, deterministic fallback.
- **Consequences:** Reports are complete without AI; AI cost is bounded.

## D-11 — Anonymous session-scoped access
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Decision:** Opaque session capability IDs (`X-Session-ID`); no user accounts in MVP.
- **Consequences:** Simple; reports expire; no cross-device history.

## D-12 — Strong custom checks scoped to FastAPI + Express
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Decision:** Deep custom rules for FastAPI and Express; Flask/Django/Next.js best-effort; others reported as unsupported, never clean.
- **Consequences:** High fidelity on target frameworks; explicit `NOT_VERIFIED` on others.

## D-13 — Retention policy
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Decision:** Purge worktrees immediately after scan; reports expire after 24h; redacted findings retained for session lifetime.
- **Consequences:** Minimal local disk consumption; zero persistent repo copies.

## D-14 — Conservative rate-limit and exposure semantics
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Decision:** Missing limiter in source/gateway config ⇒ `POTENTIAL_GAP`, never confirmed failure; sensitive-field exposure flagged only when in output schema with auth context labelled unverified.
- **Consequences:** Eliminates false certainty on deployment-level controls.

## D-15 — Patch generation and runtime testing deferred
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Decision:** Out of MVP; future phase uses disposable worktrees and rescan with states `PATCH_APPLIED … INCONCLUSIVE`.
- **Consequences:** Focuses hackathon scope on reliable, auditor-grade assessment.

## D-16 — Report: counts and coverage, no headline grade
- **Status:** Accepted (Pending Step 1 Gate Sign-off)
- **Decision:** Coverage ratio = evidenced controls ÷ applicable controls (denominator stated). Optional risk indicator must be transparent and non-certifying.
- **Consequences:** Honest, defensible compliance and security posture.

---

## Open Decisions Resolution (Step 1 Review)

| # | Question | Default | Recommendation | Decision & Rationale |
|---|---|---|---|---|
| **O-1** | Hackathon duration, team size, machine for sandboxed scans | 36 h, 3 people, local Docker | **Accept default** | Local Docker Compose running Docker CLI or sibling containers with `--network=none` and resource caps. Fits the 36-hour schedule perfectly. |
| **O-2** | Frameworks with strong custom checks | FastAPI + Express | **Accept default** | FastAPI (Python) and Express (Node.js) cover the vast majority of hackathon and modern startup APIs. Others marked `NOT_VERIFIED`. |
 
| 2026-11-14 | M0 complete: Repo layout created, Pydantic v2 domain schemas frozen, Alembic migrations verified, redaction utility tested, policy loader implemented, frontend typed contracts and mock fixtures built. | Implementation Agent |
| 2026-11-14 | M1 complete: Strict GitHub URL parser (AT-02), bounded shallow checkout with caps (AT-19), language/framework detection (AT-01), zero git hook execution proven, session quota (429) & deduplication (409) verified, cross-session isolation (AT-15) verified, worktree purge verified. 44/44 tests pass. | Implementation Agent |
| 2026-11-14 | M2 complete: Sandbox runner with --network=none caps (Z4), 4 scanner adapters (Gitleaks, Semgrep, OSV-Scanner, Bandit), deterministic fingerprinting & context deduplication, Evidence persistence, AT-03 parser-level secret redaction & absence proof, AT-04 SQLi with authentic locator & CWE-89, AT-07 dependency CVE & NOT_VERIFIED lockfile, AT-08 scanner crash fail-safe to PARTIAL. 55/55 tests pass. | Implementation Agent |
| 2026-11-14 | M3 complete: 32 security controls defined (SEC-001..032) & 64 OWASP mappings; custom AST/regex rules for FastAPI + Express; 6-state control evaluation; deterministic remediation texts; Security UI dashboard with coverage strip, severity distribution, EvidenceBlock drawer, and empty-clean copy. AT-05, AT-06, AT-18 verified. | Implementation Agent |
| 2026-11-14 | M4 complete: 18 DPDP controls (DPDP-001..018) with primary gazette citations (G.S.R. 843(E), G.S.R. 846(E)); dynamic commencement derived from as_of_date; questionnaire handling (unanswered=unknown); candidate personal data extraction; statutory penalty ceilings with mandatory caveat; zero fine predictions/sums (AT-13 verified); React DPDP tab. AT-09..AT-14 verified. 66/66 tests pass. | Implementation Agent |
| 2026-11-14 | M5 complete: Multi-engine PDF export (ReportLab fallback with NumberedCanvas running header) & canonical JSON export; collector with all mandatory sections, tool versions, OWASP/DPDP matrices, legal caveats; strict secret literal absence in exports (AT-03); prompt injection resistance with <untrusted_source_code> XML delimiters (AT-16); comprehensive report verification (AT-17); pinned commit SHA consistency (AT-20); graceful AI fallback on schema failure or provider downtime; React Report export page. 72/72 tests pass. | Implementation Agent |
| 2026-11-14 | M6 complete: Hardening, full AT regression matrix (AT-01..AT-20 verified 100% passing across 72 tests); repository copy audit against Design §11 do/don't list (zero prohibited claims found); docs/legal_sources.md authored with primary Gazette citations (G.S.R. 843(E), G.S.R. 846(E)); demo/demo_script.md 3-minute flow and real seeded dataset demo/seeded_audit_data.json created; comprehensive README.md authored; release checklist verified. | Implementation Agent |
