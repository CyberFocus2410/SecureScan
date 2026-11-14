# SecureScan AI — Summary

## What we are building

A web app that takes a **public GitHub URL**, safely imports a pinned commit, and runs two audits:

1. **Application Security Audit** — Semgrep, Gitleaks, OSV-Scanner and custom rules find secrets, injection, weak auth, data exposure, misconfiguration and vulnerable dependencies, mapped to **OWASP Top 10:2025 / API Top 10:2023 / ASVS 5.0.0**.
2. **DPDP Readiness Audit** — an applicability-aware matrix of 18 controls for India's **DPDP Act 2023 / Rules 2025**, with phased effective dates and the relevant **statutory penalty ceiling** (e.g. up to ₹250 crore for §8(5)).

Output: dashboard + **PDF/JSON report** with evidence, fixes, coverage and legal references.

**It never claims:** to find every vulnerability, to certify DPDP compliance, or to predict a fine. Unknown is shown as *Not verified*, not *Pass*.

## How it works

Import (pinned SHA) → sandboxed scanners (no network, no repo code execution) → normalize + redact → OWASP mapping → DPDP evaluation → remediation → report. Stack: React/TS + FastAPI + Postgres + Redis/RQ.

## What is being tested

| Area | Acceptance tests |
|---|---|
| Safe import | AT-01 valid repo + SHA · AT-02 bad URLs rejected · AT-19 malicious/oversized repo contained |
| Scanner accuracy | AT-03 secret found and redacted · AT-04 SQL injection · AT-07 vulnerable dependency · AT-18 clean repo, no fake findings |
| Honest coverage | AT-05 rate-limit gap is *potential*, not confirmed · AT-08 scanner crash → Partial · AT-06 sensitive-field exposure |
| DPDP logic | AT-09/10 notice evidence · AT-11 child-data conditional · AT-12 2027 duties shown as *Upcoming* |
| Penalty rules | AT-13 shows "up to ₹250 crore" only · AT-14 no summed fine |
| Security of the tool | AT-15 cross-session access denied · AT-16 prompt injection ignored |
| Reporting | AT-17 PDF + JSON complete · AT-20 both audits from the same commit |

**20 acceptance tests** across 7 milestones (M0–M6, ~36 hours). Demo: vulnerable fixture → findings and coverage → DPDP gaps and dates → penalty caveats → exported report.

## Key dates (verified 14 Nov 2026)

- **13 Nov 2026:** Rule 4 (Consent Managers), §6(9), §27(1)(d) — **in force now**.
- **13 May 2027:** most DPDP duties (Rules 3, 5–16, 22, 23) — **upcoming**.

## Status

Docs complete; **no code yet**. Next: approve decisions in `decision.md`, freeze contracts, start M0. Legal review required before release.
