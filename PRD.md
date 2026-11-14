# SecureScan AI — Product Requirements Document (PRD)

| | |
|---|---|
| **Version** | 1.1 (restructured from `SecureScan_AI_PRD_FRD_v1.md`) |
| **As-of date** | 14 November 2026 |
| **Status** | Proposed — awaiting product-owner approval |
| **Target** | Vihaan X hackathon MVP |
| **Dev environment** | Google Antigravity; implementation agent: Claude |
| **Companion docs** | FRD.md · Architecture.md · Design.md · rules.md · decision.md · memory.md · SUMMARY.md |

> **Classification:** Planning document. Not a security certificate or legal opinion.

---

## 1. Vision and mission

Accept a **public GitHub repository URL**, run a broad and transparent suite of security checks, map findings to OWASP guidance, assess technical and documentary readiness against India's **DPDP Act 2023 / DPDP Rules 2025**, and produce an evidence-based remediation report with the *relevant statutory penalty ceilings*.

**The product will not claim:** exhaustive vulnerability detection · definitive DPDP legal compliance · a calculable or predicted fine.

**Differentiator:** one **evidence graph** connecting vulnerabilities, sensitive-data flows, OWASP checks, DPDP requirements, remediation, legal citations, and the limits of the evidence.

**MVP strategy:** reliable source-based checks and honest "Not verified" results beat falsely claiming absence of controls has been proven. SecureScan is an **auditor and reporting platform**, not a general AI patch agent.

## 2. Problem and opportunity

1. Developers lack one consolidated view of secret exposure, API weaknesses, authn/authz flaws, data leakage, misconfiguration, dependency risk and control coverage.
2. Small Indian startups are unsure which technical controls and process evidence matter for DPDP, especially under phased commencement.
3. Generic SAST tools do not assess privacy notice, consent, retention and data-principal rights alongside repository evidence.

## 3. Target users

| ID | Persona | Need |
|---|---|---|
| P1 | Solo / student developer | Audit a full-stack public GitHub project quickly |
| P2 | Startup engineering lead | Prioritized remediation backlog |
| P3 | Privacy / security reviewer | Traceable evidence and explicit gaps |
| Secondary | Auditors, hackathon mentors | Reproducible demo |

## 4. Goals

1. Import a public repo and run a multi-scanner audit **without executing repo build scripts**.
2. Per finding: severity, confidence, source location, scanner evidence, OWASP mapping, remediation.
3. Explicitly check: API abuse/rate-limit coverage · hardcoded secrets & client-bundle exposure · authn/authz & BOLA/IDOR · DB credential/data exposure · injection · dependency risk · sensitive logging · CORS/security headers · risky configuration.
4. Applicability-aware **DPDP readiness matrix** separating code evidence, documents, organizational answers and unknowns.
5. Report with fixes, evidence gaps, official legal references, operative vs upcoming obligations and **relevant statutory penalty ceilings** (never per-rule predicted fines).
6. At least one reproducible end-to-end demo using vulnerable and clean fixtures.

## 5. Non-goals (MVP)

- Guaranteeing all vulnerabilities are found; ASVS certification; legal-compliance certification.
- Aggressive pentesting, brute force, uncontrolled fuzzing, exploitation of live sites.
- Running npm install hooks, setup scripts, repo workflows or arbitrary tests on the API host.
- Private-repo OAuth, cloud posture assessment, all-language support, user accounts, automatic PRs/patches.
- Predicting DPDP penalties, summing hypothetical maxima, or replacing legal review.

## 6. Success criteria

| # | Criterion |
|---|---|
| SC-1 | 100% of test URLs are either safely imported (commit SHA recorded) or rejected with a reason |
| SC-2 | Vulnerable fixture yields ≥1 secret-like finding, ≥1 injection/misconfig finding, ≥1 DPDP evidence gap |
| SC-3 | Failed/unavailable scanners are **Not verified / Partial**, never Pass |
| SC-4 | Every displayed finding has valid origin, reproducible evidence locator, redacted detail |
| SC-5 | Both reports export with exact source versions, scan coverage and legal commencement status |
| SC-6 | End-to-end demo completes with no hand-entered findings or DB manipulation |

## 7. User journey

Home → enter public GitHub URL → choose **Security / DPDP / Both** → branch (or default) → audit progress → Security & DPDP tabs → finding detail + evidence → corrective action → export PDF/JSON.

## 8. User stories

| ID | Story |
|---|---|
| US-01 | Submit a public repo and see the exact commit SHA (reproducibility) |
| US-02 | See which scanners ran, failed or were inapplicable |
| US-03 | Filter findings by severity, file, category, source, confidence |
| US-04 | See whether rate limiting is in app code, gateway manifests, or neither; **Needs verification** when deployment evidence is missing |
| US-05 | See exposed-credential findings with the secret value never in browser, logs, LLM prompt or report |
| US-06 | Locate sensitive fields returned by API serializers; distinguish necessary vs suspected excessive exposure |
| US-07 | View DPDP controls with applicability, commencement, evidence, unknowns, closing steps |
| US-08 | See only the legally relevant Schedule penalty ceiling, marked contingent and non-predictive |
| US-09 | Download a report with a prioritized engineering + compliance backlog |
| US-10 | Trace any result to a rule/version or legal clause and the evidence behind it |

## 9. Capabilities and priority

| Capability | Pri | MVP behavior | Later |
|---|---|---|---|
| Public GitHub import | P0 | Safe, bounded, pinned checkout | Private repos / GitHub App |
| Multi-scanner static audit | P0 | Semgrep + Gitleaks; OSV-Scanner where supported | Bandit, more languages |
| Custom API & data-exposure checks | P0 | Framework-scoped conservative rules | Cross-file taint engine |
| OWASP control coverage | P0 | Partial, evidence-based mapping | Full ASVS program |
| DPDP repository controls | P0 | Rules-based readiness | Organization workspace |
| DPDP evidence intake | P1 | Short questionnaire + notice URL/text | Contract/doc uploads |
| Penalty reference engine | P0 | Relevant ceiling + caveats | Legal review workflow |
| Dashboard + PDF/JSON report | P0 | Security and DPDP tabs | Scheduled reports |
| AI explanations | P1 | On-demand, grounded, redacted | Repo chat |
| Runtime HTTP checks | P2 | Out | Authorized targets only |
| AI patch generation/verification | P2 | Out | Isolated patch + rescan |
| Scan timeline / regression | P2 | Out | CI integration |

## 10. Product principles

1. **Honesty over reassurance** — unknown ≠ pass; "not found in code" ≠ "missing in production".
2. **Evidence first** — every claim links to evidence, source version, and evidence tier.
3. **Deterministic is canonical** — AI explains; it never decides severity, legal mapping or penalties.
4. **Safety by construction** — never execute untrusted repo code.
5. **Counts and coverage, not grades** — no headline "92% secure".

## 11. Security audit scope (summary)

32 checks (SEC-001…032) across secrets, API abuse, authn/authz, injection, crypto/TLS, config, dependencies, logging, CSRF and validation. Full catalogue and MVP priorities are in **FRD §3**. Taxonomy: **OWASP Top 10:2025**, **ASVS 5.0.0** (only via official machine-readable catalogue), **OWASP API Top 10:2023**.

**Control result states:** `PASS_EVIDENCED · FAIL_EVIDENCED · POTENTIAL_GAP · NOT_VERIFIED · NOT_APPLICABLE · ERROR`.

## 12. DPDP scope (summary)

18 readiness controls (DPDP-001…018), applicability questionnaire, commencement-aware labelling, penalty reference (Schedule Items 1–7). Never output "DPDP compliant / non-compliant". Use **readiness labels**: *evidence supports · potential gap · needs documents · not applicable · requires legal review*, plus a separate effective-date field.

**Commencement (verified 14 Nov 2026 against G.S.R. 843(E) / rule 1 of the Rules):**

| Date | Switches on | Status at 14 Nov 2026 |
|---|---|---|
| 13 Nov 2025 | Board/institutional machinery; Rules 1, 2, 17–21 | In force |
| 13 Nov 2026 | Act §6(9), §27(1)(d); **Rule 4** (Consent Managers) | **In force (since yesterday)** |
| 13 May 2027 | Act §§3–5, most of §6, §§7–17 etc.; Rules 3, 5–16, 22, 23 | **Upcoming** |

> Treat as "upcoming readiness", never "violation". Re-verify against Gazette before each release; amendments have been discussed publicly and not confirmed.

## 13. Non-functional requirements (summary)

Safety (no repo script execution) · input limits · sandbox isolation · privacy (no raw secrets stored/sent) · integrity (SHA + tool versions) · async availability with partial results · accessibility · AI trust · legal updateability · PDF + JSON export · retention/purge. Detailed in **FRD §9**.

## 14. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Malicious repo | Host compromise | Sandbox, no network, no execution |
| False positives | Loss of trust | Confidence labels, conservative statuses |
| Legal misstatement | Reputational/legal | Curated catalogue, no LLM legal authority, legal review before release |
| Hackathon timebox | Scope miss | Vertical slices; ordered scope cuts |
| Unsafe worker hosting | Security | Decide worker host early (decision.md D-05) |
| Law changes | Stale output | Versioned, updateable catalogue + `as_of_date` |

## 15. Milestones

Assumption: 36 hours, 3 collaborators/agents.

| Milestone | Hours | Exit tests |
|---|---|---|
| M0 Contracts + safety | 0–3 | Health + schema tests |
| M1 Import + jobs | 3–7 | AT-01, AT-02 |
| M2 Core scanners | 7–15 | AT-03, 04, 07, 08 |
| M3 Security UI + OWASP | 15–20 | AT-05, 06, 18 |
| M4 DPDP + legal refs | 20–27 | AT-09–14 |
| M5 Reports + AI | 27–32 | AT-16, 17, 20 |
| M6 Hardening + demo | 32–36 | AT-15, 19 + full demo |

**Scope cuts, in order:** animated UI → AI chat → dependency upgrade advice → Bandit → extended custom rules → doc upload.
**Never cut:** isolation, redaction, genuine scanner evidence, honest coverage, DPDP commencement, penalty caveats.

## 16. Definition of done

A user can input a GitHub URL; a safe scan returns genuine findings with coverage; rate-limit/key/DB-exposure checks give honest evidence states; OWASP mappings are version-qualified; DPDP controls separate evidence from unknown and upcoming; penalty references never look like fine estimates; and the downloadable report has concrete remediation and source references.

## 17. Open questions

See **decision.md §Open decisions** (hackathon duration/team, strong-check frameworks, notice upload vs questionnaire, worker hosting, AI budget, retention/anonymous sessions).
