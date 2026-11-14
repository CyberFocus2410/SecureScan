# SecureScan AI — UX & Visual Design

Version 1.1 · Covers screens, components, status language, accessibility, and report layout.

## 1. Design principles

1. **Honest by default** — Unknown, Partial and Upcoming are first-class states, never hidden or styled as success.
2. **Evidence one click away** — every claim shows file, line, source rule or legal clause.
3. **Counts and coverage over grades** — no hero "score".
4. **Never color alone** — every status has an icon + text label.
5. **Calm, auditor-grade tone** — dense but scannable; no alarmist copy.
6. **Legal wording is fixed** — penalty and verdict language comes from templates, not free text.

## 2. Information architecture

```text
Home (URL + scope)
 └ Repository profile / import
    └ Audit progress
       ├ Security tab ─ Finding detail
       ├ DPDP tab ─ Control detail ─ Questionnaire
       └ Report preview / download
```

## 3. Screens

| # | Screen | Purpose | Key elements |
|---|---|---|---|
| 1 | **Landing** | Start an audit | GitHub URL field with inline validation, scope selector (Security / DPDP / Both), branch field (optional), "what we do not do" note |
| 2 | **Repository profile** | Confirm import | Owner/repo, branch, **commit SHA**, languages, frameworks detected, size, rejection reasons if any |
| 3 | **Audit progress** | Engine-by-engine state | Stage stepper, per-scanner card (Semgrep, Gitleaks, OSV, Bandit, Custom): *Queued / Running / Done / Failed / Skipped (not applicable)* with version and duration |
| 4 | **Security tab** | Findings + coverage | Severity distribution, coverage strip, filters, findings table, OWASP chips |
| 5 | **DPDP tab** | Readiness matrix | Applicability banner, questionnaire entry, control matrix, effective-date column, penalty reference drawer |
| 6 | **Finding / control detail** | Evidence + fix | Redacted snippet with line numbers, provenance, mappings, remediation steps, validation method, optional "Explain with AI" |
| 7 | **Report preview** | Export | Section checklist, PDF/JSON buttons, disclaimer block |

## 4. Security tab — layout

- **Header strip:** commit SHA · scanners run/failed/skipped · scan timestamp · tool versions link.
- **Coverage summary:** `Tested / Applicable / Not applicable / Unknown` counts with denominator tooltip.
- **Severity distribution:** Critical / High / Medium / Low / Info, with **Confirmed** vs **Potential** shown as separate bars.
- **Filters:** severity, category, file path, source tool, confidence, status.
- **Findings table columns:** Severity · Title · Category · File:line · Source · Confidence · OWASP · Status.
- **Coverage matrix toggle:** SEC-001…032 with result state per control.

## 5. DPDP tab — layout

- **Disclaimer banner (persistent):** "Readiness assessment. Not a compliance determination or legal advice."
- **Applicability panel:** questionnaire completion (unanswered = *Unknown*).
- **Control matrix columns:** ID · Control · Evidence found (E1–E5 chips) · Readiness label · **Effective date label** · Action.
- **Effective-date chips:** `In force` · `Upcoming — 13 May 2027` · `Not yet determined`.
- **Penalty reference drawer** (per control, when relevant):
  > **Potential legal category: Schedule Item 1 (§8(5)).** Statutory maximum: up to ₹250 crore. *Potential legal category; applicability and liability not determined.* Source: DPDP Act 2023, Schedule. Reviewed: <date>.
  - Never shown as a fine, never summed, no emphasis styling.
- **Three-way separation** on each control: *Engineering priority* · *Legal exposure reference* · *Legal determination required*.

## 6. Status vocabulary (text + icon + shape)

| State | Label | Icon | Meaning |
|---|---|---|---|
| PASS_EVIDENCED | Passed (evidenced) | ✔ circle | Meaningful evidence supports control |
| FAIL_EVIDENCED | Failed (evidenced) | ✖ octagon | Concrete evidence of failure |
| POTENTIAL_GAP | Potential gap | ▲ triangle | Indicator found; context unverified |
| NOT_VERIFIED | Not verified | ? diamond | Evidence unavailable |
| NOT_APPLICABLE | Not applicable | — dash | Out of scope |
| ERROR | Check error | ! square | Tool/check failed |

DPDP labels: *Evidence supports · Potential gap · Needs documents · Not applicable · Requires legal review.*

## 7. Visual tokens

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | #FFFFFF | #0F1217 | Page |
| `--surface` | #F5F7FA | #181D25 | Cards |
| `--text` | #14181F | #E6EAF0 | Body |
| `--muted` | #5B6575 | #9AA5B5 | Secondary |
| `--critical` | #B42318 | #FF8A80 | Critical severity |
| `--high` | #C2410C | #FDBA74 | High |
| `--medium` | #A16207 | #FACC15 | Medium |
| `--low` | #1D4ED8 | #93C5FD | Low |
| `--info` | #475569 | #CBD5E1 | Info |
| `--ok` | #15803D | #86EFAC | Evidenced pass |
| `--unknown` | #6B21A8 | #D8B4FE | Not verified |

Contrast ≥ 4.5:1 for text. Typography: system UI stack; monospace for code/evidence (`JetBrains Mono`, fallback `ui-monospace`). 8-px spacing grid. Radius 8 px.

## 8. Key components

| Component | Notes |
|---|---|
| `RepoInput` | Validates `https://github.com/{owner}/{repo}` live; shows rejection reason |
| `ScannerCard` | State, version, duration, error code, "what this covers" |
| `CoverageBar` | Segments: tested / unknown / N/A; tooltip with denominator |
| `FindingRow` | Severity badge + status icon + redacted location |
| `EvidenceBlock` | Redacted excerpt with line numbers; secret masked as `••••[redacted:type]` |
| `OwaspChip` | Standard + version + ref (e.g. `API3:2023`) |
| `EffectiveDateChip` | Computed from `as_of_date` |
| `PenaltyReference` | Fixed template only |
| `AIExplainPanel` | Collapsed by default; labelled "AI-generated, from redacted evidence" |
| `DisclaimerBanner` | Always visible on DPDP and report preview |

## 9. Interaction & states

- **Loading:** engine-by-engine skeletons; partial results appear as stages finish.
- **Partial:** amber banner "Some checks did not run" with link to failed scanners; never green.
- **Empty (clean):** "No findings from checks that ran. N controls could not be verified." — never "Secure".
- **Rejected URL:** inline message with reason code (not GitHub, private host, malformed, too large).
- **Errors:** typed, human-readable, no stack traces.

## 10. Accessibility (NFR-08)

Full keyboard navigation (tabs, tables, drawers) · visible focus rings · ARIA roles for tabs/tables · `aria-live` for progress changes · critical findings have text status · respects `prefers-reduced-motion` · no information by color alone.

## 11. Copy rules

| Do | Don't |
|---|---|
| "Potential gap — rate limiting not visible in source" | "Your API has no rate limiting" |
| "Not verified (no lockfile found)" | "0 vulnerabilities" |
| "Upcoming from 13 May 2027" | "You are violating DPDP" |
| "Statutory maximum up to ₹250 crore" | "You may be fined ₹250 crore" |
| "Readiness: potential gap" | "Non-compliant" |

## 12. PDF report layout

Cover (repo, SHA, time, tool versions) → executive summary (counts + coverage, no grade) → methodology & exclusions → security findings table → per-finding page (proof, redacted excerpt, fix, validation) → OWASP matrix → DPDP matrix with effective-date column → legal appendix (citations, penalty ceilings, disclaimer) → prioritized remediation plan (Engineering / Documentation / Organizational) → evidence gaps & next steps. Header on every page: *"Developer-assistance report — not a security certificate or legal opinion."*

## 13. Demo script (3 minutes)

1. Paste vulnerable fixture URL → show SHA + frameworks.
2. Progress: scanners complete; one deliberately skipped → show **Partial/Not verified**.
3. Security tab: secret (redacted), injection, rate-limit potential gap.
4. DPDP tab: evidence gaps; chips show *In force* vs *Upcoming May 2027*.
5. Penalty drawer: "up to ₹250 crore" + disclaimer.
6. Export PDF + JSON.
