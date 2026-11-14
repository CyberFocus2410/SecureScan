# SecureScan AI — 3-Minute Live Demo Script

This script walks through the complete audit lifecycle of **SecureScan AI** in 3 minutes, showcasing static security detection, honesty states, India DPDP readiness assessment, and report exports.

---

## Pre-requisites & Setup
Ensure both servers are running locally:
- **Backend API:** `http://localhost:8000` (docs at `http://localhost:8000/docs`)
- **Frontend Dashboard:** `http://localhost:3000`
- **Fallback Dataset:** `demo/seeded_audit_data.json` is pre-seeded for offline demonstration.

---

## Minute 1: Safe Import & Sandboxed Execution (0:00 – 1:00)

1. **Open Application**
   - Navigate to `http://localhost:3000`.
   - Point out the clean landing view and the anonymous session-scoped capability model.

2. **Submit Repository**
   - In the Repository URL field, enter the fixture repository:
     ```text
     https://github.com/vivan/sample-fastapi-app
     ```
   - Select Scopes: Check both **Security Audit (OWASP/ASVS)** and **DPDP Readiness (India)**.
   - Click **Run Audit**.

3. **Live Progress & Sandboxed Isolation**
   - Show the live event stream as the audit transitions: `QUEUED` → `IMPORTING` → `SCANNING` → `ANALYZING` → `REPORT_READY`.
   - **Key Explanatory Point:** Emphasize that the code runs inside a zero-network sandbox (`--network=none`, non-root, read-only filesystem). Untrusted repository scripts and hooks are **never executed**.
   - Note the pinned commit SHA displayed in the header banner.

---

## Minute 2: Security Dashboard & Honesty States (1:00 – 2:00)

1. **Severity & Coverage Breakdown**
   - Switch to the **Security Findings** tab.
   - Show the summary counters: Critical, High, Medium, Low, Info findings.
   - Point out the Security Coverage Ratio (e.g. `14/32 Evidenced Controls`).
   - Highlight: *"No arbitrary letter grade like 'A+' or 'B' — we report exact counts and coverage ratios."*

2. **Parser-Level Secret Redaction (AT-03)**
   - Click on the **AWS Access Key Exposed** finding.
   - Show the code snippet: The raw key is sanitized to `[REDACTED:aws-access-key]`.
   - Explain that redaction occurs at the parser boundary; raw secret literals never enter the database, logs, or UI.

3. **Authentic Line Locator & Real SAST (AT-04)**
   - Inspect the **SQL Injection** finding in `app/db.py:25`.
   - Show the exact line reference and OWASP/CWE linkage (`CWE-89`, `A03:2025`).
   - Click **AI Explanation** to show the schema-validated root cause and technical fix.

4. **Honesty States (AT-05 & AT-07)**
   - Inspect the **Rate Limiting** control (`SEC-008`):
     - State: `POTENTIAL_GAP`.
     - Reason: Rate limiting is not visible in static source code; runtime gateway controls may exist.
   - Point out: *"Unknown is never reported as Pass. We report an honest gap instead of false reassurance."*

---

## Minute 3: India DPDP Readiness & Report Export (2:00 – 3:00)

1. **DPDP Compliance Matrix (AT-09 to AT-14)**
   - Switch to the **DPDP Readiness** tab.
   - Point out the three-state phased commencement chips:
     - `IN FORCE` (e.g., Board machinery, Consent Managers under Rule 4 since 13 Nov 2026).
     - `UPCOMING` (e.g., General notice and fiduciary obligations commencing 13 May 2027).
   - Emphasize that effective dates are computed dynamically against `as_of_date`, never hardcoded.

2. **Primary Gazette Citations (AT-14)**
   - Expand any DPDP control (e.g., `DPDP-001 Notice Requirement` or `DPDP-006 Security Safeguards`).
   - Show the official Gazette reference: `G.S.R. 843(E)` and `G.S.R. 846(E)`.

3. **Statutory Penalty Ceilings & Caveat (AT-13)**
   - Open the **Statutory Penalty Ceiling Schedule**.
   - Show the maximum statutory ceiling: *"Up to ₹250 crore (Section 8(5))"*.
   - Read the mandatory statutory caveat on every row:
     > *"Potential legal category; applicability and liability not determined."*
   - Highlight: *"We strictly prohibit fine predictions and never sum penalties across rows."*

4. **Multi-Engine Report Export (AT-17)**
   - Switch to the **Reports** tab.
   - Click **Download PDF Report**:
     - Open the generated PDF: Verify the mandatory running header on every single page:
       *"Developer-assistance report — not a security certificate or legal opinion."*
   - Click **Export JSON**:
     - Inspect the canonical machine-readable JSON structure.

---

## Emergency Fallback Procedure
If local Docker or network connectivity is unavailable during the demo:
1. Open the UI at `http://localhost:3000`.
2. The UI automatically displays the pre-seeded audit data from `demo/seeded_audit_data.json`.
3. All tabs, findings, DPDP chips, and penalty drawers are fully interactive in offline mode.

