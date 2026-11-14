# SecureScan AI

**Static Security & India DPDP (Digital Personal Data Protection) Audit Platform**

SecureScan AI takes a public GitHub repository, safely imports a pinned commit, runs sandboxed static security scanners (Gitleaks, Semgrep, OSV-Scanner, Bandit) and custom framework rules, maps findings to OWASP Top 10 and ASVS, evaluates India DPDP Act 2023 readiness with dynamic phased commencement, and exports auditable PDF and JSON reports with statutory penalty *ceilings*.

> [!IMPORTANT]
> **Developer-Assistance Disclaimer**  
> SecureScan AI is a diagnostic developer-assistance tool. It is **not** a security certification, compliance certificate, penetration test, or legal opinion. All statutory penalties listed reflect maximum statutory ceilings under the Schedule to the DPDP Act, 2023, accompanied by the mandatory caveat: *"Potential legal category; applicability and liability not determined."* Predicted fines and summed penalty totals are strictly prohibited.

---

## Key Capabilities & Core Philosophy

- **Zero Untrusted Code Execution**: Scanners run inside an isolated sandbox with `--network=none`, non-root execution, dropped capabilities, and read-only mounts. Repository scripts, hooks, or package build tasks are **never** executed.
- **Strict Secret Redaction at Parser Boundary**: Secret literals are sanitized immediately upon detection (`[REDACTED:<type>]`). Raw credentials never reach the database, logs, user interface, report documents, or AI prompts.
- **Honesty States (Unknown ≠ Pass)**:
  - `PASS_EVIDENCED`: Defensive control verified by static evidence.
  - `FAIL_EVIDENCED`: Flaw or vulnerability positively identified.
  - `POTENTIAL_GAP`: Control not visible in source code; runtime or architectural safeguards may exist upstream.
  - `NOT_VERIFIED`: Scanner unavailable, framework unsupported, or lockfile absent.
  - `NOT_APPLICABLE`: Control irrelevant to the detected application architecture.
  - `ERROR`: Scanner crashed or exited unexpectedly (triggers `PARTIAL` audit status).
- **Dynamic Phased Commencement (India DPDP)**: Calculates enforcement status dynamically against `as_of_date` using official Gazette notifications (`G.S.R. 843(E)` and `G.S.R. 846(E)`):
  - **Phase 1 (13 Nov 2025)**: Board machinery & inquiry rules.
  - **Phase 2 (13 Nov 2026)**: Section 6(9) & Rule 4 (Consent Managers).
  - **Phase 3 (13 May 2027)**: General fiduciary obligations, notice, security safeguards, children's data, and penalties.
- **Dual-Engine PDF & Canonical JSON Export**: High-fidelity reports featuring a mandatory running header on every single page: *"Developer-assistance report — not a security certificate or legal opinion."*

---

## Architecture Overview

```
SecureScan AI
├── backend/
│   ├── app/
│   │   ├── api/v1/          # REST Endpoints (repositories, audits, findings, reports)
│   │   ├── core/            # Config, database, security primitives, error handlers
│   │   ├── dpdp/            # Dynamic commencement engine & citation resolver
│   │   ├── models/          # SQLAlchemy ORM models (Audit, Finding, ControlResult, Evidence)
│   │   ├── reporting/       # Collector, HTML templates, multi-engine PDF (WeasyPrint/ReportLab), JSON
│   │   ├── rules/           # Custom AST/regex security analyzers (FastAPI, Express)
│   │   ├── scanners/        # Adapters for Gitleaks, Semgrep, OSV-Scanner, Bandit, and Sandbox Runner
│   │   ├── schemas/         # Pydantic v2 domain schemas and enums
│   │   └── services/        # GitHub import, policy loader, penalties, AI explainer
│   └── tests/               # 72 unit, integration, and security tests (AT-01..AT-20)
├── frontend/
│   ├── src/
│   │   ├── components/      # UI components (Header, EvidenceDrawer, SeverityBadge)
│   │   ├── pages/           # Landing, Security, DPDP, and Report export pages
│   │   └── services/        # API client and typed contracts
│   └── vite.config.ts       # Vite configuration with proxy to FastAPI
└── policies/
    ├── security_controls.yaml # 32 Security controls with OWASP & ASVS mappings
    ├── dpdp_controls.yaml     # 18 DPDP controls with primary Gazette citations
    └── penalty_schedule.yaml  # 7 Schedule penalty items with statutory ceilings
```

---

## Getting Started

### Prerequisites
- **Python 3.11+** (Python 3.12 recommended)
- **Node.js 18+** & **npm**
- **Docker** (optional for local mock runner; required for sandboxed containerized scanner runs)

### 1. Installation

**Backend Setup:**
```bash
# Clone the repository
git clone https://github.com/vivan/SecureScan.git
cd SecureScan

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt
```

**Frontend Setup:**
```bash
cd frontend
npm install
cd ..
```

---

### 2. Running the Application

You can start both services concurrently:

**Start Backend (FastAPI):**
```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
*Backend runs on `http://127.0.0.1:8000` with interactive API docs at `http://127.0.0.1:8000/docs`.*

**Start Frontend (Vite + React):**
```bash
cd frontend
npm run dev
```
*Frontend runs on `http://localhost:3000`.*

---

### 3. Running the Test Suite

Execute the unified CI verification suite:
```bash
python scripts/ci.py
```
This runs:
1. Python syntax compilation across all modules.
2. Policy bundle schema validation against `policies/*.yaml`.
3. Complete pytest test suite (72 unit, integration, and security tests).

To run specific test categories:
```bash
# Run all Acceptance Tests (AT-01..AT-20)
pytest backend/tests/integration backend/tests/security -v

# Run Secret Redaction & Absence tests (AT-03)
pytest backend/tests/security/test_at03_redaction.py backend/tests/security/test_report_redaction.py -v
```

---

## How to Update Policies and Legal Dates

### 1. Updating Policies (`policies/*.yaml`)
- **Security Controls**: Edit `policies/security_controls.yaml` to adjust rules, OWASP categories, or ASVS 5.0.0 references.
- **DPDP Controls**: Edit `policies/dpdp_controls.yaml` to update section numbers, rule numbers, or official Gazette IDs (`gazette_id`).
- **Penalty Ceilings**: Edit `policies/penalty_schedule.yaml` to update statutory limits or linked controls.

*Note: All YAML edits must conform to Pydantic schemas. Run `python scripts/ci.py` after editing to ensure validation passes.*

### 2. Updating Legal Effective Dates (`as_of_date`)
The DPDP engine evaluates effective dates relative to the audit's `as_of_date` (defaults to current system date). To test historical or future commencement phases, pass `as_of_date` in the audit creation request:
```json
{
  "repository_id": "<uuid>",
  "scopes": ["security", "dpdp"],
  "as_of_date": "2027-06-01"
}
```

---

## Acceptance Test Matrix (AT-01 .. AT-20)

| ID | Focus Area | Verification Strategy |
|:---:|---|---|
| **AT-01** | Language & Framework Detection | FastAPI & Express detected; pinned commit SHA recorded |
| **AT-02** | Strict GitHub URL Parsing | Canonical format only; query, IP, local files rejected without network |
| **AT-03** | Secret Redaction & Absence | Secrets redacted at parser boundary; zero literal leaks in DB, logs, PDF, JSON |
| **AT-04** | SQLi Authentic Locator | Line-level locator, CWE-89, OWASP A03:2025 linkage |
| **AT-05** | Rate Limiting Honesty | Static invisibility yields `POTENTIAL_GAP`, never false pass |
| **AT-06** | Sensitive DTO Exposure | PII fields in response models identified with authentic AST evidence |
| **AT-07** | Dependency CVEs & Lockfiles | High/Critical CVEs mapped; missing lockfiles yield `NOT_VERIFIED` |
| **AT-08** | Scanner Crash Handling | Tool failure triggers fail-safe transition to `PARTIAL` audit |
| **AT-09** | Candidate Personal Data | Uncatalogued PII fields marked with unknown purpose gap |
| **AT-10** | Applicability Questionnaire | Unanswered questions yield unknown states, never default compliance |
| **AT-11** | Personal Data Exposure Linkage | High-severity findings linked to DPDP §8(5) without claiming actual breach |
| **AT-12** | Dynamic Commencement | Real-time calculation of *In force* vs *Upcoming* from `as_of_date` |
| **AT-13** | Penalty Ceilings & Caveats | Ceilings with mandatory caveats; fine predictions and sums strictly prohibited |
| **AT-14** | Gazette Citation Completeness | 100% of DPDP controls link to primary Gazette notifications |
| **AT-15** | Cross-Session Isolation | Anonymous session IDs enforced; cross-session access returns HTTP 403 |
| **AT-16** | Prompt Injection Hardening | `<untrusted_source_code>` XML delimiters; findings are strictly immutable |
| **AT-17** | Mandatory Report Sections | PDF & JSON include metadata, versions, summaries, matrices, and disclaimers |
| **AT-18** | Unsupported Frameworks | Non-FastAPI/Express frameworks yield `NOT_VERIFIED` |
| **AT-19** | Worktree Security & Caps | File count, byte size, and symlink escape caps enforced; zero hooks executed |
| **AT-20** | SHA Consistency | Identical pinned commit SHA bound across security, DPDP, and report artifacts |

---

## License & Safety Notice

Distributed under the Apache 2.0 License. See `docs/legal_sources.md` for primary legislative sources and legal review requirements.

