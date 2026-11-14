# SecureScan AI — Master Study & Architectural Guide

> **A Comprehensive Guide to Understanding, Presenting, and Defending the SecureScan AI Security & India DPDP Audit Platform.**

---

## Table of Contents
1. [Executive Summary & The "Why" (The Core Need)](#1-executive-summary--the-why-the-core-need)
2. [Complete Tech Stack & System Architecture](#2-complete-tech-stack--system-architecture)
3. [End-to-End Workflow: Step-by-Step Execution](#3-end-to-end-workflow-step-by-step-execution)
4. [Security Checks Catalogue (The 32 Security Controls)](#4-security-checks-catalogue-the-32-security-controls)
5. [The Legal Framework: India DPDP Act 2023 & Rules 2025](#5-the-legal-framework-india-dpdp-act-2023--rules-2025)
6. [Why The App Works Without an API Key (Deterministic Engine)](#6-why-the-app-works-without-an-api-key-deterministic-engine)
7. [All Features & User Interface Capabilities](#7-all-features--user-interface-capabilities)
8. [Master Study Guide: Concepts, Defense, and Presentation Q&A](#8-master-study-guide-concepts-defense-and-presentation-qa)

---

## 1. Executive Summary & The "Why" (The Core Need)

### 1.1 What is SecureScan AI?
**SecureScan AI** is an open-source, automated developer-assistance platform that audits public GitHub repositories. In under 60 seconds, it:
1. Clones a pinned Git commit into a zero-network, read-only sandbox.
2. Runs static security analysis (SAST) and custom Abstract Syntax Tree (AST) analyzers.
3. Maps technical flaws to **OWASP Top 10 (2025)** and **OWASP ASVS 5.0.0**.
4. Evaluates compliance readiness against India's **Digital Personal Data Protection (DPDP) Act, 2023** and **DPDP Rules, 2025**.
5. Computes dynamic enforcement dates (differentiating between *in-force* and *upcoming* legal rules).
6. Generates high-fidelity PDF and JSON audit reports featuring prioritized engineering remediations and statutory penalty **ceilings**.

### 1.2 The Problem: Why Traditional Scanners Fail
Developers and engineering teams in India face three critical gaps:

| Traditional Tool Limitation | The Consequence | How SecureScan AI Solves It |
|---|---|---|
| **Zero DPDP Awareness** (Snyk, SonarQube, Bandit only know Western standards like GDPR or generic CVEs). | Startups and enterprises have no idea how their database schemas or code violate Indian law. | Implements 18 dedicated DPDP controls with primary citations to official Gazette notifications (`G.S.R. 843(E)`, `G.S.R. 846(E)`). |
| **False Reassurance ("0 Vulnerabilities = 100% Secure")** | If a tool cannot see rate limiting in code, it gives a green checkmark or ignores it. Attackers still DDoS or scrape the API. | **Honesty States**: Unknown is *never* reported as Pass. If a control cannot be statically verified, it is honestly labelled `POTENTIAL_GAP` or `NOT_VERIFIED`. |
| **Reckless Fine Speculation** | Some compliance startups claim *"You will be fined ₹250 crore!"* to create fear. | **Strict Statutory Ceilings Only**: Displays maximum legal upper limits under the Act Schedule with the mandatory statutory caveat: *"Potential legal category; applicability and liability not determined."* Fine predictions and sums are strictly prohibited. |
| **Unsafe Execution** | Many scanners execute `npm install`, build scripts, or git hooks, exposing the scanning host to remote code execution (RCE). | **Zero Untrusted Code Execution**: All scanners run with `--network=none`, non-root user, dropped capabilities, and git hooks disabled (`core.hooksPath=/dev/null`). |

---

## 2. Complete Tech Stack & System Architecture

```
                                  [ Browser Client ]
                                   (React 18 + Vite)
                                          │
                                  HTTP / SSE / REST
                                          │
                                          ▼
                                 [ FastAPI Backend ]
                             (Python 3.11+, Pydantic v2)
                                          │
                ┌─────────────────────────┼─────────────────────────┐
                ▼                         ▼                         ▼
      [ GitHub Ingestion ]        [ SQLite / Postgres ]     [ Policy Loader ]
    (Strict URL Validator +      (Audits, Findings,       (YAML Bundle: 32 Sec,
     Bounded Shallow Clone)       Evidence, Remediations)   18 DPDP, 7 Penalties)
                │                         │                         │
                ▼                         │                         │
       [ Sandboxed Runner ]               │                         │
    (--network=none, non-root)            │                         │
    ├── Gitleaks (Secrets)                │                         │
    ├── Semgrep (SAST)                    │                         │
    ├── OSV-Scanner (CVEs)                │                         │
    ├── Bandit (Python AST)               │                         │
    └── Custom AST Rules                  │                         │
                │                         │                         │
                └─────────────────────────┼─────────────────────────┘
                                          ▼
                            [ Normalization & Redaction ]
                              (Parser-boundary redactor:
                              [REDACTED:aws-access-key])
                                          │
                        ┌─────────────────┴─────────────────┐
                        ▼                                   ▼
              [ Security Engine ]                    [ DPDP Engine ]
           (32 Controls, 64 OWASP,                 (18 Controls, Dynamic
           6 Honesty States, Coverage)              Commencement, Ceilings)
                        │                                   │
                        └─────────────────┬─────────────────┘
                                          ▼
                             [ Remediation Generator ]
                            (Deterministic P0/P1 fixes)
                                          │
                        ┌─────────────────┴─────────────────┐
                        ▼                                   ▼
               [ Report Generator ]               [ Optional AI Layer ]
              (ReportLab Vector PDF +             (Gemini 2.5 Flash with
              Canonical JSON Export)             XML isolation & Fallback)
```

### 2.1 Backend Stack
- **Language**: Python 3.11+ / Python 3.12
- **Web Framework**: **FastAPI** (high performance, asynchronous endpoints, typed OpenAPI / Swagger specs).
- **Data Validation & Schemas**: **Pydantic v2** (strict type safety, field validators, JSON schema export).
- **ORM & Database**: **SQLAlchemy 2.0** + **SQLite** (local zero-config dev) / **PostgreSQL** (production ready) + **Alembic** (migrations).
- **Document & PDF Generation**: **ReportLab** (pure Python vector PDF generation engine, zero native C-library dependencies) + **Jinja2** HTML templating + **WeasyPrint** (Docker mode).
- **Background Tasks**: FastAPI `BackgroundTasks` / Redis + RQ queue runner.

### 2.2 Frontend Stack
- **Framework**: **React 18** with **TypeScript 5.7**.
- **Build Tool**: **Vite 6** (sub-second HMR and production tree-shaking).
- **Styling**: **Tailwind CSS 3.4** (responsive layouts, dark mode, high-contrast accessibility).
- **Icons**: **Lucide React**.
- **Data Fetching & Caching**: **TanStack React Query v5** (asynchronous state management, automatic background refetching).
- **Client Architecture**: Clean Service-Oriented Architecture (`frontend/src/services/api.ts`) binding strictly to backend contracts.

### 2.3 Security Scanning Engines
1. **Gitleaks (v8.21.2)**: Specialized static regular expression scanner designed to find passwords, API keys, AWS tokens, private keys, and certificates.
2. **Custom AST Analyzer (`backend/app/scanners/custom.py`)**: Custom-built Python Abstract Syntax Tree (`ast` module) and regex parser:
   - Traverses Python AST nodes (`ast.FunctionDef`, `ast.Call`, `ast.Assign`).
   - Identifies raw SQL execution without parameterized queries.
   - Inspects Pydantic response models for exposed sensitive fields (e.g. `password`, `ssn`, `auth_token`).
   - Checks whether API endpoints have pagination (`limit`, `offset`) or rate limiting.
3. **Semgrep (v1.102.0)**: Semantic pattern SAST matching for modern web frameworks.
4. **Bandit (v1.8.0)**: Python security linter evaluating dangerous functions (`eval()`, `exec()`, `pickle.loads()`, `assert`).
5. **OSV-Scanner (v1.9.2)**: Open Source Vulnerability scanner referencing Google’s distributed OSV database to detect vulnerable open-source dependencies without building the project.

---

## 3. End-to-End Workflow: Step-by-Step Execution

When a user submits a repository like `https://github.com/CyberFocus2410/LostLink`, the platform executes a 10-stage pipeline:

```
[1. URL Parse] ──▶ [2. Safe Clone] ──▶ [3. Framework Detect] ──▶ [4. Sandboxed Scan]
                                                                        │
[8. DPDP Eval] ◀── [7. Sec Controls] ◀── [6. Deduplication] ◀── [5. Redaction]
       │
       ▼
[9. Deterministic Remediations] ──▶ [10. PDF & JSON Report Export]
```

### Stage 1: Strict URL Parsing & Security Canonicalization (AT-02)
- Rejects non-HTTPS schemes (`http://`, `ssh://`, `git://`).
- Rejects user credentials embedded in URLs (`https://user:pass@github.com/...`).
- Rejects IP addresses, port numbers, query strings (`?foo=bar`), and URL fragments (`#readme`).
- Only accepts public `https://github.com/{owner}/{repo}` paths.
- Canonicalizes `.git` endings.

### Stage 2: Bounded Shallow Checkout (AT-01, AT-19)
- Executes: `git clone --depth=1 --branch <branch> --no-recurse-submodules -c core.hooksPath=/dev/null <url> <target>`
- **No Git Hooks**: By pointing `core.hooksPath` to `/dev/null`, malicious post-checkout scripts never run.
- **Resource Caps**: Enforces caps on total disk size (max 500 MB), total file count (max 20,000 files), and individual file size (max 10 MB).
- **Symlink Neutralization**: Inspects every file path to ensure symbolic links do not escape the root repository directory.

### Stage 3: Language & Framework Detection
- Analyzes project manifests (`requirements.txt`, `pyproject.toml`, `package.json`, `setup.py`).
- Determines primary language (Python, JavaScript, TypeScript) and framework (FastAPI, Express, Flask, Django).
- Records the immutable 40-character commit SHA (e.g. `84b7ecfdffd0677cb46cf96f5edd7293dcb7bfe4`).

### Stage 4: Sandboxed Scanner Execution
- The repository is mounted as **read-only** (`:ro`).
- Scanners run with `--network=none` (zero inbound/outbound network connectivity), dropping Linux root privileges.
- Scanners emit raw JSON findings into isolated memory buffers.

### Stage 5: Parser-Boundary Secret Redaction (AT-03)
- Before findings are stored in the database, logged, or displayed, snippets pass through `redact_text()`.
- AWS keys, GitHub tokens, Slack tokens, private keys, and generic `password = "..."` assignments are replaced with `[REDACTED:<type>]`.
- **Guarantee**: The raw secret literal *never* exists in SQLite, PostgreSQL, memory logs, PDF bytes, or JSON outputs.

### Stage 6: Fingerprinting & Context Deduplication
- Each finding receives a deterministic SHA-256 fingerprint:
  `fingerprint = sha256(rule_id + file_path + str(start_line) + redacted_snippet)`
- Prevents identical vulnerabilities from cluttering the audit report across multiple scanner runs.

### Stage 7: Security Controls Mapping (32 Controls)
- Findings are mapped to the 32 controls defined in `policies/security_controls.yaml`.
- Evaluates controls into one of the **6 Honesty States**:
  1. `PASS_EVIDENCED`: Verified safe by static inspection.
  2. `FAIL_EVIDENCED`: Vulnerability positively identified.
  3. `POTENTIAL_GAP`: Control cannot be confirmed from static code alone (e.g. Rate Limiting).
  4. `NOT_VERIFIED`: Scanner skipped, lockfile missing, or framework unsupported.
  5. `NOT_APPLICABLE`: Flaw irrelevant to this technology stack.
  6. `ERROR`: Scanner crashed (triggers `PARTIAL` audit status).

### Stage 8: India DPDP Readiness Engine
- Evaluates candidate personal data discovered in code (e.g. email fields, phone numbers, auth DTOs).
- Evaluates 18 controls in `policies/dpdp_controls.yaml`.
- Calculates phased commencement dynamically against the audit's `as_of_date` (`2026-11-14`).
- Links potential exposures to statutory penalty ceilings under the Schedule to the Act.

### Stage 9: Deterministic Remediation Engine
- Generates prioritized (P0/P1) engineering remediations, exact file locations, and validation commands (e.g. test curl commands or unit tests) without needing an external AI API key.

### Stage 10: Multi-Engine PDF & JSON Export
- Packages all data into an auditable vector PDF and canonical JSON file.
- Stamps every page with the mandatory running legal header:
  *"Developer-assistance report — not a security certificate or legal opinion."*

---

## 4. Security Checks Catalogue (The 32 Security Controls)

SecureScan AI maps static findings to 32 standardized security controls covering OWASP Top 10 (2025) and OWASP ASVS 5.0.0:

| Control ID | Category / Name | What It Checks | Why It Matters | Detection Method |
|---|---|---|---|---|
| **SEC-001** | SQL Injection Prevention | Dynamic string formatting (`f"SELECT... {id}"`) or string concatenation in SQL queries. | SQLi allows attackers to dump the entire database, bypass authentication, or corrupt data. | AST / Semgrep / Bandit |
| **SEC-002** | Command Injection Defense | Unsanitized inputs passed to `os.system()`, `subprocess.Popen()`, `eval()`, or `exec()`. | Allows remote attackers to execute arbitrary shell commands on the server. | Bandit / Semgrep |
| **SEC-003** | Secret Hardcoding Elimination | Plaintext AWS tokens (`AKIA...`), GitHub PATs, private keys, or passwords in source. | Hardcoded secrets committed to git history are stolen by bot scrapers within minutes. | Gitleaks regex engine |
| **SEC-004** | Cryptographic Hashing | Use of obsolete hash algorithms like MD5 or SHA-1 for passwords or signatures. | MD5 and SHA-1 suffer from collision attacks and can be cracked via rainbow tables in seconds. | Python AST / Bandit |
| **SEC-005** | Rate Limiting Enforcement | Checks for rate-limiting middleware (e.g. SlowAPI, express-rate-limit). | Prevents brute-force authentication, credential stuffing, and DoS attacks. | AST check (`POTENTIAL_GAP` if missing) |
| **SEC-006** | CORS Misconfiguration | Presence of wildcard origins: `allow_origins=["*"]` with `allow_credentials=True`. | Wildcard CORS allows malicious third-party websites to make authenticated API calls on behalf of users. | AST inspection |
| **SEC-007** | Admin Route Authentication | Administrative routes (`/admin/*`) missing dependency checks or auth decorators. | Prevents Broken Object Level Authorization (BOLA/IDOR) and unauthorized admin operations. | Route decorator AST check |
| **SEC-008** | Response DTO Sensitive Leakage | Response models returning raw password hashes, SSNs, Aadhaar numbers, or secrets. | Exposes confidential user data in API responses to unauthorized consumers. | Pydantic model AST parser |
| **SEC-009** | Mandatory Pagination | Endpoints returning unbounded lists without `limit` / `offset` parameters. | Querying millions of records without pagination exhausts server memory and triggers OOM crashes. | Function signature AST inspection |
| **SEC-010** | Dependency CVEs | Inspects package lockfiles (`package-lock.json`, `poetry.lock`, `requirements.txt`). | Prevents exploitation of known publicly disclosed supply chain vulnerabilities. | OSV-Scanner adapter |
| **SEC-011** | Debug Mode in Production | `DEBUG = True` or development flags hardcoded in configuration files. | Exposes interactive debug consoles, environment variables, and stack traces to attackers. | Configuration AST / regex |
| **SEC-012** | Insecure Deserialization | Dangerous usage of `pickle.loads()`, `yaml.load(Loader=Loader)`. | Untrusted serialized objects can execute arbitrary Python bytecode upon deserialization. | Bandit adapter |
| **SEC-013..032** | Session management, CSRF, Secure Cookies, SSRF, TLS, etc. | Comprehensive coverage of ASVS Level 1 & 2 requirements. | Defense-in-depth across the entire application attack surface. | SAST / Custom rules |

---

## 5. The Legal Framework: India DPDP Act 2023 & Rules 2025

### 5.1 Primary Legal Sources
SecureScan AI relies exclusively on primary gazette publications from the Government of India:
1. **Act No. 22 of 2023**: Digital Personal Data Protection Act, 2023 (Published 11 August 2023).
2. **G.S.R. 843(E)**: MeitY Commencement Notification under Section 1(2) (Dated 13 November 2025).
3. **G.S.R. 846(E)**: Digital Personal Data Protection Rules, 2025 (Dated 13 November 2025).

### 5.2 Dynamic Phased Commencement Matrix
The DPDP Act does not come into force all at once. SecureScan AI calculates status dynamically based on the audit’s `as_of_date` (defaults to current date, e.g., `2026-11-14`):

```
Phase 1: 13 Nov 2025               Phase 2: 13 Nov 2026               Phase 3: 13 May 2027
[STATUS: IN FORCE]                 [STATUS: IN FORCE]                 [STATUS: UPCOMING]
--------------------               --------------------               --------------------
• Data Protection Board            • Section 6(9): Registration       • Sections 3–5, 6(1)-(8)
  establishment (§18)                and duties of Consent              (Notice, Grounds of processing)
• Adjudication machinery             Managers                         • Section 8 (Safeguards, Breach)
• Inquiries & appeals (§27)        • Section 27(1)(d): Board          • Sections 9–17 (Children, SDF,
• Rules 1, 2, 17–21                  powers over Consent Managers       Rights of Data Principals)
                                   • Rule 4: Consent Manager          • Section 33 & Schedule
                                     regulations & interoperability     (Statutory Penalties)
                                                                      • Rules 3, 5–16, 22, 23
```

### 5.3 The 18 DPDP Readiness Controls
SecureScan AI evaluates 18 statutory controls (`DPDP-001` through `DPDP-018`):
- **Notice & Consent** (`DPDP-001` to `DPDP-005`): Clear itemized notice, withdrawal mechanism as easy as giving consent, multilingual notice requirements.
- **Security Safeguards & Breach Notification** (`DPDP-006` to `DPDP-008`): Reasonable security safeguards to prevent personal data breach (Section 8(5)), notification to Board and Data Principals within prescribed timeframe (Section 8(6)).
- **Children's Personal Data** (`DPDP-009`): Verifiable parental consent before processing data of children under 18; strict prohibition on behavioral tracking or targeted ads (Section 9).
- **Significant Data Fiduciary (SDF)** (`DPDP-010`, `DPDP-014`, `DPDP-017`): Appointment of India-based Data Protection Officer (DPO), independent data audits, Periodic Data Protection Impact Assessments (DPIA) (Section 10).
- **Data Principal Rights & Erasure** (`DPDP-011` to `DPDP-013`): Right to access, correction, erasure, and grievance redressal (Sections 11–13).
- **Sub-processors & Data Processors** (`DPDP-015` to `DPDP-016`): Valid contract requirement between Data Fiduciary and Data Processor (Section 8(2)).

### 5.4 The Statutory Penalty Schedule (Section 33)
Under the Schedule to Section 33 of the Act, maximum statutory ceilings are defined:

| Item | Section | Obligation / Violation | Statutory Maximum Ceiling (INR) | SecureScan Linked Controls |
|:---:|---|---|---|---|
| **1** | Section 8(5) | Breach in observing reasonable security safeguards to prevent personal data breach | **Up to ₹250 crore** | `DPDP-006`, `DPDP-018` |
| **2** | Section 8(6) | Failure to notify Board and affected Data Principals of a personal data breach | **Up to ₹200 crore** | `DPDP-008` |
| **3** | Section 9 | Non-fulfillment of obligations in relation to children | **Up to ₹200 crore** | `DPDP-009` |
| **4** | Section 10 | Non-fulfillment of additional obligations of Significant Data Fiduciary (SDF) | **Up to ₹150 crore** | `DPDP-010`, `DPDP-014`, `DPDP-017` |
| **5** | Section 15 | Non-fulfillment of duties by Data Principal | **Up to ₹10,000** | `DPDP-013` |
| **6** | Section 32 | Breach of any term of voluntary undertaking accepted by the Board | **Up to underlying amount** | `DPDP-016` |
| **7** | Other | Breach of any other provision of the Act or Rules | **Up to ₹50 crore** | `DPDP-001`..`005`, `007`, `011`, `012`, `015` |

#### Mandatory Caveats and Non-Speculation Guarantees
1. **Mandatory Caveat**: Every penalty entry displays:
   > *"Potential legal category; applicability and liability not determined."*
2. **Zero Predicted Fines**: The Data Protection Board determines fines on a case-by-case basis considering statutory factors under Section 33 (nature, gravity, duration, repetitive nature, mitigating steps taken). **Predicting a fine is legally fraudulent.**
3. **Zero Summed Fines**: Penalties across items 1 to 7 cannot be summed together (e.g., claiming a ₹250 cr + ₹200 cr = ₹450 cr fine is strictly prohibited).

---

## 6. Why The App Works Without an API Key (Deterministic Engine)

A frequent question is: *"We haven't configured an OpenAI or Gemini API key. How is the app generating root causes, fixes, and reports? Is it just displaying static mock data?"*

### 6.1 The Reality: Real Code Analysis via Deterministic Rules
The content is **not mock data**. It works via a deterministic static analysis architecture:
1. **AST Parsing (Abstract Syntax Trees)**:
   Python's built-in `ast` module parses the code into a mathematical tree of tokens. When the analyzer sees:
   `db.execute(f"SELECT * FROM users WHERE id = {user_id}")`
   it detects an `ast.FormattedValue` inside an `ast.Call`. It doesn't need an AI to know that this is SQL Injection (`CWE-89`).
2. **Deterministic Remediation Engine (`services/remediations.py`)**:
   In enterprise application security, every vulnerability pattern has a known, standard engineering mitigation:
   - `CWE-798 (Hardcoded Secret)` $\rightarrow$ Revoke credential in cloud IAM, remove from git history with BFG Repo-Cleaner, load via environment variables (`os.environ`).
   - `CWE-89 (SQL Injection)` $\rightarrow$ Replace string formatting with parameterized prepared statements (`cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`).
   - `SEC-005 (Rate Limiting)` $\rightarrow$ Install SlowAPI decorator on route: `@limiter.limit("5/minute")`.
   The engine programmatically builds prioritized P0/P1 remediation steps tailored to the exact file path and line number identified.
3. **Deterministic AI Fallback Engine (`services/ai_explain.py`)**:
   When the user clicks "AI Explanation", if no `GEMINI_API_KEY` is present, the service seamlessly routes to `_build_deterministic_explanation()`. It outputs structured, high-grade root causes, architectural risk contexts, and validation tests without touching any external API.
4. **Why This is an Advantage**:
   - **Zero Latency**: Instant explanations with no network roundtrips.
   - **Zero Cost**: Runs entirely free on local CPU.
   - **Zero Confidential Data Leakage**: Your proprietary code is never transmitted to third-party cloud LLMs.
   - **Zero Hallucinations**: Rule-based logic never invents non-existent ASVS IDs or fake DPDP clauses.

---

## 7. All Features & User Interface Capabilities

| Feature | Description | Technical Implementation |
|---|---|---|
| **Repository Submission** | Enter any public GitHub repository URL and branch. | Validates URL regex, detects frameworks, issues 202 Accepted. |
| **Real-time Pipeline Events** | Live progress visualizer with animated status badges for each scanner. | Polls `/api/v1/audits/{id}/events` with accessible `aria-live` stream. |
| **Security Coverage Strip** | Displays evidenced controls over applicable controls (e.g. `15/32`). | Calculates exact coverage ratio without arbitrary letter grades. |
| **Evidence Drawer (`EvidenceBlock`)** | Inspects exact file paths, line ranges, and sanitized excerpts. | Slide-over drawer with copyable code snippets and scanner provenance. |
| **DPDP Phased Timeline Chips** | Visual chips distinguishing between `IN FORCE` and `UPCOMING` rules. | Evaluated mathematically from `as_of_date` (13 Nov 2025, 13 Nov 2026, 13 May 2027). |
| **Interactive DPDP Questionnaire** | 5-question applicability questionnaire (processing in India, children, SDF). | Updates applicability profile dynamically, re-evaluating controls in real-time. |
| **Statutory Penalty Drawer** | Full Schedule table listing statutory maximum ceilings and caveats. | Strict prohibition on fine predictions and summed totals. |
| **Multi-Engine PDF Export** | Downloadable professional vector PDF report. | Generates via ReportLab with mandatory running header on every single page. |
| **Canonical JSON Export** | Full machine-readable JSON export for DevSecOps CI/CD pipelines. | Defensive secret-scrubbed JSON structure conforming to `docs/api_contracts.md`. |
| **Prompt Injection Resistance** | Isolated finding explanation engine. | Encloses code in `<untrusted_source_code>` XML delimiters; findings are strictly immutable. |

---

## 8. Master Study Guide: Concepts, Defense, and Presentation Q&A

Use this section to prepare for presentations, technical reviews, or architectural defense.

### 8.1 Key Concepts to Master

#### Concept 1: Static AST vs. Dynamic Pentesting
- **What is AST?** An Abstract Syntax Tree is a tree representation of the abstract syntactic structure of source code.
- **Why AST instead of running the code?** Running untrusted user repositories (`npm start`, `python main.py`) allows malicious repositories to execute remote code execution (RCE) attacks or fork bombs. AST inspection parses the text into tokens without executing a single byte of code.

#### Concept 2: The 6 Honesty States (Why "Unknown ≠ Pass")
- Most security tools report a binary `Pass` or `Fail`. If a tool cannot see rate limiting in code, it marks it passed.
- SecureScan AI enforces 6 honest states: `PASS_EVIDENCED`, `FAIL_EVIDENCED`, `POTENTIAL_GAP`, `NOT_VERIFIED`, `NOT_APPLICABLE`, `ERROR`.
- If rate limiting is not in the source code, it might exist upstream in Cloudflare or an API Gateway. SecureScan AI labels this honestly as `POTENTIAL_GAP`, preventing false security reassurance.

#### Concept 3: Parser-Boundary Redaction
- Redaction must occur at the parser boundary. Once Gitleaks or regex catches an AWS key, the raw string is immediately replaced with `[REDACTED:aws-access-key]`. The unredacted string is discarded and never written to SQLite, PostgreSQL, memory logs, or frontend payloads.

#### Concept 4: Dynamic Legal Commencement
- Laws are not static. The DPDP Act commenced in phases:
  - Board machinery active since 13 Nov 2025.
  - Consent Managers (Rule 4) active since 13 Nov 2026.
  - General notice and fiduciary rules upcoming on 13 May 2027.
- SecureScan AI calculates compliance status dynamically relative to `as_of_date`.

---

### 8.2 Common Presentation Questions & Authoritative Answers

**Q1: How is SecureScan AI different from SonarQube or Snyk?**
> *"SonarQube and Snyk are excellent Western SAST tools, but they have zero awareness of Indian legislation like the Digital Personal Data Protection (DPDP) Act, 2023. They cannot identify candidate personal data fields under Indian law, compute dynamic phased commencement from official Gazette notifications, or map statutory penalty ceilings under Section 33. Furthermore, they often produce binary pass/fail grades that give false comfort, whereas SecureScan AI introduces 6 honesty states where unknown is never reported as pass."*

**Q2: If an attacker puts prompt injection payloads in their code comments, does the AI get tricked?**
> *"No. Under Acceptance Test AT-16, untrusted source code is strictly delimited inside `<untrusted_source_code>` XML tags with a rigid system prompt instructing the model to treat all enclosed text as untrusted data. More importantly, the AI is architecturally decoupled from finding metadata: finding severity, confidence, control states, and legal citations are stored in relational database columns and cannot be mutated or overridden by AI output."*

**Q3: Can your tool predict how much fine a company will have to pay under DPDP?**
> *"Absolutely not, and doing so would be legally fraudulent. Under Section 33 of the DPDP Act, actual penalty amounts are determined solely by the Data Protection Board of India on a case-by-case basis considering statutory factors such as the nature of the breach, duration, repetitive nature, and mitigating actions taken. SecureScan AI displays only the maximum statutory ceilings (e.g. 'Up to ₹250 crore') with a mandatory legal caveat on every row, and strictly forbids fine predictions or summing penalties across categories."*

**Q4: How does the sandbox guarantee zero untrusted code execution?**
> *"When importing a repository, we disable Git hooks using `-c core.hooksPath=/dev/null`, disable submodules, and enforce shallow clones (`--depth=1`). The code is mounted into the container as read-only with `--network=none` and all Linux capabilities dropped. We never execute build scripts, test suites, or package install commands."*

**Q5: Why does the report have a running header on every page?**
> *"Per our legal compliance policy, every page of the generated PDF contains the running header: 'Developer-assistance report — not a security certificate or legal opinion.' This ensures that developers and companies cannot misrepresent an automated static diagnostic scan as a formal legal certificate or regulatory audit."*
