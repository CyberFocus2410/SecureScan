# ADR-002 — SecureScan 2.0 Architectural Evolution & Governance

- **Status:** Proposed (Awaiting Step 1 Review & Approval)
- **Date:** 2026-11-20
- **Authors:** Implementation Agent
- **Supersedes / Amends:** Amends specific clauses of `rules.md` (§B.1, §B.2, §B.3, §C.4, §E.2, §F.6) and extends `docs/adr-001-stack-and-versions.md`.

---

## 1. Context & Problem Statement

SecureScan 1.0 successfully delivered an auditor-grade static GitHub repository analysis engine for OWASP Top 10 security controls and India DPDP Act 2023 readiness. However, static-only analysis has structural visibility limits:
1. Cannot verify if identified vulnerabilities are reachable or exploitable in a deployed target.
2. Cannot assess live TLS/SSL configurations, runtime HTTP security headers, cookies, or CORS behavior of running web applications.
3. Cannot perform active API conformance or authorization checks (e.g. BOLA/IDOR between authenticated users).
4. Cannot audit running databases, cloud infrastructure endpoints, or AI/LLM integration points.
5. Emits developer reports that require manual translation into actionable remediation tasks.

**SecureScan 2.0** upgrades the platform into a *full-stack automated application security testing, risk-intelligence, and India DPDP-readiness platform* — while guaranteeing zero regressions for existing static audits, zero breaking changes to existing databases or APIs, and zero unverified/destructive testing against third parties.

---

## 2. Approved Amendments to rules.md

The amendments below represent the **only** approved alterations to `rules.md`. All other clauses (especially parser-level secret redaction, untrusted data handling, honesty states where Unknown ≠ Pass, and statutory penalty ceilings without fine predictions) remain strictly binding.

| Rule | Original Text | Approved Amendment (SecureScan 2.0) |
|---|---|---|
| **B.2 Live Targets** | *"Never run real-world pentests, brute force or fuzzing against live targets."* | Permitted **only** against targets whose **ownership is cryptographically/documentarily verified** (DNS TXT, `/.well-known/`, meta tag, or repository commit token), inside a strictly recorded scope, operating in **safe mode**. Scanning third-party hosts, `.gov.in`/`.nic.in`/`.mil` domains, major cloud/SaaS infrastructure, and private/loopback/metadata IP ranges is **hard-blocked** by software guards. |
| **B.3 Network Egress** | *"Scanners run only in the approved sandbox... no network..."* | Static scanners retain strict `--network=none`. Active DAST, API, and TLS engines run in an isolated **`dast-worker`** with egress allowed **only** to the verified target's resolved IP address (DNS pinned on each request; redirects to off-scope hosts are refused). |
| **README & UI Footers** | *"Not a security certification... penetration test..."* | Replaced with: *"Automated security assessment with consent-gated, non-destructive active validation. Not a substitute for a manual penetration test or a legal compliance certificate."* |
| **C.4 Scoring & Grading** | *"No blanket '100% secure', 'Pass/Fail', or 0–100 grade as primary output."* | Headline output remains **priority counts (P0–P3) + coverage ratio + honesty status**. Secondary, clearly labeled scores (Security, Privacy, Infrastructure, Supply Chain, DPDP Readiness 0–100) are permitted **with the full calculation methodology printed in the report** and a hard ceiling cap (a single confirmed Critical P0 caps the maximum score). |
| **E.2 DPDP Verdicts** | *"Never output 'DPDP compliant / non-compliant'."* | Maintained. Platforms emit readiness labels + a disclosed-methodology readiness score (0–100). Never "certified", "compliant", or "non-compliant". |
| **F.6 Patch Generation** | *"Patch generation is out of MVP."* | AI-suggested code diffs and patches are permitted as **advisory suggestions only**, explicitly labeled *"suggestion, not validated"*, and never auto-applied. Optional "Generate Fix PR" requires explicit user token and user confirmation, and strictly never touches the default branch. |
| **B.1 Code Execution** | *"Never execute cloned-repo install/build/test scripts, hooks, or workflows."* | Remains strictly enforced for standard workers. Optional **Lab mode** (Step 14, default OFF) permits building and running the user's *own* repository inside a disposable, network-isolated, resource-capped container exclusively to allow local DAST evaluation. |

---

## 3. Sandbox Backend Architecture Decision

### 3.1 The Problem
In SecureScan 1.0, `runner.py` executed `docker run` directly via subprocess. This approach fails on cloud PaaS hosting (Render, Railway, Vercel) where Docker-in-Docker or `/var/run/docker.sock` is unavailable. Furthermore, mounting the host Docker socket creates significant privilege-escalation risks.

### 3.2 Decision: Three-Tier Sandbox Abstraction
We define a unified sandbox interface (`backend/app/sandbox/base.py`) with three pluggable backends:

```
                  ┌──────────────────────────────┐
                  │   SandboxEngine Interface    │
                  │   execute(cmd, limits, ...)  │
                  └──────────────┬───────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  DockerSandbox   │   │ BubblewrapEngine │   │ SubprocessDev    │
│  (Rootless,      │   │ (Linux user-ns,  │   │ (Dev/Test only;  │
│   cgroups v2,    │   │  bwrap / nsjail, │   │  hard-blocked in │
│   --network=none)│   │  rlimits, ro-mnt)│   │  production)     │
└──────────────────┘   └──────────────────┘   └──────────────────┘
```

1. **`DockerSandbox`**: Used in containerized environments supporting Docker/Podman. Enforces `--network=none` (for static tools) or pinned network egress (for DAST), non-root (`1000:1000`), `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, read-only repo mounts, tmpfs `/tmp`, and strict CPU, RAM, and PID caps.
2. **`BubblewrapEngine` (`bwrap` / `nsjail`)**: For Linux host deployments without Docker (Render, VPS). Uses unprivileged Linux user namespaces to construct an ephemeral filesystem sandbox with read-only root/worktree, empty `/tmp` tmpfs, and `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NPROC` constraints.
3. **`SubprocessDev`**: Local development and CI unit testing fallback. **Hard-blocked in production:** if `ENVIRONMENT=production`, attempting to invoke `SubprocessDev` immediately raises `SandboxUnavailableError` with status code `500` / `SANDBOX_UNAVAILABLE`.

### 3.3 Production Fail-Closed Behavior
In production, if neither `docker` nor `bubblewrap` is functional, audits will fail safely with `ERROR_SANDBOX_UNAVAILABLE`. Under no circumstances will a production scan run unsandboxed.

---

## 4. Unified Finding Schema Extension Plan

The finding model in SecureScan 1.0 (`FindingModel` and `schemas/finding.py`) is preserved. The 2.0 unified model extends the schema **additively** (all new fields nullable with safe defaults) so all historical audits and tests remain 100% functional.

### 4.1 Schema Additions (Pydantic & SQLAlchemy)

```python
# Extended fields for Unified Finding Engine
engine: str = Field(default="sast")  # sast, dast, api, authz, secrets, sca, iac, container, ci, db, ai, privacy, dpdp
tool: str | None = None
tool_version: str | None = None
verified_state: str = Field(default="NEEDS_REVIEW")  # CONFIRMED, LIKELY, NEEDS_REVIEW, NOT_VERIFIED
confidence_score: float = Field(default=0.8)
exploitability: str = Field(default="unknown")  # known_exploited, easy, needs_conditions, theoretical, unknown
exposure: str = Field(default="unknown")  # public, authenticated, internal, unknown
data_sensitivity: str = Field(default="none")  # none, personal, sensitive, credentials
source_location: str | None = None  # for taint analysis source
data_flow: list[str] = Field(default_factory=list)  # taint path steps
sink_location: str | None = None  # for taint analysis sink
request_evidence: str | None = None  # redacted HTTP request
response_evidence: str | None = None  # redacted HTTP response
standards: dict = Field(default_factory=dict)  # {cwe, owasp_top10, owasp_asvs, owasp_api_top10, owasp_llm_top10, nist_csf, dpdp_controls}
priority: str = Field(default="P2")  # P0, P1, P2, P3
plain_title: str | None = None
plain_summary: str | None = None
why_it_matters: str | None = None
how_to_fix: list[str] = Field(default_factory=list)
how_to_verify_fix: str | None = None
fix_effort: str | None = None  # "15 minutes", "2 hours"
fix_prompt: str | None = None  # Agent-ready instruction text
related_finding_ids: list[str] = Field(default_factory=list)
attack_chain_id: str | None = None
first_seen_scan_id: str | None = None
status: str = Field(default="open")  # open, fixed, accepted_risk, false_positive
```

### 4.2 Deduplication and Correlation Rules
1. **Intra-Engine Deduplication:** Same rule + same target coordinate (file:line or endpoint) = merged finding.
2. **Cross-Engine Correlation:** Static finding (e.g. SQLi in `api/users.py:42`) + DAST finding (e.g. SQLi observed on `POST /api/users`) = linked finding upgraded to `verified_state = CONFIRMED`, signals list incremented (`"Confirmed by 2 independent checks"`).

---

## 5. Additive Database Migration Plan

All database schema evolutions for SecureScan 2.0 follow an **additive-only** strategy. No columns are deleted, renamed, or converted to NOT NULL without default values.

### 5.1 New Tables
1. **`targets`**: Root asset table representing a GitHub repo or verified live web URL.
2. **`target_verifications`**: Cryptographic ownership verification tokens, verification method (DNS_TXT, WELL_KNOWN, HTML_META, REPO_TOKEN), verified timestamp, and 30-day expiry.
3. **`scan_scopes`**: Per-target authorization boundary (allowed domains, path inclusion/exclusion regex, max requests/second, max crawl depth).
4. **`consent_records`**: Immutable audit log of user consent checkbox, IP address, user agent, scope hash, and timestamp.
5. **`test_accounts`**: Encrypted credentials (AES-GCM/Fernet) for authenticated multi-role testing; memory-only decryption during scan execution.
6. **`assets` & `endpoints`**: Discovered attack surface inventory (API routes, HTTP methods, authentication requirements, parameter schemas).
7. **`sbom_components`**: Software Bill of Materials inventory items (Package, Version, Ecosystem, License, Vulnerability count).
8. **`tool_runs`**: Execution log of every scanner tool run (Tool, Version, Exit status, Duration ms, Coverage metrics).
9. **`scan_comparisons`**: Scan-to-scan differential records (New findings, Resolved findings, Regressions).

### 5.2 Additive Alterations to Existing Tables
- **`findings`**: Add columns matching §4.1 (`engine`, `tool`, `verified_state`, `priority`, `plain_title`, etc.). All nullable.
- **`audits`**: Add nullable columns `target_id`, `scan_intensity` (`PASSIVE`, `STANDARD`, `DEEP`), `risk_score_json`.

---

## 6. Feature-Flag Architecture & Controls

To guarantee that in-development features never impact production stability, all SecureScan 2.0 capabilities are gated behind environment feature flags, defaulting to **OFF (`false`)**:

| Feature Flag | Default | Description | Gate Requirement |
|---|---|---|---|
| `FEATURE_DAST_ENABLED` | `false` | Enables live web testing worker and DAST pipelines | Step 7 Approved & verified |
| `FEATURE_OWNERSHIP_ENFORCEMENT` | `true` | Enforces ownership check before any active network request | Step 3 Approved & verified |
| `FEATURE_AUTHZ_TESTING` | `false` | Enables multi-account authenticated BOLA/IDOR testing | Step 9 Approved & verified |
| `FEATURE_AI_SECURITY_ANALYST` | `false` | Enables Gemini/Claude advisory patch suggestions | Step 12 Approved & verified |
| `FEATURE_LAB_MODE` | `false` | Allows building and executing user-owned repos in sandbox | Step 14 Approved & verified |
| `FEATURE_CONTINUOUS_SCANNING` | `false` | Enables scheduled periodic re-scans and webhooks | Step 15 Approved & verified |

---

## 7. Comprehensive Risk Register

| Risk ID | Category | Risk Description | Severity | Automated Mitigation Strategy |
|---|---|---|---|---|
| **RSK-01** | **Legal** | Unauthorized active security testing viewed as cyberattack or violating IT Act / CFAA. | Critical | **Mandatory ownership verification** (DNS/File/Token) before any outbound packet; immutable consent capture; strict rate limit (default 5 req/s); non-destructive payloads only. |
| **RSK-02** | **Legal** | Statutory misrepresentation of DPDP compliance or speculative fine figures. | High | Strict adherence to rules §E: statutory ceilings with mandatory caveat; dynamic commencement from `as_of_date`; zero binary compliance claims; zero fine sums. |
| **RSK-03** | **Security / SSRF** | Attacker uses SecureScan DAST to probe internal cloud metadata (`169.254.169.254`) or private networks (`10.0.0.0/8`, `192.168.0.0/16`). | Critical | `safe_fetch.py` IP resolution guard pins resolved public IP, blocks all private, link-local, loopback, and cloud metadata ranges, and terminates any redirect to off-scope hosts. |
| **RSK-04** | **Abuse / DoS** | Malicious user enters a third-party target (e.g. government `.gov.in` or rival website) to cause denial of service. | Critical | Hardcoded blocklist for `.gov.in`, `.nic.in`, `.mil`, cloud control planes, and SaaS endpoints. Strict rate-limiting and global emergency kill switch (`DAST_ENABLED=false`). |
| **RSK-05** | **Cost / Resource** | Long-running active scans or recursive crawls exhaust worker CPU, memory, and disk. | Medium | Hard budget caps: max 20 minutes duration, max crawl depth 3, max 500 requests per scan, process timeouts on all child execution. |
| **RSK-06** | **Integrity** | False positives causing panic or reputational damage to audited software. | Medium | 4-tier confidence scoring (`CONFIRMED`, `LIKELY`, `NEEDS_REVIEW`, `NOT_VERIFIED`); static code matches must have runtime validation to become `CONFIRMED`. |

---

## 8. Definition of Done for Step 1
- [x] All 85 baseline tests verified passing in clean environment.
- [x] ADR-002 authored and placed in `docs/adr-002-securescan-2.md`.
- [x] Gap analysis of current repo completed.
- [x] 15-step task breakdown authored in `docs/task_breakdown_2_0.md`.
- [x] `decision.md` and `memory.md` updated.
- [x] **Zero feature code written.**
