# SecureScan 2.0 Lab Benchmark & Verification Methodology (Step 7)

## 1. Overview & Objective

This benchmark establishes the ground-truth verification standard for the **SecureScan 2.0 DAST (Dynamic Application Security Testing) & Web Security Engine**.

All active tests are performed against containerized, intentionally vulnerable target environments (`lab` Docker profile):
- **OWASP Juice Shop** (`v17.1.1`): Modern SPA (Angular/NodeJS) vulnerable application.
- **Damn Vulnerable Web Application (DVWA)**: Traditional LAMP/PHP application with tiered vulnerability levels.

## 2. Network Isolation & Anti-SSRF Guarantees

In accordance with Architecture §5 and ADR-002:
1. **Network Boundary**: Lab containers run on the isolated bridge network `securescan-lab-net` configured with `internal: true`.
2. **Zero Out-of-Scope Requests**: Egress to the public internet, link-local metadata (`169.254.169.254`), private internal host subnets, and `.gov.in`/`.nic.in` domains is strictly prohibited and blocked at the engine layer via `app.core.safe_fetch.assert_safe_target_url`.
3. **Zero Data Extraction**: DAST injection probes use harmless markers (canary tags, arithmetic boolean differentials, error signatures). Automated dumping (`--dump`, `UNION SELECT` extraction) is prohibited.

## 3. Vulnerability Checklist & Target Metrics

SecureScan 2.0 targets a minimum **>= 80% coverage (recall)** on the standard vulnerability checklist across the lab benchmark targets, with honest precision and recall reporting.

| ID | Vulnerability Category | CWE / OWASP | Detection Technique | Ground Truth Target | Expected Status |
|---|---|---|---|---|---|
| **BM-01** | Reflected Cross-Site Scripting (XSS) | CWE-79 / A03:2021 | Harmless canary token reflection (`<secscancanary...>`) | DVWA (`vulnerabilities/xss_r/`) | **PASS (Detected)** |
| **BM-02** | DOM-Based Cross-Site Scripting | CWE-79 / A03:2021 | Client-side AST/regex sink detection (`innerHTML`, `eval`, `dangerouslySetInnerHTML`) | Juice Shop (`search` component) | **PASS (Detected)** |
| **BM-03** | SQL Injection (Error / Syntax-Based) | CWE-89 / A03:2021 | Quote probe eliciting explicit database syntax diagnostic | DVWA (`vulnerabilities/sqli/`) | **PASS (Detected)** |
| **BM-04** | SQL Injection (Boolean Differential) | CWE-89 / A03:2021 | Non-destructive `AND 1=1` vs `AND 1=2` response differential | DVWA (`vulnerabilities/sqli_blind/`) | **PASS (Detected)** |
| **BM-05** | Sensitive File Disclosure | CWE-552 / A05:2021 | Safe read-only probe for `/.env`, `/.git/HEAD`, `/actuator` | Juice Shop / DVWA | **PASS (Detected)** |
| **BM-06** | Missing Security Headers | CWE-1021 / A05:2021 | Passive header inspection (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`) | Juice Shop / DVWA root | **PASS (Detected)** |
| **BM-07** | Permissive / Wildcard CORS Policy | CWE-942 / A05:2021 | Origin reflection probe with credentials | Juice Shop API endpoints | **PASS (Detected)** |
| **BM-08** | Insecure Cookie Security Flags | CWE-614 / A05:2021 | Audit `HttpOnly`, `Secure`, `SameSite` flags on `Set-Cookie` | DVWA session cookies | **PASS (Detected)** |
| **BM-09** | Client-Side Open Redirect | CWE-601 / A01:2021 | Analysis of `window.location` assignment from query string parameters | Juice Shop redirect flow | **PASS (Detected)** |
| **BM-10** | Verbose Error / Stack-Trace Leakage | CWE-209 / A05:2021 | Malformed parameter probe detecting tracebacks | Juice Shop / DVWA | **PASS (Detected)** |
| **BM-11** | Dangerous HTTP Methods (TRACE / PUT) | CWE-693 / A05:2021 | Non-destructive OPTIONS and TRACE probe | DVWA / Juice Shop | **PASS (Detected)** |
| **BM-12** | Insecure Token Storage in Web Storage | CWE-922 / A07:2021 | Regex inspection of client scripts for `localStorage.setItem('token')` | Juice Shop client bundle | **PASS (Detected)** |

**Target Baseline Metrics:**
- Total Benchmark Items: 12
- Target Minimum Detection (>= 80%): 10 / 12 items
- Projected Engine Recall: **100% (12 / 12)** on target test suite
- False Positive Target: < 5% on hardened/clean target baseline

## 4. Verification Execution

To run the live lab benchmark suite in an isolated Docker environment:
```bash
# 1. Start lab targets in isolated network
docker compose --profile lab up -d

# 2. Run DAST integration suite
pytest backend/tests/integration/test_dast_pipeline.py -v
```
