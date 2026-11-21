# Security Report: SecureScan AI Hardening & Audit Verification

This audit and hardening report documents the security posture of the **SecureScan AI** platform against the 20 vulnerability classes defined in the *Web App Security Audit and Hardening Playbook* (`SECURITY_AUDIT.md`).

---

## Summary

- **Stack Detected:**
  - **Backend:** Python 3.11+, FastAPI 0.115+, SQLAlchemy 2.0 (Relational ORM), SQLite / PostgreSQL, Pydantic v2 (Pydantic Settings & ConfigDict), Uvicorn.
  - **Frontend:** React 18, TypeScript, Tailwind CSS, Vite.
  - **Static Analysis Engines:** Semgrep, Bandit, Gitleaks, OSV-Scanner, AST Custom Heuristic Scanner.
  - **Authentication / Authorization:** Ephemeral capability-based session management (`X-Session-ID: <UUIDv4>`), no persistent passwords or cookies.
  - **Storage:** Local disk sandboxes in `tmp/worktrees` and `tmp/reports` with strict lifecycle bounding caps (50 MB, 2,000 files, 24h TTL).
- **Findings by Severity:**
  - **Critical:** 1 (SSRF outbound fetch risk)
  - **High:** 4 (Overly permissive CORS, Security headers/CSP, Path traversal on report download, IDOR cross-session scoping)
  - **Medium:** 3 (Missing rate limiting middleware, Missing schema extra-field rejection / Mass assignment, Unhandled exception traceback leakage)
  - **Low:** 3 (Open redirect defense helper, Webhook HMAC signature verification helper, Session UUID validation)
  - **Total Findings Remediated:** 11

---

## Findings & Remediations

| # | Class | Severity | File:Line | Issue | Fix Applied | Verified (test / manual) |
|---|---|---|---|---|---|---|
| **1** | Cross-Site Scripting (XSS) & CSP | High | `backend/app/main.py:28` | Missing Content-Security-Policy and HTTP security headers. | Added `SecurityHeadersMiddleware` with strict CSP (`default-src 'self'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`. React JSX auto-escaping verified across frontend; zero `dangerouslySetInnerHTML`. | `tests/security/test_security_audit_playbook.py::test_security_headers_are_present` |
| **2** | Path Traversal | High | `backend/app/services/reports.py:95` | Report download artifact retrieved `safe_storage_key` without canonical root containment validation against `REPORTS_STORAGE_DIR`. | Added path canonicalization check `Path.resolve().relative_to(base_dir)` and file existence validation; returns 403/404 if path escapes base directory. | `tests/security/test_security_audit_playbook.py::test_path_traversal_in_report_download_is_blocked` |
| **3** | Server-Side Request Forgery (SSRF) | Critical | `backend/app/services/github_import.py:49` | Ingestion fetch lacked centralized IP address and DNS resolution validation, posing potential SSRF risk to cloud metadata or loopback services. | Created `backend/app/core/safe_fetch.py` implementing `is_safe_url()` and `is_private_ip()` blocking RFC1918, loopback (`127.0.0.1`, `::1`), link-local, multicast, and AWS/GCP cloud metadata (`169.254.169.254`). Integrated into `parse_and_validate_github_url`. | `tests/security/test_security_audit_playbook.py::test_ssrf_blocking_cloud_metadata_and_private_ips` |
| **4** | Missing Input Validation | Medium | `backend/app/schemas/audit.py:8`, `audit.py:26`, `report.py:8`, `ai.py:7` | Input schemas defaulted to ignoring extra fields rather than rejecting untyped parameters. | Configured `model_config = ConfigDict(extra="forbid")` across all input request DTOs (`RepositoryCreate`, `AuditCreate`, `ReportCreateRequest`, `AIExplainRequest`). | `tests/security/test_security_audit_playbook.py::test_input_validation_malformed_urls_rejected` |
| **5** | Overly Permissive CORS | High | `backend/app/main.py:29` | CORS middleware configured with `allow_origins=["*"]` combined with `allow_credentials=True`. | Refactored CORS in `main.py` to use explicit origin allow-list `settings.CORS_ORIGINS` from environment config, restricted HTTP methods to standard verbs, and whitelisted specific headers. | Verified via middleware integration and client CORS preflight |
| **6** | IDOR / BOLA | High | `backend/app/api/v1/audits.py:102`, `findings.py:157`, `reports.py:96` | Audit, findings, event stream, and report artifact queries required strict capability-based authorization verification across sessions. | Validated that every audit, finding, event, and report query is strictly scoped to `session_id == audit.session_id`, rejecting cross-session access with 403/404. | `tests/security/test_security_audit_playbook.py::test_idor_cross_session_audit_access_is_blocked` and `test_idor_cross_session_report_download_is_blocked` |
| **7** | Mass Assignment | Medium | `backend/app/schemas/audit.py:26` | Potential injection of unvalidated fields (`role`, `isAdmin`, `status`) in audit and repository creation. | Enforced `extra="forbid"` on all Pydantic DTOs, rejecting any payload containing undeclared fields with HTTP 422. | `tests/security/test_security_audit_playbook.py::test_mass_assignment_extra_fields_rejected_on_audit_create` and `test_mass_assignment_extra_fields_rejected_on_repo_create` |
| **8** | Missing Rate Limits | Medium | `backend/app/main.py:25` & `audit_worker.py:65` | Application lacked global IP-based rate limiting middleware, and hourly quota (10 audits/hour) was un-enforced. | Implemented `RateLimitMiddleware` sliding window limiter returning HTTP 429 with `Retry-After` header. Enforced hourly session quota in `check_session_quotas_and_dedupe`. | `tests/security/test_security_audit_playbook.py::test_rate_limiting_enforcement_returns_429` |
| **9** | Open Redirects | Low | `backend/app/core/security.py:75` | Need shared defense helper to guarantee safe redirects and scan target codebases for open redirect vulnerabilities. | Implemented `is_safe_redirect_url()` rejecting protocol-relative (`//`), backslash (`/\`), non-HTTP, and unverified hosts. Added `sec-014-open-redirect-risk` scanner rule in `CustomRulesScanner`. | `tests/security/test_security_audit_playbook.py::test_open_redirect_defense` |
| **10** | Unverified Webhook Signatures | Low | `backend/app/core/security.py:115` | Need shared cryptographic verification helper for incoming webhooks with constant-time equality and replay protection. | Implemented `verify_webhook_signature()` using `hmac.compare_digest`, timestamp expiration checks (drift > 300s), and raw bytes HMAC-SHA256. Added `sec-007-unverified-webhook` scanner rule in `CustomRulesScanner`. | `tests/security/test_security_audit_playbook.py::test_webhook_signature_verification_success_and_rejection` |
| **11** | Cross-cutting Hardening | Medium | `backend/app/core/errors.py:155` & `.env.example` | Unhandled server exceptions could leak raw tracebacks and internal file paths; `.env.example` was missing. | Added `unhandled_exception_handler` masking internal tracebacks and returning generic 500 JSON. Created `.env.example` with complete configuration options and placeholder values. Verified zero secrets in code. | `tests/security/test_security_audit_playbook.py::test_generic_500_error_masks_internal_stack_trace` |

---

## Not Applicable

| Vulnerability Class | Reason for Non-Applicability |
|---|---|
| **2. Cross-Site Request Forgery (CSRF)** | SecureScan is a stateless JSON REST API that uses custom capability headers (`X-Session-ID`) rather than ambient browser cookies. Per Playbook §2: *"Bearer-token APIs that don't use cookies are mostly exempt; note that in the report."* |
| **3. SQL Injection** | All database interactions use SQLAlchemy ORM (`db.query(...).filter(...)`) with parameterized query compilation. No raw string interpolation (`text()`, `execute()`) is used anywhere in the codebase. |
| **4. NoSQL Injection** | Relational SQL database (SQLite / PostgreSQL) only; MongoDB or Document NoSQL stores are not used in the architecture. |
| **5. Insecure File Uploads** | No public multipart file upload endpoints exist. Code repositories are fetched directly from GitHub into ephemeral worktrees with strict size bounds (50 MB, 2,000 files). |
| **12. Weak Password Reset Flows** | No user account system or password reset mechanism exists in the application. |
| **13. Account Enumeration** | No user registration or login authentication exists. |
| **14. Weak Session Management (Cookies)** | The application does not issue browser cookies; session capability is tracked via ephemeral UUIDv4 tokens. |
| **15. Vulnerable JWT Implementation** | JWT tokens are not utilized in the current capability token design. |
| **17. Frontend-Only Payment Checks** | The application does not process payments or bill users. Additionally, rule `sec-004-client-supplied-pricing` audits target repositories for this flaw. |

---

## Needs Human Decision

- **Reverse Proxy vs. In-Memory Rate Limiter in Production:**
  The included `RateLimitMiddleware` operates as an in-memory sliding window limiter, ideal for single-instance or local deployment. For high-scale multi-instance production deployments (e.g. multi-node Kubernetes or Cloud Run), we recommend offloading rate limiting to an upstream reverse proxy (Cloudflare, NGINX) or backed by Redis.

---

## Residual Risks and Recommended Next Steps

1. **Production Reverse Proxy / TLS Termination:**
   In production, deploy behind NGINX, Cloudflare, or AWS ALB to enforce HTTPS, terminate TLS 1.3, and provide DDoS buffering.
2. **PostgreSQL Migration:**
   For multi-tenant or concurrent production workloads, switch `DATABASE_URL` from SQLite to PostgreSQL using the provided `.env.example` template.
3. **Continuous OSV & Semgrep Rule Updates:**
   Schedule automated weekly updates of the vulnerability databases (`osv-scanner` data feeds and Semgrep rule registries) in CI/CD.

---

## New Environment Variables & Setup Required

The following environment variables have been added to `.env.example`:

```bash
# Security & CORS
CORS_ORIGINS=["http://localhost:3000","http://127.0.0.1:3000","http://localhost:5173","http://127.0.0.1:5173"]
SECURITY_HEADERS_ENABLED=true

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=120

# Webhook Cryptographic Verification
WEBHOOK_SECRET="<configured-via-environment-variable>"
```

No breaking migration or database modifications were required.
