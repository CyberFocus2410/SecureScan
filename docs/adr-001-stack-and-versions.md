# ADR-001: Technology Stack and Pinned Dependency Versions

- **Status:** Proposed (Ready for Approval)
- **Date:** 2026-11-14
- **Context:** SecureScan AI is a safety-critical application security and DPDP compliance auditing platform built within a ~36-hour hackathon timeframe. The architecture requires a FastAPI control plane, PostgreSQL database, Redis/RQ queue, containerized zero-network scanner workers, React + TypeScript frontend, and deterministic PDF/JSON report generation. Per rules.md §G, all tools, libraries, and rule-packs must be pinned to exact stable versions and stored with every audit.

---

## 1. Stack Components & Pinned Versions

| Component | Target Version | Release / Image Tag | Source Link | Rationale & Compatibility Notes |
|---|---|---|---|---|
| **Python** | `3.12.8` | `python:3.12-slim-bookworm` | [Python 3.12](https://www.python.org/downloads/release/python-3128/) | Stable baseline for FastAPI, Pydantic v2, and typing features. Supported on Linux and Windows. |
| **FastAPI** | `0.115.6` | `fastapi==0.115.6` | [FastAPI PyPI](https://pypi.org/project/fastapi/) | Production-ready ASGI framework with native Pydantic v2 support and OpenAPI documentation. |
| **Pydantic** | `2.10.4` | `pydantic==2.10.4` | [Pydantic PyPI](https://pypi.org/project/pydantic/) | High-performance data validation and contract enforcement. Paired with `pydantic-settings==2.7.0`. |
| **SQLAlchemy** | `2.0.36` | `sqlalchemy==2.0.36` | [SQLAlchemy PyPI](https://pypi.org/project/SQLAlchemy/) | Core ORM with explicit 2.0-style queries, JSONB column support, and typing stubs (`psycopg2-binary==2.9.10`). |
| **Alembic** | `1.14.0` | `alembic==1.14.0` | [Alembic PyPI](https://pypi.org/project/alembic/) | Schema migration tool for PostgreSQL. Clean initial migrations and immutable catalogue schema tracking. |
| **PostgreSQL** | `16.6` | `postgres:16.6-alpine` | [Docker Hub Postgres](https://hub.docker.com/_/postgres) | Battle-tested relational database with native JSONB indexing for scanner evidence and questionnaire data. |
| **Redis** | `7.4.1` | `redis:7.4.1-alpine` | [Docker Hub Redis](https://hub.docker.com/_/redis) | In-memory broker for RQ task queues, job status, and rate-limiting counters. |
| **RQ (Redis Queue)** | `2.1.0` | `rq==2.1.0` | [RQ PyPI](https://pypi.org/project/rq/) | Lightweight Python job queue. Paired with `redis==5.2.1`. Minimal operational overhead compared to Celery. |
| **Node.js** | `20.18.1 LTS` | `node:20.18.1-alpine` | [Node.js Releases](https://nodejs.org/en/about/previous-releases) | Active LTS node environment for reproducible frontend Vite builds. (Host node v24 compatible). |
| **React** | `18.3.1` | `react@18.3.1`, `react-dom@18.3.1` | [React npm](https://www.npmjs.com/package/react) | Rock-solid UI library with broad ecosystem stability across TanStack Query and Lucide icons. |
| **Vite** | `6.0.7` | `vite@6.0.7` | [Vite npm](https://www.npmjs.com/package/vite) | Next-generation frontend tooling providing rapid HMR and optimized production bundles. |
| **Tailwind CSS** | `3.4.17` | `tailwindcss@3.4.17` | [Tailwind npm](https://www.npmjs.com/package/tailwindcss) | Utility-first CSS framework with official plugins `@tailwindcss/typography` and `@tailwindcss/forms`. |
| **TanStack Query** | `5.62.11` | `@tanstack/react-query@5.62.11` | [TanStack npm](https://www.npmjs.com/package/@tanstack/react-query) | Server-state management for async polling of audit events, scanner cards, and findings. |
| **Semgrep** | `1.102.0` | `semgrep/semgrep:1.102.0` | [Semgrep GitHub](https://github.com/semgrep/semgrep/releases/tag/v1.102.0) | Multi-language SAST engine (Python/JS/TS). Rules baked into offline image. |
| **Gitleaks** | `8.21.2` | `zricethezav/gitleaks:v8.21.2` | [Gitleaks GitHub](https://github.com/gitleaks/gitleaks/releases/tag/v8.21.2) | Secret detection scanner. Fast, zero-dependency, works directly on worktrees. |
| **OSV-Scanner** | `1.9.2` | `ghcr.io/google/osv-scanner:v1.9.2` | [OSV-Scanner GitHub](https://github.com/google/osv-scanner/releases/tag/v1.9.2) | Google's dependency vulnerability scanner. Offline lockfile parser + separate trusted advisory query. |
| **Bandit** | `1.8.0` | `bandit==1.8.0` | [Bandit PyPI](https://pypi.org/project/bandit/) | Dedicated Python AST security scanner (conditional in P0/P1 scope-cut order). |
| **HTML-to-PDF** | WeasyPrint `63.1` | `weasyprint==63.1` | [WeasyPrint PyPI](https://pypi.org/project/weasyprint/) | Pure Python/Pango/Cairo HTML+CSS to PDF engine supporting `@page` headers, page numbers, and vector output. |

---

## 2. Selection Rationale for HTML-to-PDF Tool

### Options Evaluated:
1. **WeasyPrint 63.1 (Selected):**
   - *Pros:* Native Python package, zero browser binaries required, strict CSS Paged Media (`@page`, `@top-left`, `@bottom-right`, `counter(pages)`), excellent typographic formatting, deterministically embeds metadata, no headless Chromium security attack surface.
   - *Cons:* Requires system C-libraries (`libpango`, `libcairo`, `libgdk-pixbuf`) which are easily baked into the standard Docker image (`python:3.12-slim-bookworm` via `apt-get install -y libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libffi-dev`).
2. **Puppeteer / Playwright (Chromium Headless):**
   - *Pros:* Identical rendering to Chrome.
   - *Cons:* Requires 400MB+ Chromium binary, heavy memory footprint (~150MB per render), complex sandbox flags in Docker, slower startup, overkill for standardized audit reports.
3. **wkhtmltopdf:**
   - *Pros:* Familiar CLI.
   - *Cons:* Deprecated upstream, unpatched WebKit vulnerabilities, poor modern CSS support.

**Decision:** WeasyPrint 63.1 is selected. It produces clean, paginated, auditor-grade PDF reports directly from Jinja2 HTML templates inside the backend container without running a browser.

---

## 3. Scanner Sandbox Execution Model

Per Architecture §5 and NFR-03:
- Scanners run with `--network=none`, `--cap-drop=ALL`, `--user=1000:1000` (non-root), `--read-only` repository volume mount, and temporary writable `tmpfs` for scratch output.
- In Docker Compose, the worker mounts the Docker socket (`/var/run/docker.sock`) strictly as a controller or executes scanner binaries directly using isolated container invocations (`docker run --rm --network=none ...`).
- When running in local development mode without Docker-in-Docker, a fallback to CLI subprocess invocation with sandbox security flags and strict timeouts is supported for automated test suites.

---

## 4. Compatibility and Version Pinning Rules

1. Every audit record persisted in the database stores:
   - Git commit SHA of the audited target repository.
   - SecureScan application version.
   - Scanner image/binary versions (`semgrep`, `gitleaks`, `osv-scanner`, `bandit`).
   - Pinned policy rule-pack hash (`policies/*.yaml`).
2. Dependency lockfiles:
   - Backend: `requirements.txt` with strict hashes and pinned version pins (`==`).
   - Frontend: `package-lock.json` checked into Git.
3. No runtime network downloads: all scanner rule definitions and container dependencies are baked into container images during build.

