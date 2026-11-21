# SecureScan 2.0 Static Worker Container
# Pinned scanner binaries, user-namespace bubblewrap sandbox, real RQ worker execution.
# Zero Docker-in-Docker, zero /var/run/docker.sock reliance (ADR-002, Step 2).

FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    SANDBOX_BACKEND=bubblewrap \
    ENVIRONMENT=production

WORKDIR /app

# 1. Base OS Packages & Bubblewrap
RUN apt-get update && apt-get install -y --no-install-recommends \
    bubblewrap \
    curl \
    git \
    tar \
    gzip \
    ca-certificates \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# 2. Pinned CLI Binaries from tools.lock

# Gitleaks 8.21.2
RUN curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# TruffleHog 3.88.3
RUN curl -sSL https://github.com/trufflesecurity/trufflehog/releases/download/v3.88.3/trufflehog_3.88.3_linux_amd64.tar.gz | tar -xz -C /usr/local/bin trufflehog \
    && chmod +x /usr/local/bin/trufflehog

# OSV-Scanner 1.9.2
RUN curl -sSL -o /usr/local/bin/osv-scanner https://github.com/google/osv-scanner/releases/download/v1.9.2/osv-scanner_linux_amd64 \
    && chmod +x /usr/local/bin/osv-scanner

# Trivy 0.58.0
RUN curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.58.0/trivy_0.58.0_Linux-64bit.tar.gz | tar -xz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy

# Syft 1.19.0
RUN curl -sSL https://github.com/anchore/syft/releases/download/v1.19.0/syft_1.19.0_linux_amd64.tar.gz | tar -xz -C /usr/local/bin syft \
    && chmod +x /usr/local/bin/syft

# Hadolint 2.12.0
RUN curl -sSL -o /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 \
    && chmod +x /usr/local/bin/hadolint

# Actionlint 1.7.4
RUN curl -sSL https://github.com/rhysd/actionlint/releases/download/v1.7.4/actionlint_1.7.4_linux_amd64.tar.gz | tar -xz -C /usr/local/bin actionlint \
    && chmod +x /usr/local/bin/actionlint

# Retire.js 5.2.4 & ESLint Security Plugin 3.0.1
RUN npm install -g retire@5.2.4 eslint@9.15.0 eslint-plugin-security@3.0.1

# 3. Pinned Python Scanners and App Requirements
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && \
    pip install -r /app/requirements.txt && \
    pip install semgrep==1.102.0 bandit==1.8.0 pip-audit==2.7.3 checkov==3.2.355

# 4. Copy Application Source and Policies
COPY backend/ /app/
COPY policies/ /policies/
COPY tools.lock /app/tools.lock

# 5. Non-root unprivileged execution user
RUN groupadd -g 1000 securescan && \
    useradd -u 1000 -g securescan -s /bin/bash -m securescan && \
    mkdir -p /tmp/worktrees /tmp/reports && \
    chown -R securescan:securescan /app /policies /tmp/worktrees /tmp/reports

USER securescan

# 6. Real RQ Worker Entrypoint
CMD ["python", "-m", "app.workers.audit_worker"]
