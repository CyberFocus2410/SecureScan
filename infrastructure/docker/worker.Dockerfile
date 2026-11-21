# SecureScan Worker Dockerfile (Alias to static-worker.Dockerfile)
FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    SANDBOX_BACKEND=bubblewrap \
    ENVIRONMENT=production

WORKDIR /app

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

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && \
    pip install -r /app/requirements.txt && \
    pip install semgrep==1.102.0 bandit==1.8.0 pip-audit==2.7.3 checkov==3.2.355

COPY backend/ /app/
COPY policies/ /policies/
COPY tools.lock /app/tools.lock

RUN groupadd -g 1000 securescan && \
    useradd -u 1000 -g securescan -s /bin/bash -m securescan && \
    mkdir -p /tmp/worktrees /tmp/reports && \
    chown -R securescan:securescan /app /policies /tmp/worktrees /tmp/reports

USER securescan

CMD ["python", "-m", "app.workers.audit_worker"]
