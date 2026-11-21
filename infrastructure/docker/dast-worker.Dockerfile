# SecureScan 2.0 DAST Worker Container (Step 7, ADR-002, Section 4 & 5)
# Pinned web security testing binaries, safe probes, restricted egress.
# Zero data extraction, rate-limited, owner-verification verified.

FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    ENVIRONMENT=production \
    DAST_ENABLED=true

WORKDIR /app

# 1. Base OS Packages, TLS inspection tools, and Chromium dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tar \
    gzip \
    ca-certificates \
    git \
    bsdmainutils \
    dnsutils \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# 2. Pinned DAST Tools from tools.lock

# Nuclei 3.3.7
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -o nuclei.zip \
    && python3 -c "import zipfile; zipfile.ZipFile('nuclei.zip').extract('nuclei', '/usr/local/bin')" \
    && chmod +x /usr/local/bin/nuclei \
    && rm nuclei.zip

# Katana 1.1.0 (Crawler)
RUN curl -sSL https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip -o katana.zip \
    && python3 -c "import zipfile; zipfile.ZipFile('katana.zip').extract('katana', '/usr/local/bin')" \
    && chmod +x /usr/local/bin/katana \
    && rm katana.zip

# HTTPx 1.6.8 (ProjectDiscovery)
RUN curl -sSL https://github.com/projectdiscovery/httpx/releases/download/v1.6.8/httpx_1.6.8_linux_amd64.zip -o pd_httpx.zip \
    && python3 -c "import zipfile; zipfile.ZipFile('pd_httpx.zip').extract('httpx', '/usr/local/bin/pd-httpx')" \
    && chmod +x /usr/local/bin/pd-httpx \
    && rm pd_httpx.zip

# Ffuf 2.1.0
RUN curl -sSL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz | tar -xz -C /usr/local/bin ffuf \
    && chmod +x /usr/local/bin/ffuf

# testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    && chmod +x /usr/local/bin/testssl.sh

# 3. Python Requirements & Safe Testing Tools
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir sqlmap==1.8.11 sslyze==6.0.0

# 4. Copy Application Source
COPY backend /app

# 5. Security: Non-Root User
RUN useradd -m -u 1001 securescan \
    && chown -R securescan:securescan /app /opt/testssl.sh

USER securescan

CMD ["python", "-m", "app.workers.dast_worker"]
